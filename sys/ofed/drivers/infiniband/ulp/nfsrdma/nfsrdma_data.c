/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 VersatusHPC
 *	Vinícius Ferrão <ferrao@versatushpc.com.br>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "nfsrdma_var.h"

static void	svc_rdma_read_extfree(struct mbuf *m);
static int	svc_rdma_read_start(struct svc_rdma_conn *conn,
	    struct svc_rdma_recv *rr, const struct svc_rdma_msg *msg, uint32_t len);
static void	svc_rdma_repost(struct svc_rdma_conn *conn,
	    struct svc_rdma_recv *rr);
static void	svc_rdma_wc_rdma_read(struct ib_cq *cq, struct ib_wc *wc);
static void	svc_rdma_read_sink_detach(struct svc_rdma_conn *conn,
	    struct svc_rdma_read_state *rs, void **bufp, u64 *dmap,
	    uint32_t *maplenp);
static void	svc_rdma_read_sink_free_detached(void *buf);
static void	svc_rdma_wc_rdma_write(struct ib_cq *cq, struct ib_wc *wc);

/*
 * ext_free for the read sink, run once at the last reference.  It must not
 * touch the device: the mbuf is nfsd-owned and can outlive the connection, so
 * the ib_device may already be gone.  The mapping is torn down in the read
 * completion instead, leaving the mbuf owning plain memory.
 */
static void
svc_rdma_read_extfree(struct mbuf *m)
{
	void *buf = m->m_ext.ext_arg1;

	/*
	 * Recycle rather than free: the buffer is plain unmapped contiguous
	 * memory by now, and returning it to the free list keeps its KVA out
	 * of kmem and avoids the per-write TLB shootdown.
	 */
	svc_rdma_sink_put(buf);
}

/*
 * Receive completion, in IB_POLL_WORKQUEUE context: a workqueue thread, but
 * treated as non-sleepable, so no sleepable lock and no blocking teardown.
 * The device caps wc->byte_len at the posted SGE length, and it is
 * bounds-checked again before any header word is read.
 */
void
svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	uint32_t len;
	bool ready;

	/*
	 * The quiescence counters assume IB_POLL_WORKQUEUE: one work item per
	 * CQ, which cannot run concurrently with itself, so completions on a CQ
	 * are serialized.  The two CQs still run together, hence sc_lock.  A
	 * different poll context would reopen the completion-versus-teardown
	 * hazard, so assert rather than fail quietly.
	 */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	rr = container_of(wc->wr_cqe, struct svc_rdma_recv, rr_cqe);
	conn = rr->rr_conn;

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * A flush is expected for every recv WR as the QP drains and
		 * the teardown frees the buffers, so it is swallowed; anything
		 * else closes without reposting.  This returns before
		 * sc_reposts is touched, since a flush is not an in-flight
		 * repost, and a flush reaped during ib_drain_qp() still sees a
		 * live conn.
		 */
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: recv completion error %u\n",
				    wc->status);
			svc_rdma_conn_close(conn);
		}
		return;
	}

	/*
	 * Parse before reposting.  The device already caps wc->byte_len at the
	 * posted SGE length, but clamping again means the parser can never be
	 * told the buffer is larger than it is; it gates every word read on
	 * that length, so a truncated header errors rather than overreads.
	 */
	len = wc->byte_len;
	if (len > SVC_RDMA_INLINE)
		len = SVC_RDMA_INLINE;

	/*
	 * Sync before the CPU reads what the device wrote: the mapping may be
	 * bounced, and on a weakly ordered machine this is also the load
	 * barrier against the completion.  A no-op on a direct strongly ordered
	 * mapping, but without it an IOMMU path reads stale contents and
	 * rejects every header.
	 */
	ib_dma_sync_single_for_cpu(conn->sc_id->device, rr->rr_dma, len,
	    DMA_FROM_DEVICE);

	/*
	 * Recvs are posted before rdma_accept(), so this can arrive before the
	 * ESTABLISHED handler sets sc_newconn_done.  The call must not be
	 * dropped, since a reliable QP never retransmits a delivered call and a
	 * dropped first RPC hangs the mount; it waits on sc_early instead,
	 * bounded by sc_nrecv / 2 so the RQ cannot deplete.  Held buffers carry
	 * no device WR, so they need no accounting.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state == SC_CLOSING) {
		mtx_unlock(&conn->sc_lock);
		return;
	}
	ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
	if (!ready) {
		/* Hold at most half the RQ depth (>=1) so the RQ never depletes. */
		int cap = max_t(int, conn->sc_nrecv / 2, 1);

		if (conn->sc_nearly < cap) {
			rr->rr_early_len = len;
			STAILQ_INSERT_TAIL(&conn->sc_early, rr, rr_early);
			conn->sc_nearly++;
			mtx_unlock(&conn->sc_lock);
			return;
		}
		mtx_unlock(&conn->sc_lock);
		svc_rdma_conn_close(conn);
		return;
	}
	mtx_unlock(&conn->sc_lock);
	svc_rdma_dispatch_recv(conn, rr, len);
}

/*
 * Parse and dispatch one received call, separate from the recv completion so
 * the ESTABLISHED handler can replay one held on sc_early.  The caller has
 * synced rr_buf and found the connection ready, so the gate below only catches
 * a flip to SC_CLOSING in between.
 */
void
svc_rdma_dispatch_recv(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr,
    uint32_t len)
{
	struct svc_rdma_msg msg;
	int rc;
	bool ready;

	rc = svc_rdma_parse_header(rr->rr_buf, len, &msg);
	if (rc != 0) {
		/*
		 * EBADMSG for a malformed header, EOPNOTSUPP for a well-formed
		 * one over a cap.  The log is rate-limited, the arrival rate
		 * being peer-controlled, and nothing is reposted on a
		 * connection being torn down.
		 */
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
			if (rc == EPROTONOSUPPORT)
				printf("nfsrdma: RPC-over-RDMA version unsupported "
				    "xid=0x%08x, replying ERR_VERS and closing\n",
				    msg.xid);
			else if (rc == EOPNOTSUPP)
				printf("nfsrdma: unsupported RPC-over-RDMA "
				    "request (proc or over fixed cap), closing "
				    "(%u bytes)\n", len);
			else
				printf("nfsrdma: malformed RPC-over-RDMA header "
				    "(%u bytes), closing\n", len);
		}
		/*
		 * Only a version mismatch leaves a trustworthy xid, the parser
		 * having proved the fixed prefix present, so it alone gets an
		 * RDMA_ERROR.  The SEND takes the same gate and barrier as any
		 * reply, so the following close drains it.
		 */
		if (rc == EPROTONOSUPPORT)
			svc_rdma_send_error(conn, msg.xid, ERR_VERS);
		svc_rdma_conn_close(conn);
		return;
	}

	/*
	 * Route by chunk shape.  A read list means the body is not in our
	 * memory yet, so read_start() copies the metadata and inline head into
	 * the durable rr_rs and its completion assembles, dispatches and
	 * reposts.  A bodyless RDMA_NOMSG with no read list is closed.
	 */
	if (msg.rdma_proc == RDMA_NOMSG && msg.rd_nchunks == 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: RPC-over-RDMA v1 RDMA_NOMSG xid=0x%08x "
			    "credit=%u no read list (bodyless), closing\n",
			    msg.xid, msg.credit);
		svc_rdma_conn_close(conn);
		return;
	}

	if (msg.rd_nchunks != 0) {
		rc = svc_rdma_read_start(conn, rr, &msg, len);
		if (rc != 0)
			svc_rdma_conn_close(conn);
		/*
		 * On success the read owns rr_buf until svc_rdma_wc_rdma_read
		 * reposts it; on failure the conn is closing and the teardown
		 * reclaims rr_buf.  Either way: do NOT repost here.
		 */
		return;
	}

	/*
	 * Dispatch only once SC_UP and sc_newconn_done both hold: newconn has
	 * attached its state, and a synchronous send from sro_recv will not see
	 * ENOTCONN.  The count in sc_upcalls is what the teardown drains before
	 * sro_disconnect.  Both callers checked already, so this only catches a
	 * disconnect landing in between.
	 */
	mtx_lock(&conn->sc_lock);
	ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
	if (ready)
		conn->sc_upcalls++;
	mtx_unlock(&conn->sc_lock);
	if (!ready)
		goto repost;

	/*
	 * msg, and msg.rpc pointing into rr_buf, are valid only for this call.
	 * The sc_upcalls count is dropped before the result is acted on: a
	 * nonzero return closes, and the teardown barrier waits for that count,
	 * so holding it across the close would wait on ourselves.
	 */
	rc = 0;
	if (conn->sc_ops != NULL && conn->sc_ops->sro_recv != NULL)
		rc = conn->sc_ops->sro_recv(conn->sc_ctx, conn, &msg);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_upcalls == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		svc_rdma_conn_close(conn);
		return;
	}

repost:
	svc_rdma_repost(conn, rr);
}

/*
 * Repost one recv buffer unless the connection is closing, when the teardown
 * owns it.  The count in sc_reposts is drained before ib_drain_qp(): mlx5 does
 * not reject ib_post_recv() on a QP in error, so without it a repost that lost
 * the CPU could enqueue behind the drain sentinel and flush against a freed
 * connection.  A recv bearing a read list is reposted by the read completion
 * instead.
 */
static void
svc_rdma_repost(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr)
{
	const struct ib_recv_wr *bad_wr;
	int rc;

	mtx_lock(&conn->sc_lock);
	if (conn->sc_state == SC_CLOSING) {
		mtx_unlock(&conn->sc_lock);
		return;
	}
	conn->sc_reposts++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * The mapping and SGE are unchanged, so rr_wr reposts as built, but the
	 * buffer goes back to the device first: the CPU just read the previous
	 * receive out of it, and the DMA API requires the matching
	 * sync_for_device to re-arm a bounce mapping and order the device's
	 * writes after those reads.  A no-op on a direct mapping.
	 */
	ib_dma_sync_single_for_device(conn->sc_id->device, rr->rr_dma,
	    SVC_RDMA_INLINE, DMA_FROM_DEVICE);
	rc = ib_post_recv(conn->sc_id->qp, &rr->rr_wr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_reposts == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_recv (repost) failed: %d\n",
			    rc);
		svc_rdma_conn_close(conn);
	}
}

/*
 * RDMA Read engine, for inbound NFS WRITE data and large call arguments.  The
 * read list is pulled into one contiguous buffer and spliced with the inline
 * head at its rdma_position (RFC 8166 4.3).  Segments are re-validated at post
 * time, since that buffer is sized from their sum; the handle and offset reach
 * the HCA unchanged, so a bad rkey fails the WR and closes.
 *
 * The chain is accounted in sc_sends under SC_UP, so the teardown barrier
 * waits it out.  Buffer and mapping live in the recv's durable rr_rs, released
 * once by the read completion or the teardown, with rs_active and rs_mapped as
 * the idempotency tokens.
 */

/*
 * Start the RDMA Read from the recv completion, with msg still pointing into
 * rr_buf.  The message and inline head are copied into the durable rr_rs
 * first, so nothing the read uses points into rr_buf.  On success the read
 * owns rr_buf until its completion reposts it; a nonzero return has already
 * released everything.
 */
static int
svc_rdma_read_start(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr,
    const struct svc_rdma_msg *msg, uint32_t len)
{
	struct svc_rdma_read_state *rs = &rr->rr_rs;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t total;
	uint32_t i, n;
	int rc;

	n = msg->rd_nchunks;

	/*
	 * Re-check the shape at post time, so this engine is correct
	 * independently of the parser and a later parser change cannot let an
	 * over-cap request reach the HCA.
	 */
	if (n == 0 || n > SVC_RDMA_MAX_READ_SEGS)
		return (EINVAL);

	/*
	 * Re-total the inbound length in uint64, with each length and the count
	 * capped, so it cannot wrap.  The server buffer is sized from this
	 * value rather than from a peer field.
	 */
	total = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = msg->reads[i].rc_seg.rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN)
			return (EINVAL);
		total += slen;
	}
	if (total == 0 || total > SVC_RDMA_MAX_READ)
		return (EMSGSIZE);

	/*
	 * Copy the parsed call and inline head into the durable rr_rs, after
	 * which nothing the read uses points into rr_buf.  rs_head holds the
	 * bytes the read data splices into, capped at SVC_RDMA_INLINE.
	 */
	rs->rs_msg = *msg;
	rs->rs_total = (uint32_t)total;
	rs->rs_headlen = msg->rpc_len;
	/*
	 * rpc_len is already within the received length, but clamp it to both
	 * that and the buffer size so it can never drive a copy past the bytes
	 * that actually landed.
	 */
	rs->rs_headlen = min_t(uint32_t, rs->rs_headlen, len);
	rs->rs_headlen = min_t(uint32_t, rs->rs_headlen, SVC_RDMA_INLINE);
	rs->rs_head = malloc(SVC_RDMA_INLINE, M_NFSRDMA, M_NOWAIT);
	if (rs->rs_head == NULL)
		return (ENOMEM);
	if (rs->rs_headlen != 0)
		memcpy(rs->rs_head, msg->rpc, rs->rs_headlen);

	/*
	 * Take a pre-mapped pool buffer when free: rs_rb records the borrow and
	 * rs_mapped stays false, since the pool owns that mapping.  The buffer
	 * must be physically contiguous, as ib_dma_map_single() maps one region
	 * from the first page and a scattered allocation would land the data in
	 * the wrong physical pages.
	 */
	rs->rs_rb = NULL;
	mtx_lock(&conn->sc_lock);
	{
		int rbk;
		for (rbk = 0; rbk < conn->sc_nrbpool; rbk++) {
			if (!conn->sc_rbpool[rbk].rb_inuse) {
				conn->sc_rbpool[rbk].rb_inuse = true;
				rs->rs_rb = &conn->sc_rbpool[rbk];
				break;
			}
		}
	}
	mtx_unlock(&conn->sc_lock);
	/*
	 * Re-stock a slot a previous zero-copy detach emptied, off the latency
	 * path and outside sc_lock so the allocation and map do not nest the
	 * DMA lock under it.  On failure the slot goes back and the fallback
	 * runs.
	 */
	if (rs->rs_rb != NULL && rs->rs_rb->rb_buf == NULL) {
		struct svc_rdma_readbuf *rb = rs->rs_rb;
		void *nbuf;
		u64 ndma;

		nbuf = svc_rdma_sink_get();
		if (nbuf != NULL) {
			ndma = ib_dma_map_single(dev, nbuf, SVC_RDMA_MAX_READ,
			    DMA_FROM_DEVICE);
			if (ib_dma_mapping_error(dev, ndma)) {
				svc_rdma_sink_put(nbuf);
				nbuf = NULL;
			}
		}
		if (nbuf == NULL) {
			/* Re-stock failed: release the slot, take the fallback. */
			mtx_lock(&conn->sc_lock);
			rb->rb_inuse = false;
			mtx_unlock(&conn->sc_lock);
			rs->rs_rb = NULL;
		} else {
			rb->rb_buf = nbuf;
			rb->rb_dma = ndma;
			rb->rb_mapped = true;
		}
	}
	if (rs->rs_rb != NULL) {
		rs->rs_buf = rs->rs_rb->rb_buf;
		rs->rs_dma = rs->rs_rb->rb_dma;
		rs->rs_mapped = false;	/* pool owns the mapping; not per-read */
		/* Hand the buffer to the device for this read (DMA_FROM_DEVICE). */
		ib_dma_sync_single_for_device(dev, rs->rs_dma, rs->rs_total,
		    DMA_FROM_DEVICE);
	} else {
		/*
		 * Otherwise borrow from the recycle list and map it.  The
		 * buffer is full size but only the rs_total prefix is mapped,
		 * so the detach and release paths use that same length.
		 */
		rs->rs_buf = svc_rdma_sink_get();
		if (rs->rs_buf == NULL) {
			free(rs->rs_head, M_NFSRDMA);
			rs->rs_head = NULL;
			return (ENOMEM);
		}
		rs->rs_dma = ib_dma_map_single(dev, rs->rs_buf, rs->rs_total,
		    DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(dev, rs->rs_dma)) {
			svc_rdma_sink_put(rs->rs_buf);
			rs->rs_buf = NULL;
			free(rs->rs_head, M_NFSRDMA);
			rs->rs_head = NULL;
			return (EIO);
		}
		/*
		 * Mark the mapping live straight after the map, before the
		 * state check, since the release path unmaps only when this is
		 * set: setting it inside that check would let a teardown racing
		 * between the map and the lock free the buffer with the mapping
		 * still live.
		 */
		rs->rs_mapped = true;	/* fallback mapping; read_free unmaps it */
	}

	/*
	 * One read WR per segment, each with a local SGE at the running offset
	 * within rs_buf and the peer's rkey and address unchanged.  Only the
	 * last is signaled, so one completion fires for the chain, and every
	 * wr_cqe aliases &rs_cqe so it recovers the state.
	 */
	{
		uint32_t off = 0;

		rs->rs_nwr = n;
		rs->rs_cqe.done = svc_rdma_wc_rdma_read;
		for (i = 0; i < n; i++) {
			const struct svc_rdma_segment *seg =
			    &msg->reads[i].rc_seg;
			uint32_t slen = seg->rs_length;

			rs->rs_sge[i].addr = rs->rs_dma + off;
			rs->rs_sge[i].length = slen;
			rs->rs_sge[i].lkey = conn->sc_pd->local_dma_lkey;

			memset(&rs->rs_wr[i], 0, sizeof(rs->rs_wr[i]));
			rs->rs_wr[i].wr.wr_cqe = &rs->rs_cqe;
			rs->rs_wr[i].wr.sg_list = &rs->rs_sge[i];
			rs->rs_wr[i].wr.num_sge = 1;
			rs->rs_wr[i].wr.opcode = IB_WR_RDMA_READ;
			rs->rs_wr[i].wr.send_flags = 0;
			rs->rs_wr[i].remote_addr = seg->rs_offset;
			rs->rs_wr[i].rkey = seg->rs_handle;
			rs->rs_wr[i].wr.next = (i + 1 < n) ?
			    &rs->rs_wr[i + 1].wr : NULL;
			off += slen;
		}
		/* Signal only the tail -- one completion for the whole chain. */
		rs->rs_wr[n - 1].wr.send_flags = IB_SEND_SIGNALED;
	}

	/*
	 * Arm and post as svc_rdma_conn_send() does: one sc_lock section checks
	 * SC_UP, marks the read in flight and counts it in sc_sends, and the
	 * post runs with the lock dropped.  rs_active is set before the post,
	 * since a partially committed chain flushes its prefix and those
	 * completions must find it set to claim the reclaim.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		/*
		 * Tearing down before anything was posted, so no completion
		 * will fire and this read can be reclaimed inline.  That is
		 * safe only because nothing reached the SQ.
		 */
		svc_rdma_read_free(conn, rr);
		return (ENOTCONN);
	}
	rs->rs_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp, &rs->rs_wr[0].wr, &bad_wr);

	/*
	 * mlx5 builds WQEs one at a time and rings the doorbell for the prefix
	 * already built even when it returns an error, so on failure some reads
	 * are live and will write into rs_buf.  Reclaiming inline would be a
	 * DMA-after-free, so the teardown is the single reclaimer; sc_sends is
	 * still dropped, since the post itself has finished and the barrier
	 * must reach zero to drain that prefix.
	 */
	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (RDMA Read) failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);
}

/*
 * Move the read sink out of rr_rs for the zero-copy mbuf; the caller unmaps it
 * while the device is still alive, then wraps the plain memory in an
 * EXT_DISPOSABLE mbuf.  *maplenp returns the length it was mapped at so that
 * unmap matches.  Under sc_lock, so the fields flip atomically against a
 * concurrent release or teardown, which then finds nothing to do.
 */
static void
svc_rdma_read_sink_detach(struct svc_rdma_conn *conn,
    struct svc_rdma_read_state *rs, void **bufp, u64 *dmap, uint32_t *maplenp)
{
	mtx_lock(&conn->sc_lock);
	if (rs->rs_rb != NULL) {
		*bufp = rs->rs_rb->rb_buf;
		*dmap = rs->rs_rb->rb_dma;
		*maplenp = SVC_RDMA_MAX_READ;	/* pool slot mapped at MAX_READ */
		rs->rs_rb->rb_buf = NULL;	/* evacuated: pool no longer owns it */
		rs->rs_rb->rb_dma = 0;
		rs->rs_rb->rb_mapped = false;
		rs->rs_rb->rb_inuse = false;	/* slot free to be re-stocked */
		rs->rs_rb = NULL;
	} else {
		*bufp = rs->rs_buf;
		*dmap = rs->rs_dma;
		*maplenp = rs->rs_total;	/* fallback mapped at rs_total */
	}
	rs->rs_buf = NULL;
	rs->rs_dma = 0;
	rs->rs_mapped = false;		/* read_free now unmaps/frees nothing for the sink */
	mtx_unlock(&conn->sc_lock);
}

/*
 * Unwind a detached sink that no mbuf took ownership of.  The caller unmapped
 * it before the allocation, so this is plain memory and only needs freeing,
 * with no device touch, as in svc_rdma_read_extfree().
 */
static void
svc_rdma_read_sink_free_detached(void *buf)
{
	svc_rdma_sink_put(buf);		/* recycle, do not free() */
}

/*
 * Release the durable read state exactly once.  Reclaim is driven by
 * rs_mapped, rs_buf and rs_head, not by the completion one-shot rs_active, so
 * either reclaimer may call this and the second is a no-op.  Call it without
 * sc_lock, since ib_dma_unmap_single() takes its own.  The mapping must stay
 * live until the device is done writing, which is why the teardown reclaims
 * only after ib_free_cq(); ib_drain_qp() alone does not quiesce that queue.
 */
void
svc_rdma_read_free(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr)
{
	struct svc_rdma_read_state *rs = &rr->rr_rs;
	struct ib_device *dev;

	/*
	 * A pooled buffer goes back to the free list, neither unmapped nor
	 * freed, since the pool owns both.  rs_rb keeps it idempotent: both
	 * reclaimers may call this, but only the one finding rs_rb non-NULL
	 * returns the buffer.  Under sc_lock so rb_inuse and rs_rb flip
	 * atomically, and the lock is dropped before the unmap below, which
	 * takes its own.
	 */
	mtx_lock(&conn->sc_lock);
	if (rs->rs_rb != NULL) {
		rs->rs_rb->rb_inuse = false;
		rs->rs_rb = NULL;
		rs->rs_buf = NULL;	/* belongs to the pool; do not free below */
		rs->rs_dma = 0;
		rs->rs_mapped = false;
	}
	mtx_unlock(&conn->sc_lock);

	/* Fallback buffer: unmap + free exactly once (idempotent via rs_mapped/rs_buf). */
	if (rs->rs_mapped) {
		dev = (conn->sc_id != NULL) ? conn->sc_id->device : NULL;
		if (dev != NULL)
			ib_dma_unmap_single(dev, rs->rs_dma, rs->rs_total,
			    DMA_FROM_DEVICE);
		rs->rs_mapped = false;
	}
	if (rs->rs_buf != NULL) {
		svc_rdma_sink_put(rs->rs_buf);	/* recycle, do not free() */
		rs->rs_buf = NULL;
	}
	if (rs->rs_head != NULL) {
		free(rs->rs_head, M_NFSRDMA);
		rs->rs_head = NULL;
	}
	rs->rs_active = false;
}

/*
 * RDMA Read completion.  A chained post can deliver more than one: only the
 * tail is signaled, but flush and error CQEs are reported for the prefix too,
 * so rs_active is a one-shot tested and cleared under sc_lock.
 *
 * On success the body is assembled as head[0, pos), the read data, then
 * head[pos, headlen); the parser rejected a list whose segments disagree on
 * that position.  On error or flush rs_active is cleared but rr_rs is not
 * freed, leaving the teardown as the single reclaimer, gated by rs_mapped and
 * rs_buf instead.
 *
 * Every completion for this read lands on the send CQ, whose work item cannot
 * run concurrently with itself, and the recv owning rr_rs is never reposted
 * while rs_active.
 */
static void
svc_rdma_wc_rdma_read(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_read_state *rs;
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	uint32_t pos, bodylen;
	int rc;
	bool ready, first;

	/* Same single-workqueue-thread invariant as the other wc handlers. */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	rs = container_of(wc->wr_cqe, struct svc_rdma_read_state, rs_cqe);
	rr = container_of(rs, struct svc_rdma_recv, rr_rs);
	conn = rr->rr_conn;

	/*
	 * Only the first completion for this read proceeds; a duplicate finds
	 * rs_active already clear and returns, so the dispatch, release and
	 * repost happen once.
	 */
	mtx_lock(&conn->sc_lock);
	first = rs->rs_active;
	rs->rs_active = false;
	mtx_unlock(&conn->sc_lock);
	if (!first)
		return;

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * A flush during teardown is expected and rr_rs is reclaimed
		 * there, so its tokens are left set; any other status,
		 * including a bad peer rkey, closes.  Neither path frees or
		 * reposts: the teardown owns both.
		 */
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: RDMA Read completion error %u "
				    "(bad rkey/addr/len or fault), closing\n",
				    wc->status);
			svc_rdma_conn_close(conn);
		}
		return;
	}

	/*
	 * The splice point is where the read data belongs in the XDR stream,
	 * clamped to the head length so a peer position cannot index past it.
	 * Both lengths are capped, so their sum cannot overflow.
	 */
	pos = rs->rs_msg.reads[0].rc_position;
	pos = min_t(uint32_t, pos, rs->rs_headlen);
	bodylen = rs->rs_headlen + rs->rs_total;

	/*
	 * Sync the sink before the CPU reads it: the mapping may be bounced, so
	 * the data is only guaranteed visible afterwards.  Without it a bounced
	 * read leaves stale bytes in the assembled body.
	 */
	ib_dma_sync_single_for_cpu(conn->sc_id->device, rs->rs_dma,
	    rs->rs_total, DMA_FROM_DEVICE);

	/*
	 * Assemble without copying the data: the chain is
	 *     head[0,pos) -> the sink as external storage -> head[pos,headlen)
	 * so only the two small head fragments are copied and the middle
	 * segment wraps the sink under its own ext_free.  Ownership passes to
	 * that mbuf, so the teardown never touches the sink afterwards.
	 * Everything here is M_NOWAIT and a failure drops the call.
	 */
	{
		struct mbuf *mhead, *mext, *mt;
		struct svc_rdma_write_chunk reply = { 0 };
		void *sinkbuf;
		u64 sinkdma;
		uint32_t sinkmaplen, xid = 0;
		bool has_reply = false;

		/*
		 * Take the sink out of rr_rs and unmap it here, while the
		 * connection and device are still alive; the data is already
		 * coherent from the sync above, so the sink becomes plain
		 * memory.  The mbuf outlives the connection, and an ext_free
		 * touching a released device would be a use-after-free.
		 */
		svc_rdma_read_sink_detach(conn, rs, &sinkbuf, &sinkdma, &sinkmaplen);
		ib_dma_unmap_single(conn->sc_id->device, sinkdma, sinkmaplen,
		    DMA_FROM_DEVICE);

		/* The EXT segment over the (now plain-memory) sink. */
		mext = m_get(M_NOWAIT, MT_DATA);
		if (mext == NULL) {
			/* No mbuf took the sink yet: free the plain buffer, once. */
			svc_rdma_read_sink_free_detached(sinkbuf);
			svc_rdma_read_free(conn, rr);	/* frees rs_head */
			svc_rdma_repost(conn, rr);
			return;
		}

		/*
		 * EXT_DISPOSABLE wraps the sink, with the buffer pointer as
		 * ext_arg1 for the ext_free.  flags is 0 because
		 * EXT_DISPOSABLE already selects the embedded-refcount branch,
		 * so the free fires once even if the chain is copied and
		 * passing the flag would set a stray m_flags bit.
		 */
		m_extadd(mext, (char *)sinkbuf, rs->rs_total,
		    svc_rdma_read_extfree, sinkbuf, NULL, 0, EXT_DISPOSABLE);
		mext->m_len = rs->rs_total;

		/*
		 * The chain head carries the pkthdr, pre-sized so the copy
		 * cannot truncate on extend.
		 */
		mhead = m_getm2(NULL, pos, M_NOWAIT, MT_DATA, M_PKTHDR);
		if (mhead == NULL) {
			m_freem(mext);		/* releases sink via ext_free, once */
			svc_rdma_read_free(conn, rr);
			svc_rdma_repost(conn, rr);
			return;
		}
		if (pos != 0)
			m_copyback(mhead, 0, pos, rs->rs_head);
		mhead->m_next = mext;

		/* head[pos,headlen): the post-splice tail, if any. */
		if (rs->rs_headlen > pos) {
			uint32_t tlen = rs->rs_headlen - pos;

			mt = m_getm2(NULL, tlen, M_NOWAIT, MT_DATA, 0);
			if (mt == NULL) {
				/* mhead owns mext (and thus the sink): one m_freem. */
				m_freem(mhead);
				svc_rdma_read_free(conn, rr);
				svc_rdma_repost(conn, rr);
				return;
			}
			m_copyback(mt, 0, tlen, rs->rs_head + pos);
			mext->m_next = mt;
		}
		mhead->m_pkthdr.len = bodylen;

		/*
		 * Snapshot the reply-chunk identity before the release.  rs_msg
		 * is durable storage the release does not touch today, but
		 * reading it afterwards would be fragile.
		 */
		xid = rs->rs_msg.xid;
		has_reply = rs->rs_msg.reply_present;
		if (has_reply)
			reply = rs->rs_msg.reply;	/* pure value copy */

		/* rs_head is copied into the small mbufs; the sink already detached. */
		svc_rdma_read_free(conn, rr);

		/*
		 * Same readiness gate and upcall barrier as the inline path.
		 * Every branch that counted an upcall drops it again, since a
		 * leak would hang the teardown, and the chain is freed once:
		 * sro_recv_mbuf owns it on a 0 return, this frees it otherwise.
		 * rr_buf is reposted only as this returns, which keeps rr_rs
		 * single-owner; the consumer-reject path closes instead, and
		 * the teardown then owns rr_buf.
		 */
		mtx_lock(&conn->sc_lock);
		ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
		if (ready)
			conn->sc_upcalls++;
		mtx_unlock(&conn->sc_lock);

		if (ready && conn->sc_ops != NULL &&
		    conn->sc_ops->sro_recv_mbuf != NULL) {
			rc = conn->sc_ops->sro_recv_mbuf(conn->sc_ctx, conn,
			    mhead, xid, has_reply, &reply);
			mtx_lock(&conn->sc_lock);
			if (--conn->sc_upcalls == 0)
				wakeup(&conn->sc_upcalls);
			mtx_unlock(&conn->sc_lock);
			if (rc != 0) {
				/* Consumer rejected: it did NOT take the chain. */
				m_freem(mhead);
				svc_rdma_conn_close(conn);
				return;		/* closing: do NOT repost */
			}
			/* On rc == 0 the consumer owns mhead; do not touch it. */
		} else {
			/* Not ready / no consumer: we still own the chain. */
			m_freem(mhead);
			if (ready) {
				mtx_lock(&conn->sc_lock);
				if (--conn->sc_upcalls == 0)
					wakeup(&conn->sc_upcalls);
				mtx_unlock(&conn->sc_lock);
			}
		}

		/* Normal completion: repost rr_buf for the next call (original). */
		svc_rdma_repost(conn, rr);
		return;
	}
}

/*
 * RDMA Write engine, for outbound NFS READ data and large replies: the reply
 * goes into the memory the client pre-registered, then a header reports the
 * lengths written.  Segments are re-validated at post time and each takes at
 * most its own length, so a short later segment cannot over-write; the handle
 * and offset reach the HCA unchanged for it to enforce against the MR.
 *
 * sc_sends accounts only the post call, so it is ib_drain_qp() that quiesces
 * the WRs.  State is threaded on sc_writes and released once, by the tail SEND
 * completion or the teardown, with ws_active and the mapped flags as the
 * idempotency tokens.  mlx5 commits prefix WQEs even when the post fails, so a
 * failed post never reclaims inline.
 */

/*
 * Release one outbound write state exactly once, driven by ws_src_mapped,
 * ws_hdr_mapped and the buffer pointers rather than by ws_active, so a second
 * call is a no-op.  The caller has already detached ws from sc_writes, or is
 * the teardown draining the list, so this never touches the list.  The source
 * mapping must stay live until the device is done reading, which is why the
 * teardown reclaims only after ib_free_cq().
 */
void
svc_rdma_write_free(struct svc_rdma_write_state *ws)
{
	struct svc_rdma_conn *conn = ws->ws_conn;
	struct ib_device *dev;

	dev = (conn != NULL && conn->sc_id != NULL) ? conn->sc_id->device : NULL;

	/*
	 * Every caller has removed ws from sc_writes, or never inserted it, and
	 * cleared ws_active first, so a freed write is never left on the
	 * registry for a stale completion to find.
	 */
	MPASS(!ws->ws_active);

	/*
	 * The loop runs over ws_npgs, not ws_nwr, since one WR gathers several
	 * pages and counting by WR would leak.  ws_npgs grows as pages map, so
	 * a failure part way through unmaps exactly the mapped prefix.
	 */
	if (ws->ws_pages_mapped) {
		uint32_t p;

		for (p = 0; p < ws->ws_npgs; p++)
			if (dev != NULL)
				ib_dma_unmap_single(dev, ws->ws_pg_dma[p],
				    ws->ws_pg_len[p], DMA_TO_DEVICE);
		ws->ws_pages_mapped = false;
	}

	if (ws->ws_src_mapped) {
		if (dev != NULL)
			ib_dma_unmap_single(dev, ws->ws_src_dma, ws->ws_srclen,
			    DMA_TO_DEVICE);
		ws->ws_src_mapped = false;
	}
	if (ws->ws_hdr_mapped) {
		if (dev != NULL)
			ib_dma_unmap_single(dev, ws->ws_hdr_dma, ws->ws_hdrlen,
			    DMA_TO_DEVICE);
		ws->ws_hdr_mapped = false;
	}
	if (ws->ws_src != NULL) {
		if (ws->ws_src_pooled)
			svc_rdma_sink_put(ws->ws_src);	/* recycle */
		else
			free(ws->ws_src, M_NFSRDMA);
		ws->ws_src = NULL;
	}
	if (ws->ws_hdr != NULL) {
		free(ws->ws_hdr, M_NFSRDMA);
		ws->ws_hdr = NULL;
	}
	/*
	 * Free the source chain last: the device read its pages, so it had to
	 * outlive the write, and this is the only reference drop.
	 */
	if (ws->ws_keepm != NULL) {
		m_freem(ws->ws_keepm);
		ws->ws_keepm = NULL;
	}
	ws->ws_active = false;
	free(ws, M_NFSRDMA);
}

/*
 * Write an over-inline reply into the client's reply chunk and send the
 * RDMA_NOMSG header reporting the length.  Runs on a krpc pool thread under
 * the consumer's per-connection lock, the same caller-reference rule as
 * svc_rdma_conn_send(), and does not sleep.  buf and len are the ONC RPC body
 * only.  A nonzero return has already released everything for a never-posted
 * attempt; a posted-but-failed chain is left to the teardown.
 */
int
svc_rdma_conn_reply_chunk(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *reply, const void *buf, uint32_t len)
{
	struct svc_rdma_write_state *ws;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t capacity;
	uint32_t i, n, off, remaining, hdrlen;
	char *h;
	int rc;

	/*
	 * len is the server's own marshalled reply size.  Zero is a caller bug,
	 * and anything over the whole-reply cap is refused rather than written.
	 */
	if (len == 0 || len > SVC_RDMA_MAX_WRITE)
		return (EINVAL);

	/*
	 * Re-check the chunk shape at post time, so this engine is correct
	 * independently of the parser and a later parser change cannot let an
	 * over-cap chunk reach the HCA.
	 */
	n = reply->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS)
		return (EINVAL);

	/*
	 * Sum the offered capacity without overflow, re-checking each length.
	 * A reply that does not fit returns EMSGSIZE and writes nothing.
	 * Exactly len bytes are written, each segment capped at its own length.
	 */
	capacity = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN)
			return (EINVAL);
		capacity += slen;
	}
	if ((uint64_t)len > capacity)
		return (EMSGSIZE);

	/*
	 * The write state outlives this call, since the writes and the header
	 * SEND complete later.  M_NOWAIT because xp_reply may run under the
	 * consumer's leaf mutex.
	 */
	ws = malloc(sizeof(*ws), M_NFSRDMA, M_NOWAIT);
	if (ws == NULL)
		return (ENOMEM);
	ws->ws_conn = conn;
	ws->ws_src = NULL;
	ws->ws_src_mapped = false;
	ws->ws_src_pooled = false;
	ws->ws_hdr = NULL;
	ws->ws_hdr_mapped = false;
	ws->ws_active = false;
	ws->ws_pages_mapped = false;
	ws->ws_npgs = 0;
	ws->ws_keepm = NULL;

	/*
	 * Copy the reply into the source buffer and map it, since the HCA reads
	 * from here.  It is sized by the server's own length.
	 */
	ws->ws_srclen = len;
	/*
	 * Like the read sink, the source must be physically contiguous for
	 * ib_dma_map_single(), or a multi-page reply would source the wrong
	 * physical pages.
	 */
	ws->ws_src = contigmalloc(len, M_NFSRDMA, M_NOWAIT, 0, ~(vm_paddr_t)0,
	    PAGE_SIZE, 0);
	if (ws->ws_src == NULL) {
		free(ws, M_NFSRDMA);
		return (ENOMEM);
	}
	memcpy(ws->ws_src, buf, len);
	ws->ws_src_dma = ib_dma_map_single(dev, ws->ws_src, len, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_src_dma)) {
		free(ws->ws_src, M_NFSRDMA);
		free(ws, M_NFSRDMA);
		return (EIO);
	}
	ws->ws_src_mapped = true;

	/*
	 * The RDMA_NOMSG header: the fixed prefix, two empty lists, then the
	 * counted reply chunk, whose segments echo the client's handle and
	 * offset with the length actually written into each.
	 */
	hdrlen = RPCRDMA_HDR_FIXED + 2 * RPCRDMA_WORD +
	    2 * RPCRDMA_WORD +
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD);
	ws->ws_hdrlen = hdrlen;
	ws->ws_hdr = malloc(hdrlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);
	be32enc(h +  4, RPCRDMA_VERSION);
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);
	be32enc(h + 12, RDMA_NOMSG);
	be32enc(h + 16, 0);
	be32enc(h + 20, 0);
	be32enc(h + 24, 1);
	be32enc(h + 28, n);
	off = 32;
	remaining = len;
	for (i = 0; i < n; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;
		uint32_t wlen = min_t(uint32_t, remaining, slen);

		be32enc(h + off + 0, reply->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);
		be64enc(h + off + 8, reply->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, hdrlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * One write WR per segment that carries bytes, each with a local SGE
	 * into ws_src and the peer's rkey and address unchanged.  The writes
	 * are unsignaled and the header SEND is chained last and signaled, so
	 * one completion fires for the chain.
	 *
	 * That SEND's wr_cqe aliases &ws_cqe while the writes route to the
	 * per-connection sink, so a flushed write cannot deliver a duplicate
	 * completion for this state.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	off = 0;			/* source offset within ws_src */
	remaining = len;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;
		uint32_t wlen = min_t(uint32_t, remaining, slen);
		int k = ws->ws_nwr;

		ws->ws_sge[k].addr = ws->ws_src_dma + off;
		ws->ws_sge[k].length = wlen;
		ws->ws_sge[k].lkey = conn->sc_pd->local_dma_lkey;

		memset(&ws->ws_wr[k], 0, sizeof(ws->ws_wr[k]));
		ws->ws_wr[k].wr.wr_cqe = &conn->sc_write_sink_cqe;	/* unsignaled: route flush to sink */
		ws->ws_wr[k].wr.sg_list = &ws->ws_sge[k];
		ws->ws_wr[k].wr.num_sge = 1;
		ws->ws_wr[k].wr.opcode = IB_WR_RDMA_WRITE;
		ws->ws_wr[k].wr.send_flags = 0;		/* unsignaled */
		ws->ws_wr[k].remote_addr = reply->wc_segs[i].rs_offset;
		ws->ws_wr[k].rkey = reply->wc_segs[i].rs_handle;
		ws->ws_nwr++;
		off += wlen;		/* bounded by len, no overflow */
		remaining -= wlen;
	}

	/* The tail header SEND, signaled -- one completion for the whole chain. */
	ws->ws_sndsge.addr = ws->ws_hdr_dma;
	ws->ws_sndsge.length = hdrlen;
	ws->ws_sndsge.lkey = conn->sc_pd->local_dma_lkey;
	memset(&ws->ws_sndwr, 0, sizeof(ws->ws_sndwr));
	ws->ws_sndwr.wr_cqe = &ws->ws_cqe;
	ws->ws_sndwr.sg_list = &ws->ws_sndsge;
	ws->ws_sndwr.num_sge = 1;
	ws->ws_sndwr.opcode = IB_WR_SEND;
	ws->ws_sndwr.send_flags = IB_SEND_SIGNALED;
	ws->ws_sndwr.next = NULL;

	/* Link writes -> ... -> header SEND. */
	for (i = 0; i + 1 < (uint32_t)ws->ws_nwr; i++)
		ws->ws_wr[i].wr.next = &ws->ws_wr[i + 1].wr;
	if (ws->ws_nwr > 0)
		ws->ws_wr[ws->ws_nwr - 1].wr.next = &ws->ws_sndwr;

	/*
	 * Arm the barrier and post as svc_rdma_read_start() does: one sc_lock
	 * section checks SC_UP, registers the write on sc_writes, marks it in
	 * flight and counts it in sc_sends; the post runs with the lock
	 * dropped; then the count is dropped and the teardown woken if last.
	 *
	 * ws_active is set before the post, since a partially committed chain
	 * flushes its prefix and those completions must find it set for the
	 * one-shot guard to take ownership of the reclaim.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		/* Nothing posted and not yet on sc_writes, so reclaim here. */
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * Post the writes then the header SEND, which is the chain head when
	 * there are no writes.  bad_wr must be passed: mlx5 dereferences it on
	 * an immediate error.
	 */
	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	/*
	 * mlx5 commits the prefix it built even when the post fails, so nothing
	 * is reclaimed inline: that prefix is live.  A committed write flushes
	 * to the sink, and a committed tail SEND frees the state; if the SEND
	 * was never reached nothing frees it, so the drained teardown is the
	 * single reclaimer and the state stays on sc_writes.
	 *
	 * sc_sends is still dropped, since the post itself finished, and
	 * ib_drain_qp() then quiesces the prefix before the reclaim.
	 */
	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (RDMA Write) failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);
}

/*
 * Flush sink for a chain's unsignaled write WRs, which raise no completion on
 * success, so this is reached only on a flush or a per-WR fault.  It touches
 * no write state, those being owned through the signaled tail SEND; the
 * connection comes from cq->cq_context, and a non-flush fault closes, so a bad
 * client rkey surfaces without waiting for that SEND.
 */
void
svc_rdma_wc_write_sink(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_conn *conn = cq->cq_context;

	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	if (wc->status == IB_WC_SUCCESS)
		return;				/* unsignaled: not expected, ignore */
	if (wc->status == IB_WC_WR_FLUSH_ERR) {
		conn->sc_write_sink_flushes++;	/* QP draining: the SEND closes */
		return;
	}
	conn->sc_write_sink_errs++;
	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: RDMA Write WR error %u (bad rkey/addr/len), "
		    "closing\n", wc->status);
	svc_rdma_conn_close(conn);
}

/*
 * RDMA Write completion.  Only the signaled tail SEND carries &ws_cqe, the
 * unsignaled writes routing to the sink, so this runs once per state and no
 * duplicate can alias one already freed and its address reused.  The
 * connection comes from cq->cq_context without touching ws, and ws is
 * confirmed on sc_writes and active under sc_lock first: the one way it is
 * absent is a SEND racing a teardown that freed it.  That teardown walks
 * sc_writes only after ib_free_cq() has flushed this CQ.
 */
static void
svc_rdma_wc_rdma_write(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_write_state *cand, *ws;
	struct svc_rdma_conn *conn;

	/* Same single-workqueue-thread invariant as the other wc handlers. */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	/*
	 * The connection comes from the CQ context rather than the candidate
	 * state, which a prior completion may already have freed.  cand is only
	 * an address to match against the registry until proven live below.
	 */
	conn = cq->cq_context;
	cand = container_of(wc->wr_cqe, struct svc_rdma_write_state, ws_cqe);

	/*
	 * Search sc_writes for that exact pointer.  Present and still active
	 * means this is the first completion, and whoever removes the state
	 * owns its free; absent means it is already freed and nothing has been
	 * dereferenced.
	 */
	ws = NULL;
	mtx_lock(&conn->sc_lock);
	{
		struct svc_rdma_write_state *p;

		TAILQ_FOREACH(p, &conn->sc_writes, ws_link) {
			if (p == cand && p->ws_active) {
				p->ws_active = false;
				TAILQ_REMOVE(&conn->sc_writes, p, ws_link);
				ws = p;
				break;
			}
		}
	}
	mtx_unlock(&conn->sc_lock);
	if (ws == NULL)
		return;

	/*
	 * The state was created for this connection, whose CQ delivered the
	 * completion, so a mismatch would mean a clobbered pointer or a
	 * cross-connection alias.  Trip here rather than free the wrong state.
	 */
	MPASS(ws->ws_conn == conn);

	if (wc->status != IB_WC_SUCCESS) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: RDMA Write completion error %u "
				    "(bad rkey/addr/len or fault), closing\n",
				    wc->status);
		}
		/*
		 * Close before the free, so SC_CLOSING is published first.  One
		 * faulted write puts the QP in error and flushes every other
		 * write in flight, and publishing on the first makes the SC_UP
		 * gate refuse new ones while the rest drain, so a freed state's
		 * address cannot be handed to a live one.
		 */
		svc_rdma_conn_close(conn);
		svc_rdma_write_free(ws);
		return;
	}

	svc_rdma_write_free(ws);
}

/*
 * Write a DDP-eligible READ's data into the client's write-list chunk and SEND
 * the reduced RDMA_MSG.  The twin of svc_rdma_conn_reply_chunk(), reusing its
 * state, release path, completion handler and one-shot guard.  Two things
 * differ: the source is the read data, and the tail SEND carries the echoed
 * write list then the reduced body, so ws_hdr holds both and must fit one
 * send buffer.
 */
int
svc_rdma_conn_write_list(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *write, void *src,
    uint32_t datalen, const void *reduced, uint32_t reducedlen,
    bool src_pooled)
{
	struct svc_rdma_write_state *ws;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t capacity;
	uint32_t i, n, off, remaining, hdrlen, sendlen;
	char *h;
	int rc;

	/*
	 * datalen is the server's own length.  A zero-length read never reaches
	 * here, and one over the transfer cap is refused rather than written.
	 */
	if (datalen == 0 || datalen > SVC_RDMA_MAX_WRITE) {
		rc = EINVAL;
		goto badsrc;
	}

	/*
	 * Re-check the chunk shape at post time, as reply_chunk does.
	 */
	n = write->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS) {
		rc = EINVAL;
		goto badsrc;
	}

	/*
	 * Sum the offered capacity without overflow, re-checking each length.
	 * Data that does not fit returns EMSGSIZE and writes nothing.
	 */
	capacity = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN) {
			rc = EINVAL;
			goto badsrc;
		}
		capacity += slen;
	}
	if ((uint64_t)datalen > capacity) {
		rc = EMSGSIZE;
		goto badsrc;
	}

	/*
	 * The reduced SEND is the transport header carrying the echoed write
	 * list, then the reduced inline body.  Both must fit one send buffer.
	 */
	hdrlen = RPCRDMA_HDR_FIXED +
	    RPCRDMA_WORD +
	    2 * RPCRDMA_WORD +
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD) +
	    RPCRDMA_WORD +
	    RPCRDMA_WORD;				/* reply chunk absent */
	if ((uint64_t)hdrlen + reducedlen > SVC_RDMA_INLINE) {
		rc = EMSGSIZE;
		goto badsrc;
	}
	sendlen = hdrlen + reducedlen;

	/*
	 * The write state outlives this call, since the writes and the SEND
	 * complete later.  M_NOWAIT because xp_reply runs under a leaf mutex.
	 */
	ws = malloc(sizeof(*ws), M_NFSRDMA, M_NOWAIT);
	if (ws == NULL) {
		rc = ENOMEM;
		goto badsrc;
	}
	ws->ws_conn = conn;
	ws->ws_src = NULL;
	ws->ws_src_mapped = false;
	ws->ws_src_pooled = src_pooled;
	ws->ws_hdr = NULL;
	ws->ws_hdr_mapped = false;
	ws->ws_active = false;
	ws->ws_pages_mapped = false;
	ws->ws_npgs = 0;
	ws->ws_keepm = NULL;

	/*
	 * Take ownership of the caller's source buffer and map it for the HCA
	 * to read.  The caller filled it before taking xr_lock, so the per-READ
	 * copy stays off that critical section.  It is physically contiguous
	 * for the same reason as the reply-chunk source.
	 */
	ws->ws_srclen = datalen;
	ws->ws_src = src;
	ws->ws_src_dma = ib_dma_map_single(dev, ws->ws_src, datalen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_src_dma)) {
		/*
		 * The mapping failed, so ws_src_mapped stays false and the
		 * release path frees the source, pooled or not.
		 */
		svc_rdma_write_free(ws);
		return (EIO);
	}
	ws->ws_src_mapped = true;

	/*
	 * Build the reduced SEND buffer: the header, echoing the chunk with the
	 * bytes actually written, followed by the reduced inline body.
	 */
	ws->ws_hdrlen = sendlen;
	ws->ws_hdr = malloc(sendlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees ws */
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);
	be32enc(h +  4, RPCRDMA_VERSION);
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);
	be32enc(h + 12, RDMA_MSG);
	be32enc(h + 16, 0);
	be32enc(h + 20, 1);
	be32enc(h + 24, n);
	off = 28;
	remaining = datalen;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = min_t(uint32_t, remaining, slen);

		be32enc(h + off + 0, write->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);		/* bytes written into this seg */
		be64enc(h + off + 8, write->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	be32enc(h + off, 0);
	off += RPCRDMA_WORD;
	be32enc(h + off, 0);
	off += RPCRDMA_WORD;
	if (reducedlen > 0)
		memcpy(h + off, reduced, reducedlen);
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, sendlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees both + ws */
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Build the chain into the chunk's segments as reply_chunk does, one
	 * unsignaled write per byte-carrying segment, then chain the reduced
	 * SEND last and signal only that.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	off = 0;			/* source offset within ws_src */
	remaining = datalen;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = min_t(uint32_t, remaining, slen);
		int k = ws->ws_nwr;

		ws->ws_sge[k].addr = ws->ws_src_dma + off;
		ws->ws_sge[k].length = wlen;
		ws->ws_sge[k].lkey = conn->sc_pd->local_dma_lkey;

		memset(&ws->ws_wr[k], 0, sizeof(ws->ws_wr[k]));
		ws->ws_wr[k].wr.wr_cqe = &conn->sc_write_sink_cqe;	/* unsignaled: route flush to sink */
		ws->ws_wr[k].wr.sg_list = &ws->ws_sge[k];
		ws->ws_wr[k].wr.num_sge = 1;
		ws->ws_wr[k].wr.opcode = IB_WR_RDMA_WRITE;
		ws->ws_wr[k].wr.send_flags = 0;		/* unsignaled */
		ws->ws_wr[k].remote_addr = write->wc_segs[i].rs_offset;
		ws->ws_wr[k].rkey = write->wc_segs[i].rs_handle;
		ws->ws_nwr++;
		off += wlen;		/* bounded by datalen, no overflow */
		remaining -= wlen;
	}

	/* The tail reduced-RDMA_MSG SEND, signaled -- one completion per chain. */
	ws->ws_sndsge.addr = ws->ws_hdr_dma;
	ws->ws_sndsge.length = sendlen;
	ws->ws_sndsge.lkey = conn->sc_pd->local_dma_lkey;
	memset(&ws->ws_sndwr, 0, sizeof(ws->ws_sndwr));
	ws->ws_sndwr.wr_cqe = &ws->ws_cqe;
	ws->ws_sndwr.sg_list = &ws->ws_sndsge;
	ws->ws_sndwr.num_sge = 1;
	ws->ws_sndwr.opcode = IB_WR_SEND;
	ws->ws_sndwr.send_flags = IB_SEND_SIGNALED;
	ws->ws_sndwr.next = NULL;

	/* Link writes -> ... -> reduced-RDMA_MSG SEND. */
	for (i = 0; i + 1 < (uint32_t)ws->ws_nwr; i++)
		ws->ws_wr[i].wr.next = &ws->ws_wr[i + 1].wr;
	if (ws->ws_nwr > 0)
		ws->ws_wr[ws->ws_nwr - 1].wr.next = &ws->ws_sndwr;

	/*
	 * Arm and post as svc_rdma_conn_reply_chunk() does, with the same
	 * partial-post discipline on failure.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (write-list READ) failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);

	/*
	 * Failures before the write state exists still own the caller's source
	 * buffer, never attached, so it is freed here.  Later paths free it
	 * through the release path and must not reach this label.
	 */
badsrc:
	/* A pooled buffer goes back to the recycle pool rather than free(). */
	if (src_pooled)
		svc_rdma_sink_put(src);
	else
		free(src, M_NFSRDMA);
	return (rc);
}

/*
 * Zero-copy form of svc_rdma_conn_write_list, with the same contract and
 * lifetime rules.  Only the source differs: the reply's M_EXTPG pages, already
 * wired, are mapped a page at a time and gathered into the write WRs, up to
 * sc_max_send_sge pages per WR and never crossing a segment.
 *
 * The engine owns mrep on every return and frees it, since the device read
 * those pages and they had to outlive the write.
 */
int
svc_rdma_conn_write_list_pages(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *write, struct mbuf *mrep,
    const struct svc_rdma_page *pages, uint32_t npages,
    uint32_t datalen, const void *reduced, uint32_t reducedlen)
{
	struct svc_rdma_write_state *ws;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t capacity, pgsum;
	uint32_t i, n, off, remaining, hdrlen, sendlen, p, pgoff, nsge_total;
	char *h;
	int rc;

	if (datalen == 0 || datalen > SVC_RDMA_MAX_WRITE) {
		rc = EINVAL;
		goto badm;
	}
	n = write->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS) {
		rc = EINVAL;
		goto badm;
	}
	capacity = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN) {
			rc = EINVAL;
			goto badm;
		}
		capacity += slen;
	}
	if ((uint64_t)datalen > capacity) {
		rc = EMSGSIZE;
		goto badm;
	}

	/*
	 * The page vector is server-built, but the lengths must still sum to
	 * exactly datalen so neither more nor less is written.
	 */
	if (npages == 0 || npages > SVC_RDMA_MAX_WRITE_PAGES) {
		rc = EINVAL;
		goto badm;
	}
	pgsum = 0;
	for (p = 0; p < npages; p++) {
		if (pages[p].pg_len == 0 || pages[p].pg_len > PAGE_SIZE) {
			rc = EINVAL;
			goto badm;
		}
		pgsum += pages[p].pg_len;
	}
	if (pgsum != datalen) {
		rc = EINVAL;
		goto badm;
	}

	/* The same header size check as write_list. */
	hdrlen = RPCRDMA_HDR_FIXED + RPCRDMA_WORD + 2 * RPCRDMA_WORD +
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD) + RPCRDMA_WORD + RPCRDMA_WORD;
	if ((uint64_t)hdrlen + reducedlen > SVC_RDMA_INLINE) {
		rc = EMSGSIZE;
		goto badm;
	}
	sendlen = hdrlen + reducedlen;

	ws = malloc(sizeof(*ws), M_NFSRDMA, M_NOWAIT);
	if (ws == NULL) {
		rc = ENOMEM;
		goto badm;
	}
	ws->ws_conn = conn;
	ws->ws_src = NULL;
	ws->ws_src_mapped = false;
	ws->ws_src_pooled = false;
	ws->ws_hdr = NULL;
	ws->ws_hdr_mapped = false;
	ws->ws_active = false;
	ws->ws_pages_mapped = false;
	ws->ws_npgs = 0;
	ws->ws_srclen = datalen;
	/*
	 * The state owns mrep from here, so every later error path frees it
	 * exactly once through the release path.  It is set before the map loop
	 * for that reason.
	 */
	ws->ws_keepm = mrep;

	/*
	 * ws_npgs grows as the pages map, so a failure part way through unmaps
	 * exactly the mapped prefix with no manual unwind.  Each page is wired
	 * and reachable through the direct map.
	 */
	for (p = 0; p < npages; p++) {
		u64 d = ib_dma_map_single(dev,
		    (void *)(PHYS_TO_DMAP(pages[p].pg_pa) + pages[p].pg_off),
		    pages[p].pg_len, DMA_TO_DEVICE);

		if (ib_dma_mapping_error(dev, d)) {
			svc_rdma_write_free(ws);	/* unmaps prefix, m_freem(mrep) */
			return (EIO);
		}
		ws->ws_pg_dma[p] = d;
		ws->ws_pg_len[p] = pages[p].pg_len;
		ws->ws_npgs = p + 1;
		ws->ws_pages_mapped = true;
	}

	/* The reduced SEND buffer, built as in write_list. */
	ws->ws_hdrlen = sendlen;
	ws->ws_hdr = malloc(sendlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);
	be32enc(h +  4, RPCRDMA_VERSION);
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);
	be32enc(h + 12, RDMA_MSG);
	be32enc(h + 16, 0);
	be32enc(h + 20, 1);
	be32enc(h + 24, n);
	off = 28;
	remaining = datalen;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = min_t(uint32_t, remaining, slen);

		be32enc(h + off + 0, write->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);
		be64enc(h + off + 8, write->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	be32enc(h + off, 0);
	off += RPCRDMA_WORD;
	be32enc(h + off, 0);
	off += RPCRDMA_WORD;
	if (reducedlen > 0)
		memcpy(h + off, reduced, reducedlen);
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, sendlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Walk the segments outer and the source pages inner: each segment
	 * takes at most its own length, consecutive pages gather into one WR's
	 * SGE list up to sc_max_send_sge, and a new WR starts when that fills
	 * or the segment ends, a WR carrying one segment's rkey and address.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	remaining = datalen;
	p = 0;
	pgoff = 0;
	nsge_total = 0;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = min_t(uint32_t, remaining, slen);
		uint64_t raddr = write->wc_segs[i].rs_offset;
		uint32_t seg_left = wlen;

		while (seg_left > 0) {
			int k = ws->ws_nwr;
			struct ib_sge *sg = &ws->ws_sge[nsge_total];
			int nsge = 0;
			uint32_t wbytes = 0;

			if (k >= SVC_RDMA_MAX_WRITE_WRS) {
				svc_rdma_write_free(ws);
				return (EMSGSIZE);
			}
			while (seg_left > 0 && nsge < (int)conn->sc_max_send_sge &&
			    p < npages && nsge_total < SVC_RDMA_MAX_WRITE_SGE) {
				uint32_t pavail = ws->ws_pg_len[p] - pgoff;
				uint32_t take = min_t(uint32_t,
				    seg_left, pavail);

				sg[nsge].addr = ws->ws_pg_dma[p] + pgoff;
				sg[nsge].length = take;
				sg[nsge].lkey = conn->sc_pd->local_dma_lkey;
				nsge++;
				nsge_total++;
				wbytes += take;
				seg_left -= take;
				pgoff += take;
				if (pgoff == ws->ws_pg_len[p]) {
					p++;
					pgoff = 0;
				}
			}
			if (nsge == 0 || (seg_left > 0 && p >= npages)) {
				/* pages ran out mid-segment, or SGE array full: bug/overflow */
				svc_rdma_write_free(ws);
				return (EFAULT);
			}
			memset(&ws->ws_wr[k], 0, sizeof(ws->ws_wr[k]));
			ws->ws_wr[k].wr.wr_cqe = &conn->sc_write_sink_cqe;	/* unsignaled: route flush to sink */
			ws->ws_wr[k].wr.sg_list = sg;
			ws->ws_wr[k].wr.num_sge = nsge;
			ws->ws_wr[k].wr.opcode = IB_WR_RDMA_WRITE;
			ws->ws_wr[k].wr.send_flags = 0;		/* unsignaled */
			ws->ws_wr[k].remote_addr = raddr;
			ws->ws_wr[k].rkey = write->wc_segs[i].rs_handle;
			ws->ws_nwr++;
			raddr += wbytes;
		}
		remaining -= wlen;
	}

	/* The tail reduced-RDMA_MSG SEND, signaled -- one completion per chain. */
	ws->ws_sndsge.addr = ws->ws_hdr_dma;
	ws->ws_sndsge.length = sendlen;
	ws->ws_sndsge.lkey = conn->sc_pd->local_dma_lkey;
	memset(&ws->ws_sndwr, 0, sizeof(ws->ws_sndwr));
	ws->ws_sndwr.wr_cqe = &ws->ws_cqe;
	ws->ws_sndwr.sg_list = &ws->ws_sndsge;
	ws->ws_sndwr.num_sge = 1;
	ws->ws_sndwr.opcode = IB_WR_SEND;
	ws->ws_sndwr.send_flags = IB_SEND_SIGNALED;
	ws->ws_sndwr.next = NULL;

	for (i = 0; i + 1 < (uint32_t)ws->ws_nwr; i++)
		ws->ws_wr[i].wr.next = &ws->ws_wr[i + 1].wr;
	if (ws->ws_nwr > 0)
		ws->ws_wr[ws->ws_nwr - 1].wr.next = &ws->ws_sndwr;

	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (write-list READ pages) failed: "
			    "%d (prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);

	/*
	 * Failures before the write state exists own mrep without having
	 * attached it, so it is freed here to keep the engine-owns-mrep
	 * contract.  Every path after ws_keepm is set frees it through the
	 * release path instead and must not reach this label.
	 */
badm:
	if (mrep != NULL)
		m_freem(mrep);
	return (rc);
}


