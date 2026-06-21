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
 * mbuf ext_free for the read sink.  The mbuf carries the sink
 * buffer pointer DIRECTLY as ext_arg1; this callback runs at refcount->0
 * (EXT_DISPOSABLE -> fires exactly once) and frees ONLY that PLAIN CPU MEMORY.
 *
 * CRITICAL: the sink mbuf is nfsd-owned and OUTLIVES the conn -- it can be freed
 * long after svc_rdma_conn_free_verbs has run rdma_destroy_id(sc_id), which
 * RELEASES the ib_device.  Therefore this callback MUST NOT touch the device:
 * the DMA mapping is torn down in svc_rdma_wc_rdma_read, while the conn and
 * device are provably alive (the completion runs on this conn's CQ),
 * leaving the mbuf owning plain memory only.  No ib_device, no dma cookie here ->
 * no device use-after-free on DEVICE_REMOVAL / HCA kldunload.  svc_rdma_sink_put
 * never sleeps and takes only the leaf svc_rdma_sink_lock (never sc_lock/xr_lock,
 * and nothing is taken while holding it), so the callback adds no lock-order edge
 * and cannot deadlock the teardown.
 */
static void
svc_rdma_read_extfree(struct mbuf *m)
{
	void *buf = m->m_ext.ext_arg1;

	/*
	 * RECYCLE, do not free() (#60): the buffer is plain unmapped
	 * SVC_RDMA_MAX_READ-sized contiguous memory here (the mapping was torn
	 * down in svc_rdma_wc_rdma_read).  Returning it to the free-list keeps
	 * its KVA mapping out of kmem and avoids the per-write TLB shootdown.
	 */
	svc_rdma_sink_put(buf);
}

/*
 * Receive completion.  Dispatched by the CQ core (ib_cq.c: wc->wr_cqe->done)
 * in IB_POLL_WORKQUEUE context -- a kernel workqueue thread, NOT an ithread,
 * so it is technically sleepable, but the reviewer treats it as hostile: keep
 * it short, take no sleepable lock, and start no blocking teardown here.
 *
 * The WR's wr_cqe aliases &rr->rr_cqe, so container_of() recovers the recv
 * descriptor and rr_conn the owning connection.  wc->byte_len is the device's
 * count of bytes actually written into our buffer; the device caps it at the
 * posted SGE length (SVC_RDMA_INLINE), so a peer that sends more than the inline
 * size cannot make byte_len exceed the buffer -- the surplus is simply not
 * delivered.  We still treat byte_len as fully untrusted: svc_rdma_parse_header()
 * bounds-checks every header word against it before any read.
 *
 * The success path parses the RFC 8166 transport header and decodes any
 * read/write/reply chunk lists into the bounded svc_rdma_msg, then hands off to
 * svc_rdma_dispatch_recv(), which routes by chunk shape:
 *   - a PURE-INLINE RDMA_MSG (no chunks) is dispatched to the consumer and the
 *     recv buffer reposted via the SC_UP-gated barrier;
 *   - a request bearing a READ list (NFS WRITE / large call argument) is pulled
 *     by the RDMA Read engine into a server buffer, then dispatched;
 *   - an inline call that also offers a WRITE list or REPLY chunk is dispatched
 *     inline; the parsed chunks travel to the consumer, whose xp_reply replies
 *     inline when the result fits or RDMA-Writes a large result into the client's
 *     chunks via the outbound RDMA Write engine;
 *   - a bodyless RDMA_NOMSG with no read list (no inline body and no read chunk
 *     to assemble one) is closed cleanly;
 *   - a hard protocol violation (too short/truncated, bad version, unsupported
 *     proc, bad discriminator, 0/oversized segment, overflow) or a request over a
 *     fixed cap is logged with its reason and the connection closed via the
 *     deferred teardown path -- we do NOT repost a connection we are tearing down.
 */
void
svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	uint32_t len;
	bool ready;

	/*
	 * Invariant guard: this handler -- and the sc_lock-protected
	 * quiescence counters sc_reposts/sc_sends/sc_upcalls it drives -- relies on
	 * IB_POLL_WORKQUEUE for its completion model.  Each CQ is polled by its own
	 * workqueue work item, and a work_struct cannot run concurrently with itself,
	 * so completions ON ONE CQ are serialized (the send CQ and recv CQ are
	 * distinct work items and MAY run concurrently on two CPUs; the counters are
	 * therefore maintained under sc_lock, and the teardown waits them out under
	 * sc_lock -- it is sc_lock, not a single per-conn thread, that serializes the
	 * counter updates).  If a future change allocated the CQ with
	 * IB_POLL_DIRECT/SOFTIRQ the completion would run in an unexpected context and
	 * reopen a completion-vs-teardown hazard; assert the context so that mistake
	 * trips INVARIANTS here instead of failing silently.
	 */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	rr = container_of(wc->wr_cqe, struct svc_rdma_recv, rr_cqe);
	conn = rr->rr_conn;

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * IB_WC_WR_FLUSH_ERR is the expected status for every recv WR
		 * flushed when the QP goes to error/drains during teardown:
		 * swallow it silently (the buffers are freed by the teardown
		 * task, not here).  Any other error is a real connection fault
		 * -- start a deferred teardown; do NOT repost (the QP is no
		 * longer usable and a post would just fail).
		 *
		 * Note we take the non-SUCCESS exit BEFORE touching sc_reposts:
		 * a flushed/errored completion never counts as an in-flight
		 * repost.  Flush completions reaped DURING the teardown task's
		 * ib_drain_qp() still see a live conn -- the task frees conn
		 * only AFTER ib_drain_qp() + ib_free_cq() -- and return here
		 * without dereferencing freed memory.
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
	 * Parse the RFC 8166 transport header before reposting.  Defend in depth:
	 * although the device caps wc->byte_len at the posted SGE length, clamp it
	 * to SVC_RDMA_INLINE anyway so the parser's bounds math can never be told
	 * the buffer is larger than it is, then hand the parser exactly the bytes
	 * that landed in rr_buf.  svc_rdma_parse_header() gates every wire-word
	 * read on this length, so a short/truncated/garbage header returns an
	 * error rather than overreading rr_buf.
	 */
	len = wc->byte_len;
	if (len > SVC_RDMA_INLINE)
		len = SVC_RDMA_INLINE;

	/*
	 * DMA-API contract: a buffer the device wrote (DMA_FROM_DEVICE) must be
	 * sync_for_cpu'd before the CPU reads it.  rr_buf is mapped once at accept
	 * and never per-recv remapped, but ib_dma_map_single may bounce it, and on
	 * a weakly-ordered CPU this POSTREAD sync also supplies the load barrier
	 * against the recv completion -- so the just-landed bytes are only
	 * guaranteed visible to the CPU afterwards.  Omitting it is a latent bug:
	 * a no-op on a direct, strongly-ordered mapping (x86, where it stayed
	 * hidden), but on the ppc64le DDW/busdma path svc_rdma_parse_header() reads
	 * stale buffer contents and rejects every RPC-over-RDMA header, hanging
	 * NFS/RDMA.  Inbound mirror of the read-sink sync (see svc_rdma_wc_rdma_read).
	 */
	ib_dma_sync_single_for_cpu(conn->sc_id->device, rr->rr_dma, len,
	    DMA_FROM_DEVICE);

	/*
	 * Readiness/defer decision.  sro_newconn is delivered
	 * SOLELY by the ESTABLISHED CM handler, which sets sc_newconn_done strictly
	 * after it returns; recv buffers are posted before rdma_accept(), so this
	 * completion can arrive BEFORE that handler has run.  We must NOT drop such an
	 * early call: RPC-over-RDMA runs over a reliable QP and never retransmits a
	 * delivered call, so a dropped first RPC hangs the mount (the SC_UP ->
	 * sc_newconn_done window is sub-microsecond on x86 but higher CM
	 * latency widens it on ppc64le).
	 *
	 * So we DEFER instead of drop.  In one sc_lock section:
	 *   - SC_CLOSING: a teardown owns this buffer and reclaims it after
	 *     ib_drain_qp(); return without reposting (the repost gate would decline
	 *     anyway), exactly the closing behavior of the parse-error path.
	 *   - not ready (SC_CONNECTING, or SC_UP before sc_newconn_done): HOLD this
	 *     recv on sc_early, un-reposted, and return.  The ESTABLISHED handler
	 *     drains it once the gate opens.  Bounded by sc_nearly < sc_nrecv/2 so the
	 *     RQ never depletes; past the cap we close (the client reconnects).
	 *   - ready: dispatch now.  The held buffers carry no in-flight device WR, so
	 *     they need no sc_reposts/sc_sends accounting -- the drained teardown
	 *     frees sc_recv[] wholesale.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state == SC_CLOSING) {
		mtx_unlock(&conn->sc_lock);
		return;
	}
	ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
	if (!ready) {
		/* Hold at most half the RQ depth (>=1) so the RQ never depletes. */
		int cap = conn->sc_nrecv / 2;

		if (cap < 1)
			cap = 1;
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
 * Parse and dispatch one received RPC-over-RDMA call.  Split out of
 * svc_rdma_wc_recv so the ESTABLISHED handler can replay an early call it held on
 * sc_early once the readiness gate opens.  The caller has already DMA-synced
 * rr_buf for the CPU and decided the connection is ready (recv path) or is the
 * ESTABLISHED drainer (gate just opened, SC_UP set).  The inline readiness gate
 * below is retained as defense in depth (state can flip to SC_CLOSING between the
 * caller's check and here).
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
		 * Parse rejected the message (UNTRUSTED-PEER reject path):
		 *   EBADMSG    - too short/truncated, bad version, unsupported
		 *                proc, bad chunk discriminator, a 0/oversized
		 *                segment, or a length overflow.
		 *   EOPNOTSUPP - well-formed but over a FIXED CAP (too many chunks
		 *                or too many segments in a chunk) -- not served.
		 * Log the reason (rate-limited -- the arrival rate is peer-
		 * controlled) and close the connection via the deferred
		 * teardown path.  We deliberately do NOT repost: this connection
		 * is being torn down, and the SC_CLOSING gate below would skip the
		 * repost once conn_close() publishes SC_CLOSING anyway.
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
		 * (A) ERR_VERS (RFC 8166 4.4/5).  ONLY the version-mismatch return
		 * (EPROTONOSUPPORT) leaves a trustworthy xid: parse_header proved the
		 * fixed prefix was present and stamped msg.xid before bailing.  Reply
		 * RDMA_ERROR/ERR_VERS carrying our supported version range on the
		 * still-SC_UP conn, THEN close.  The SEND is posted through the same
		 * SC_UP-gated, sc_sends-counted bounded pool as every reply, so
		 * posting it BEFORE svc_rdma_conn_close() publishes SC_CLOSING is
		 * safe: the in-flight WR is drained by the close's sc_sends barrier
		 * ahead of ib_drain_qp(), and a racing close makes the post a benign
		 * ENOTCONN drop.  Every other rc (EBADMSG/EOPNOTSUPP) has NO
		 * guaranteed-readable xid (the header may be too short), so we MUST
		 * NOT fabricate an RDMA_ERROR -- we just close, exactly as before.
		 */
		if (rc == EPROTONOSUPPORT)
			svc_rdma_send_error(conn, msg.xid, ERR_VERS);
		svc_rdma_conn_close(conn);
		return;
	}

	/*
	 * Well-formed and within caps.  Route by chunk shape:
	 *
	 *   - A request bearing a READ list (NFS WRITE / large call argument) is the
	 *     RDMA Read engine's job.  We must NOT repost rr_buf yet and must NOT
	 *     dispatch inline: the call body is not fully in our memory until the async
	 *     RDMA Read completes.  Hand off to svc_rdma_read_start(), which copies the
	 *     chunk metadata + inline head into the recv's DURABLE rr_rs (so nothing
	 *     points into rr_buf once we return), allocates+maps a server buffer, and
	 *     posts the read chain.  The read completion (svc_rdma_wc_rdma_read)
	 *     assembles the body, dispatches sro_recv (carrying the whole parsed msg,
	 *     reply chunk included), frees the buffer, and reposts rr_buf.  On a start
	 *     error we close; on success we return WITHOUT reposting (the read owns
	 *     rr_buf until completion).
	 *
	 *   - An inline call body (RDMA_MSG), INCLUDING one that also carries a WRITE
	 *     list or a REPLY chunk for an over-inline result, is dispatched inline
	 *     like any inline call (below).  The parsed write list / reply chunk
	 *     travels to the consumer in msg; the consumer's xp_reply replies inline
	 *     when the result fits, or RDMA-Writes a large result into the client's
	 *     reply chunk / write list via the outbound RDMA Write engine
	 *     (svo_conn_reply_chunk / svo_conn_write_list) when it does not.
	 *
	 *   - A bodyless RDMA_NOMSG with no read list has no inline call body and no
	 *     read chunk to assemble one, so it is unserveable -- close it cleanly.
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
	 * Readiness gate + upcall barrier.  sro_newconn is delivered
	 * SOLELY by the ESTABLISHED CM handler, which sets sc_newconn_done strictly
	 * AFTER sro_newconn returns and only on the SC_CONNECTING -> SC_UP win.  This
	 * dispatch path never delivers newconn; it only DISPATCHES sro_recv, and must
	 * do so only once the consumer is ready.  In ONE sc_lock section capture
	 *   ready == (sc_state == SC_UP && sc_newconn_done)
	 * and, if ready, bump sc_upcalls (this sro_recv becomes an in-flight consumer
	 * upcall that the teardown drains before sro_disconnect -- the send-side
	 * mirror of the sc_reposts/sc_sends arm).  The two conjuncts guarantee (a)
	 * sro_newconn has fully completed and (b) the conn is SC_UP, so a synchronous
	 * svc_rdma_conn_send() from sro_recv does not hit the SC_UP gate's ENOTCONN.
	 *
	 * Both callers reach here only when the gate was open: svc_rdma_wc_recv()
	 * checks readiness and DEFERS an early call onto sc_early instead of
	 * dispatching it (so a not-yet-ready call is never dropped), and the
	 * ESTABLISHED drainer runs us only after publishing SC_UP && sc_newconn_done.
	 * This re-check is therefore defense in depth against the one residual race --
	 * a disconnect/error flipping the conn to SC_CLOSING between the caller's
	 * sample and here.  On !ready (SC_CLOSING) we skip the dispatch and fall to the
	 * repost barrier, which sees SC_CLOSING and declines; the teardown reclaims
	 * the buffer.  No reply is fabricated for an undispatched call.
	 */
	mtx_lock(&conn->sc_lock);
	ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
	if (ready)
		conn->sc_upcalls++;
	mtx_unlock(&conn->sc_lock);
	if (!ready)
		goto repost;

	/*
	 * Hand the parsed call to the consumer.  The krpc consumer's sro_recv
	 * enqueues the message and calls xprt_active().
	 *
	 * Contract honored here: the ready gate above guarantees sro_newconn has
	 * already COMPLETED for this conn and the conn is SC_UP, so a consumer's
	 * sro_recv may safely svc_rdma_conn_get_ctx() the state its sro_newconn
	 * attached, and a synchronous svc_rdma_conn_send() will not see ENOTCONN.
	 * sro_recv runs in THIS completion context and MUST NOT sleep; msg (and
	 * msg.rpc, which points into rr_buf) is valid only for the duration of this
	 * call -- we repost rr_buf right after, so a consumer that needs the bytes
	 * must copy them before returning.  A consumer may call svc_rdma_conn_send()
	 * synchronously from within sro_recv.
	 *
	 * After the upcall returns we drop the sc_upcalls refcount (waking the
	 * teardown if it was the last) BEFORE acting on the result.  sro_recv
	 * returns 0 to continue (fall through to repost) or nonzero to close (the
	 * consumer rejected the call).  Decrementing first is essential: a close
	 * publishes SC_CLOSING and enqueues the teardown, whose barrier waits for
	 * sc_upcalls == 0 -- if we still held the refcount it would wait on us
	 * forever.  After the decrement we close and return; we do NOT repost a
	 * connection we are tearing down (identical to the parse-error path above).
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
 * Repost one recv buffer to keep the receive queue from starving -- while the
 * connection is NOT SC_CLOSING (admitting SC_CONNECTING as well as SC_UP), and
 * under an in-flight repost refcount (sc_reposts) that the teardown task drains
 * before it calls ib_drain_qp().  This closes a post-after-drain UAF: mlx5's
 * ib_post_recv does NOT reject an ERR-state QP, so without the barrier a repost
 * that sampled a non-closing state, dropped the lock, then lost the CPU could
 * enqueue a WR AFTER the drain sentinel; that WR's flush completion would fire
 * against an already-freed conn/recv.
 *
 * Factored out of svc_rdma_wc_recv so the RDMA Read completion can
 * repost the SAME recv buffer once it has consumed the inbound data -- a recv
 * whose request bore a read list is NOT reposted by the recv handler; the read
 * completion reposts it here after the assembled body is dispatched.
 *
 * The gate is SC_CLOSING-based, not SC_UP-based: an RPC that arrives before
 * ESTABLISHED is HELD on sc_early (not reposted) and replayed by the ESTABLISHED
 * drainer at SC_UP, so in practice every repost runs at SC_UP.  Admitting
 * SC_CONNECTING here is therefore defensive (harmless if a repost ever races the
 * CONNECTING window) rather than load-bearing.  Post-after-drain safety is
 * UNCHANGED: svc_rdma_conn_close() publishes SC_CLOSING under sc_lock
 * BEFORE enqueuing the teardown, so once teardown is pending NO new repost passes
 * the SC_CLOSING check; the task's barrier then waits only for already-counted
 * reposts to finish their ib_post_recv and decrement.  After the count hits 0
 * every posted WR is on the QP before ib_drain_qp(), so the drain catches them
 * all and nothing posts afterward.
 *
 * Sequence: take sc_lock; if SC_CLOSING, bail (the teardown owns this buffer and
 * reclaims it after ib_drain_qp(), so skipping the repost cannot leak).
 * Otherwise bump sc_reposts and drop the lock before the (non-sleeping;
 * mlx5_ib_post_recv only takes the RQ spinlock) ib_post_recv.  Reacquire,
 * decrement, and wake the teardown (on the shared &sc_upcalls channel) if we
 * were the last in-flight repost.
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
	 * The DMA mapping and SGE are unchanged and still valid (the buffer is
	 * DMA_FROM_DEVICE and was never unmapped), so re-post the prebuilt rr_wr
	 * as-is -- but hand the buffer back to the device first.  The CPU just read
	 * the previous receive out of rr_buf (svc_rdma_wc_recv's sync_for_cpu); the
	 * DMA API requires a matching sync_for_device (PREREAD) before the NIC DMAs
	 * the next receive into it, to re-arm the bounce mapping and order the
	 * device's writes after the CPU's reads.  No-op on a direct, strongly-
	 * ordered mapping (x86); mirrors the read-sink repost sync.
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
 * ===========================================================================
 * RDMA Read engine -- inbound NFS WRITE / large-call data.
 *
 * For a request bearing a read list, the CLIENT has registered memory it wants
 * us to RDMA-READ FROM (the data of an NFS WRITE, or a large call argument).
 * Each read-list segment is a peer-supplied { rs_handle(rkey), rs_offset(remote
 * virtual address), rs_length }.  We pull every segment into one contiguous
 * server destination buffer, splice it together with the inline head at the
 * read list's rdma_position (RFC 8166 4.3), and hand the assembled call body to
 * the consumer's sro_recv -- so nfsd sees the full NFS WRITE.
 *
 * UNTRUSTED PEER (RFC 8166 5) -- re-validated AT POST TIME, not trusted from the
 * parse:
 *   - every rs_length re-checked in (0, SVC_RDMA_MAX_SEG_LEN];
 *   - the segment/WR count re-checked <= SVC_RDMA_MAX_READ_SEGS;
 *   - the running SUM re-checked against SVC_RDMA_MAX_READ (1 MiB) with no
 *     uint32 overflow -- the server buffer is sized by THIS bounded sum, never
 *     by an unbounded peer total;
 *   - rs_handle(rkey) and rs_offset are passed VERBATIM to the HCA: the hardware
 *     enforces the rkey against the client's MR, so a bad rkey/addr fails the WR
 *     with an error completion, which we handle by CLOSING -- never by trusting.
 * A read that fails for any reason is a clean close, never a panic/overread.
 *
 * COMPLETION-vs-TEARDOWN lifetime (the #1 hazard):
 *   - the read WR chain is accounted in sc_sends (armed only under SC_UP), so the
 *     drained teardown's barrier waits it out before ib_drain_qp();
 *   - the server destination buffer + its DMA mapping live in the recv's DURABLE
 *     rr_rs and are freed/unmapped EXACTLY ONCE -- on the read completion, or by
 *     the teardown for a read still in flight at close (rs_active/rs_mapped
 *     idempotency, the rr_mapped / ss_mapped pattern);
 *   - svc_rdma_conn_close() publishes SC_CLOSING before enqueuing the teardown,
 *     so once teardown is pending no new read passes the SC_UP gate.
 * ===========================================================================
 */

/*
 * Kick off the RDMA Read for a request whose read list we just parsed.  Called
 * from the recv completion (IB_POLL_WORKQUEUE) with the parsed msg still pointing
 * into rr_buf; len is the clamped recv byte length.  On success a read chain is
 * on the SQ, accounted in sc_sends, and rr_buf is OWNED by the read until the
 * completion reposts it -- the caller must NOT repost.  Returns 0 on success or a
 * positive errno (the caller closes the conn on error; this routine has already
 * released everything it allocated before returning nonzero).
 *
 * Durability: BEFORE posting, copy the parsed msg (the bounded chunk arrays) and
 * the inline head bytes into the recv's durable rr_rs, so nothing the read or its
 * completion touches points into rr_buf (which the recv path reposts as soon as a
 * recv handler returns -- but here we do not repost, and the durable copy means
 * even a future repost cannot corrupt the read state).
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
	 * Re-validate the read-list SHAPE at post time (untrusted peer).  The
	 * parser already enforced n <= SVC_RDMA_MAX_READ_SEGS and each rs_length in
	 * (0, SVC_RDMA_MAX_SEG_LEN]; re-assert here so this engine is correct
	 * independent of the parser's caps and so a future parser change cannot
	 * silently let an over-cap request reach the HCA.
	 */
	if (n == 0 || n > SVC_RDMA_MAX_READ_SEGS)
		return (EINVAL);

	/*
	 * Re-compute and re-bound the TOTAL inbound length.  uint64 accumulation
	 * cannot wrap (each rs_length <= 1<<30, n <= SVC_RDMA_MAX_READ_SEGS (64) ->
	 * at most 2^36, far under UINT64_MAX).  Reject 0 (a read list of
	 * only zero-length segments is malformed -- though the parser already
	 * rejects a 0-length segment) and anything over the whole-request cap.  The
	 * server buffer is sized by THIS value, never by a raw peer field.
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
	 * Copy the parsed call + inline head into the DURABLE rr_rs.  After this no
	 * field the read or its completion uses points into rr_buf.  rs_head holds
	 * the inline bytes (the head the read data splices into at rdma_position);
	 * cap the copy at SVC_RDMA_INLINE (len is already clamped to it).
	 */
	rs->rs_msg = *msg;			/* durable copy of chunk arrays */
	rs->rs_total = (uint32_t)total;
	rs->rs_headlen = msg->rpc_len;
	/*
	 * Defense in depth: rpc_len is (len - chunk-list bytes) and so already
	 * <= len <= SVC_RDMA_INLINE, but clamp explicitly to the received byte
	 * count and the buffer size so a malformed rpc_len can never drive a copy
	 * past the bytes that actually landed in rr_buf.
	 */
	if (rs->rs_headlen > len)
		rs->rs_headlen = len;
	if (rs->rs_headlen > SVC_RDMA_INLINE)
		rs->rs_headlen = SVC_RDMA_INLINE;
	rs->rs_head = malloc(SVC_RDMA_INLINE, M_NFSRDMA, M_NOWAIT);
	if (rs->rs_head == NULL)
		return (ENOMEM);
	if (rs->rs_headlen != 0)
		memcpy(rs->rs_head, msg->rpc, rs->rs_headlen);

	/*
	 * Grab a pre-mapped pool buffer if one is free (the fast path):
	 * no per-write contigmalloc/map.  rs_rb records the borrow; rs_mapped stays
	 * FALSE (the pool owns the permanent mapping -- it must NOT be unmapped per
	 * read).  Fall back to a per-read contigmalloc+map if the pool is empty.
	 *
	 * contigmalloc: rs_buf must be PHYSICALLY contiguous -- ib_dma_map_single maps
	 * one contiguous region (vtophys of the first page); a scattered multi-page
	 * malloc buffer would land the RDMA-Read data in the wrong physical pages
	 * (a data-corruption hazard if violated).  Freed with free() (contigfree deprecated).
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
	 * RE-STOCK an evacuated slot.  A prior zero-copy
	 * detach handed this slot's buffer to an mbuf and left rb_buf == NULL
	 * (rb_mapped == false).  Re-stock it lazily here -- OFF the latency path
	 * (the read that evacuated it already completed) and OUTSIDE sc_lock so the
	 * contigmalloc/map does not nest the DMA lock under sc_lock (the same
	 * lock-order discipline svc_rdma_read_free relies on).  On failure, return
	 * the slot to the pool and fall through to the per-read fallback alloc.
	 */
	if (rs->rs_rb != NULL && rs->rs_rb->rb_buf == NULL) {
		struct svc_rdma_readbuf *rb = rs->rs_rb;
		void *nbuf;
		u64 ndma;

		nbuf = svc_rdma_sink_get();	/* recycle list, else contigmalloc (#60) */
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
		 * Fallback: borrow from the recycle list (else contigmalloc) and
		 * map (#60).  The buffer is full SVC_RDMA_MAX_READ size but only the
		 * rs_total prefix is mapped/used, so read_sink_detach's rs_total
		 * maplen and read_free's rs_total unmap stay exact.
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
		 * Mark the mapping live IMMEDIATELY after a successful
		 * map, BEFORE the SC_UP check below.  svc_rdma_read_free unmaps iff
		 * rs_mapped, so any reclaim after this point (the SC_UP-lost-race
		 * early-out, or the drained teardown) unmaps exactly once.  Setting
		 * it only inside the SC_UP branch would leave a window where a teardown
		 * racing between the map and the lock would free() rs_buf with the DMA
		 * mapping still live (leaked mapping + device translation onto freed
		 * memory) -- remotely triggerable by a mid-flight disconnect.  It is
		 * plain memory the recv owns until the post, so setting it before
		 * taking sc_lock is safe (no completion can reach rr_rs yet: nothing
		 * is posted).
		 */
		rs->rs_mapped = true;	/* fallback mapping; read_free unmaps it */
	}

	/*
	 * Build the RDMA Read WR chain: one IB_WR_RDMA_READ per read segment, each
	 * with a single local SGE pointing at the running offset within rs_buf
	 * (lkey = the PD's local_dma_lkey -- the server dest is local memory, no
	 * FRWR registration needed for the SINK of a read), and the peer's
	 * { rkey, remote_addr } passed VERBATIM as wr.rdma.{rkey, remote_addr}.
	 * Chain them next->next and SIGNAL ONLY THE LAST so a single completion
	 * fires for the whole chain.  rs_cqe.done routes that completion to
	 * svc_rdma_wc_rdma_read; every WR's wr_cqe aliases &rs_cqe so the (last)
	 * completion recovers rs via container_of.
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
			off += slen;	/* bounded by rs_total, no overflow */
		}
		/* Signal only the tail -- one completion for the whole chain. */
		rs->rs_wr[n - 1].wr.send_flags = IB_SEND_SIGNALED;
	}

	/*
	 * Arm the send-side teardown barrier and post, IDENTICALLY to
	 * svc_rdma_conn_send(): in one sc_lock section verify
	 * SC_UP, mark this read in flight on the recv (rs_active -- with rs_mapped
	 * already set after the map), and bump sc_sends; then ib_post_send with the
	 * lock dropped; then reacquire, decrement sc_sends, and wake the teardown if
	 * we were the last in-flight SQ WR.  Because conn_close() publishes SC_CLOSING
	 * before enqueuing the teardown, once teardown is pending this post cannot
	 * pass the SC_UP gate, and the barrier waits only for an already-counted post
	 * to finish.  After sc_sends hits 0 the chain is on the SQ before
	 * ib_drain_qp(), so the SQ drain sentinel catches it (its flush completion
	 * reaches svc_rdma_wc_rdma_read with a live conn) and nothing posts afterward.
	 *
	 * rs_active is set BEFORE the post (the one-shot completion token): a chained
	 * post that partially commits (see the failure handling below) generates flush
	 * completions for the committed prefix, which must find rs_active set so the
	 * one-shot guard in svc_rdma_wc_rdma_read claims reclaim ownership correctly.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		/*
		 * Tearing down before we posted anything: no WR reached the SQ, so
		 * no completion will ever fire for this read.  Reclaim inline
		 * (svc_rdma_read_free unmaps via the now-early rs_mapped) and let
		 * the caller close.  This is the ONLY inline-reclaim path left --
		 * it is safe precisely because nothing was posted.
		 */
		svc_rdma_read_free(conn, rr);
		return (ENOTCONN);
	}
	rs->rs_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp, &rs->rs_wr[0].wr, &bad_wr);

	/*
	 * Partial-post hazard: a CHAINED ib_post_send can PARTIALLY commit.  mlx5's
	 * mlx5_ib_post_send builds WQEs one WR at a time and, on a mid-chain
	 * begin_wqe/mlx5_wq_overflow failure, `goto out` where `if (likely(nreq))`
	 * RINGS THE DOORBELL for the already-built prefix while returning -ENOMEM
	 * (mlx5_ib_qp.c:3952-3958 begin_wqe failure -> :4178-4200 out:).  So on rc
	 * != 0 we must assume the worst: some prefix RDMA Reads are LIVE on the HCA
	 * and will DMA-write rs_buf, and their completions (flush on QP->ERR, or an
	 * error CQE) will run svc_rdma_wc_rdma_read via container_of on rr_rs.  We
	 * therefore do NOT reclaim inline (no svc_rdma_read_free, no repost): freeing
	 * rs_buf here would be a DMA-after-free, and the SINGLE post-drain reclaimer
	 * (svc_rdma_conn_free_verbs -> svc_rdma_read_free, after ib_drain_qp) frees it
	 * exactly once.  We DO still decrement sc_sends (the POSTING operation has
	 * finished, success or fail) so the teardown's barrier can reach 0 and proceed
	 * to drain the committed prefix -- leaving rs_active/rs_mapped/rs_buf intact
	 * for that drained reclaim.  Then conn_close and return nonzero; the caller's
	 * close is idempotent with ours.
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
 * Hand the read sink to the zero-copy mbuf.  Transfers ownership of
 * the DMA'd destination buffer + its mapping out of rr_rs and into the bufp/dmap
 * out-params; the caller unmaps it (in the completion, device alive) and wraps the
 * resulting plain-memory buffer in an EXT_DISPOSABLE mbuf.  *maplenp returns the
 * length the buffer was MAPPED at, so the caller's ib_dma_unmap_single matches the
 * original map exactly: SVC_RDMA_MAX_READ for a POOLED buffer (the pool maps every
 * slot at SVC_RDMA_MAX_READ at accept time), rs_total for the per-read FALLBACK
 * buffer (mapped at rs_total in read_start).  For a POOLED sink the slot is
 * EVACUATED (rb_buf=NULL, rb_dma=0, rb_mapped=false, rb_inuse=false, rs_rb=NULL)
 * so the pool no longer owns that buffer; svc_rdma_read_start re-stocks the empty
 * slot lazily.  rs_buf/rs_dma/rs_mapped are cleared unconditionally, so
 * the subsequent svc_rdma_read_free becomes a no-op for the SINK (it still frees
 * rs_head).  Done under sc_lock so the slot/rr_rs fields flip atomically against a
 * concurrent read_free / teardown.  Caller holds NO lock.
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
 * Alloc-failure unwind for a DETACHED sink that no mbuf took ownership of.  The
 * caller already unmapped the sink (in svc_rdma_wc_rdma_read, right after detach
 * and BEFORE the extref/mbuf alloc), so this is now plain CPU memory: just free
 * it, exactly once.  No device touch here (and none possible -- the mapping is
 * already gone), matching svc_rdma_read_extfree.
 */
static void
svc_rdma_read_sink_free_detached(void *buf)
{
	svc_rdma_sink_put(buf);		/* recycle, do not free() (#60) */
}

/*
 * Release the durable read state for a recv: unmap+free the server destination
 * buffer and free the inline-head copy, EXACTLY ONCE.  RECLAIM IS DRIVEN BY THE
 * idempotent rs_mapped (unmap) and rs_buf/rs_head != NULL (free) tokens -- the
 * rr_mapped / ss_mapped pattern -- NOT by rs_active (which is the completion one-shot
 * guard, a separate concern this routine merely clears defensively).  So the two
 * legitimate reclaimers -- the first read completion (success or assemble-alloc
 * drop), and the drained teardown (svc_rdma_conn_free_verbs) -- can each call this
 * and the SECOND is a harmless no-op (all tokens already cleared/NULL).  Call it
 * WITHOUT sc_lock held: it calls ib_dma_unmap_single, which takes DMA_PRIV_LOCK
 * (so it is not lock-free), though it never sleeps.  All callers comply -- the
 * read completion and the drained teardown both drop sc_lock before calling.
 *
 * The DMA / read-vs-teardown rule: the server buffer's DMA mapping MUST stay live
 * until the device is done writing into it (the read completion) or the QP is
 * drained AND the recv CQ freed (teardown).  ib_drain_qp() drains the QP, but the
 * recv buffers (and this read state) are reclaimed only AFTER ib_free_cq(), whose
 * flush_work() is the barrier that quiesces the completion workqueue; so by the
 * time the teardown calls this no read completion can be touching rs_buf/rs_dma.
 */
void
svc_rdma_read_free(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr)
{
	struct svc_rdma_read_state *rs = &rr->rr_rs;
	struct ib_device *dev;

	/*
	 * Pooled buffer: return it to the free-list; do NOT unmap or
	 * free it (the pool owns the permanent mapping and the memory).  Idempotent
	 * via rs_rb: the read completion and the drained teardown may both call this,
	 * but only the one that finds rs_rb != NULL returns the buffer.  Done under
	 * sc_lock so rb_inuse + rs_rb flip atomically.  sc_lock is dropped BEFORE the
	 * ib_dma_unmap_single below (which takes DMA_PRIV_LOCK) -- no lock nesting.
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
		svc_rdma_sink_put(rs->rs_buf);	/* recycle, do not free() (#60) */
		rs->rs_buf = NULL;
	}
	if (rs->rs_head != NULL) {
		free(rs->rs_head, M_NFSRDMA);
		rs->rs_head = NULL;
	}
	rs->rs_active = false;
}

/*
 * RDMA Read completion.  Dispatched by the CQ core in the same
 * IB_POLL_WORKQUEUE context as the send/recv handlers; keep it short, take no
 * sleepable lock, start no blocking teardown.  The signaled tail WR's wr_cqe
 * aliases &rs->rs_cqe, so container_of recovers the read state, then the recv
 * descriptor and the owning conn.
 *
 * ONE-SHOT (the multi-completion guard).  A chained post can deliver MORE THAN
 * ONE completion for a single read: only the tail WR is signaled, but flush
 * (QP->ERR) and error CQEs are reported for UNSIGNALED prefix WRs too, and a
 * partially-committed failed post (see svc_rdma_read_start's partial-post
 * handling) can leave a committed prefix that flushes.  So this handler can be
 * invoked >1x for one rr_rs.  rs_active is the one-shot token: at the top, under
 * sc_lock,
 * test-and-clear it; if it was already clear this is a DUPLICATE completion and
 * we return immediately (the first invocation, or the drained teardown, owns
 * reclaim).  Only the FIRST completion proceeds.  sc_sends is NOT touched here --
 * it is decremented exactly once at the POSTING site (svc_rdma_read_start), so no
 * completion path can double-decrement it.
 *
 * SUCCESS (first completion): rs_buf holds the inbound data the peer registered.
 * Assemble the full call body = head[0, pos) ++ read_data ++ head[pos, headlen)
 * where pos is the read list's rdma_position (RFC 8166 4.3); the parser already
 * rejected a read list whose segments carry DIFFERING positions, so a single
 * reads[0].rc_position describes the whole splice (clamped to headlen).  For the
 * common NFS WRITE pos == headlen, so the read data appends after the inline
 * head.  Dispatch via sro_recv under the same readiness gate + sc_upcalls barrier
 * the inline path uses, then free the read state and repost rr_buf.
 *
 * ERROR/FLUSH (first completion): a bad rkey/addr/length fails the WR (the HCA
 * enforced the rkey), or the chain flushed during teardown.  We clear rs_active
 * (one-shot) but do NOT free rr_rs -- the DRAINED teardown is the single reclaimer
 * for a closing conn, gated by the idempotent rs_mapped/rs_buf tokens (NOT
 * rs_active), so leaving them set is correct and reclaim happens exactly once
 * after ib_drain_qp().  IB_WC_WR_FLUSH_ERR is swallowed; any other status closes.
 * rr_buf is NOT reposted (the teardown owns it).  This mirrors the recv/send flush
 * handling exactly.
 *
 * Serialization (the true model): completions on ONE CQ are serialized because a
 * CQ's IB_POLL_WORKQUEUE work item cannot run concurrently with itself -- and
 * every completion this RDMA Read can produce lands on the SEND CQ, so they are
 * serialized with each other (the recv CQ is a separate work item and may run
 * concurrently, but the recv that owns rr_rs is single-owner: never reposted while
 * rs_active, so no recv completion races this read's rr_rs).  ib_drain_qp() is
 * FIFO, so every completion this read can ever produce has run before the teardown
 * frees conn/rr.  The rs_active one-shot then makes the >1-completion case safe:
 * exactly one invocation does the work, the rest no-op.
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
	 * One-shot test-and-clear: only the FIRST completion for this read proceeds;
	 * any duplicate (a prefix flush after the tail already ran, a second flush)
	 * finds rs_active already false and returns.  This makes dispatch+free+repost
	 * (and the close) happen at most once per read.
	 */
	mtx_lock(&conn->sc_lock);
	first = rs->rs_active;
	rs->rs_active = false;
	mtx_unlock(&conn->sc_lock);
	if (!first)
		return;

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * Flushed during teardown: expected; the DRAINED teardown reclaims
		 * rr_rs after ib_drain_qp() via the idempotent rs_mapped/rs_buf
		 * tokens, so leave them set and touch nothing else.  Any other
		 * status (including the error a bad peer rkey/addr/length produces)
		 * is a real fault -> close; again do NOT free rr_rs here (the conn
		 * is closing and the teardown is the single reclaimer), and do NOT
		 * repost rr_buf (the teardown owns it).
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
	 * Splice point: the position in the XDR stream where the read data belongs.
	 * Clamp to the inline head length so a peer-supplied position can never
	 * index past the head we copied (defense in depth -- pos beyond headlen just
	 * appends).  bodylen = head + read data; both bounded (headlen <=
	 * SVC_RDMA_INLINE, rs_total <= SVC_RDMA_MAX_READ), so the sum cannot
	 * overflow uint32.
	 */
	pos = rs->rs_msg.reads[0].rc_position;
	if (pos > rs->rs_headlen)
		pos = rs->rs_headlen;
	bodylen = rs->rs_headlen + rs->rs_total;

	/*
	 * DMA sync the read sink before the CPU reads it (a corruption hazard if
	 * omitted).  ib_dma_map_single may bounce rs_buf, so the RDMA-Read data is
	 * only guaranteed visible to the CPU after a DMA_FROM_DEVICE sync_for_cpu.
	 * Without it a
	 * bounced read leaves stale (uninitialized) rs_buf bytes in the assembled
	 * body -- intermittent NFS-WRITE data corruption under load.
	 */
	ib_dma_sync_single_for_cpu(conn->sc_id->device, rs->rs_dma,
	    rs->rs_total, DMA_FROM_DEVICE);

	/*
	 * ZERO-COPY ASSEMBLE.  rs_buf (the read sink) holds [read_data]
	 * of rs_total bytes, already DMA-synced for the CPU above.  Instead of
	 * malloc(bodylen) + 3 memcpy + a second copy in sro_recv, build an mbuf chain
	 *     mhead(head[0,pos)) -> mext(EXT_DISPOSABLE sink) -> [mt(head[pos,headlen))]
	 * where mext wraps the DMA'd sink as external storage owned by its own
	 * ext_free (svc_rdma_read_extfree); only the two small (<=4 KiB) head fragments
	 * are copied.  Ownership of the sink TRANSFERS to mext via m_extadd, so after
	 * detach the verbs teardown never touches it (see svc_rdma_read_sink_detach).
	 *
	 * All allocations are M_NOWAIT (completion context); on ANY failure we drop the
	 * call (the RC client retransmits) and free EXACTLY the sink/chain we hold --
	 * never twice, never zero.  m_getm2 pre-sizes each head fragment so the
	 * internally-M_NOWAIT m_copyback cannot SILENTLY TRUNCATE on extend.
	 */
	{
		struct mbuf *mhead, *mext, *mt;
		struct svc_rdma_write_chunk reply = { 0 };
		void *sinkbuf;
		u64 sinkdma;
		uint32_t sinkmaplen, xid = 0;
		bool has_reply = false;

		/*
		 * Take the sink out of rr_rs (locals only from here), then UNMAP it
		 * IMMEDIATELY while conn + device are provably alive (this completion
		 * runs on this conn's CQ).  The data is already CPU-coherent from the
		 * ib_dma_sync_single_for_cpu above, so after the unmap the sink is plain
		 * CPU memory.  Review fix (b): the mbuf must own NO device handle -- it
		 * outlives the conn, and a later ext_free touching a device released by
		 * rdma_destroy_id() at teardown would be a use-after-free.  Unmap LENGTH
		 * = sinkmaplen, the length the buffer was originally mapped at.
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
		 * EXT_DISPOSABLE wraps the plain sink buffer as external storage; the
		 * buffer pointer is carried DIRECTLY as ext_arg1 and svc_rdma_read_extfree
		 * frees it.  flags=0: EXT_DISPOSABLE already selects the embedded-refcount
		 * branch internally (so ext_free fires EXACTLY ONCE at refcount->0, even
		 * if nfsd m_copym's the chain -- m_dupcl shadows the EMBREF), and passing
		 * EXT_FLAG_EMBREF in `flags` would wrongly OR a bit into m_flags.  From
		 * this point the sink is owned by mext; freeing mext (directly or via
		 * m_freem of any chain containing it) releases the sink via ext_free.
		 */
		m_extadd(mext, (char *)sinkbuf, rs->rs_total,
		    svc_rdma_read_extfree, sinkbuf, NULL, 0, EXT_DISPOSABLE);
		mext->m_len = rs->rs_total;

		/*
		 * head[0,pos): the chain head, carries the pkthdr.  Pre-size with
		 * m_getm2 (>= pos bytes, never less than a pkthdr mbuf) so m_copyback
		 * cannot truncate the <=4 KiB head copy.
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
		 * Capture the reply-chunk identity into LOCALS BEFORE read_free
		 * (stale-read hardening, review NIT): rs_msg is durable storage in rr
		 * that read_free does not currently touch, but reading it after the
		 * reclaim is fragile -- snapshot it now and pass the locals below.
		 */
		xid = rs->rs_msg.xid;
		has_reply = rs->rs_msg.reply_present;
		if (has_reply)
			reply = rs->rs_msg.reply;	/* pure value copy */

		/* rs_head is copied into the small mbufs; the sink already detached. */
		svc_rdma_read_free(conn, rr);

		/*
		 * Dispatch the assembled chain under the SAME readiness gate +
		 * sc_upcalls barrier as the inline path.  EVERY branch that did
		 * sc_upcalls++ balances it with --sc_upcalls + wakeup under sc_lock
		 * (a leak hangs teardown forever), and the chain is freed EXACTLY
		 * once: sro_recv_mbuf takes ownership on return 0 (we must NOT free),
		 * and on every other outcome we m_freem(mhead) ourselves.
		 *
		 * REPOST AT COMPLETION.  rr_buf is NOT reposted until this completion
		 * fully returns, so the single-owner rr_rs invariant holds (see the
		 * "One posted receive buffer" note above): no new call can land on
		 * rr_buf or touch rr_rs while a
		 * read is in flight.  We repost on the normal-completion exits
		 * (dispatch-success AND not-ready/no-consumer), but NOT on the
		 * consumer-reject path (it closes the conn; the teardown owns rr_buf).
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
 * ===========================================================================
 * RDMA Write engine -- outbound NFS READ result / large reply.
 *
 * For a reply that does not fit the inline send buffer, the CLIENT pre-registered
 * memory it wants us to RDMA-WRITE INTO: a REPLY CHUNK (the whole RPC reply, e.g.
 * the NFSv4 mount-handshake case) or a WRITE LIST (NFS READ data).
 * Each segment is a peer-supplied { rs_handle(rkey), rs_offset(remote virtual
 * address), rs_length }.  We push the server's marshalled reply OUT into those
 * segments and then SEND a small RPC-over-RDMA header reporting the lengths
 * written: RDMA_NOMSG + the reply-chunk list for a reply chunk (RFC 8166 4.3).
 *
 * UNTRUSTED PEER (RFC 8166 5) -- re-validated AT POST TIME, not trusted from the
 * parse, and the source is SERVER-KNOWN so we NEVER write more than the client
 * offered:
 *   - every rs_length re-checked in (0, SVC_RDMA_MAX_SEG_LEN];
 *   - the segment/WR count re-checked <= SVC_RDMA_MAX_WRITE_SEGS;
 *   - the running SUM of segment lengths (the client's offered capacity) computed
 *     with no uint32 overflow; the reply length (our own, bounded by
 *     SVC_RDMA_MAX_WRITE) must be <= that capacity -- if the reply is LARGER than
 *     the client's reply chunk we return EMSGSIZE and write NOTHING, never an
 *     over-write of the client's memory;
 *   - we write at most rs_length bytes into each segment (min(remaining, len)),
 *     so a segment is never over-written even if a later segment is short;
 *   - rs_handle(rkey) and rs_offset are passed VERBATIM to the HCA: the hardware
 *     enforces the rkey against the client's MR, so a bad rkey/addr fails the WR
 *     with an error completion, which we handle by CLOSING -- never by trusting.
 *
 * COMPLETION-vs-TEARDOWN lifetime (the #1 hazard), mirroring the RDMA Read engine
 * EXACTLY:
 *   - sc_sends accounts only the POST CALL (incremented under SC_UP, decremented
 *     right after ib_post_send returns), NOT the async WRs; ib_drain_qp() -- not
 *     the sc_sends barrier -- is what quiesces the in-flight write/SEND WRs before
 *     the teardown reclaims;
 *   - the write state (source + header buffers + DMA maps) lives in a malloc'd
 *     svc_rdma_write_state threaded on conn->sc_writes and is freed/unmapped
 *     EXACTLY ONCE -- on the (tail-SEND) completion, or by the teardown for a write
 *     still in flight at close (ws_active one-shot + ws_*_mapped idempotency, the
 *     rr_mapped / ss_mapped pattern);
 *   - svc_rdma_conn_close() publishes SC_CLOSING before enqueuing the teardown, so
 *     once teardown is pending no new write passes the SC_UP gate.
 *
 * PARTIAL-POST rule (mlx5 commits prefix WQEs even on -ENOMEM): on ib_post_send
 * rc != 0 we do NOT reclaim inline -- a committed prefix is live and will flush; we
 * leave the write state on sc_writes for the drained teardown to reclaim, exactly
 * as svc_rdma_read_start does.
 * ===========================================================================
 */

/*
 * Release one outbound write state: remove it from the registry, unmap+free the
 * source and header buffers, EXACTLY ONCE.  RECLAIM IS DRIVEN BY the idempotent
 * ws_src_mapped/ws_hdr_mapped (unmap) and ws_src/ws_hdr != NULL (free) tokens --
 * NOT by ws_active (the completion one-shot, a separate concern this routine
 * merely clears defensively).  The two legitimate reclaimers -- the first
 * completion and the drained teardown -- can each call this and the SECOND is a
 * harmless no-op.  Callable WITHOUT sc_lock (the first completion) or WITH the
 * registry already emptied by the teardown loop; it only ib_dma_unmap_single /
 * free, neither sleeps.  The caller has already detached ws from sc_writes (or is
 * the teardown draining the whole list), so this never touches the list itself --
 * the detach is done at the call site under sc_lock to keep the registry coherent.
 *
 * The DMA / write-vs-teardown rule: the source mapping MUST stay live until the
 * device is done READING it (the write completion) or the QP is drained AND the
 * send CQ freed (teardown).  The teardown reclaims write state only AFTER
 * ib_free_cq(), whose flush_work() quiesces the completion workqueue (ib_drain_qp()
 * alone does not -- a dispatched-but-unrun SEND completion may remain), so the
 * teardown calling this for a write that never completed is safe.
 */
void
svc_rdma_write_free(struct svc_rdma_write_state *ws)
{
	struct svc_rdma_conn *conn = ws->ws_conn;
	struct ib_device *dev;

	dev = (conn != NULL && conn->sc_id != NULL) ? conn->sc_id->device : NULL;

	/*
	 * Detach-before-free contract -- the cornerstone of the ABA
	 * safety argued in svc_rdma_wc_rdma_write.  Every caller (the
	 * completion one-shot, the pre-insert error paths, the drained
	 * teardown) has already removed ws from sc_writes -- or never
	 * inserted it -- and cleared ws_active before reaching here, so a
	 * freed write is never on the registry for a stale or duplicate
	 * completion to re-find.  A still-active (hence possibly still-
	 * registered) write must never be freed.
	 */
	MPASS(!ws->ws_active);

	/*
	 * Zero-copy M_EXTPG page source: unmap EACH mapped page.
	 * Drive the loop off ws_npgs (PAGES), never ws_nwr (a WR gathers several
	 * pages, so coalescing by WR would leak).  ws_pages_mapped is the idempotent
	 * token; ws_npgs is bumped incrementally as pages map, so a mid-map failure
	 * unmaps exactly the mapped prefix.  ws_npgs==0 on every non-page path.
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
			svc_rdma_sink_put(ws->ws_src);	/* recycle, not free (#B1) */
		else
			free(ws->ws_src, M_NFSRDMA);
		ws->ws_src = NULL;
	}
	if (ws->ws_hdr != NULL) {
		free(ws->ws_hdr, M_NFSRDMA);
		ws->ws_hdr = NULL;
	}
	/*
	 * Free the source M_EXTPG mbuf chain LAST: the device read
	 * the data pages out of it, so it had to outlive the RDMA Write; this is the
	 * sole reference drop.  ws_keepm is NULL on every non-page path.
	 */
	if (ws->ws_keepm != NULL) {
		m_freem(ws->ws_keepm);
		ws->ws_keepm = NULL;
	}
	ws->ws_active = false;
	free(ws, M_NFSRDMA);
}

/*
 * RDMA-Write a too-large-for-inline reply into the client's reply chunk and SEND
 * the RDMA_NOMSG header reporting the bytes written.  PUBLIC entry
 * point (declared in <rdma/svc_rdma.h>); the krpc consumer's xp_reply calls it
 * when a marshalled reply exceeds the inline size and the request carried a reply
 * chunk.  Context: a krpc pool thread under the consumer's per-conn lock (the
 * caller-reference rule that keeps conn alive, identical to svc_rdma_conn_send);
 * it does NOT sleep.
 *
 * buf/len are the marshalled ONC RPC reply BODY ONLY; reply is the parsed,
 * validated reply chunk the client offered (a pure value type the consumer
 * captured during sro_recv).  On success an RDMA Write chain + the header SEND are
 * on the SQ and the write state is on sc_writes until the tail-SEND completion (or
 * the drained teardown) frees it.  Returns 0 or a positive errno; on nonzero it
 * has already released everything it allocated for a NEVER-posted attempt (a
 * posted-but-failed chain is left for the drained teardown -- the partial-post
 * rule).
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
	 * Validate the reply LENGTH (server-known, bounded).  A 0-length reply is a
	 * caller bug; a reply over the whole-reply cap is refused rather than written
	 * (we never size a transfer past SVC_RDMA_MAX_WRITE).  len is the server's own
	 * marshalled reply size, NOT a peer field.
	 */
	if (len == 0 || len > SVC_RDMA_MAX_WRITE)
		return (EINVAL);

	/*
	 * Re-validate the reply-chunk SHAPE at post time (untrusted peer).  The parser
	 * already enforced wc_nsegs <= SVC_RDMA_MAX_SEGS and each rs_length in
	 * (0, SVC_RDMA_MAX_SEG_LEN]; re-assert here so this engine is correct
	 * independent of the parser and so a future parser change cannot let an
	 * over-cap reply chunk reach the HCA.
	 */
	n = reply->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS)
		return (EINVAL);

	/*
	 * Compute the client's offered CAPACITY (sum of segment lengths) with no
	 * uint32 overflow, re-checking each length.  The reply must FIT: len <=
	 * capacity, else the client did not offer enough reply-chunk space -> EMSGSIZE
	 * and we write nothing.  This is the never-over-write invariant: we will write
	 * exactly len bytes, spread across segments, each capped at its own rs_length.
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
	 * Allocate the durable write state (it outlives this call -- the writes and the
	 * header SEND complete async).  M_NOWAIT: xp_reply may run under the consumer's
	 * leaf mutex, so do not block.  Fields initialized explicitly below.
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
	 * Copy the reply bytes into the DMA source buffer and map it DMA_TO_DEVICE (the
	 * HCA READS this buffer to push it into the client).  Sized by the SERVER-KNOWN
	 * len (bounded by SVC_RDMA_MAX_WRITE), never a raw peer field.
	 */
	ws->ws_srclen = len;
	/* contigmalloc: ws_src is the RDMA-Write SOURCE for the reply chunk; like the
	 * read sink it must be physically contiguous for ib_dma_map_single (a
	 * multi-page reply -- e.g. a large READDIR -- otherwise sources wrong
	 * physical pages and the write fails REM_INV_REQ).  Same fix as rs_buf. */
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
	ws->ws_src_mapped = true;	/* mark the mapping live IMMEDIATELY */

	/*
	 * Build the RDMA_NOMSG transport header: the fixed 4-word prefix, two empty
	 * lists (read list, write list), then the reply chunk present marker + the
	 * counted write chunk whose segments echo the client's { handle, offset } with
	 * the LENGTH updated to the bytes we actually wrote into each segment.  Layout
	 * (big-endian XDR words, RFC 8166 4.3):
	 *   w0 rdma_xid, w1 rdma_vers(1), w2 rdma_credit, w3 rdma_proc(RDMA_NOMSG),
	 *   w4 read_list=0, w5 write_list=0,
	 *   w6 reply_chunk_present=1, w7 nsegs,
	 *   then nsegs * { handle, length(written), offset(64) } (4 words each).
	 * The header is a fixed local size (<= a few hundred bytes for <= 16 segs), so
	 * we size it exactly and it can never be driven past SVC_RDMA_INLINE by a peer.
	 */
	hdrlen = RPCRDMA_HDR_FIXED + 2 * RPCRDMA_WORD +	/* prefix + 2 empty lists */
	    2 * RPCRDMA_WORD +				/* present + nsegs */
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD);	/* the segments */
	ws->ws_hdrlen = hdrlen;
	ws->ws_hdr = malloc(hdrlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees ws */
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);				/* w0  rdma_xid */
	be32enc(h +  4, RPCRDMA_VERSION);		/* w1  rdma_vers */
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);	/* w2  rdma_credit (granted) */
	be32enc(h + 12, RDMA_NOMSG);			/* w3  rdma_proc */
	be32enc(h + 16, 0);				/* w4  read_list (empty) */
	be32enc(h + 20, 0);				/* w5  write_list (empty) */
	be32enc(h + 24, 1);				/* w6  reply chunk present */
	be32enc(h + 28, n);				/* w7  nsegs */
	off = 32;
	remaining = len;
	for (i = 0; i < n; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;

		be32enc(h + off + 0, reply->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);		/* bytes written into this seg */
		be64enc(h + off + 8, reply->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, hdrlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees both + ws */
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Build the RDMA Write WR chain: one IB_WR_RDMA_WRITE per segment that carries
	 * bytes, each with a single local SGE into ws_src at the running source offset
	 * (lkey = the PD's local_dma_lkey -- the source is local memory, no FRWR
	 * registration needed for the SOURCE of a write), and the peer's { rkey,
	 * remote_addr } passed VERBATIM.  Chain them next->next; all UNSIGNALED.  Then
	 * chain the header SEND last and SIGNAL ONLY IT, so a single completion fires
	 * for the whole chain.  The SEND's wr_cqe aliases &ws_cqe (-> ws); the
	 * UNSIGNALED write WRs route to the per-conn sink cqe instead, so a flushed
	 * write never delivers a duplicate completion for this ws.
	 *
	 * We emit a WR only for a segment that actually carries bytes (wlen > 0); once
	 * the reply is exhausted, trailing client segments get length 0 in the header
	 * and no WR (we never write 0 bytes nor over-write a spare segment).
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	off = 0;			/* source offset within ws_src */
	remaining = len;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;
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
	 * Arm the send-side teardown barrier and post, IDENTICALLY to
	 * svc_rdma_read_start / svc_rdma_conn_send: in one sc_lock section verify
	 * SC_UP, register the write on sc_writes, mark it in flight (ws_active -- with
	 * ws_*_mapped already set after the maps), and bump sc_sends; then ib_post_send
	 * with the lock dropped; then reacquire, decrement sc_sends, wake the teardown
	 * if last.  ws_active is set BEFORE the post (the one-shot token): a partially-
	 * committed chained post flushes its prefix, whose completions must find
	 * ws_active set so the one-shot guard claims reclaim correctly.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		/*
		 * Tearing down before we posted anything: no WR reached the SQ, so no
		 * completion will fire.  Reclaim inline (it is not yet on sc_writes) and
		 * return ENOTCONN.  Safe precisely because nothing was posted.
		 */
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * Post the chain (RDMA Writes... + header SEND).  If ws_nwr == 0 (degenerate:
	 * a 0-length reply was rejected above, so this cannot happen for len > 0), the
	 * head is the SEND itself.  bad_wr MUST be passed (mlx5 dereferences it on an
	 * immediate error).
	 */
	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	/*
	 * PARTIAL-POST rule (mlx5 commits the built prefix on a mid-chain failure while
	 * returning -ENOMEM): on rc != 0 do NOT reclaim inline -- a committed prefix is
	 * live.  A committed unsignaled write WR flushes to the per-conn sink cqe (not to
	 * svc_rdma_wc_rdma_write); a committed tail SEND flushes to svc_rdma_wc_rdma_write
	 * and frees ws; if the SEND was NOT reached, no completion frees ws, so the
	 * DRAINED teardown (svc_rdma_conn_free_verbs, after ib_drain_qp) is the single
	 * reclaimer.  Leave ws on sc_writes with ws_active/ws_*_mapped intact.  We DO
	 * still decrement sc_sends (the posting op finished); ib_drain_qp then quiesces
	 * the committed prefix before the teardown reclaims, then close.
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
 * Sink completion for the UNSIGNALED RDMA Write WRs of a chain.
 * Dispatched on the SAME SEND-CQ IB_POLL_WORKQUEUE context as the real write/send
 * handlers.  An unsignaled WR raises NO completion on success, so this is reached
 * ONLY when the QP is in error and the WR flushes (IB_WC_WR_FLUSH_ERR), or in the
 * rare case the HCA reports a per-WR fault (bad rkey/addr/len) on the write itself.
 * It must touch NO ws: the write states are owned and freed via the signaled tail
 * SEND's svc_rdma_wc_rdma_write, and a flushed write WR carries this shared per-conn
 * cqe, not any ws_cqe.  Recover conn from cq->cq_context (== conn) and do O(1) work:
 * count the event, and on a non-flush fault close the connection (idempotent) so a
 * bad client rkey surfaces promptly instead of waiting for the trailing SEND flush.
 * The counters are read/written only by this single-threaded workqueue, so they
 * need no lock.
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
 * RDMA Write completion.  Dispatched by the CQ core in the same
 * IB_POLL_WORKQUEUE context as the read/send handlers; keep it short, take no
 * sleepable lock, start no blocking teardown.  ONLY the signaled tail SEND of a
 * write chain carries &ws->ws_cqe (the unsignaled write WRs carry the per-conn
 * sink cqe), so container_of recovers the write state, then conn,
 * and this handler runs EXACTLY ONCE per ws: once on the SEND's success, or once
 * on the SEND's flush when the QP went to error.  There is therefore NO duplicate
 * completion for a ws and NO stale CQE can alias a freed/recycled ws address --
 * the prior design aliased every WR to &ws_cqe, so a flush storm delivered a
 * duplicate per unsignaled WR and the first completion's free-then-recycle of the
 * ws ADDRESS let a trailing duplicate re-match a recycled live ws and free it
 * mid-ib_post_send (the 256-concurrent-read ABA GPF).
 *
 * The sc_writes membership search is retained as DEFENSE IN DEPTH: recover conn
 * from cq->cq_context WITHOUT touching ws, then under sc_lock confirm ws is still
 * ON the list (and ws_active) before dereferencing it.  The only way it is absent
 * is a SEND completion that races the drained teardown after the teardown already
 * detached+freed it (the teardown runs only after ib_drain_qp(), which is FIFO on
 * this same CQ, so in practice the SEND completion precedes it); the search makes
 * that benign rather than a UAF.  sc_sends is NOT touched here (it is decremented
 * once at the post site; it accounts the post CALL, not the async WR).
 *
 * SUCCESS: the reply was RDMA-Written into the client's chunk and the header SEND
 * transmitted, so the device is done reading ws_src/ws_hdr -- free the write state.
 *
 * FLUSH/ERROR: the chain flushed (the QP is going down -- a bad rkey on a write
 * reaches the sink, or a teardown drain).  Close on ANY non-success before the
 * free (idempotent); the write state is freed here since we removed it from the
 * registry.  The teardown walks sc_writes only AFTER ib_free_cq() has flush_work()ed
 * this CQ, so no completion for a ws is still in flight when it does.
 */
static void
svc_rdma_wc_rdma_write(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_write_state *cand, *ws;
	struct svc_rdma_conn *conn;

	/* Same single-workqueue-thread invariant as the other wc handlers. */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	/*
	 * Recover conn from the CQ context (NOT from the candidate ws -- ws may have
	 * been freed by a prior completion).  cand is only an ADDRESS to match against
	 * the registry; we do not dereference it until proven still-live below.
	 */
	conn = cq->cq_context;
	cand = container_of(wc->wr_cqe, struct svc_rdma_write_state, ws_cqe);

	/*
	 * Prove ownership: search sc_writes for the exact cand pointer.  If present and
	 * still active, this is the FIRST completion -- remove it (clearing ws_active)
	 * and we own the free.  If absent, this is a DUPLICATE (the first completion, or
	 * the drained teardown, already removed+freed it); return having dereferenced
	 * nothing.  Detaching here keeps the registry coherent and makes ownership
	 * unambiguous: whoever removes ws from the list owns its free.
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
	 * Registry coherence (defense in depth): the write we matched on
	 * sc_writes was created for THIS conn (whose CQ delivered this
	 * completion), so ws_conn must point back at conn.  A mismatch
	 * would mean a clobbered ws_cqe/ws_conn or a cross-conn alias --
	 * trip loudly under INVARIANTS rather than free the wrong state.
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
		 * Close on ANY non-success completion -- INCLUDING flush -- BEFORE the
		 * free, so SC_CLOSING is published first.  This closes an ABA window the
		 * one-shot essay above relies on NOT existing: a single bad/stale client
		 * rkey faults one RDMA-Write WR, which puts the whole QP in ERR and
		 * FLUSHES every other in-flight write, raising a storm of
		 * IB_WC_WR_FLUSH_ERR completions ahead of the one error CQE.  The old
		 * code closed only on the NON-flush sub-case, so the first flush freed
		 * its ws while the conn was still SC_UP; a krpc pool thread then passed
		 * the SC_UP insert gate, malloc recycled that exact address as a NEW
		 * live ws and posted it, and a trailing duplicate flush matched the new
		 * ws by address and freed it mid-post -> corrupted num_sge at
		 * ib_post_send + a use-after-free deref of ws_cqe in the completion
		 * workqueue (GPF), reproducible under ~256 concurrent small reads.
		 * Closing here publishes SC_CLOSING on the FIRST flush, so the SC_UP
		 * gate refuses every recycled insert while duplicate flushes drain.  A
		 * flush means the QP is already in ERR (the connection is going down
		 * regardless), so closing is correct; svc_rdma_conn_close is idempotent,
		 * so a normal drained-teardown flush remains a no-op.
		 */
		svc_rdma_conn_close(conn);
		svc_rdma_write_free(ws);
		return;
	}

	svc_rdma_write_free(ws);
}

/*
 * RDMA-Write a DDP-eligible NFS READ's data into the client's write-list chunk
 * and SEND a REDUCED RDMA_MSG reporting the bytes written (write-list READ
 * engine).  PUBLIC entry point (declared in <rdma/svc_rdma.h>); the krpc
 * consumer's xp_reply calls it when an over-inline READ reply carries a write
 * list.  It is the OUTBOUND-write twin of svc_rdma_conn_reply_chunk and reuses
 * its svc_rdma_write_state, svc_rdma_write_free, and svc_rdma_wc_rdma_write
 * completion VERBATIM.  The ONLY structural differences from reply_chunk:
 *   - the RDMA Write SOURCE is the READ DATA (data/datalen), not a reply body;
 *   - the tail SEND carries a REDUCED RDMA_MSG = [transport header with the
 *     echoed write list] ++ [reduced inline ONC RPC body], not a bodyless
 *     RDMA_NOMSG header.  ws_hdr therefore holds header + reduced body and the
 *     SEND covers both.
 *
 * UNTRUSTED PEER -- re-validated at post time, never trusted from the parse, and
 * the source is SERVER-KNOWN so we never write more than the client offered:
 *   - datalen re-checked in (0, SVC_RDMA_MAX_WRITE];
 *   - the write chunk's segment count re-checked <= SVC_RDMA_MAX_WRITE_SEGS;
 *   - each rs_length re-checked in (0, SVC_RDMA_MAX_SEG_LEN] and SUMMED with no
 *     uint32 overflow; datalen must be <= that capacity (else EMSGSIZE, write
 *     NOTHING);
 *   - at most rs_length bytes into each segment (min(remaining, rs_length));
 *   - rs_handle(rkey)/rs_offset passed VERBATIM to the HCA, which enforces them.
 * reducedlen is server-known; header + reduced body must fit one inline send
 * buffer (SVC_RDMA_INLINE) or EMSGSIZE.
 *
 * COMPLETION-vs-TEARDOWN lifetime, PARTIAL-POST, and ws one-shot are IDENTICAL
 * to svc_rdma_conn_reply_chunk (same sc_writes registry, same ws_active guard,
 * same svc_rdma_wc_rdma_write).  Context: a krpc pool thread under the
 * consumer's per-conn lock; does NOT sleep.
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
	 * Validate the DATA length (server-known, bounded).  A 0-length read does
	 * not reach here (the consumer skips DDP for cnt == 0); a read over the
	 * whole-transfer cap is refused rather than written.
	 */
	if (datalen == 0 || datalen > SVC_RDMA_MAX_WRITE) {
		rc = EINVAL;
		goto badsrc;
	}

	/*
	 * Re-validate the write chunk SHAPE at post time (untrusted peer), exactly
	 * as reply_chunk re-validates the reply chunk.
	 */
	n = write->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS) {
		rc = EINVAL;
		goto badsrc;
	}

	/*
	 * Offered CAPACITY (sum of segment lengths) with no uint32 overflow,
	 * re-checking each length.  The data must FIT: datalen <= capacity, else
	 * EMSGSIZE and we write nothing (never-over-write invariant).
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
	 * The reduced RDMA_MSG SEND = transport header (with the echoed write
	 * list) + the reduced inline body.  Header layout (big-endian XDR words,
	 * RFC 8166 4.3, write-list form):
	 *   w0 rdma_xid, w1 rdma_vers(1), w2 rdma_credit, w3 rdma_proc(RDMA_MSG),
	 *   w4 read_list = 0,
	 *   w5 = 1 (write list: one chunk present), w6 nsegs,
	 *     then nsegs * { handle, length(written), offset(64) } (4 words each),
	 *   w  = 0 (write list terminator),
	 *   w  = 0 (reply chunk: absent),
	 *   then the reduced inline ONC RPC body.
	 * The header is a fixed local size (bounded by n <= SVC_RDMA_MAX_WRITE_SEGS
	 * and cannot be driven past the cap by a peer); with the reduced body it
	 * must fit one inline send buffer (SVC_RDMA_INLINE -- the receive-buffer
	 * size, the bound svc_rdma_conn_send also uses), else EMSGSIZE -> the
	 * caller drops, exactly as the pre-engine over-inline path did.
	 */
	hdrlen = RPCRDMA_HDR_FIXED +			/* prefix */
	    RPCRDMA_WORD +				/* read list = 0 */
	    2 * RPCRDMA_WORD +				/* write list: present + nsegs */
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD) +	/* the segments */
	    RPCRDMA_WORD +				/* write list terminator */
	    RPCRDMA_WORD;				/* reply chunk absent */
	if ((uint64_t)hdrlen + reducedlen > SVC_RDMA_INLINE) {
		rc = EMSGSIZE;
		goto badsrc;
	}
	sendlen = hdrlen + reducedlen;

	/*
	 * Allocate the durable write state (outlives this call -- the writes and
	 * the SEND complete async).  M_NOWAIT (xp_reply runs under a leaf mutex);
	 * fields initialized explicitly below.
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
	 * Take ownership of the caller-supplied DMA source buffer and map it
	 * DMA_TO_DEVICE (the HCA READS it to push into the client).  src was
	 * contigmalloc'd AND filled with the read data by the caller BEFORE it took
	 * xr_lock -- the ~100 us per-READ copy that used to run here under the lock
	 * (serializing every concurrent read, the measured read ceiling) is now off
	 * the critical section; this routine only maps + posts.  contigmalloc'd for
	 * the same reason as reply_chunk's ws_src: a multi-page transfer must be
	 * physically contiguous for ib_dma_map_single.  ws owns src from here on
	 * (svc_rdma_write_free frees it).
	 */
	ws->ws_srclen = datalen;
	ws->ws_src = src;
	ws->ws_src_dma = ib_dma_map_single(dev, ws->ws_src, datalen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_src_dma)) {
		/* map failed (ws_src_mapped still false): write_free
		 * releases ws_src pooled-aware (#B1) and frees ws. */
		svc_rdma_write_free(ws);
		return (EIO);
	}
	ws->ws_src_mapped = true;	/* mark the mapping live IMMEDIATELY */

	/*
	 * Build the reduced RDMA_MSG SEND buffer: the transport header (echoing
	 * the write chunk with the bytes actually written) followed by the reduced
	 * inline body, mapped DMA_TO_DEVICE.
	 */
	ws->ws_hdrlen = sendlen;
	ws->ws_hdr = malloc(sendlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees ws */
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);				/* w0  rdma_xid */
	be32enc(h +  4, RPCRDMA_VERSION);		/* w1  rdma_vers */
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);	/* w2  rdma_credit (granted) */
	be32enc(h + 12, RDMA_MSG);			/* w3  rdma_proc */
	be32enc(h + 16, 0);				/* w4  read list (empty) */
	be32enc(h + 20, 1);				/* w5  write list: 1 chunk */
	be32enc(h + 24, n);				/* w6  nsegs */
	off = 28;
	remaining = datalen;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;

		be32enc(h + off + 0, write->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);		/* bytes written into this seg */
		be64enc(h + off + 8, write->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	be32enc(h + off, 0);				/* write list terminator */
	off += RPCRDMA_WORD;
	be32enc(h + off, 0);				/* reply chunk absent */
	off += RPCRDMA_WORD;
	if (reducedlen > 0)
		memcpy(h + off, reduced, reducedlen);	/* reduced inline body */
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, sendlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees both + ws */
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Build the RDMA Write WR chain into the write chunk's segments, exactly as
	 * reply_chunk does (one IB_WR_RDMA_WRITE per byte-carrying segment, single
	 * local SGE into ws_src, peer { rkey, remote_addr } verbatim, all
	 * unsignaled), then chain the reduced-RDMA_MSG SEND last and signal ONLY it.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	off = 0;			/* source offset within ws_src */
	remaining = datalen;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;
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
	 * Arm the send-side teardown barrier and post, IDENTICALLY to
	 * svc_rdma_conn_reply_chunk: register on sc_writes, mark in flight, bump
	 * sc_sends under SC_UP; post with the lock dropped; decrement; partial-post
	 * discipline on failure.
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
	 * Pre-ws-allocation failures (untrusted-peer validation, EMSGSIZE, ENOMEM):
	 * we own the caller's src buffer but never attached it to a ws, so free it
	 * here.  Once ws exists and ws_src = src, every later path frees src through
	 * svc_rdma_write_free (the completion, the SC_UP/post-fail teardown), so they
	 * must NOT reach this label.
	 */
badsrc:
	/* ws was never allocated, so it cannot own src; release src here.  A
	 * pooled buffer (#B1) MUST go back to the recycle pool, not free(). */
	if (src_pooled)
		svc_rdma_sink_put(src);
	else
		free(src, M_NFSRDMA);
	return (rc);
}

/*
 * Zero-copy twin of svc_rdma_conn_write_list (Rick Macklem's enable_mextpg
 * direction).  Same contract, lifetime, completion, one-shot, sink cqe and
 * partial-post rules; the ONLY difference is the RDMA Write
 * SOURCE.  Instead of a contigmalloc'd copy the caller hands us the READ reply's
 * M_EXTPG data pages (mrep + pages[0..npages), summing to datalen) -- already in
 * page-aligned wired kernel pages -- which we map DMA_TO_DEVICE one page at a time
 * and gather into the write WRs (up to sc_max_send_sge pages per WR, never
 * crossing a write-list segment).  We TAKE OWNERSHIP of mrep on EVERY return
 * (0 or errno) -- a faithful twin of svc_rdma_conn_write_list's "engine owns src
 * on every return": a pre-ws validation failure m_freem()s it at the badm label,
 * a post-ws failure through svc_rdma_write_free, and success / committed partial
 * post at write completion or drain (the device read those pages, so they must
 * outlive the Write).  The caller must NOT touch mrep after this call.
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

	/* Validate datalen + write-chunk shape, IDENTICAL to write_list. */
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
	 * Validate the page vector (server-built, but bound it anyway): count fits
	 * the arrays, each page <= PAGE_SIZE, and the pages sum EXACTLY to datalen
	 * (the never-over-write invariant -- we write neither more nor less than the
	 * read data the header advertises).
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

	/* Reduced-RDMA_MSG header size check, IDENTICAL to write_list. */
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
	 * Ownership transfer point: ws owns mrep from here on, so EVERY post-alloc
	 * error path (all of which call svc_rdma_write_free) m_freem()s it exactly
	 * once.  Set it BEFORE the page map loop.
	 */
	ws->ws_keepm = mrep;

	/*
	 * Map each source page DMA_TO_DEVICE.  Bump ws_npgs and set ws_pages_mapped
	 * INCREMENTALLY, so on a mid-loop mapping error svc_rdma_write_free unmaps
	 * exactly the mapped prefix (no leak, no manual unwind).  The page is a wired
	 * kernel page reachable through the direct map (PHYS_TO_DMAP); no FRWR/MR
	 * registration is needed for a LOCAL source -- the PD's local_dma_lkey covers
	 * it, same as the contig path.
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

	/* Build the reduced-RDMA_MSG SEND buffer, IDENTICAL to write_list. */
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
		uint32_t wlen = (remaining < slen) ? remaining : slen;

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
	 * Build the RDMA Write WR chain.  Walk write-list segments OUTER and source
	 * pages INNER in lockstep: cap each segment at min(remaining, rs_length)
	 * (never-over-write), gather consecutive pages into one WR's SGE list up to
	 * sc_max_send_sge, and start a new WR when the SGE list fills OR the segment
	 * ends (a WR carries exactly one segment's rkey/remote_addr).  Unsignaled,
	 * routed to the per-conn sink cqe; only the tail SEND is signaled.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	remaining = datalen;
	p = 0;
	pgoff = 0;
	nsge_total = 0;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;
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
				uint32_t take = (seg_left < pavail) ? seg_left : pavail;

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
	 * Pre-ws-allocation failures (validation, EMSGSIZE, ENOMEM before ws
	 * exists): we own mrep but never attached it to a ws, so m_freem() it here
	 * -- the "engine owns mrep on every return" contract, mirroring the contig
	 * twin's badsrc.  Every path AFTER ws_keepm = mrep frees mrep through
	 * svc_rdma_write_free (or, on a committed partial post, at drain) and must
	 * not reach this label.
	 */
badm:
	if (mrep != NULL)
		m_freem(mrep);
	return (rc);
}


