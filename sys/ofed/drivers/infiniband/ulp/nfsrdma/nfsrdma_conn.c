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

struct svc_rdma_listener svc_rdma_listener = {
	.sl_id = NULL,
	.sl_id6 = NULL,
	.sl_ops = NULL,
	.sl_ctx = NULL,
};

struct svc_rdma_conn_list svc_rdma_conns =
    TAILQ_HEAD_INITIALIZER(svc_rdma_conns);
struct mtx svc_rdma_conns_lock;

/*
 * Serializes bring-up against tear-down, so a stop cannot clear the ops
 * reservation mid-bring-up and leave a live listener with none.  The CM
 * callbacks never take it.  Order: this sx before sl_lock.
 */
struct sx svc_rdma_listen_cfg_lock;

struct timeval svc_rdma_log_last;
int svc_rdma_log_pps;
volatile u_int svc_rdma_cqv;
int svc_rdma_listen_port;

static int	svc_rdma_cm_event_handler(struct rdma_cm_id *id,
	    struct rdma_cm_event *event);
static int	svc_rdma_accept(struct rdma_cm_id *id);
static void	svc_rdma_conn_free_verbs(struct svc_rdma_conn *conn);
static void	svc_rdma_conn_destroy(void *arg, int pending);
static void	svc_rdma_wc_send(struct ib_cq *cq, struct ib_wc *wc);

/*
 * CM event handler for the listener id and its children, in the rdma_cm work
 * context.  id->context tells the two apart: accept() rewrites a child's to its
 * conn before creating any verbs resource, while a CONNECT_REQUEST still
 * carries the listener's, inherited at creation.  On FreeBSD that id is the
 * handler's argument, not event->id, and rdma_cm.h forbids destroying it from
 * the callback, so accept() always returns 0 and defers failure.
 */
static int
svc_rdma_cm_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct svc_rdma_conn *conn;
	const struct sockaddr *sa;
#ifdef INET
	const struct sockaddr_in *sin;
#endif
#ifdef INET6
	const struct sockaddr_in6 *sin6;
#endif
	bool owned, deliver;

	/* Handled first, so the listener switch below never sees one. */
	if (id->context != &svc_rdma_listener &&
	    event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		conn = id->context;

		switch (event->event) {
		case RDMA_CM_EVENT_ESTABLISHED:
			/*
			 * The only place sro_newconn is delivered.  Recvs are
			 * posted before rdma_accept(), so a peer's first call
			 * can arrive first; it waits on sc_early and is drained
			 * here, since an RC client never retransmits a
			 * delivered call.  Only the thread winning
			 * SC_CONNECTING -> SC_UP delivers, with
			 * sc_newconn_fired set in that same section so a later
			 * teardown still pairs disconnect with it.
			 * sc_newconn_done is set only after the upcall returns,
			 * so the dispatch gate cannot open early.
			 */
			mtx_lock(&conn->sc_lock);
			deliver = (conn->sc_state == SC_CONNECTING);
			if (deliver) {
				conn->sc_state = SC_UP;
				conn->sc_newconn_fired = true;
				conn->sc_upcalls++;
			}
			mtx_unlock(&conn->sc_lock);
			if (deliver) {
				if (conn->sc_ops != NULL &&
				    conn->sc_ops->sro_newconn != NULL)
					conn->sc_ops->sro_newconn(conn->sc_ctx,
					    conn);
				mtx_lock(&conn->sc_lock);
				conn->sc_newconn_done = true;
				/*
				 * Splice under the lock that publishes
				 * sc_newconn_done, so every recv is either ours
				 * to drain or dispatches itself.  The
				 * sc_upcalls reference is held across the
				 * drain, so the teardown cannot free one
				 * mid-replay.
				 */
				{
					STAILQ_HEAD(, svc_rdma_recv) early =
					    STAILQ_HEAD_INITIALIZER(early);
					struct svc_rdma_recv *erp;

					STAILQ_CONCAT(&early, &conn->sc_early);
					conn->sc_nearly = 0;
					mtx_unlock(&conn->sc_lock);

					/*
					 * Dispatch does its own sc_upcalls
					 * accounting, and this runs in the
					 * sleepable CM context.
					 */
					while ((erp = STAILQ_FIRST(&early)) !=
					    NULL) {
						STAILQ_REMOVE_HEAD(&early,
						    rr_early);
						svc_rdma_dispatch_recv(conn,
						    erp, erp->rr_early_len);
					}
				}
				mtx_lock(&conn->sc_lock);
				if (--conn->sc_upcalls == 0)
					wakeup(&conn->sc_upcalls);
				mtx_unlock(&conn->sc_lock);
			}
			if (bootverbose && ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: connection established\n");
			return (0);

		case RDMA_CM_EVENT_DISCONNECTED:
		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
			/*
			 * The unwind blocks and the callback may not destroy
			 * the passed-in id, so defer and return 0.
			 */
			svc_rdma_conn_close(conn);
			return (0);

		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			/*
			 * A connection owns a QP, CQs, a PD and mapped buffers,
			 * none of which rdma_destroy_id() frees, so a nonzero
			 * return would leak them; the unwind sleeps, so it is
			 * deferred and that task is the only destroyer.
			 * Removal does not hang on it: cma_process_remove()
			 * waits on the cma_device completion while the id holds
			 * a reference, and the task runs on taskqueue_thread,
			 * not the CM workqueue doing that wait.
			 */
			svc_rdma_conn_close(conn);
			return (0);

		default:
			if (bootverbose)
				printf("nfsrdma: conn CM event %u\n",
				    event->event);
			return (0);
		}
	}

	/* Listener (and CONNECT_REQUEST) events. */
	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		/* Always returns 0, so the core keeps the id. */
		sa = (const struct sockaddr *)&id->route.addr.dst_addr;
		if (bootverbose &&
		    ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
			char *buf;

			buf = malloc(INET6_ADDRSTRLEN, M_TEMP, M_WAITOK);
			switch (sa->sa_family) {
#ifdef INET
			case AF_INET:
				sin = (const struct sockaddr_in *)sa;
				printf("nfsrdma: CONNECT_REQUEST from "
				    "%s:%u\n",
				    inet_ntop(sin->sin_family,
				    &sin->sin_addr.s_addr, buf,
				    INET6_ADDRSTRLEN),
				    ntohs(sin->sin_port));
				break;
#endif
#ifdef INET6
			case AF_INET6:
				sin6 = (const struct sockaddr_in6 *)sa;
				printf("nfsrdma: CONNECT_REQUEST from "
				    "%s:%u\n",
				    inet_ntop(sin6->sin6_family,
				    &sin6->sin6_addr, buf,
				    INET6_ADDRSTRLEN),
				    ntohs(sin6->sin6_port));
				break;
#endif
			default:
				printf("nfsrdma: CONNECT_REQUEST (af %u)\n",
				    sa->sa_family);
			}
			free(buf, M_TEMP);
		}

		return (svc_rdma_accept(id));

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/*
		 * rdma_destroy_id() is not idempotent, so exactly one of the CM
		 * core or svc_rdma_listen_stop() may call it.  sl_id and sl_id6
		 * are the ownership tokens under sl_lock: whoever clears one
		 * owns the destroy.  The id holds a cma_device reference until
		 * then, and cma_remove_one() waits for it.
		 */
		mtx_lock(&svc_rdma_listener.sl_lock);
		owned = (id == svc_rdma_listener.sl_id ||
		    id == svc_rdma_listener.sl_id6);
		if (owned) {
			if (id == svc_rdma_listener.sl_id)
				svc_rdma_listener.sl_id = NULL;
			else
				svc_rdma_listener.sl_id6 = NULL;
			/*
			 * Clear the consumer binding only once BOTH
			 * listener ids are gone (see listen_stop).
			 */
			if (svc_rdma_listener.sl_id == NULL &&
			    svc_rdma_listener.sl_id6 == NULL) {
				svc_rdma_listener.sl_ops = NULL;
				svc_rdma_listener.sl_ctx = NULL;
				svc_rdma_listen_port = 0;
			}
		}
		mtx_unlock(&svc_rdma_listener.sl_lock);
		if (owned) {
			printf("nfsrdma: DEVICE_REMOVAL, destroying listener\n");
			return (ECONNABORTED);
		}
		return (0);

	default:
		/* Logged at debug only; do not flood for benign events. */
		if (bootverbose)
			printf("nfsrdma: CM event %u\n", event->event);
		return (0);
	}
}

/*
 * Copy a marshalled inline reply into a free send buffer and post it.  buf is
 * copied, and a reply past SVC_RDMA_INLINE belongs on the Write path and is
 * refused, not truncated.  Does not sleep, so a consumer may call it from
 * sro_recv, but not once sro_disconnect has returned, when the teardown owns
 * the pool and the SC_UP gate only turns a late call into a drop.
 *
 * One sc_lock section gates on SC_UP, claims a pool buffer and counts the
 * send, and the post runs with the lock dropped.  SC_CLOSING is published
 * before the teardown is queued, so the barrier waits only for sends already
 * counted and every SEND is on the SQ ahead of ib_drain_qp().
 */
int
svc_rdma_conn_send(struct svc_rdma_conn *conn, const void *buf, uint32_t len)
{
	struct svc_rdma_send *ss;
	const struct ib_send_wr *bad_wr;
	int i, rc;

	/*
	 * A reply larger than one send buffer takes the RDMA Write path rather
	 * than being truncated.
	 */
	if (len == 0 || len > SVC_RDMA_INLINE)
		return (EINVAL);

	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		return (ENOTCONN);
	}
	ss = NULL;
	for (i = 0; i < conn->sc_nsend; i++) {
		if (!conn->sc_send[i].ss_inuse) {
			ss = &conn->sc_send[i];
			ss->ss_inuse = true;
			break;
		}
	}
	if (ss == NULL) {
		/*
		 * The pool is exhausted, so drop the reply rather than block
		 * the completion or grow the pool.
		 */
		mtx_unlock(&conn->sc_lock);
		return (EBUSY);
	}
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * Copy into the send buffer mapped at accept time; the post doorbell
	 * orders the write before the device reads it.
	 */
	memcpy(ss->ss_buf, buf, len);

	ss->ss_sge.addr = ss->ss_dma;
	ss->ss_sge.length = len;
	ss->ss_sge.lkey = conn->sc_pd->local_dma_lkey;

	ss->ss_cqe.done = svc_rdma_wc_send;
	ss->ss_wr.next = NULL;
	ss->ss_wr.wr_cqe = &ss->ss_cqe;
	ss->ss_wr.sg_list = &ss->ss_sge;
	ss->ss_wr.num_sge = 1;
	ss->ss_wr.opcode = IB_WR_SEND;
	ss->ss_wr.send_flags = IB_SEND_SIGNALED;

	/*
	 * Post with the lock dropped, as the recv repost does.  bad_wr must be
	 * passed: mlx5_ib_post_send() dereferences it on an immediate error.
	 */
	rc = ib_post_send(conn->sc_id->qp, &ss->ss_wr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (rc != 0) {
		/*
		 * The WR never reached the SQ, so no completion will fire and
		 * the buffer has to be released here.
		 */
		ss->ss_inuse = false;
	}
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (reply) failed: %d\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);
}

/*
 * The verbs layer never interprets or frees this; sc_lock is taken only to
 * order set against get across the upcall contexts.
 */
void
svc_rdma_conn_set_ctx(struct svc_rdma_conn *conn, void *cctx)
{

	mtx_lock(&conn->sc_lock);
	conn->sc_cctx = cctx;
	mtx_unlock(&conn->sc_lock);
}

void *
svc_rdma_conn_get_ctx(struct svc_rdma_conn *conn)
{
	void *cctx;

	mtx_lock(&conn->sc_lock);
	cctx = conn->sc_cctx;
	mtx_unlock(&conn->sc_lock);
	return (cctx);
}

/*
 * The recv buffers actually posted, which a reply advertises in rdma_credit.
 * Written once at accept, so the read needs no lock.
 */
uint32_t
svc_rdma_conn_credits(struct svc_rdma_conn *conn)
{

	return ((uint32_t)conn->sc_nrecv);
}

/*
 * Pre-allocate the calling thread's linuxkpi current shadow, which the first
 * entry into mlx5_ib_post_send() would otherwise allocate M_WAITOK under
 * xr_lock.  Called off-lock at the top of a reply, and a no-op once it exists.
 */
void
svc_rdma_thread_setup(void)
{

	linux_set_current(curthread);
}

/*
 * The peer address the CM resolved into the cm_id, which the consumer copies
 * into xp_rtaddr for the export address checks.  sa_len is normalized from the
 * family, since the OFED path may leave it 0.
 */
void
svc_rdma_conn_peeraddr(struct svc_rdma_conn *conn, struct sockaddr_storage *ss)
{
	struct sockaddr *sa;

	memset(ss, 0, sizeof(*ss));
	if (conn->sc_id == NULL)
		return;
	sa = (struct sockaddr *)&conn->sc_id->route.addr.dst_addr;
	switch (sa->sa_family) {
#ifdef INET
	case AF_INET:
		memcpy(ss, sa, sizeof(struct sockaddr_in));
		ss->ss_len = sizeof(struct sockaddr_in);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		memcpy(ss, sa, sizeof(struct sockaddr_in6));
		ss->ss_len = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		break;
	}
}

/*
 * Marshal and post an RDMA_ERROR reply (RFC 8166 4.4).  ERR_VERS appends our
 * supported range and is followed by a close; ERR_CHUNK leaves the connection
 * up.  rdma_credit carries sc_nrecv, the credit we grant rather than the
 * peer's offer, read without sc_lock since it is set at accept and never
 * mutated.  The caller must pass an xid from a header whose fixed prefix
 * parsed.  Goes through svc_rdma_conn_send(), so it takes the usual gate, pool
 * and barrier.
 */
int
svc_rdma_send_error(struct svc_rdma_conn *conn, uint32_t xid, uint32_t errcode)
{
	char err[RPCRDMA_HDR_FIXED + 3 * RPCRDMA_WORD];
	char *p = err;
	uint32_t len;
	int rc;

	be32enc(p +  0, xid);
	be32enc(p +  4, RPCRDMA_VERSION);
	be32enc(p +  8, (uint32_t)conn->sc_nrecv);
	be32enc(p + 12, RDMA_ERROR);
	be32enc(p + 16, errcode);
	len = RPCRDMA_HDR_FIXED + RPCRDMA_WORD;
	if (errcode == ERR_VERS) {
		be32enc(p + 20, RPCRDMA_VERSION);
		be32enc(p + 24, RPCRDMA_VERSION);
		len += 2 * RPCRDMA_WORD;
	}

	rc = svc_rdma_conn_send(conn, err, len);
	if (rc != 0 && ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
		if (rc == EBUSY)
			printf("nfsrdma: send buffers exhausted, dropping "
			    "RDMA_ERROR err=%u (xid=0x%08x)\n", errcode, xid);
		else if (rc == ENOTCONN)
			; /* connection tearing down; silent (expected) */
		else
			printf("nfsrdma: RDMA_ERROR err=%u post failed: %d "
			    "(xid=0x%08x)\n", errcode, rc, xid);
	}
	return (rc);
}

/*
 * Lets the consumer report ERR_CHUNK by xid without knowing the wire header.
 * Does not close the connection.
 */
int
svc_rdma_conn_error(struct svc_rdma_conn *conn, uint32_t xid, uint32_t errcode)
{

	return (svc_rdma_send_error(conn, xid, errcode));
}

/*
 * Send completion, in the same workqueue context as the recv completion.  On
 * success ss_buf goes back to the pool under sc_lock.  A flush is expected for
 * a reply caught by a draining QP and is swallowed; anything else closes.
 * Buffers are neither unmapped nor freed here, as on the recv side.
 */
static void
svc_rdma_wc_send(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_send *ss;
	struct svc_rdma_conn *conn;

	/* Same single-workqueue-thread invariant as svc_rdma_wc_recv: the
	 * sc_sends lockless-decrement quiescence relies on it. */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	ss = container_of(wc->wr_cqe, struct svc_rdma_send, ss_cqe);
	conn = ss->ss_conn;

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * A flush during teardown is expected and reclaimed there; any
		 * other error closes.  ss_inuse is left set either way.
		 */
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: send completion error %u\n",
				    wc->status);
			svc_rdma_conn_close(conn);
		}
		return;
	}

	mtx_lock(&conn->sc_lock);
	ss->ss_inuse = false;
	mtx_unlock(&conn->sc_lock);
}

/*
 * Request a deferred teardown, from any context including the CM callback and
 * the recv completion, neither of which may block.  Only the caller that wins
 * the transition to SC_CLOSING enqueues the task, so the id is destroyed once.
 */
void
svc_rdma_conn_close(struct svc_rdma_conn *conn)
{
	bool start;

	mtx_lock(&conn->sc_lock);
	start = (conn->sc_state != SC_CLOSING);
	conn->sc_state = SC_CLOSING;
	mtx_unlock(&conn->sc_lock);

	if (start)
		taskqueue_enqueue(taskqueue_thread, &conn->sc_teardown);
}

/*
 * Free every verbs resource in reverse order of allocation, NULL-guarded, so a
 * partial build unwinds and a second call is harmless; sc_id is left to the
 * teardown, which must already have drained the QP.  The CQs go before the
 * writes and buffers, since ib_free_cq() flushes the completion workqueue and
 * ib_drain_qp() does not.  A CQ is never freed under a live QP, the PD
 * outlives every SGE using its local_dma_lkey, and rdma_destroy_qp() clears
 * sc_id->qp itself.
 */
static void
svc_rdma_conn_free_verbs(struct svc_rdma_conn *conn)
{
	struct ib_device *dev;
	int i;

	if (conn->sc_id != NULL && conn->sc_id->qp != NULL)
		rdma_destroy_qp(conn->sc_id);

	/*
	 * Free the CQs before anything a completion could reference: a
	 * successful tail SEND can sit undispatched in the send CQ, and
	 * ib_free_cq() flushes that workqueue where ib_drain_qp() does not.
	 */
	if (conn->sc_rcq != NULL) {
		ib_free_cq(conn->sc_rcq);
		conn->sc_rcq = NULL;
	}
	if (conn->sc_scq != NULL) {
		ib_free_cq(conn->sc_scq);
		conn->sc_scq = NULL;
	}

	/*
	 * Reclaim any write whose completion never ran, stranded by a racing
	 * close or with a tail SEND that never reached the SQ.  The CQ frees
	 * above leave nothing here with a pending completion, so this is the
	 * only reclaimer.
	 */
	for (;;) {
		struct svc_rdma_write_state *ws;

		mtx_lock(&conn->sc_lock);
		ws = TAILQ_FIRST(&conn->sc_writes);
		if (ws != NULL) {
			TAILQ_REMOVE(&conn->sc_writes, ws, ws_link);
			ws->ws_active = false;
		}
		mtx_unlock(&conn->sc_lock);
		if (ws == NULL)
			break;
		svc_rdma_write_free(ws);
	}

	if (conn->sc_recv != NULL) {
		/*
		 * The id outlives this unwind, so sc_id->device is still the
		 * map device.  rr_mapped gates the unmap, so a slot from a
		 * partial build is freed without one.
		 */
		dev = conn->sc_id->device;
		for (i = 0; i < conn->sc_nrecv; i++) {
			struct svc_rdma_recv *rr = &conn->sc_recv[i];

			/*
			 * Idempotent, so a read that already completed is a
			 * no-op, and ib_drain_qp() has run, so no completion is
			 * touching the buffer.
			 */
			svc_rdma_read_free(conn, rr);

			if (rr->rr_mapped && dev != NULL)
				ib_dma_unmap_single(dev, rr->rr_dma,
				    SVC_RDMA_INLINE, DMA_FROM_DEVICE);
			free(rr->rr_buf, M_NFSRDMA);
		}
		free(conn->sc_recv, M_NFSRDMA);
		conn->sc_recv = NULL;
		conn->sc_nrecv = 0;
	}

	if (conn->sc_send != NULL) {
		/* As the recv pool: ss_mapped gates the unmap. */
		dev = conn->sc_id->device;
		for (i = 0; i < conn->sc_nsend; i++) {
			struct svc_rdma_send *ss = &conn->sc_send[i];

			if (ss->ss_mapped && dev != NULL)
				ib_dma_unmap_single(dev, ss->ss_dma,
				    SVC_RDMA_INLINE, DMA_TO_DEVICE);
			free(ss->ss_buf, M_NFSRDMA);
		}
		free(conn->sc_send, M_NFSRDMA);
		conn->sc_send = NULL;
		conn->sc_nsend = 0;
	}

	/*
	 * The read pool runs after ib_drain_qp() and after the per-recv
	 * reclaim above, so no read can still hold one of these buffers.
	 */
	if (conn->sc_rbpool != NULL) {
		dev = conn->sc_id->device;
		for (i = 0; i < conn->sc_nrbpool; i++) {
			struct svc_rdma_readbuf *rb = &conn->sc_rbpool[i];

			if (rb->rb_mapped && dev != NULL)
				ib_dma_unmap_single(dev, rb->rb_dma,
				    SVC_RDMA_MAX_READ, DMA_FROM_DEVICE);
			if (rb->rb_buf != NULL)
				svc_rdma_sink_put(rb->rb_buf);	/* recycle */
		}
		free(conn->sc_rbpool, M_NFSRDMA);
		conn->sc_rbpool = NULL;
		conn->sc_nrbpool = 0;
	}

	if (conn->sc_pd != NULL) {
		ib_dealloc_pd(conn->sc_pd);
		conn->sc_pd = NULL;
	}
}

/*
 * Deferred teardown (taskqueue_thread, sleepable).  The only place that drains
 * the QP and the only destroyer of the child cm_id; svc_rdma_conn_close()
 * enqueues it once, so neither happens twice.  Every resource is NULL-guarded,
 * so a connection that failed mid-accept unwinds whatever subset exists.
 *
 * The order matters.  The wait on &sc_upcalls comes first, since SC_CLOSING
 * was published before this was queued and ib_drain_sq()/ib_drain_rq() need
 * nothing else posting, which mlx5 does not enforce for a QP in error.
 * sro_disconnect follows that drain, so it never overlaps another upcall.
 * ib_drain_qp() flushes both queues without dispatching the completion
 * workqueue, so the CQs are freed before any completion-referenced state;
 * ib_free_cq() is what flushes it.  rdma_destroy_id() needs the QP gone.
 */
static void
svc_rdma_conn_destroy(void *arg, int pending __unused)
{
	struct svc_rdma_conn *conn = arg;

	/*
	 * Every decrement site wakes the shared &sc_upcalls channel and the
	 * whole predicate is rechecked on each wake, so no wakeup is lost.
	 */
	mtx_lock(&conn->sc_lock);
	while (conn->sc_reposts != 0 || conn->sc_sends != 0 ||
	    conn->sc_upcalls != 0)
		msleep(&conn->sc_upcalls, &conn->sc_lock, 0, "svcrdq", 0);
	mtx_unlock(&conn->sc_lock);

	/*
	 * Gated on sc_newconn_fired so it pairs with sro_newconn and is skipped
	 * for a connection the consumer was never told about.  SC_CLOSING is
	 * published, so a reply issued from here is a gated drop.
	 */
	if (conn->sc_newconn_fired && conn->sc_ops != NULL &&
	    conn->sc_ops->sro_disconnect != NULL)
		conn->sc_ops->sro_disconnect(conn->sc_ctx, conn);

	if (conn->sc_id != NULL && conn->sc_id->qp != NULL) {
		rdma_disconnect(conn->sc_id);
		ib_drain_qp(conn->sc_id->qp);
	}

	svc_rdma_conn_free_verbs(conn);

	if (conn->sc_id != NULL)
		rdma_destroy_id(conn->sc_id);

	if (bootverbose && ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: connection torn down\n");

	/*
	 * Last step before the free, with no sc_lock held, honouring the
	 * conns_lock before sc_lock order.  A concurrent sweep is serialized by
	 * conns_lock and only sets SC_CLOSING, so this stays the single free.
	 */
	mtx_lock(&svc_rdma_conns_lock);
	TAILQ_REMOVE(&svc_rdma_conns, conn, sc_link);
	mtx_unlock(&svc_rdma_conns_lock);

	mtx_destroy(&conn->sc_lock);
	free(conn, M_NFSRDMA);
}

/*
 * Accept an inbound connection on the freshly created child id.  conn is made
 * live from the first statement, so every failure funnels through
 * svc_rdma_conn_close() and the deferred teardown reclaims the id.  Nothing is
 * rejected or freed inline: rdma_accept() already does the modify-to-error,
 * reject and recv flush on its own failure.
 *
 * Recv buffers are posted before rdma_accept(), since an RC peer sends its
 * first call as soon as the connection establishes and an empty RQ RNR-NAKs.
 * Always returns 0, so the CM core never destroys the id from under us.
 */
static int
svc_rdma_accept(struct rdma_cm_id *id)
{
	struct ib_qp_init_attr qp_attr;
	struct rdma_conn_param conn_param;
	struct svc_rdma_conn *conn;
	struct ib_device *dev = id->device;
	const struct ib_recv_wr *bad_wr;
	u32 max_wr, max_send_wr, max_sge, max_send_sge;
	u32 send_vec, recv_vec;
	int i, rc;

	conn = malloc(sizeof(*conn), M_NFSRDMA, M_WAITOK | M_ZERO);

	/*
	 * Live before any verbs resource exists, so every failure from here can
	 * go to the deferred teardown.
	 */
	mtx_init(&conn->sc_lock, "nfsrdma_conn", NULL, MTX_DEF);
	TASK_INIT(&conn->sc_teardown, 0, svc_rdma_conn_destroy, conn);
	TAILQ_INIT(&conn->sc_writes);
	STAILQ_INIT(&conn->sc_early);
	conn->sc_write_sink_cqe.done = svc_rdma_wc_write_sink;
	conn->sc_state = SC_CONNECTING;
	conn->sc_id = id;
	id->context = conn;

	/*
	 * Copy the listener's ops and ctx under sl_lock, so completions and the
	 * teardown reach the consumer without touching the listener and a stop
	 * cannot pull them out from under an in-flight completion.
	 */
	mtx_lock(&svc_rdma_listener.sl_lock);
	conn->sc_ops = svc_rdma_listener.sl_ops;
	conn->sc_ctx = svc_rdma_listener.sl_ctx;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	/*
	 * Register before any verbs resource exists, so a failure below still
	 * leaves something for the teardown.  The insert completes inside the
	 * CM handler, which rdma_destroy_id() waits out, so no accept inserts
	 * after a sweep.  No sc_lock held, honouring conns_lock before sc_lock.
	 */
	mtx_lock(&svc_rdma_conns_lock);
	TAILQ_INSERT_TAIL(&svc_rdma_conns, conn, sc_link);
	mtx_unlock(&svc_rdma_conns_lock);

	/*
	 * max_qp_wr and max_sge are signed in the FreeBSD ib_device_attr, so
	 * clamp to at least 1; mlx rejects a zero-entry QP or CQ.  The SQ
	 * carries reply SENDs, Read chains and Write chains with their header
	 * SEND, so max_send_wr reserves one read and one write chain per recv
	 * buffer.  These are local bounds, not peer counts; on a small-cap
	 * device the clamp wins and an overflowing chain fails the post.
	 */
	max_wr = SVC_RDMA_RECV_DEPTH;
	if (dev->attrs.max_qp_wr > 0 &&
	    (u32)dev->attrs.max_qp_wr < max_wr)
		max_wr = dev->attrs.max_qp_wr;
	max_send_wr = max_wr +
	    max_wr * SVC_RDMA_MAX_READ_SEGS +
	    max_wr * (SVC_RDMA_MAX_WRITE_WRS + 1);
	if (dev->attrs.max_qp_wr > 0 &&
	    (u32)dev->attrs.max_qp_wr < max_send_wr)
		max_send_wr = dev->attrs.max_qp_wr;
	max_sge = 1;
	if (dev->attrs.max_sge > 0 && (u32)dev->attrs.max_sge < max_sge)
		max_sge = dev->attrs.max_sge;
	/*
	 * A recv WR uses one SGE; a send WR gathers up to
	 * SVC_RDMA_MAX_SEND_SGE pages for the zero-copy READ.
	 */
	max_send_sge = SVC_RDMA_MAX_SEND_SGE;
	if (dev->attrs.max_sge > 0 && (u32)dev->attrs.max_sge < max_send_sge)
		max_send_sge = dev->attrs.max_sge;

	conn->sc_pd = ib_alloc_pd(dev, 0);
	if (IS_ERR(conn->sc_pd)) {
		rc = -PTR_ERR(conn->sc_pd);
		conn->sc_pd = NULL;
		printf("nfsrdma: ib_alloc_pd failed: %d\n", rc);
		goto fail;
	}

	/*
	 * Each CQ is its QP cap plus one, the extra being head room for
	 * ib_drain_qp()'s sentinel WR alongside a full queue of flushed ones.
	 * comp_vector rotates per connection so completion processing is not
	 * all on one core.  IB_POLL_WORKQUEUE matters: the handlers decrement
	 * sc_reposts, sc_sends and sc_upcalls without a lock, correct only
	 * because one workqueue thread serializes completions per CQ.
	 */
	{
		u32 ncv = (dev->num_comp_vectors > 0) ?
		    (u32)dev->num_comp_vectors : 1;
		u32 base = atomic_fetchadd_int(&svc_rdma_cqv, 2);
		send_vec = base % ncv;
		recv_vec = (base + 1) % ncv;
	}
	conn->sc_scq = ib_alloc_cq(dev, conn, max_send_wr + 1, send_vec,
	    IB_POLL_WORKQUEUE);
	if (IS_ERR(conn->sc_scq)) {
		rc = -PTR_ERR(conn->sc_scq);
		conn->sc_scq = NULL;
		printf("nfsrdma: ib_alloc_cq (send) failed: %d\n", rc);
		goto fail;
	}
	conn->sc_rcq = ib_alloc_cq(dev, conn, max_wr + 1, recv_vec,
	    IB_POLL_WORKQUEUE);
	if (IS_ERR(conn->sc_rcq)) {
		rc = -PTR_ERR(conn->sc_rcq);
		conn->sc_rcq = NULL;
		printf("nfsrdma: ib_alloc_cq (recv) failed: %d\n", rc);
		goto fail;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_context = conn;
	qp_attr.send_cq = conn->sc_scq;
	qp_attr.recv_cq = conn->sc_rcq;
	qp_attr.srq = NULL;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.cap.max_send_wr = max_send_wr;
	qp_attr.cap.max_recv_wr = max_wr;
	qp_attr.cap.max_send_sge = max_send_sge;
	qp_attr.cap.max_recv_sge = max_sge;
	qp_attr.cap.max_inline_data = 0;

	/*
	 * max_send_sge inflates the per-WQE size and mlx5 rounds the WQE buffer
	 * to a power of two, so the SQ ceiling is not statically predictable.
	 * Ask for the ideal size and halve on ENOMEM, down to a floor holding
	 * one full chain; a smaller SQ only means the post can fill under load,
	 * which every post path handles by closing.  The provider may write
	 * granted caps back into qp_attr.cap, so sc_max_send_sge keeps ours.
	 */
	{
		u32 min_send_wr = max_wr +
		    SVC_RDMA_MAX_READ_SEGS + (SVC_RDMA_MAX_WRITE_WRS + 1);

		if (min_send_wr > max_send_wr)
			min_send_wr = max_send_wr;
		for (;;) {
			qp_attr.cap.max_send_wr = max_send_wr;
			rc = rdma_create_qp(id, conn->sc_pd, &qp_attr);
			if (rc == 0)
				break;
			if ((rc == -ENOMEM || rc == ENOMEM) &&
			    max_send_wr > min_send_wr) {
				u32 half = max_send_wr / 2;

				max_send_wr = (half > min_send_wr) ?
				    half : min_send_wr;
				continue;
			}
			printf("nfsrdma: rdma_create_qp failed: %d\n",
			    rc < 0 ? -rc : rc);
			goto fail;
		}
	}
	conn->sc_max_send_sge = max_send_sge;
	if (bootverbose && ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 1))
		printf("nfsrdma: QP up: send-queue %u WRs, send-sge %u\n",
		    max_send_wr, max_send_sge);

	/*
	 * Each recv buffer is mapped DMA_FROM_DEVICE and described by one SGE,
	 * with rr_wr.wr_cqe aliasing &rr_cqe so completions reach
	 * svc_rdma_wc_recv().  sc_nrecv is clamped to the QP recv cap, since
	 * posting the full depth on a smaller device would fail part way
	 * through the loop.
	 */
	conn->sc_nrecv = (SVC_RDMA_RECV_DEPTH < max_wr) ?
	    SVC_RDMA_RECV_DEPTH : max_wr;
	conn->sc_recv = malloc(conn->sc_nrecv * sizeof(*conn->sc_recv),
	    M_NFSRDMA, M_WAITOK | M_ZERO);

	for (i = 0; i < conn->sc_nrecv; i++) {
		struct svc_rdma_recv *rr = &conn->sc_recv[i];

		rr->rr_conn = conn;
		rr->rr_buf = malloc(SVC_RDMA_INLINE, M_NFSRDMA, M_WAITOK);
		rr->rr_dma = ib_dma_map_single(dev, rr->rr_buf,
		    SVC_RDMA_INLINE, DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(dev, rr->rr_dma)) {
			/*
			 * Map failed: leave rr_mapped false so the unwinder
			 * skips the unmap for this slot (it still frees
			 * rr_buf).
			 */
			printf("nfsrdma: ib_dma_map_single failed\n");
			goto fail;
		}
		rr->rr_mapped = true;

		rr->rr_sge.addr = rr->rr_dma;
		rr->rr_sge.length = SVC_RDMA_INLINE;
		rr->rr_sge.lkey = conn->sc_pd->local_dma_lkey;

		rr->rr_cqe.done = svc_rdma_wc_recv;
		rr->rr_wr.next = NULL;
		rr->rr_wr.wr_cqe = &rr->rr_cqe;
		rr->rr_wr.sg_list = &rr->rr_sge;
		rr->rr_wr.num_sge = 1;

		rc = ib_post_recv(id->qp, &rr->rr_wr, &bad_wr);
		if (rc != 0) {
			printf("nfsrdma: ib_post_recv failed: %d\n", rc);
			goto fail;
		}
	}

	/*
	 * The send-side mirror of the recv buffers, but not posted now: a SEND
	 * draws a free buffer when a call arrives.  Each is mapped whole so map
	 * and unmap stay symmetric, with ss_mapped set only after a successful
	 * map.  sc_nsend is clamped to the QP send cap.
	 */
	conn->sc_nsend = (SVC_RDMA_SEND_DEPTH < max_wr) ?
	    SVC_RDMA_SEND_DEPTH : max_wr;
	conn->sc_send = malloc(conn->sc_nsend * sizeof(*conn->sc_send),
	    M_NFSRDMA, M_WAITOK | M_ZERO);

	for (i = 0; i < conn->sc_nsend; i++) {
		struct svc_rdma_send *ss = &conn->sc_send[i];

		ss->ss_conn = conn;
		ss->ss_inuse = false;
		ss->ss_buf = malloc(SVC_RDMA_INLINE, M_NFSRDMA, M_WAITOK);
		ss->ss_dma = ib_dma_map_single(dev, ss->ss_buf,
		    SVC_RDMA_INLINE, DMA_TO_DEVICE);
		if (ib_dma_mapping_error(dev, ss->ss_dma)) {
			/*
			 * Map failed: leave ss_mapped false so the unwinder
			 * skips the unmap for this slot (it still frees
			 * ss_buf).
			 */
			printf("nfsrdma: ib_dma_map_single (send) failed\n");
			goto fail;
		}
		ss->ss_mapped = true;
	}

	/*
	 * Borrow and map contiguous read sinks so the WRITE path does not map
	 * per read.  Best effort: capped at the recv depth and stopping at the
	 * first failure, a short pool only meaning more fallback.  M_NOWAIT
	 * because accept runs under the RDMA-CM handler mutex, which serializes
	 * every new connection, and a contiguous M_WAITOK request can block
	 * indefinitely under fragmentation.
	 */
	conn->sc_nrbpool = (SVC_RDMA_READBUF_POOL < conn->sc_nrecv) ?
	    SVC_RDMA_READBUF_POOL : conn->sc_nrecv;
	conn->sc_rbpool = malloc(conn->sc_nrbpool * sizeof(*conn->sc_rbpool),
	    M_NFSRDMA, M_WAITOK | M_ZERO);
	{
		int rbk;
		for (rbk = 0; rbk < conn->sc_nrbpool; rbk++) {
			struct svc_rdma_readbuf *rb = &conn->sc_rbpool[rbk];

			rb->rb_buf = svc_rdma_sink_get();
			if (rb->rb_buf == NULL) {
				conn->sc_nrbpool = rbk;	/* short pool */
				break;
			}
			rb->rb_dma = ib_dma_map_single(dev, rb->rb_buf,
			    SVC_RDMA_MAX_READ, DMA_FROM_DEVICE);
			if (ib_dma_mapping_error(dev, rb->rb_dma)) {
				svc_rdma_sink_put(rb->rb_buf);
				rb->rb_buf = NULL;
				conn->sc_nrbpool = rbk;
				break;
			}
			rb->rb_mapped = true;
		}
	}

	/*
	 * responder_resources comes from the device's read depth capped to the
	 * u8 field, with a matching initiator depth: the server issues RDMA
	 * Reads to pull WRITE data, so the client must allow them through
	 * max_dest_rd_atomic.
	 *
	 * RNR retry 7 means retry forever.  The RQ momentarily drains under a
	 * burst and the client's SEND takes an RNR NAK; with retry 0 the QP
	 * would error on the first one and kill the connection.
	 */
	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources =
	    min_t(u32, U8_MAX, (u32)dev->attrs.max_qp_rd_atom);
	conn_param.initiator_depth =
	    min_t(u32, U8_MAX, (u32)dev->attrs.max_qp_init_rd_atom);
	conn_param.flow_control = 0;
	conn_param.rnr_retry_count = 7;
	conn_param.private_data = NULL;
	conn_param.private_data_len = 0;

	rc = rdma_accept(id, &conn_param);
	if (rc != 0) {
		/*
		 * rdma_accept() has already moved the QP to error, rejected and
		 * flushed the posted recvs, so doing either here would
		 * duplicate it and race those completions.  Return 0 to keep
		 * the id for the teardown, which drains before freeing.
		 */
		printf("nfsrdma: rdma_accept failed: %d\n", rc);
		goto fail;
	}

	{
		struct sockaddr_storage pss;
		const char *astr = "unknown";
#if defined(INET) || defined(INET6)
		char abuf[INET6_ADDRSTRLEN];
#endif

		svc_rdma_conn_peeraddr(conn, &pss);
#if defined(INET) || defined(INET6)
		switch (pss.ss_family) {
#ifdef INET
		case AF_INET:
			astr = inet_ntop(AF_INET,
			    &((struct sockaddr_in *)&pss)->sin_addr,
			    abuf, sizeof(abuf));
			break;
#endif
#ifdef INET6
		case AF_INET6:
			astr = inet_ntop(AF_INET6,
			    &((struct sockaddr_in6 *)&pss)->sin6_addr,
			    abuf, sizeof(abuf));
			break;
#endif
		}
#endif
		if (bootverbose && ppsratecheck(&svc_rdma_log_last,
		    &svc_rdma_log_pps, 5))
			printf("nfsrdma: accept: recv_depth=%d "
			    "send_depth=%d peer_af=%d peer=%s\n",
			    conn->sc_nrecv, conn->sc_nsend,
			    pss.ss_family, astr);
	}

	return (0);

fail:
	/*
	 * One failure path: the teardown task is the single destroyer of both
	 * the verbs resources and the id, so nothing is freed or rejected
	 * inline and we return 0 to keep the core from destroying the id too.
	 */
	svc_rdma_conn_close(conn);
	return (0);
}

/*
 * One wildcard listening cm_id for a single address family, bound to the
 * module listener context so a CONNECT_REQUEST routes through
 * svc_rdma_cm_event_handler.  *idp is left NULL on failure.  The FreeBSD
 * rdma_*() helpers return negative errnos, normalized here.
 */
static int
svc_rdma_bind_listener(sa_family_t af, uint16_t port, struct rdma_cm_id **idp)
{
	struct sockaddr_storage ss;
	struct rdma_cm_id *id;
	int rc;

	*idp = NULL;
	id = rdma_create_id(&init_net, svc_rdma_cm_event_handler,
	    &svc_rdma_listener, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id)) {
		rc = -PTR_ERR(id);
		return (rc != 0 ? rc : EINVAL);
	}

	rc = rdma_set_afonly(id, 1);
	if (rc != 0) {
		rdma_destroy_id(id);
		return (rc < 0 ? -rc : rc);
	}

	memset(&ss, 0, sizeof(ss));
	switch (af) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
		sin->sin_port = htons(port);
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = htons(port);
		break;
	}
#endif
	default:
		rdma_destroy_id(id);
		return (EAFNOSUPPORT);
	}

	rc = rdma_bind_addr(id, (struct sockaddr *)&ss);
	if (rc == 0)
		rc = rdma_listen(id, SVC_RDMA_CM_BACKLOG);
	if (rc != 0) {
		rdma_destroy_id(id);
		return (rc < 0 ? -rc : rc);
	}
	*idp = id;
	return (0);
}

/*
 * Bring up the passive listener on the wildcard address of each compiled-in
 * family.  ops and ctx are published with the ids in one sl_lock section, so a
 * racing CONNECT_REQUEST sees a consistent triple; ops must outlive the
 * listener and ctx svc_rdma_listen_stop(), and a failure publishes nothing.
 * Returns a positive errno.
 */
int
svc_rdma_listen_start_ops(uint16_t port, const struct svc_rdma_ops *ops,
    void *ctx)
{
	struct rdma_cm_id *id4 = NULL, *id6 = NULL;
	int rc4, rc6;

	if (port == 0 || ops == NULL)
		return (EINVAL);

	/*
	 * Hold the config lock across the whole bring-up so a concurrent
	 * svc_rdma_listen_stop() cannot cancel our reservation between the
	 * publish below and the per-id assignments that follow.
	 */
	sx_xlock(&svc_rdma_listen_cfg_lock);

	/*
	 * Publish ops and ctx before any cm_id goes live, so a CONNECT_REQUEST,
	 * which can only arrive after rdma_listen(), always finds the binding.
	 * sl_ops doubles as the busy token, so a second start without a stop
	 * gets EBUSY.
	 */
	mtx_lock(&svc_rdma_listener.sl_lock);
	if (svc_rdma_listener.sl_id != NULL ||
	    svc_rdma_listener.sl_id6 != NULL ||
	    svc_rdma_listener.sl_ops != NULL) {
		mtx_unlock(&svc_rdma_listener.sl_lock);
		sx_xunlock(&svc_rdma_listen_cfg_lock);
		return (EBUSY);
	}
	svc_rdma_listener.sl_ops = ops;
	svc_rdma_listener.sl_ctx = ctx;
	svc_rdma_listen_port = port;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	/*
	 * One wildcard cm_id per compiled-in family, each recorded as it goes
	 * live; a family that is compiled in but unavailable fails its own bind
	 * without sinking the other.  The window between rdma_listen() and the
	 * store cannot be closed, sl_lock not being held across the sleepable
	 * listen, and is only reachable by a device removal racing bring-up.
	 */
	rc4 = rc6 = EAFNOSUPPORT;
#ifdef INET
	rc4 = svc_rdma_bind_listener(AF_INET, port, &id4);
	if (rc4 == 0) {
		mtx_lock(&svc_rdma_listener.sl_lock);
		svc_rdma_listener.sl_id = id4;
		mtx_unlock(&svc_rdma_listener.sl_lock);
	} else
		printf("nfsrdma: IPv4 listener on port %u failed: %d\n",
		    port, rc4);
#endif
#ifdef INET6
	rc6 = svc_rdma_bind_listener(AF_INET6, port, &id6);
	if (rc6 == 0) {
		mtx_lock(&svc_rdma_listener.sl_lock);
		svc_rdma_listener.sl_id6 = id6;
		mtx_unlock(&svc_rdma_listener.sl_lock);
	} else
		printf("nfsrdma: IPv6 listener on port %u failed: %d\n",
		    port, rc6);
#endif
	if (id4 == NULL && id6 == NULL) {
		/* Nothing bound; release the reservation. */
		mtx_lock(&svc_rdma_listener.sl_lock);
		svc_rdma_listener.sl_ops = NULL;
		svc_rdma_listener.sl_ctx = NULL;
		svc_rdma_listen_port = 0;
		mtx_unlock(&svc_rdma_listener.sl_lock);
		sx_xunlock(&svc_rdma_listen_cfg_lock);
		return (rc4 != 0 ? rc4 : (rc6 != 0 ? rc6 : EAFNOSUPPORT));
	}

	if (bootverbose)
		printf("nfsrdma: listening on port %u (%s%s%s)\n", port,
		    id4 != NULL ? "IPv4" : "",
		    (id4 != NULL && id6 != NULL) ? "+" : "",
		    id6 != NULL ? "IPv6" : "");
	sx_xunlock(&svc_rdma_listen_cfg_lock);
	return (0);
}

/*
 * Tear the listener down and reclaim every connection it accepted.  The ids
 * are detached under sl_lock and destroyed outside it, since the CM teardown
 * blocks; rdma_destroy_id() does not return while the handler runs, so no
 * accept is still in progress afterwards.
 *
 * The listener id goes first, so the registry can only shrink from here.  The
 * walk then closes each connection under svc_rdma_conns_lock, which is safe
 * while iterating because close neither blocks nor frees.  The final drain is
 * taskqueue_drain_all() rather than a per-connection drain, since the task
 * frees the conn and &conn->sc_teardown would already be dangling.
 *
 * It runs even when no id was published: a connection established before an
 * explicit stop outlives the listener.
 */
void
svc_rdma_listen_stop(void)
{
	struct rdma_cm_id *id, *id6;
	struct svc_rdma_conn *conn;

	/* Serialize against svc_rdma_listen_start_ops() (see sl_cfg_lock). */
	sx_xlock(&svc_rdma_listen_cfg_lock);

	mtx_lock(&svc_rdma_listener.sl_lock);
	id = svc_rdma_listener.sl_id;
	id6 = svc_rdma_listener.sl_id6;
	svc_rdma_listener.sl_id = NULL;
	svc_rdma_listener.sl_id6 = NULL;
	/*
	 * Clear the binding with the ids so a later start begins fresh.  Live
	 * connections are unaffected: each carries its own copy taken at
	 * accept, so the sweep below still reaches the consumer.
	 */
	svc_rdma_listener.sl_ops = NULL;
	svc_rdma_listener.sl_ctx = NULL;
	svc_rdma_listen_port = 0;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	if (id != NULL)
		rdma_destroy_id(id);
	if (id6 != NULL)
		rdma_destroy_id(id6);
	if ((id != NULL || id6 != NULL) && bootverbose)
		printf("nfsrdma: listener stopped\n");

	/*
	 * Reclaim every live connection.  conns_lock is the outer lock;
	 * conn_close takes sc_lock (inner) -- consistent with the documented
	 * order.
	 */
	mtx_lock(&svc_rdma_conns_lock);
	TAILQ_FOREACH(conn, &svc_rdma_conns, sc_link)
		svc_rdma_conn_close(conn);
	mtx_unlock(&svc_rdma_conns_lock);

	/*
	 * Wait out every enqueued+running teardown (each removes itself from
	 * the registry and frees its conn).  Drain the whole queue, never a
	 * per-conn task pointer -- the task frees the conn.
	 */
	taskqueue_drain_all(taskqueue_thread);

	sx_xunlock(&svc_rdma_listen_cfg_lock);
}
