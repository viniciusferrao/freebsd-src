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
	.sl_ops = NULL,
	.sl_ctx = NULL,
};

struct svc_rdma_conn_list svc_rdma_conns =
    TAILQ_HEAD_INITIALIZER(svc_rdma_conns);
struct mtx svc_rdma_conns_lock;

/*
 * Initialize/destroy sl_lock and svc_rdma_conns_lock at module load/unload via
 * MTX_SYSINIT.  This file is linked into the nfsrdma KLD, so it has no module
 * event of its own; SYSINIT machinery is how an nfsrdma-internal source unit gets
 * init/teardown hooks.
 */
MTX_SYSINIT(svc_rdma_listener_lock, &svc_rdma_listener.sl_lock,
    "nfsrdma_listener", MTX_DEF);
MTX_SYSINIT(svc_rdma_conns_lock, &svc_rdma_conns_lock,
    "nfsrdma_conns", MTX_DEF);

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
 * CM event handler for the *listener* cm_id and for the child cm_ids it
 * spawns.  Runs in the rdma_cm work context.
 *
 * Untrusted peer: every field reachable through "event" that originates from
 * the wire (private data, param.conn.*) is attacker-controlled and is NOT
 * touched here.  We read exactly one peer-derived datum,
 * id->route.addr.dst_addr, only to log it.  Be precise about why that is safe:
 * for an IP-based CM request the dst_addr is NOT "purely local" -- it is
 * derived from the CM REQ header the peer sent (cma_save_ip4_info() copies
 * hdr->src_addr/hdr->port into dst_addr, ib_cma.c), but the CM core has
 * validated/resolved it into a well-formed sockaddr_storage before this
 * handler runs.  So reading a fixed-size sockaddr and logging it is safe, yet
 * the value is still peer-originated.  This file is the template the rest of
 * the server will copy: future code MUST keep treating peer-supplied lengths,
 * offsets, chunk counts, and private data as hostile and bounds-check them --
 * the validity of this one resolved sockaddr does not extend to anything else
 * in the event.
 *
 * Event routing: the handler is shared by the listener id and every child
 * id it spawns.  id->context discriminates them: the listener id was created
 * with context == &svc_rdma_listener; svc_rdma_accept() rewrites the child id's
 * context to its struct svc_rdma_conn (right after allocating it, before any
 * verbs resource), so every subsequent event on that child (ESTABLISHED,
 * DISCONNECTED, errors, DEVICE_REMOVAL) is delivered with id->context == conn.
 * A CONNECT_REQUEST always arrives with id->context still == &svc_rdma_listener
 * (the child inherits the listener's context at creation in cma_req_handler()),
 * so it is unambiguously the listener event even though "id" is the brand-new
 * child.
 *
 * CONNECT_REQUEST contract (FreeBSD ib_cma.c cma_req_handler()):
 *   - "id" here IS the freshly-created child cm_id (Linux's event->id); the
 *     FreeBSD rdma_cm_event has no ->id member.
 *   - Per rdma_cm.h: "Users may not call rdma_destroy_id from this callback to
 *     destroy the passed in id ... Returning a non-zero value from the callback
 *     will destroy the passed in id."  svc_rdma_accept() therefore ALWAYS
 *     returns 0 and keeps the id: on success the connection is up, and on ANY
 *     post-allocation failure it hands the id to the deferred teardown task
 *     (the single drained destroyer) instead of rejecting/destroying inline.
 *     We never rdma_reject() here (a failed rdma_accept already rejected
 *     internally) and never rdma_destroy_id(id) from the callback (forbidden
 *     reentrant destroy of the passed-in id).  See svc_rdma_accept() and
 *     svc_rdma_conn_destroy() for the full failure model.
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

	/*
	 * Connection events: id->context is the per-connection object, not the
	 * listener.  Handle them first so the listener-only switch below never
	 * sees a child event.  (CONNECT_REQUEST is the one exception: it routes
	 * to the listener even though "id" is the child -- see above.)
	 */
	if (id->context != &svc_rdma_listener &&
	    event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		conn = id->context;

		switch (event->event) {
		case RDMA_CM_EVENT_ESTABLISHED:
			/*
			 * The ESTABLISHED CM event is the SOLE deliverer of
			 * sro_newconn.  Recv buffers are posted
			 * before rdma_accept(), so the peer's first inline call can
			 * complete and reach svc_rdma_wc_recv() in the recv CQ
			 * context BEFORE this event runs -- but that recv path does
			 * NOT deliver newconn; it gates its sro_recv dispatch on
			 * (SC_UP && sc_newconn_done) and, when not yet ready, HOLDS
			 * the early call on sc_early (un-reposted) instead of dropping
			 * it.  This handler DRAINS sc_early right after it publishes
			 * sc_newconn_done below, replaying each held call.  (Dropping
			 * was the old behavior and was a bug: an RC client never
			 * retransmits a delivered call, so a dropped first RPC hung the
			 * mount.)  Making ESTABLISHED the single deliverer AND the
			 * single early-call drainer removes every two-deliverer race.
			 *
			 * Win the SC_CONNECTING -> SC_UP transition under sc_lock
			 * (so we do not race a teardown a recv-error completion may
			 * have already started); only the winner delivers.  In that
			 * same section set sc_newconn_fired (the DURABLE pairing
			 * token -- set BEFORE the upcall, so a teardown landing in the
			 * post-upcall/pre-done window still pairs disconnect with it)
			 * and bump sc_upcalls (this sro_newconn is now an in-flight
			 * consumer upcall the teardown must drain before disconnect).
			 *
			 * Deliver sro_newconn with the lock DROPPED (the consumer may
			 * xprt_register etc. in this sleepable CM-handler context),
			 * and ONLY AFTER it returns set sc_newconn_done and drop the
			 * sc_upcalls refcount under sc_lock.  Ordering is load-bearing:
			 * sc_newconn_done becomes true strictly after sro_newconn has
			 * completed, so the recv path's (SC_UP && sc_newconn_done)
			 * dispatch gate is satisfied only once newconn has finished.
			 * Because we are the sole SC_UP winner, exactly one thread ever
			 * does this, so newconn is delivered exactly once.
			 *
			 * Publishing SC_UP here enables the repost/send paths;
			 * sro_recv dispatch gates on (SC_UP && sc_newconn_done).
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
				 * Splice the early-recv hold list out under the
				 * SAME lock that publishes sc_newconn_done: any recv
				 * that enqueued while we were not ready is now ours
				 * to drain, and any recv completing after this unlock
				 * sees the open gate and dispatches itself.  We KEEP
				 * our ESTABLISHED sc_upcalls reference held across the
				 * drain (dropped only after it) so the teardown
				 * barrier (sc_upcalls == 0) cannot free a held rr
				 * while we replay it.
				 */
				{
					STAILQ_HEAD(, svc_rdma_recv) early =
					    STAILQ_HEAD_INITIALIZER(early);
					struct svc_rdma_recv *erp;

					STAILQ_CONCAT(&early, &conn->sc_early);
					conn->sc_nearly = 0;
					mtx_unlock(&conn->sc_lock);

					/*
					 * Replay each held early call now that the
					 * gate is open and SC_UP is set.  Dropping a
					 * first RPC is what hung the mount; replaying
					 * it is the fix.  svc_rdma_dispatch_recv() does
					 * its own per-call sc_upcalls accounting, so the
					 * teardown still drains every replayed upcall.
					 * Runs in the sleepable CM-handler context --
					 * the same context that just ran sro_newconn,
					 * strictly more permissive than the recv-
					 * completion context sro_recv normally sees.
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
			 * Peer-driven shutdown or failure.  Defer the (blocking)
			 * unwind to the teardown task; the callback cannot sleep
			 * and may not rdma_destroy_id() the passed-in id.  Return
			 * 0 so the core keeps the id alive until the task -- the
			 * single destroyer -- runs.
			 */
			svc_rdma_conn_close(conn);
			return (0);

		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			/*
			 * The device under a live connection is going away.
			 * Unlike the listener (which has no verbs resources and
			 * lets the CM core destroy its id on a nonzero return),
			 * a connection owns a QP/CQ/PD and posted DMA buffers.
			 * rdma_destroy_id() does NOT free those (ib_cma.c:1883:
			 * it only tears down CM state and kfree()s id_priv), so
			 * letting the core destroy the id on a nonzero return
			 * would LEAK the QP/CQ/PD/buffers.  We must instead run
			 * the full verbs unwind ourselves -- which sleeps -- so
			 * we defer it to the teardown task exactly like the
			 * disconnect path and return 0.
			 *
			 * Returning 0 means the CM core does NOT destroy the id
			 * here; the teardown task is still its sole destroyer.
			 * This does not hang device removal: cma_process_remove()
			 * (ib_cma.c:4597) drops its own ref and then blocks on
			 * wait_for_completion(&cma_dev->comp); the id holds a
			 * cma_device reference until our task's rdma_destroy_id()
			 * calls cma_release_dev(), at which point the completion
			 * fires.  Our task runs on taskqueue_thread, a different
			 * thread from the CM workqueue doing the wait, so the
			 * wait is always satisfiable -- the same cross-thread
			 * dependency the listener teardown relies on.
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
		/*
		 * A real inbound connection request landed on the listener.
		 * Log the peer (rate-limited) and accept it into a fresh QP with
		 * receive buffers posted.  svc_rdma_accept() ALWAYS returns 0 and
		 * keeps the child id: on success the connection is up; on any
		 * failure it hands the id to the deferred drained teardown task
		 * (no inline reject/free).  We propagate that 0 so the CM core
		 * never reentrant-destroys the passed-in id.
		 */
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
		 * The underlying device is going away.  Exactly ONE party must
		 * rdma_destroy_id() this id: either us-via-the-CM-core (by
		 * returning nonzero here -- cma_process_remove() ->
		 * cma_remove_id_dev() in ib_cma.c calls rdma_destroy_id() iff
		 * the handler returns nonzero) or svc_rdma_listen_stop().
		 * rdma_destroy_id() is NOT idempotent (it cma_exch()es to
		 * DESTROYING and unconditionally kfree()s id_priv), so a double
		 * call is a use-after-free.
		 *
		 * sl_id is the single ownership token, mutated only under
		 * sl_lock.  Whoever NULLs it owns the destroy:
		 *   - If id == sl_id here, WE take ownership (NULL it) and
		 *     return nonzero so the core destroys it now, while cma_dev
		 *     is still alive.  A later listen_stop() sees sl_id == NULL
		 *     and does nothing.
		 *   - If id != sl_id, listen_stop() already claimed this id and
		 *     will rdma_destroy_id() it; we return 0 so the core does
		 *     NOT also destroy it.  This is leak/hang-free: the id holds
		 *     a cma_device reference until that destroy calls
		 *     cma_release_dev(), and cma_remove_one() blocks on
		 *     wait_for_completion(&cma_dev->comp) until that reference
		 *     drops -- so cma_dev is never freed under the pending
		 *     destroy, and the device-removal completes once
		 *     listen_stop() finishes.
		 * The two sl_lock critical sections (here and in listen_stop())
		 * are serialized, so ownership is unambiguous.  We never call
		 * rdma_destroy_id() ourselves from the callback (forbidden
		 * reentrant destroy of the passed-in id).
		 */
		mtx_lock(&svc_rdma_listener.sl_lock);
		owned = (id == svc_rdma_listener.sl_id);
		if (owned) {
			svc_rdma_listener.sl_id = NULL;
			/* Clear the consumer binding with sl_id (see listen_stop). */
			svc_rdma_listener.sl_ops = NULL;
			svc_rdma_listener.sl_ctx = NULL;
			svc_rdma_listen_port = 0;
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
 * svc_rdma_conn_send() -- copy a caller-marshalled inline reply into a free
 * send buffer and post it.  This is the reusable send-pool path: the bytes come
 * from a caller buffer (buf/len).  A consumer's sro_recv posts replies through
 * here; the SC_UP gate, bounded-pool free-list, and sc_sends quiescence barrier
 * are honored IDENTICALLY for every caller.
 *
 * PUBLIC entry point (declared in <rdma/svc_rdma.h>).  Context: callable from
 * the recv completion (IB_POLL_WORKQUEUE) -- it does NOT sleep and takes only
 * sc_lock briefly, exactly as before.  A consumer MAY call it synchronously from
 * within sro_recv (the krpc consumer may).  It MUST NOT be called after this
 * conn's sro_disconnect has returned (the teardown owns the pool by then); the
 * SC_UP gate makes a stray late call a harmless drop rather than a UAF, but the
 * consumer must not rely on that.
 *
 * buf is caller-owned and only read here: we COPY len bytes into ss_buf (no
 * ownership transfer), so the caller may free/reuse buf the instant this
 * returns.  len must be <= SVC_RDMA_INLINE (the mapped buffer size); a longer
 * reply needs the RDMA Write chunk path and is rejected with EINVAL rather than
 * truncated.
 *
 * UNTRUSTED PEER.  This routine copies exactly the bytes the caller marshalled;
 * it trusts nothing from the wire itself.  The consumer is responsible for
 * bounds-checking anything peer-derived BEFORE handing the marshalled reply here.
 *
 * Bounded pool + send-quiescence barrier (the send-side mirror of the recv
 * repost barrier).  Under sc_lock, in one critical section:
 *   - bail (ENOTCONN) if the connection is no longer SC_UP (a teardown is in
 *     progress; the send pool is reclaimed by that task after ib_drain_qp(), so
 *     dropping the reply here cannot leak and must not post behind the drain
 *     sentinel);
 *   - claim a free send buffer (ss_inuse) from the bounded pool, dropping the
 *     reply (EBUSY) if none is free (a peer flooding calls cannot make us
 *     over-allocate or block this completion);
 *   - bump sc_sends (the in-flight-send refcount the teardown drains before
 *     ib_drain_qp()).
 * We then copy + ib_post_send() with the lock DROPPED (matching the recv path,
 * which drops sc_lock across ib_post_recv).  After the post we reacquire,
 * decrement sc_sends, and wake the teardown if we were the last in-flight send.
 * On post failure we release the buffer and close the conn.
 *
 * Because svc_rdma_conn_close() publishes SC_CLOSING BEFORE enqueuing the
 * teardown task, once teardown is pending no NEW reply passes the SC_UP check;
 * the task's barrier then waits only for already-counted sends to finish their
 * ib_post_send and decrement.  After sc_sends hits 0 every SEND WR is on the SQ
 * before ib_drain_qp(), so the SQ drain sentinel catches them all and nothing
 * posts afterward -- the identical argument the recv barrier makes for the RQ.
 */
int
svc_rdma_conn_send(struct svc_rdma_conn *conn, const void *buf, uint32_t len)
{
	struct svc_rdma_send *ss;
	const struct ib_send_wr *bad_wr;
	int i, rc;

	/*
	 * The reply must fit a single mapped send buffer.  A fixed local bound,
	 * not peer-derived; a larger reply takes the RDMA Write chunk path, not a
	 * truncation.
	 */
	if (len == 0 || len > SVC_RDMA_INLINE)
		return (EINVAL);

	/*
	 * Claim a free send buffer and arm the send barrier, all while SC_UP,
	 * in a single sc_lock critical section -- the send-side mirror of the
	 * repost barrier's "sample SC_UP, bump refcount, drop lock" sequence.
	 */
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
		 * Bounded pool exhausted (peer is flooding calls faster than
		 * our sends complete).  Drop this reply -- never block the
		 * completion, never over-allocate.
		 */
		mtx_unlock(&conn->sc_lock);
		return (EBUSY);
	}
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * Copy the caller's already-marshalled reply into our DMA-mapped send
	 * buffer.  The mapping is DMA_TO_DEVICE and was set up once at accept
	 * time; the device reads ss_buf as we just wrote it (CPU-then-device
	 * ordering is provided by the post doorbell).  Build the prebuilt-shape
	 * SGE/WR each time with this reply's length (<= SVC_RDMA_INLINE).
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
	 * Post with the lock dropped (mirroring the recv repost).  bad_wr MUST
	 * be passed (never NULL): mlx5_ib_post_send dereferences *bad_wr on an
	 * immediate error, the same defect the recv path was fixed for.
	 */
	rc = ib_post_send(conn->sc_id->qp, &ss->ss_wr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (rc != 0) {
		/*
		 * The WR never reached the SQ, so no completion will ever fire
		 * for it: release the buffer here so it is not leaked from the
		 * pool.  Then drop the send barrier and close the connection.
		 */
		ss->ss_inuse = false;
	}
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);	/* shared quiesce channel */
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
 * Attach/retrieve the consumer's per-connection state.  The verbs
 * layer never interprets or frees sc_cctx; it is opaque consumer-owned state
 * that the consumer sets (typically from sro_newconn) and reclaims (from
 * sro_disconnect).  We take sc_lock only to give set/get a defined ordering
 * against the upcall contexts; the verbs layer itself does not read sc_cctx.
 * Declared in <rdma/svc_rdma.h>.
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
 * Report the granted flow-control credit -- the number of recv buffers we
 * actually posted for this connection (sc_nrecv), clamped at accept time to the
 * device's QP recv cap.  This is the value a consumer's reply should advertise
 * in the RPC-over-RDMA rdma_credit field.  sc_nrecv is written once during accept and never
 * mutated thereafter (see the accept-path comment), so this read needs no
 * sc_lock.  Declared in <rdma/svc_rdma.h>.
 */
uint32_t
svc_rdma_conn_credits(struct svc_rdma_conn *conn)
{

	return ((uint32_t)conn->sc_nrecv);
}

/*
 * Pre-allocate the calling thread's linuxkpi `current` shadow (#59).  The krpc
 * reply paths call ib_post_send while holding the xr_lock leaf mutex, trusting
 * that the post does not sleep.  That holds EXCEPT the first time a given krpc
 * pool thread enters mlx5_ib_post_send: it dereferences `current`, and linuxkpi
 * lazily allocates the per-thread shadow with M_WAITOK (a sleepable uma_zalloc),
 * which WITNESS flags under the mutex.  The krpc consumer calls this once at the
 * top of a reply -- OFF every lock, where M_WAITOK is legal -- so the shadow
 * already exists when the under-lock post runs and mlx5 never allocates.
 * linux_set_current is a no-op once the shadow is set, so per-reply calls are
 * cheap.  Declared in <rdma/svc_rdma.h>.
 */
void
svc_rdma_thread_setup(void)
{

	linux_set_current(curthread);
}

/*
 * Surface the connection's PEER address.  RDMA-CM resolved the
 * client's address into the cm_id during connection setup; for NFS-over-RDMA the
 * client did rdma_resolve_addr() on an IP (its IPoIB address), so
 * route.addr.dst_addr is the client's sockaddr_in/in6.  The krpc consumer copies
 * this into the SVCXPRT's xp_rtaddr so NFS export-address checks
 * (svc_getrpccaller -> xp_rtaddr) match the client against -network/-host
 * exports, exactly as a TCP transport's peer address does.  We normalize sa_len
 * from the family (the OFED address path may leave it 0) and copy only known
 * families; an unknown/absent address yields AF_UNSPEC (the prior behavior).
 * Declared in <rdma/svc_rdma.h>.
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
 * Marshal and post an RPC-over-RDMA version 1 RDMA_ERROR reply (RFC 8166 4.4/5),
 * echoing the call's KNOWN opaque xid.  Rather than silently conn_close()ing a
 * recoverable protocol error, this tells the client WHY with a transport-level
 * error reply.
 *
 *   ERR_VERS  - the inbound rdma_vers was not 1; we report our supported version
 *               range [vers_low, vers_high] = [1, 1] (words 5,6).  The recv path
 *               sends this then closes the mismatched connection.
 *   ERR_CHUNK - the chunk lists could not place the reply (over-inline reply with
 *               no usable reply chunk; write-list read DDP boundary out of range).
 *               Per-request: the connection stays up and the client may retry.
 *
 * Header layout (all big-endian XDR words, RFC 8166 4.4):
 *   w0 rdma_xid    = echoed call xid (the ONLY peer-derived value)
 *   w1 rdma_vers   = RPCRDMA_VERSION (1)
 *   w2 rdma_credit = conn->sc_nrecv -- the credit we GRANT (posted recv depth),
 *                    never the peer's offered
 *                    credit.  Set once at accept time, never mutated, so reading
 *                    it here without sc_lock is safe.
 *   w3 rdma_proc   = RDMA_ERROR (4)
 *   w4 rdma_err    = errcode (ERR_VERS | ERR_CHUNK)
 *   ERR_VERS only:
 *     w5 vers_low  = RPCRDMA_VERSION (1)
 *     w6 vers_high = RPCRDMA_VERSION (1)
 * Total: 5 words (20 bytes) for ERR_CHUNK, 7 words (28 bytes) for ERR_VERS --
 * both well under SVC_RDMA_INLINE, so the fixed local buffer cannot overflow.
 *
 * UNTRUSTED PEER / LIFETIME.  The ONLY peer-derived datum is the 32-bit xid,
 * echoed verbatim; every other word is our own fixed constant, and no peer
 * length sizes the buffer.  The caller MUST pass a real xid that came from a
 * header whose fixed prefix parsed (svc_rdma_parse_header stamped it); we NEVER
 * build an RDMA_ERROR from an unparseable header.  The reply is built into a
 * local stack buffer we own and handed to svc_rdma_conn_send(), which copies it
 * into the bounded DMA send pool under the SAME SC_UP gate, free-list, and
 * sc_sends quiescence barrier as every other reply -- the send buffer is
 * reclaimed by svc_rdma_wc_send() (or the drained teardown) on completion, never
 * here, so there is no UAF and no double-free.  Context: callable from the recv
 * completion (IB_POLL_WORKQUEUE) and from a krpc pool thread holding a conn
 * reference; it does not sleep.  A drop (pool exhausted / closing) is logged and
 * ignored -- for ERR_VERS the close follows regardless; for ERR_CHUNK the
 * client's RC retransmit recovers.
 */
int
svc_rdma_send_error(struct svc_rdma_conn *conn, uint32_t xid, uint32_t errcode)
{
	char err[RPCRDMA_HDR_FIXED + 3 * RPCRDMA_WORD];
	char *p = err;
	uint32_t len;
	int rc;

	be32enc(p +  0, xid);			/* w0  rdma_xid */
	be32enc(p +  4, RPCRDMA_VERSION);	/* w1  rdma_vers */
	be32enc(p +  8, (uint32_t)conn->sc_nrecv); /* w2 rdma_credit: posted depth */
	be32enc(p + 12, RDMA_ERROR);		/* w3  rdma_proc */
	be32enc(p + 16, errcode);		/* w4  rdma_err */
	len = RPCRDMA_HDR_FIXED + RPCRDMA_WORD;	/* w0..w4 = 5 words = 20 bytes */
	if (errcode == ERR_VERS) {
		be32enc(p + 20, RPCRDMA_VERSION); /* w5  vers_low  = 1 */
		be32enc(p + 24, RPCRDMA_VERSION); /* w6  vers_high = 1 */
		len += 2 * RPCRDMA_WORD;		/* now 7 words = 28 bytes */
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
 * Consumer-facing RDMA_ERROR entry point (the svo_conn_error op).  The
 * krpc consumer (sys/rpc/svc_rdma.c) reaches this through the registered
 * verbs-ops table when it cannot place a reply with the offered chunk lists and
 * wants to report ERR_CHUNK keyed by the request's xid instead of dropping
 * silently.  Thin wrapper over svc_rdma_send_error() so the consumer needs no
 * knowledge of the wire header; it does NOT close the connection (ERR_CHUNK is a
 * per-request error and the connection stays UP).  Declared extern in
 * <rdma/svc_rdma.h>; OPTIONAL (krpc NULL-checks it at the call site and
 * svc_rdma_register_verbs does not require it, so an older nfsrdma still loads and
 * over-inline drops keep their prior behavior).
 */
int
svc_rdma_conn_error(struct svc_rdma_conn *conn, uint32_t xid, uint32_t errcode)
{

	return (svc_rdma_send_error(conn, xid, errcode));
}

/*
 * Send completion.  Dispatched by the CQ core in the same IB_POLL_WORKQUEUE
 * context as svc_rdma_wc_recv(); keep it short, take no sleepable lock, start no
 * blocking teardown.  ss_wr.wr_cqe aliases &ss->ss_cqe so container_of()
 * recovers the send descriptor and ss_conn the owning connection.
 *
 * On success the reply has been transmitted and the device is done reading
 * ss_buf, so return the buffer to the bounded pool (clear ss_inuse under
 * sc_lock).  IB_WC_WR_FLUSH_ERR is the expected status for any reply WR flushed
 * when the QP drains during teardown: swallow it silently (the teardown task
 * unmaps and frees the send buffers, not here -- and it does so only AFTER
 * ib_drain_qp(), so this completion sees a still-live conn).  Any other error is
 * a real send fault -> start a deferred teardown.  We do NOT free ss_buf or
 * unmap here: that is the drained-teardown's exactly-once job, exactly as the
 * recv completion never frees rr_buf.
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
		 * Flushed during teardown: expected, ignore (the buffer is
		 * reclaimed by the teardown task).  Any other error: the send
		 * failed for a live connection -> tear it down.  Either way we
		 * leave ss_inuse as-is; the teardown frees the whole pool.
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

	/* Return the buffer to the bounded pool. */
	mtx_lock(&conn->sc_lock);
	ss->ss_inuse = false;
	mtx_unlock(&conn->sc_lock);
}

/*
 * Request a deferred teardown of conn.  Callable from any context, including
 * the CM callback and the recv completion (both of which forbid blocking).
 *
 * sc_state is the single ownership token.  The SC_CONNECTING/SC_UP -> SC_CLOSING
 * transition is performed at most once, under sc_lock; only the caller that
 * wins it enqueues sc_teardown.  Every later request (a DISCONNECTED racing a
 * recv error racing a DEVICE_REMOVAL) finds SC_CLOSING and is a no-op, so the
 * task is enqueued exactly once and rdma_destroy_id() is called exactly once.
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
 * Free every verbs resource a connection owns, in strict reverse order of
 * allocation, NULL-guarding each so this tolerates an arbitrary partial build
 * and is idempotent.  It does NOT touch sc_id (the teardown task destroys that
 * after this returns).  The caller (svc_rdma_conn_destroy) MUST have already
 * drained the QP via ib_drain_qp(); this routine then frees the CQs FIRST, and
 * ib_free_cq()'s flush_work() -- NOT ib_drain_qp() -- is the barrier that
 * guarantees the completion workqueue has dispatched every completion, so no
 * completion can fire against the writes/buffers/conn this frees afterward.
 *
 * Order: QP (clears sc_id->qp) -> recv CQ -> send CQ -> reclaim in-flight writes
 * -> unmap+free each recv buffer -> unmap+free each send buffer -> free the
 * read-buffer pool -> PD.  The CQs are freed BEFORE any completion-referenced
 * state (writes/recv/send/rbpool buffers) so the workqueue is quiesced first.
 * A CQ is never freed under a live QP, and the PD (whose local_dma_lkey the
 * recv/send SGEs reference) outlives every buffer that used it.
 * rdma_destroy_qp() is the cm_id-paired QP destructor: it must only be called
 * when a QP actually exists (sc_id->qp != NULL), and it clears sc_id->qp itself,
 * so we must not poke sc_id->qp by hand.
 */
static void
svc_rdma_conn_free_verbs(struct svc_rdma_conn *conn)
{
	struct ib_device *dev;
	int i;

	if (conn->sc_id != NULL && conn->sc_id->qp != NULL)
		rdma_destroy_qp(conn->sc_id);

	/*
	 * Free the CQs BEFORE reclaiming any completion-referenced state.
	 * ib_free_cq() flush_work()s the completion workqueue, so once it returns NO
	 * completion can still run; that is the real quiescence barrier, NOT
	 * ib_drain_qp().  Under heavy close churn -- every ENOMEM / SQ-full post closes
	 * the conn -- a SUCCESSFUL tail-SEND completion can still be sitting
	 * undispatched in the send CQ when this teardown runs; ib_drain_qp() does not
	 * guarantee the workqueue has dispatched it.  The recv buffers, send pool, and
	 * MRs are freed AFTER the CQs for exactly this reason, and so is the sc_writes
	 * reclaim below: reclaiming a ws before the CQ free would let a pending SEND
	 * completion dereference a freed ws_cqe.
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
	 * Reclaim any outbound RDMA Write whose completion NEVER ran:
	 * a never-posted / partially-posted attempt a racing close stranded, or a
	 * write whose tail SEND never reached the SQ.  The CQ frees above guarantee
	 * every dispatched completion has finished (each reclaimed its OWN ws via the
	 * sc_writes one-shot), so what remains here has no pending completion and WE
	 * are its single reclaimer.  Detach each under sc_lock and free it (unmaps
	 * ws_src/ws_hdr via the idempotent mapped tokens, frees the state) -- exactly
	 * once.  svc_rdma_write_free does not sleep; we drop the lock across it.
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
		 * sc_id->device is the map device; it is still valid here (the
		 * id outlives the verbs unwind).  Each slot was mapped exactly
		 * once at accept time and is unmapped exactly once here.
		 * rr_mapped is set true only after a successful
		 * ib_dma_map_single(); a slot whose map failed (or was never
		 * reached) during a partial build has rr_mapped == false --
		 * skip its unmap but still free its buffer.
		 */
		dev = conn->sc_id->device;
		for (i = 0; i < conn->sc_nrecv; i++) {
			struct svc_rdma_recv *rr = &conn->sc_recv[i];

			/*
			 * Reclaim any RDMA Read still in flight for
			 * this recv at close: free+unmap the server destination
			 * buffer and the inline-head copy.  svc_rdma_read_free is
			 * idempotent (rs_mapped/rs_active), so a read that already
			 * completed normally is a no-op here, and one that never
			 * completed (closed mid-read, or a flushed read WR) is
			 * freed exactly once.  ib_drain_qp() already ran in
			 * svc_rdma_conn_destroy(), so no RDMA Read completion can
			 * be touching rs_buf/rs_dma when we release them.
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
		/*
		 * Send-buffer pool, the exact mirror of the recv unwind.
		 * Each slot was DMA-mapped DMA_TO_DEVICE exactly once at accept
		 * time and is unmapped exactly once here; ss_mapped (set true
		 * only after a successful ib_dma_map_single) gates the unmap so
		 * a slot whose map failed during a partial build is freed but
		 * not unmapped.  ib_drain_qp() already ran, so no send
		 * completion can be reading ss_buf when we free it.
		 */
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
	 * Read-buffer pool.  Runs AFTER ib_drain_qp() (via caller
	 * svc_rdma_conn_destroy), so no in-flight read can still hold a pool buffer:
	 * every committed RDMA Read WR has flushed, and svc_rdma_read_free has been
	 * called for each recv above.  Unmap + free each slot, then free the array.
	 */
	if (conn->sc_rbpool != NULL) {
		dev = conn->sc_id->device;
		for (i = 0; i < conn->sc_nrbpool; i++) {
			struct svc_rdma_readbuf *rb = &conn->sc_rbpool[i];

			if (rb->rb_mapped && dev != NULL)
				ib_dma_unmap_single(dev, rb->rb_dma,
				    SVC_RDMA_MAX_READ, DMA_FROM_DEVICE);
			if (rb->rb_buf != NULL)
				svc_rdma_sink_put(rb->rb_buf);	/* recycle (#60) */
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
 * Deferred connection teardown task (taskqueue_thread, sleepable).  This is the
 * SINGLE place that drains the QP and the SINGLE destroyer of the child cm_id.
 * It is enqueued exactly once via svc_rdma_conn_close() (the sc_state guard
 * stops re-enqueue), so it runs once per connection and there is no double
 * rdma_destroy_id() and no double-drain -- for disconnect, recv-error,
 * device-removal, AND accept-failure, which all funnel through conn_close().
 *
 * Teardown order, and why it is UAF-free:
 *   1. Unified quiescence barrier: msleep on the shared &sc_upcalls channel until
 *      sc_reposts == 0 AND sc_sends == 0 AND sc_upcalls == 0.
 *      svc_rdma_conn_close() published SC_CLOSING before enqueuing this task, so no
 *      NEW repost passes the non-SC_CLOSING gate in svc_rdma_wc_recv(), no NEW reply
 *      send passes the SC_UP gate in svc_rdma_conn_send(), and no NEW sro_recv/
 *      sro_newconn passes its dispatch gate; this wait only drains work already
 *      counted (each between its refcount++ and the matching decrement).  When it
 *      returns, every WR a completion will ever post -- on the RQ OR the SQ -- is on
 *      the QP and none can be posted afterward, AND no consumer upcall is in flight.
 *      This makes step 2/3's "no concurrent posters" precondition true
 *      (ib_drain_sq/ib_drain_qp require it) and closes the post-after-drain UAF on
 *      both queues (mlx5 ib_post_recv/ib_post_send do not reject an ERR-state QP).
 *      We run on taskqueue_thread, distinct from the CQ workqueue (reposts/sends/
 *      sro_recv) and the CM work context (sro_newconn); those decrementers hold
 *      sc_lock only briefly and never block on us, so this cannot self-deadlock.
 *   1b. sro_disconnect: delivered here, after the sc_upcalls drain (so
 *      it never overlaps an sro_recv/sro_newconn) and gated on the durable
 *      sc_newconn_fired token, so it is exactly-once and paired with sro_newconn.
 *      The consumer may free its per-conn state in it.
 *   2. rdma_disconnect() (if a QP exists) -- best-effort; moves the QP toward
 *      error and tells the peer.  Errors ignored (peer may already be gone).
 *   3. ib_drain_qp() (if a QP exists) -- ib_drain_sq() then ib_drain_rq()
 *      (ib_verbs.c:2292): each modifies the QP to IB_QPS_ERR, posts a sentinel
 *      WR on its queue, and BLOCKS (wait_for_completion) until that sentinel CQE
 *      is reaped.  Step 1 made this safe by guaranteeing no other context is
 *      still posting on the SQ or RQ (the drain contract requires exactly that).
 *      This flushes the QP and bounds the work, but it does NOT by itself
 *      guarantee the completion WORKQUEUE has dispatched every earlier CQE:
 *      empirically a SUCCESSFUL tail-SEND completion can still be sitting
 *      undispatched in the send CQ when this returns.  The hard quiescence
 *      barrier is ib_free_cq()'s flush_work() in step 4.
 *   4. svc_rdma_conn_free_verbs() -- destroy QP, then free the CQs (ib_free_cq()
 *      flush_work()s the completion workqueue: AFTER this no completion can run),
 *      THEN reclaim in-flight writes, unmap+free buffers, free the read-buffer
 *      pool, dealloc PD.  Freeing the CQs before any completion-referenced state
 *      is what makes the rest safe -- no completion can be touching the
 *      buffers or DMA mappings this frees afterward.
 *   5. rdma_destroy_id() -- a QP must be destroyed before its id (rdma_cm.h);
 *      this also blocks until no CM callback is running, after which no event
 *      can reference conn.
 *   6. destroy sc_lock; free(conn).
 * Every verbs resource is NULL-guarded in step 4, so a connection torn down
 * mid-construction (accept-path failure) unwinds whatever subset exists.  Flush
 * completions reaped during step 3 see a still-live conn (freed only in step 6)
 * and return early on IB_WC_WR_FLUSH_ERR without touching freed memory.
 */
static void
svc_rdma_conn_destroy(void *arg, int pending __unused)
{
	struct svc_rdma_conn *conn = arg;

	/*
	 * Step 1: unified quiescence barrier.  Drain in-flight recv
	 * reposts (sc_reposts), reply sends (sc_sends), AND consumer upcalls
	 * (sc_upcalls) before touching the QP or delivering sro_disconnect.  All
	 * three are armed only while not-closing / SC_UP, which conn_close() already
	 * cleared (SC_CLOSING is published before this task is enqueued), so this
	 * only waits out work already counted.  All three decrement sites wake the
	 * SINGLE shared channel &sc_upcalls; we msleep on it and re-check the whole
	 * predicate on every wake, so no decrement can be missed (any of the three
	 * hitting 0 re-evaluates all three) and there is no lost wakeup.  We run on
	 * taskqueue_thread, distinct from the CQ workqueue (reposts/sends/sro_recv)
	 * and the CM work context (sro_newconn); those decrementers hold sc_lock
	 * only briefly and never block on us, so this cannot self-deadlock.
	 *
	 * When it returns: every recv/send WR a completion will ever post is on the
	 * QP (the post-after-drain barrier for steps 2/3, unchanged), AND no
	 * sro_newconn or sro_recv is in flight -- so the sro_disconnect below cannot
	 * overlap another consumer upcall, and the consumer may free its per-conn
	 * state inside disconnect.
	 */
	mtx_lock(&conn->sc_lock);
	while (conn->sc_reposts != 0 || conn->sc_sends != 0 ||
	    conn->sc_upcalls != 0)
		msleep(&conn->sc_upcalls, &conn->sc_lock, 0, "svcrdq", 0);
	mtx_unlock(&conn->sc_lock);

	/*
	 * Step 1b: deliver sro_disconnect, exactly once, paired with
	 * sro_newconn via the DURABLE sc_newconn_fired token.  sc_newconn_fired is
	 * set in the SC_UP-winning section BEFORE sro_newconn is called, so even a
	 * teardown that raced into the post-sro_newconn / pre-sc_newconn_done window
	 * still observes it -- disconnect is never skipped for a conn the consumer
	 * was told about.  A conn that never won the SC_CONNECTING -> SC_UP
	 * transition (accept-path failure, or a disconnect/error before establish)
	 * never set sc_newconn_fired, so it fires NO sro_disconnect.  Set-once /
	 * never-cleared by the sole deliverer + this task running once (sc_state
	 * guard) makes it exactly-once; no read-clear is needed.
	 *
	 * This runs AFTER the sc_upcalls drain (so no sro_recv overlaps it) but
	 * before the verbs drain/free, in the sleepable taskqueue_thread context the
	 * contract promises.  SC_CLOSING is published, so any svc_rdma_conn_send()
	 * the consumer might still issue from disconnect is a harmless SC_UP-gated
	 * drop; the consumer holds only the opaque conn handle, never a verbs
	 * resource this task is about to free.
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
	 * Remove from the registry exactly once, as the last step before the
	 * conn is freed.  Done with no sc_lock held (we already dropped it
	 * above), honoring the conns_lock -> sc_lock order -- and after this the
	 * conn no longer exists, so a concurrent sweep that already snapshotted
	 * this entry has its own list-walk serialized by conns_lock: either it
	 * removed nothing for us (we remove ourselves here) or, if it called
	 * conn_close() on us, that only set SC_CLOSING (a no-op since the task is
	 * already running) and never frees -- the single free is here.
	 */
	mtx_lock(&svc_rdma_conns_lock);
	TAILQ_REMOVE(&svc_rdma_conns, conn, sc_link);
	mtx_unlock(&svc_rdma_conns_lock);

	mtx_destroy(&conn->sc_lock);
	free(conn, M_NFSRDMA);
}

/*
 * Accept an inbound connection (CONNECT_REQUEST handler path).  "id" is the
 * freshly-created child cm_id.
 *
 * Failure model -- ONE path, no special-casing.  conn is allocated with
 * M_WAITOK (cannot fail) and immediately made "live" (sc_lock/sc_teardown
 * initialized, id->context = conn, conn->sc_id = id, sc_state = SC_CONNECTING),
 * so from the very first statement EVERY failure -- PD/CQ/QP create, recv map/
 * post, rdma_accept -- funnels through svc_rdma_conn_close(conn) and RETURNS 0.
 * We keep the id; the deferred teardown task (the single, drained destroyer)
 * reclaims the QP/CQ/PD/buffers and rdma_destroy_id()s the id.
 *
 * We do NOT rdma_reject() and do NOT inline-free on failure: rdma_accept()
 * already performs cma_modify_qp_err + rdma_reject + flushes posted recvs on
 * its own failure (ib_cma.c:3976-3979), so an inline reject would be a double
 * reject and an inline free would race the flush completions.  For a failure
 * BEFORE rdma_accept the QP is simply never accepted; the task's ib_drain_qp()
 * + rdma_destroy_id() closes it and the client times out -- acceptable.  This
 * is the same drained teardown path used by DISCONNECTED, recv-error, and
 * DEVICE_REMOVAL, so there is exactly one drained teardown and one destroy for
 * every way a connection can end -- including a half-built one.
 *
 * Receive buffers are mapped and posted BEFORE rdma_accept(): an RC peer sends
 * its first RPC-over-RDMA call the instant the connection establishes, and a
 * QP with no posted recv would RNR-NAK and the connection would die.
 *
 * Always returns 0: the child id is always retained, either by a successful
 * accept or by the deferred teardown that now owns it.  (We never return
 * non-zero, so the CM core never reentrant-destroys the passed-in id.)
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
	 * Make the connection "live" before allocating any verbs resource, so
	 * that from here on EVERY failure can be handed to the single deferred
	 * teardown path (svc_rdma_conn_close -> svc_rdma_conn_destroy).  In
	 * particular id->context = conn routes any CM event (and the teardown's
	 * rdma_destroy_id) to this conn, and conn->sc_id = id lets the task
	 * destroy the id.
	 */
	mtx_init(&conn->sc_lock, "nfsrdma_conn", NULL, MTX_DEF);
	TASK_INIT(&conn->sc_teardown, 0, svc_rdma_conn_destroy, conn);
	TAILQ_INIT(&conn->sc_writes);	/* in-flight RDMA Write registry */
	STAILQ_INIT(&conn->sc_early);	/* deferred early-recv hold list */
	conn->sc_write_sink_cqe.done = svc_rdma_wc_write_sink;	/* unsignaled-write flush sink */
	conn->sc_state = SC_CONNECTING;
	conn->sc_id = id;
	id->context = conn;

	/*
	 * Bind the consumer ops/ctx to this connection NOW, reading
	 * the listener's sl_ops/sl_ctx under sl_lock and stashing an IMMUTABLE
	 * copy on the conn.  After this the completions and the teardown task
	 * reach the consumer through conn->sc_ops/sc_ctx, never through the
	 * listener -- so a svc_rdma_listen_stop() that clears the listener while
	 * this conn is still live cannot pull the ops out from under an in-flight
	 * completion.  We are in the CONNECT_REQUEST handler, which runs only
	 * while the listening cm_id (and thus its sl_ops/sl_ctx, set before the
	 * listener was published) is alive, so the snapshot is well-defined.
	 */
	mtx_lock(&svc_rdma_listener.sl_lock);
	conn->sc_ops = svc_rdma_listener.sl_ops;
	conn->sc_ctx = svc_rdma_listener.sl_ctx;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	/*
	 * Register the connection so listener-stop / module-unload can find and
	 * reclaim it.  Inserted exactly once, here, the instant it is live and
	 * before any verbs resource exists, so a failure anywhere below still
	 * leaves a registered conn that the deferred teardown will REMOVE (once)
	 * at its end.  This runs entirely inside the CM handler; svc_rdma_accept
	 * therefore returns -- and thus this insert completes -- before
	 * svc_rdma_listen_stop()'s rdma_destroy_id() (which waits out the
	 * handler) can return and start the sweep, so no accept can insert after
	 * the sweep has run.  conns_lock is the outer lock; we hold no sc_lock
	 * here, honoring the conns_lock -> sc_lock order.
	 */
	mtx_lock(&svc_rdma_conns_lock);
	TAILQ_INSERT_TAIL(&svc_rdma_conns, conn, sc_link);
	mtx_unlock(&svc_rdma_conns_lock);

	/*
	 * Bound the QP/CQ caps by what the device reports.
	 * max_qp_wr/max_sge are signed in the FreeBSD
	 * ib_device_attr; clamp to >= 1 so a degenerate device report cannot
	 * size a zero-entry QP/CQ (mlx rejects those).  The recv path posts one SGE
	 * per recv (a single inline segment), so one recv SGE is sufficient.
	 *
	 * max_wr is the RECV cap (and the reply-send pool depth).  max_send_wr is
	 * the SEND-queue cap: the reply depth PLUS RDMA Read head-room PLUS RDMA
	 * Write head-room.  The SQ carries reply SENDs, RDMA Read WR chains, AND
	 * RDMA Write WR chains (+ their header SEND), so it must hold them all
	 * without overflow.  We reserve:
	 *   - one RDMA Read WR per chunk per concurrently-readable recv: at most
	 *     SVC_RDMA_MAX_READ_SEGS WRs per recv buffer (one read in flight per
	 *     recv, never reposted while its read is outstanding) across max_wr
	 *     recvs -> max_wr * SVC_RDMA_MAX_READ_SEGS;
	 *   - one RDMA Write chain + its header SEND per concurrently-replyable request:
	 *     at most SVC_RDMA_MAX_WRITE_SEGS write WRs + 1 SEND per in-flight reply,
	 *     bounded by the request depth (max_wr) -> max_wr * (SVC_RDMA_MAX_WRITE_SEGS
	 *     + 1).
	 * All are FIXED LOCAL bounds, never peer counts (the parser caps the read list
	 * at SVC_RDMA_MAX_READ_SEGS and the reply chunk at SVC_RDMA_MAX_SEGS ==
	 * SVC_RDMA_MAX_WRITE_SEGS).  Every cap is clamped to the device's max_qp_wr; on
	 * a small-cap device the clamp wins and a chain that would overflow simply fails
	 * ib_post_send -> clean close, never a panic.
	 */
	max_wr = SVC_RDMA_RECV_DEPTH;
	if (dev->attrs.max_qp_wr > 0 &&
	    (u32)dev->attrs.max_qp_wr < max_wr)
		max_wr = dev->attrs.max_qp_wr;
	max_send_wr = max_wr +
	    max_wr * SVC_RDMA_MAX_READ_SEGS +
	    max_wr * (SVC_RDMA_MAX_WRITE_WRS + 1);	/* page-gather write chain */
	if (dev->attrs.max_qp_wr > 0 &&
	    (u32)dev->attrs.max_qp_wr < max_send_wr)
		max_send_wr = dev->attrs.max_qp_wr;
	max_sge = 1;
	if (dev->attrs.max_sge > 0 && (u32)dev->attrs.max_sge < max_sge)
		max_sge = dev->attrs.max_sge;
	/*
	 * Recv WRs use one SGE (an inline recv buffer); send WRs gather up to
	 * SVC_RDMA_MAX_SEND_SGE pages for the zero-copy outbound READ,
	 * clamped to the device.  The page-gather loop uses the GRANTED value
	 * (conn->sc_max_send_sge), set after rdma_create_qp.
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
	 * Separate send/recv CQs, each sized to its QP cap PLUS ONE.  The +1 is
	 * drain-sentinel head-room: ib_drain_qp() (the teardown precondition)
	 * posts one extra sentinel WR per queue whose completion can coexist
	 * with up to the queue's WR cap of flushed completions, so the CQ must
	 * hold (cap + 1) CQEs to honor that contract on an exact-fit provider
	 * (mlx5 happens to round entries up to a power of two, but we do not rely
	 * on that).  The send CQ is sized to max_send_wr + 1 (the reply depth plus
	 * RDMA Read + RDMA Write head-room), the recv CQ to max_wr + 1.
	 * comp_vector: rotate per connection and put this
	 * connection's send and recv CQ on ADJACENT vectors, instead of pinning every
	 * CQ to vector 0 (which funnels all completion processing onto one core).
	 * Bounded to the device's num_comp_vectors.  conn is the CQ context.
	 * IB_POLL_WORKQUEUE dispatches completions from a workqueue thread (see
	 * svc_rdma_wc_recv()'s context note).  This poll context is load-bearing: the
	 * completion handlers' lockless decrements of sc_reposts/sc_sends/sc_upcalls
	 * and the teardown quiescence barrier are correct only because a single
	 * workqueue thread serializes per-CQ completions; changing the VECTOR keeps
	 * one work item per CQ (only the core changes), so it preserves that.  Leaving
	 * IB_POLL_WORKQUEUE is what would trip INVARIANTS, not the vector.
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
	qp_attr.cap.max_send_sge = max_send_sge;	/* page gather */
	qp_attr.cap.max_recv_sge = max_sge;
	qp_attr.cap.max_inline_data = 0;

	/*
	 * Create the QP.  The page-gather SQ requests a large send queue
	 * whose per-WQE size is inflated by max_send_sge; on some providers the
	 * ideal SQ exceeds what can be allocated and rdma_create_qp returns
	 * -ENOMEM (mlx5 rounds the WQE-buffer up to a power of two, so the exact
	 * ceiling is hard to predict statically).  Rather than guess, request the
	 * ideal size and, on ENOMEM, halve max_send_wr and retry down to a floor
	 * that still holds ONE full in-flight chain (one inbound read + one
	 * page-write reply + its SEND).  A smaller SQ only means
	 * ib_post_send can fill under heavy concurrency -- which every post path
	 * already handles by closing the connection -- never a silent overflow.
	 * rdma_create_qp() records id->qp on success; on failure id->qp stays
	 * NULL, which svc_rdma_conn_free_verbs() relies on to decide whether to
	 * rdma_destroy_qp().  The provider may write granted caps back into
	 * qp_attr.cap, so we keep using our own max_send_sge (<= requested) for
	 * conn->sc_max_send_sge, never the written-back value.
	 */
	{
		u32 min_send_wr = max_wr +
		    SVC_RDMA_MAX_READ_SEGS + (SVC_RDMA_MAX_WRITE_WRS + 1);

		if (min_send_wr > max_send_wr)		/* tiny-cap device */
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
	conn->sc_max_send_sge = max_send_sge;	/* page-gather loop reads this */
	if (bootverbose && ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 1))
		printf("nfsrdma: QP up: send-queue %u WRs, send-sge %u\n",
		    max_send_wr, max_send_sge);

	/*
	 * Allocate and post the receive buffers.  Each buffer is a fixed
	 * SVC_RDMA_INLINE-byte kernel allocation (heap, never stack/pageable),
	 * DMA-mapped DMA_FROM_DEVICE and described by a one-element SGE using
	 * the PD's local_dma_lkey.  rr_cqe.done routes completions to
	 * svc_rdma_wc_recv(); rr_wr.wr_cqe aliases &rr_cqe.
	 *
	 * sc_nrecv is clamped to the QP recv cap (max_wr): on a device whose
	 * max_qp_wr is below SVC_RDMA_RECV_DEPTH, posting the full depth would
	 * fail mid-loop, so we size both the allocation and the post loop to
	 * what the QP can actually hold.
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
			 * skips the unmap for this slot (it still frees rr_buf).
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
	 * Allocate and DMA-map (DMA_TO_DEVICE) the reply-send buffer pool,
	 * the send-side mirror of the recv buffers.  Unlike recvs these are NOT
	 * posted now: a SEND WR is posted on demand when a call arrives, drawing
	 * a free buffer from this bounded pool.  Each buffer is a fixed
	 * SVC_RDMA_INLINE-byte heap allocation (never stack/pageable); we map the
	 * whole SVC_RDMA_INLINE so the map/unmap size is the symmetric mirror of
	 * the recv side.  ss_mapped is set true ONLY after a successful map so the
	 * teardown unmaps each slot exactly once.
	 *
	 * sc_nsend is clamped to the QP send cap (max_wr) for the same reason
	 * sc_nrecv is clamped: a device whose max_qp_wr is below the configured
	 * depth must not be handed a pool larger than its SQ (which is also why
	 * the pool can never outrun the send CQ, sized max_wr + 1).
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
			 * skips the unmap for this slot (it still frees ss_buf).
			 */
			printf("nfsrdma: ib_dma_map_single (send) failed\n");
			goto fail;
		}
		ss->ss_mapped = true;
	}

	/*
	 * Read-buffer pool: borrow + DMA-map contiguous read sinks
	 * (from the global recycle list, #60) so the NFS-WRITE RDMA-Read hot path
	 * does not allocate+map per write.  Best-effort: cap at the recv depth, and
	 * stop at the first allocation/map failure (a shorter pool just means more
	 * fallback, never an accept failure).
	 *
	 * M_NOWAIT for the backing contigmalloc: svc_rdma_accept
	 * runs under the RDMA-CM listener's handler_mutex, which serializes ALL new
	 * connection acceptance.  A 1 MiB PHYSICALLY-contiguous M_WAITOK request can
	 * block indefinitely on the physical-page allocator under fragmentation, so one
	 * fragmented accept would stall every new NFS/RDMA client.  M_NOWAIT returns NULL
	 * instead, which the short-pool branch already handles (more per-read fallback,
	 * never a stall) -- matching the per-read fallback at svc_rdma_read_start, which
	 * is M_NOWAIT for the same reason.
	 */
	conn->sc_nrbpool = (SVC_RDMA_READBUF_POOL < conn->sc_nrecv) ?
	    SVC_RDMA_READBUF_POOL : conn->sc_nrecv;
	conn->sc_rbpool = malloc(conn->sc_nrbpool * sizeof(*conn->sc_rbpool),
	    M_NFSRDMA, M_WAITOK | M_ZERO);
	{
		int rbk;
		for (rbk = 0; rbk < conn->sc_nrbpool; rbk++) {
			struct svc_rdma_readbuf *rb = &conn->sc_rbpool[rbk];

			rb->rb_buf = svc_rdma_sink_get();	/* recycle list (#60) */
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
	 * Conservative accept parameters:
	 * advertise responder_resources from the device's RDMA
	 * read/atomic depth (capped to the u8 field) AND a matching initiator depth
	 * (the server ISSUES RDMA Reads to pull NFS WRITE data, so the client must
	 * allow them via max_dest_rd_atomic), and
	 * RNR retry = 7 (infinite): when the server's RQ momentarily drains under a
	 * concurrent WRITE burst, an inbound SEND from the client gets an RNR NAK;
	 * with rnr_retry_count 0 the QP would error on the first RNR -> connection
	 * kill -> a 60 s NFS retransmit stall.  7 means retry-forever, so transient
	 * receive-side pressure PAUSES the peer instead of killing the connection.
	 * retry_count is ignored when accepting.  No private data
	 * is exchanged.  Because a QP is already bound to the id, the qp_num/srq/qkey
	 * fields are ignored.
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
		 * rdma_accept() has ALREADY done cma_modify_qp_err + rdma_reject
		 * + flushed the posted recvs internally (ib_cma.c).  Do NOT
		 * reject again and do NOT free inline (that would race the flush
		 * completions).  Hand off to the deferred drained teardown,
		 * which ib_drain_qp()s before freeing -- closing the race -- and
		 * then destroys the id.  Return 0: we retain the id for the task.
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
	 * Unified post-allocation failure: the deferred teardown task is the
	 * single drained destroyer for the verbs resources AND the id.  Return
	 * 0 so the CM core does NOT also destroy the id (the task owns it now);
	 * svc_rdma_conn_close() enqueues the task exactly once via the sc_state
	 * guard.  No inline free, no inline reject.
	 */
	svc_rdma_conn_close(conn);
	return (0);
}

/*
 * Bring up the passive listener on the wildcard AF_INET address and the given
 * (host-order) port, bound to the supplied consumer ops/ctx.
 * Leak-free unwind: any failure destroys the cm_id we created and leaves sl_id
 * NULL (and sl_ops/sl_ctx NULL).  Idempotent-safe against double start: a second
 * start while one is up is rejected (EBUSY) rather than leaking the first cm_id.
 *
 * ops MUST be non-NULL (it is the consumer's upcall table).  ops and ctx are
 * PUBLISHED with sl_id, in the
 * same sl_lock critical section, so any racing CONNECT_REQUEST snapshots a
 * consistent (id, ops, ctx) triple onto the conn.  ops must outlive the listener
 * and ctx must outlive svc_rdma_listen_stop().
 *
 * Returns a POSITIVE errno on failure.  The FreeBSD rdma_*() helpers return
 * NEGATIVE Linux errnos (rdma_bind_addr/rdma_listen, ib_cma.c), and
 * rdma_create_id reports via ERR_PTR; this function normalizes all of them to
 * positive so callers (the sysctl below, and the SVCXPRT wiring) get a
 * conventional FreeBSD errno.  Declared in <rdma/svc_rdma.h>.
 */
int
svc_rdma_listen_start_ops(uint16_t port, const struct svc_rdma_ops *ops,
    void *ctx)
{
#ifdef INET
	struct sockaddr_in sin;
#endif
	struct rdma_cm_id *id;
	int rc;

	if (port == 0 || ops == NULL)
		return (EINVAL);

	mtx_lock(&svc_rdma_listener.sl_lock);
	if (svc_rdma_listener.sl_id != NULL) {
		mtx_unlock(&svc_rdma_listener.sl_lock);
		return (EBUSY);
	}
	mtx_unlock(&svc_rdma_listener.sl_lock);

	/*
	 * &init_net is the default vnet (vnet0); the in-tree server-side users
	 * (e.g. sdp_main.c) pass it to rdma_create_id().  RDMA_PS_TCP / IB_QPT_RC
	 * match the iWARP/RoCE/IB RC transport NFS-over-RDMA uses.
	 */
	id = rdma_create_id(&init_net, svc_rdma_cm_event_handler,
	    &svc_rdma_listener, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id)) {
		rc = -PTR_ERR(id);
		if (bootverbose || ppsratecheck(&svc_rdma_log_last,
		    &svc_rdma_log_pps, 1))
			printf("nfsrdma: rdma_create_id failed: %d\n", rc);
		return (rc != 0 ? rc : EINVAL);
	}

	/*
	 * Bind AF_INET only (IPv4/IPoIB/RoCE wildcard).  IPv6/rdma6 dual-stack
	 * listener support is a TODO: rdma_bind_addr would need an AF_INET6
	 * sockaddr_in6 with IN6ADDR_ANY and a separate rdma_cm_id for the v6
	 * endpoint, or a kernel that maps v4-mapped v6 addresses automatically.
	 */
#ifdef INET
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);

	rc = rdma_bind_addr(id, (struct sockaddr *)&sin);
	if (rc != 0) {
		printf("nfsrdma: rdma_bind_addr(port %u) failed: %d\n",
		    port, rc);
		goto out_destroy;
	}
#else
	rc = EAFNOSUPPORT;
	goto out_destroy;
#endif

	rc = rdma_listen(id, SVC_RDMA_CM_BACKLOG);
	if (rc != 0) {
		printf("nfsrdma: rdma_listen(port %u) failed: %d\n", port, rc);
		goto out_destroy;
	}

	mtx_lock(&svc_rdma_listener.sl_lock);
	if (svc_rdma_listener.sl_id != NULL) {
		/* Lost a start race; drop ours rather than overwrite/leak. */
		mtx_unlock(&svc_rdma_listener.sl_lock);
		rc = EBUSY;
		goto out_destroy;
	}
	/*
	 * Publish (id, ops, ctx) atomically under sl_lock so the accept path's
	 * snapshot is always consistent: no CONNECT_REQUEST can see sl_id set with
	 * a stale/NULL ops.  sl_ops/sl_ctx are cleared again in
	 * svc_rdma_listen_stop() alongside sl_id.
	 */
	svc_rdma_listener.sl_id = id;
	svc_rdma_listener.sl_ops = ops;
	svc_rdma_listener.sl_ctx = ctx;
	/* Publish the port under the same lock that guards sl_id. */
	svc_rdma_listen_port = port;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	if (bootverbose)
		printf("nfsrdma: listening on port %u\n", port);
	return (0);

out_destroy:
	/*
	 * No cm_id is stored yet on this path, so this cannot double-free.
	 * Normalize the (possibly negative LinuxKPI) errno to positive; never
	 * return 0 from a failure path.
	 */
	rdma_destroy_id(id);
	rc = (rc < 0) ? -rc : rc;
	return (rc != 0 ? rc : EINVAL);
}

/*
 * Tear the listener down AND reclaim every connection it ever accepted.  Safe
 * vs an in-flight CONNECT_REQUEST: we detach the stored pointer under the lock
 * first, then rdma_destroy_id() the listener outside the lock.
 * rdma_destroy_id() cancels in-flight asynchronous CM operations associated with
 * the id and does not return until the handler is no longer running, so no
 * CONNECT_REQUEST can be in or enter the handler for this
 * listener after it returns -- and therefore no svc_rdma_accept() can still be
 * running, so every conn it ever created has already been INSERTed into the
 * registry before we sweep.  Idempotent: a second call finds sl_id NULL.
 *
 * We must drop sl_lock before rdma_destroy_id(): the CM teardown can block, and
 * holding a non-sleepable mtx across it would be wrong; nothing else needs the
 * lock once we have unpublished the pointer.
 *
 * Connection sweep (ordering is load-bearing):
 *   1. Destroy the listener id FIRST (above), so no NEW connection can be
 *      accepted/inserted after this point -- this is what makes the sweep
 *      complete: the registry can only shrink from here on.
 *   2. Under svc_rdma_conns_lock, walk the registry and svc_rdma_conn_close()
 *      each conn.  conn_close() takes sc_lock (inner) to transition SC_CLOSING
 *      and enqueues that conn's sc_teardown exactly once -- it never blocks and
 *      never frees, so it is safe to call while holding the registry lock and
 *      while iterating (FOREACH, not FOREACH_SAFE: conn_close does not remove
 *      from or free the list; only the teardown task removes, and it cannot run
 *      until we drop the lock).  A conn already CLOSING (its teardown already
 *      enqueued by a disconnect/error) is a harmless no-op.
 *   3. Drop the lock, then taskqueue_drain_all(taskqueue_thread): block until
 *      EVERY queued and running sc_teardown has finished.  Each teardown drains
 *      its QP, frees its verbs resources, rdma_destroy_id()s its id, REMOVEs
 *      itself from the registry, and frees the conn.  We must drain the WHOLE
 *      queue, NOT a per-conn task pointer: the task frees the conn, so any
 *      &conn->sc_teardown would be dangling by the time we waited on it.  When
 *      drain_all returns, no sc_teardown task and no posted-WR completion
 *      callback (rr_cqe.done / ss_cqe.done) can run anymore -- critical on the
 *      unload path, where those callbacks live in nfsrdma text about to be freed.
 * After the drain the registry is empty.  The sweep runs unconditionally (even
 * when sl_id was already NULL): a connection established before an explicit
 * svc_rdma_listen_stop() outlives the listener id, so unload must still reclaim it.
 */
void
svc_rdma_listen_stop(void)
{
	struct rdma_cm_id *id;
	struct svc_rdma_conn *conn;

	mtx_lock(&svc_rdma_listener.sl_lock);
	id = svc_rdma_listener.sl_id;
	svc_rdma_listener.sl_id = NULL;
	/*
	 * Clear the consumer binding alongside sl_id so a later start begins
	 * fresh.  This does NOT disturb live connections: each already carries an
	 * immutable copy (sc_ops/sc_ctx) taken at accept time, so the sweep below
	 * and every in-flight completion/teardown still reach the consumer through
	 * the conn, not through the listener we are clearing here.
	 */
	svc_rdma_listener.sl_ops = NULL;
	svc_rdma_listener.sl_ctx = NULL;
	svc_rdma_listen_port = 0;	/* keep read-back in sync */
	mtx_unlock(&svc_rdma_listener.sl_lock);

	if (id != NULL) {
		rdma_destroy_id(id);
		if (bootverbose)
			printf("nfsrdma: listener stopped\n");
	}

	/*
	 * Reclaim every live connection.  conns_lock is the outer lock; conn_close
	 * takes sc_lock (inner) -- consistent with the documented order.
	 */
	mtx_lock(&svc_rdma_conns_lock);
	TAILQ_FOREACH(conn, &svc_rdma_conns, sc_link)
		svc_rdma_conn_close(conn);
	mtx_unlock(&svc_rdma_conns_lock);

	/*
	 * Wait out every enqueued+running teardown (each removes itself from the
	 * registry and frees its conn).  Drain the whole queue, never a per-conn
	 * task pointer -- the task frees the conn.
	 */
	taskqueue_drain_all(taskqueue_thread);
}
