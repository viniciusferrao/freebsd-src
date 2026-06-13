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

/*
 * svc_verbs.c -- server-side RDMA-CM listener for NFS-over-RDMA.
 *
 * This is the passive (server) counterpart to the active-connect substrate in
 * This is the passive (server) side.  Note FreeBSD's rdma_cm API:
 * rdma_create_id() takes a leading struct vnet *, and the rdma_cm_event
 * carries no ->id member (the child cm_id of a CONNECT_REQUEST is
 * delivered as the handler's id argument).
 *
 * TASK_003 (3a) scope: bring up a passive RDMA-CM listener that binds a port
 * and logs incoming connection-management events.
 *
 * TASK_003 (3b) scope (this increment): accept an inbound connection into a
 * real QP, post receive buffers BEFORE accepting (an RC peer transmits its
 * first RPC-over-RDMA call immediately on ESTABLISHED; an unposted recv would
 * RNR-NAK and kill the connection), and log the byte count of the first inline
 * message the recv completion delivers.  RFC 8166 header PARSING, the reply/
 * send path, SVCXPRT/nfsd dispatch, and RDMA Read/Write chunks all arrive in
 * later increments (3c..3f).  We do NOT touch any peer-supplied byte beyond
 * logging wc->byte_len here.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>	/* SI_SUB_OFED_MODINIT */
#include <linux/netdevice.h>	/* init_net */
#include <linux/dma-mapping.h>	/* DMA_FROM_DEVICE */
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>		/* SYSUNINIT, bootverbose */
#include <sys/lock.h>
#include <sys/malloc.h>		/* malloc/free, MALLOC_DEFINE */
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>	/* deferred (sleepable) connection teardown */
#include <sys/time.h>		/* ppsratecheck */

#include <netinet/in.h>

/*
 * Single module-global listener instance.  3a only needs one passive endpoint;
 * the real SVCXPRT-per-netconfig wiring (rdma/rdma6) is TASK_003e.
 *
 * sl_lock serializes access to sl_id (and the sysctl-visible port) and makes
 * sl_id the single ownership token for destroying the listening cm_id.  sl_id
 * is the listening cm_id, or NULL when no listener is up.
 *
 * Two contexts mutate sl_id, both under sl_lock:
 *   - svc_rdma_listen_start()/stop() (driven by the sysctl today): publish on
 *     start, capture-and-NULL on stop.
 *   - the CM event handler's RDMA_CM_EVENT_DEVICE_REMOVAL path: it acquires
 *     sl_lock to test/NULL sl_id and thereby decide whether IT or a racing
 *     listen_stop() owns the rdma_destroy_id() (see the long comment there).
 * The CONNECT_REQUEST path does NOT touch sl_id: that event is delivered on a
 * fresh child cm_id (the handler's id argument), which is declined and
 * destroyed by the CM core, independent of the listener.
 */
struct svc_rdma_listener {
	struct mtx		 sl_lock;
	struct rdma_cm_id	*sl_id;
};

static struct svc_rdma_listener svc_rdma_listener = {
	.sl_id = NULL,
};

MALLOC_DEFINE(M_NFSRDMA, "nfsrdma", "NFS over RDMA server");

/*
 * Per-accepted-connection sizing.
 *
 * SVC_RDMA_INLINE is the receive-buffer size.  RFC 8166 (RPC-over-RDMA v1)
 * defaults the inline threshold to 1024 bytes; 4096 is safe head-room and
 * matches a page, so a single map covers one buffer with no straddle.  The
 * peer cannot make us post a larger buffer -- this is a fixed local constant,
 * not a peer-supplied length -- and the device truncates anything bigger than
 * the posted SGE, so an oversize inbound message can over-run nothing here.
 *
 * SVC_RDMA_RECV_DEPTH is how many recv buffers (and thus recv WRs) we keep
 * posted.  It bounds the recv-side QP/CQ caps below.
 */
#define	SVC_RDMA_INLINE		4096
#define	SVC_RDMA_RECV_DEPTH	8

struct svc_rdma_conn;

/*
 * One posted receive buffer.  rr_cqe.done is the completion callback the CQ
 * core dispatches (ib_cq.c: wc->wr_cqe->done(cq, wc)); rr_wr.wr_cqe aliases
 * &rr_cqe in the ib_recv_wr union, so a completion for this WR lands in
 * svc_rdma_wc_recv() with this exact rr_* in hand via container_of.
 */
struct svc_rdma_recv {
	struct ib_cqe		 rr_cqe;
	struct svc_rdma_conn	*rr_conn;
	void			*rr_buf;	/* SVC_RDMA_INLINE bytes */
	u64			 rr_dma;	/* ib_dma_map_single() address */
	bool			 rr_mapped;	/* rr_dma is a live mapping */
	struct ib_sge		 rr_sge;
	struct ib_recv_wr	 rr_wr;
};

/*
 * Per-accepted-connection state.  id->context points here for the child cm_id
 * (the listener's own id keeps context == &svc_rdma_listener), which is how the
 * shared CM handler tells a connection event from a listener event.
 *
 * sc_state, guarded by sc_lock, is the single ownership token for tearing this
 * connection down -- the exact analogue of sl_id for the listener.  The
 * SC_UP/SC_CONNECTING -> SC_CLOSING transition happens at most once; only the
 * thread that wins it enqueues sc_teardown, and sc_teardown is the SINGLE place
 * that frees the verbs resources and calls rdma_destroy_id(sc_id).  See the
 * lifetime essay above svc_rdma_conn_destroy().
 *
 * sc_reposts, also under sc_lock, counts recv reposts currently in flight in
 * svc_rdma_wc_recv() (incremented while still SC_UP, decremented after
 * ib_post_recv returns).  The teardown task waits for it to reach 0 (msleep on
 * &sc_reposts) BEFORE ib_drain_qp(), so no late WR can be posted after the
 * drain sentinel -- this is the post-after-drain UAF barrier.
 */
struct svc_rdma_conn {
	struct rdma_cm_id	*sc_id;		/* child cm_id; QP is sc_id->qp */
	struct ib_pd		*sc_pd;
	struct ib_cq		*sc_scq;	/* send CQ */
	struct ib_cq		*sc_rcq;	/* recv CQ */
	struct svc_rdma_recv	*sc_recv;	/* sc_nrecv-element array */
	int			 sc_nrecv;
	struct mtx		 sc_lock;
	enum {
		SC_CONNECTING = 0,
		SC_UP,
		SC_CLOSING
	}			 sc_state;
	int			 sc_reposts;	/* in-flight reposts (sc_lock) */
	struct task		 sc_teardown;	/* deferred (sleepable) unwind */
};

/*
 * Initialize/destroy sl_lock at module load/unload via MTX_SYSINIT.  This file
 * is linked into the ibcore KLD, so it has no module event of its own; SYSINIT
 * machinery is how an ibcore-internal source unit gets init/teardown hooks.
 */
MTX_SYSINIT(svc_rdma_listener_lock, &svc_rdma_listener.sl_lock,
    "nfsrdma_listener", MTX_DEF);

SYSCTL_NODE(_vfs, OID_AUTO, nfsrdma, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "NFS over RDMA server");

/*
 * Rate limiter for the per-CONNECT_REQUEST log line.  A remote peer controls
 * the arrival rate of connection requests, so logging one line per request
 * unconditionally is a remotely-triggerable console-flood.  ppsratecheck()
 * caps us at a few lines per second and counts the suppressed remainder.
 */
static struct timeval svc_rdma_log_last;
static int svc_rdma_log_pps;

/*
 * Last requested listen port; 0 means stopped.  This is the value the sysctl
 * read-back reports.  It is kept in sync with svc_rdma_listener.sl_id and is
 * read/written ONLY under sl_lock so the read-back can never be stale or
 * mismatched against the actual listener state (including when the CM core
 * destroys the id from under us on DEVICE_REMOVAL).
 */
static int svc_rdma_listen_port;

static int svc_rdma_listen_start(uint16_t port);
static void svc_rdma_listen_stop(void);

static int svc_rdma_accept(struct rdma_cm_id *id);
static void svc_rdma_conn_free_verbs(struct svc_rdma_conn *conn);
static void svc_rdma_conn_destroy(void *arg, int pending);
static void svc_rdma_conn_close(struct svc_rdma_conn *conn);
static void svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc);

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
 * Event routing (3b): the handler is shared by the listener id and every child
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
	const struct sockaddr_in *sin;
	bool owned;

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
			 * Recv buffers were posted before rdma_accept(), so the
			 * peer's first inline call may already be completing.
			 * Just publish SC_UP (under sc_lock, so we do not race
			 * a teardown that a recv-error completion may have
			 * already started) and log once, rate-limited.
			 */
			mtx_lock(&conn->sc_lock);
			if (conn->sc_state == SC_CONNECTING)
				conn->sc_state = SC_UP;
			mtx_unlock(&conn->sc_lock);
			if (ppsratecheck(&svc_rdma_log_last,
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
			 * dependency the 3a listener relies on.
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
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
			if (sa->sa_family == AF_INET) {
				uint32_t a;

				sin = (const struct sockaddr_in *)sa;
				/*
				 * Format the dotted quad by hand: native
				 * printf(9)/kvprintf() does NOT implement the
				 * LinuxKPI-only %pI4 extension.  s_addr is in
				 * network byte order; ntohl() gives host order
				 * so the high octet prints first.
				 */
				a = ntohl(sin->sin_addr.s_addr);
				printf("nfsrdma: CONNECT_REQUEST from "
				    "%u.%u.%u.%u:%u\n",
				    (a >> 24) & 0xff, (a >> 16) & 0xff,
				    (a >> 8) & 0xff, a & 0xff,
				    ntohs(sin->sin_port));
			} else {
				printf("nfsrdma: CONNECT_REQUEST (af %u)\n",
				    sa->sa_family);
			}
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
 * Receive completion.  Dispatched by the CQ core (ib_cq.c: wc->wr_cqe->done)
 * in IB_POLL_WORKQUEUE context -- a kernel workqueue thread, NOT an ithread,
 * so it is technically sleepable, but the reviewer treats it as hostile: keep
 * it short, take no sleepable lock, and start no blocking teardown here.
 *
 * The WR's wr_cqe aliases &rr->rr_cqe, so container_of() recovers the recv
 * descriptor and rr_conn the owning connection.  3b does not parse the bytes:
 * we log the length and repost.  wc->byte_len is the device's count of bytes
 * actually written into our buffer; the device caps it at the posted SGE
 * length (SVC_RDMA_INLINE), so a peer that sends more than the inline size
 * cannot make byte_len exceed the buffer -- the surplus is simply not
 * delivered.  We still treat byte_len as untrusted and only print it.
 */
static void
svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	const struct ib_recv_wr *bad_wr;
	int rc;

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

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: received %u bytes\n", wc->byte_len);

	/*
	 * Repost the same buffer to keep the receive queue from starving --
	 * but ONLY while the connection is still SC_UP, and under an in-flight
	 * repost refcount (sc_reposts) that the teardown task drains before it
	 * calls ib_drain_qp().  This closes a post-after-drain UAF: mlx5's
	 * ib_post_recv does NOT reject an ERR-state QP, so without the barrier a
	 * repost that sampled SC_UP, dropped the lock, then lost the CPU could
	 * enqueue a WR AFTER the drain sentinel; that WR's flush completion
	 * would fire against an already-freed conn/recv.
	 *
	 * Sequence: take sc_lock; if no longer SC_UP, bail (the teardown owns
	 * this buffer and reclaims it after ib_drain_qp(), so skipping the
	 * repost cannot leak).  Otherwise bump sc_reposts and drop the lock
	 * before the (non-sleeping; mlx5_ib_post_recv only takes the RQ
	 * spinlock, mlx5_ib_qp.c:4211) ib_post_recv.  Reacquire, decrement, and
	 * wake the teardown if we were the last in-flight repost.
	 *
	 * Because svc_rdma_conn_close() publishes SC_CLOSING BEFORE enqueuing
	 * the teardown task, once teardown is pending no NEW repost passes the
	 * SC_UP check; the task's msleep loop then waits only for already
	 * counted reposts to finish their ib_post_recv and decrement.  After
	 * the count hits 0 every posted WR is on the QP before ib_drain_qp(),
	 * so the drain catches them all and nothing posts afterward.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		return;
	}
	conn->sc_reposts++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * The DMA mapping and SGE are unchanged and still valid (the buffer is
	 * DMA_FROM_DEVICE and was never unmapped), so re-post the prebuilt
	 * rr_wr as-is.
	 */
	rc = ib_post_recv(conn->sc_id->qp, &rr->rr_wr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_reposts == 0)
		wakeup(&conn->sc_reposts);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_recv (repost) failed: %d\n",
			    rc);
		svc_rdma_conn_close(conn);
	}
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
static void
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
 * after this returns) and it does NOT drain: the caller (svc_rdma_conn_destroy)
 * MUST have already drained the QP via ib_drain_qp() so that no completion can
 * fire against the buffers/conn this frees.
 *
 * Order: QP (clears sc_id->qp) -> recv CQ -> send CQ -> unmap+free each recv
 * buffer -> PD.  A CQ is never freed under a live QP, and the PD (whose
 * local_dma_lkey the SGEs reference) outlives every buffer that used it.
 * rdma_destroy_qp() is the cm_id-paired QP destructor: it must only be called
 * when a QP actually exists (sc_id->qp != NULL), and it clears sc_id->qp
 * itself, so we must not poke sc_id->qp by hand.
 */
static void
svc_rdma_conn_free_verbs(struct svc_rdma_conn *conn)
{
	struct ib_device *dev;
	int i;

	if (conn->sc_id != NULL && conn->sc_id->qp != NULL)
		rdma_destroy_qp(conn->sc_id);

	if (conn->sc_rcq != NULL) {
		ib_free_cq(conn->sc_rcq);
		conn->sc_rcq = NULL;
	}
	if (conn->sc_scq != NULL) {
		ib_free_cq(conn->sc_scq);
		conn->sc_scq = NULL;
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

			if (rr->rr_mapped && dev != NULL)
				ib_dma_unmap_single(dev, rr->rr_dma,
				    SVC_RDMA_INLINE, DMA_FROM_DEVICE);
			free(rr->rr_buf, M_NFSRDMA);
		}
		free(conn->sc_recv, M_NFSRDMA);
		conn->sc_recv = NULL;
		conn->sc_nrecv = 0;
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
 *   1. Repost-quiescence barrier: msleep until sc_reposts == 0.  svc_rdma_conn_close()
 *      published SC_CLOSING before enqueuing this task, so no NEW repost can pass
 *      the SC_UP gate in svc_rdma_wc_recv(); this wait only drains reposts already
 *      counted (between their sc_reposts++ and their ib_post_recv returning).  When
 *      it returns, every WR a completion will ever post is already on the QP, and
 *      none can be posted afterward.  This is the barrier that makes step 2's
 *      "no concurrent posters" precondition true and closes the post-after-drain
 *      UAF (mlx5 ib_post_recv does not reject an ERR-state QP, so a late post would
 *      otherwise slip in behind the drain sentinel).  We run on taskqueue_thread,
 *      distinct from the CQ workqueue running svc_rdma_wc_recv(), and the completion
 *      path holds sc_lock only briefly and never blocks on us, so this cannot
 *      self-deadlock.
 *   2. rdma_disconnect() (if a QP exists) -- best-effort; moves the QP toward
 *      error and tells the peer.  Errors ignored (peer may already be gone).
 *   3. ib_drain_qp() (if a QP exists) -- modifies the QP to IB_QPS_ERR, posts a
 *      sentinel WR on the SQ and RQ, and BLOCKS (wait_for_completion) until the
 *      sentinel CQEs are reaped (ib_verbs.c:2292).  CQs are FIFO, so when this
 *      returns EVERY earlier recv/send completion -- including any flushed WRs
 *      and the now-quiesced reposts from step 1 -- has already run
 *      svc_rdma_wc_recv() to completion.  No completion can fire after this point.
 *   4. svc_rdma_conn_free_verbs() -- destroy QP, free CQs, unmap+free buffers,
 *      dealloc PD.  Safe now: step 3 guarantees nothing is touching them.
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

	/* Step 1: drain in-flight reposts before touching the QP. */
	mtx_lock(&conn->sc_lock);
	while (conn->sc_reposts != 0)
		msleep(&conn->sc_reposts, &conn->sc_lock, 0, "svcrdrp", 0);
	mtx_unlock(&conn->sc_lock);

	if (conn->sc_id != NULL && conn->sc_id->qp != NULL) {
		rdma_disconnect(conn->sc_id);
		ib_drain_qp(conn->sc_id->qp);
	}

	svc_rdma_conn_free_verbs(conn);

	if (conn->sc_id != NULL)
		rdma_destroy_id(conn->sc_id);

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: connection torn down\n");

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
	u32 max_wr, max_sge;
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
	conn->sc_state = SC_CONNECTING;
	conn->sc_id = id;
	id->context = conn;

	/*
	 * Bound the QP/CQ caps by what the device reports, exactly like
	 * rpcrdma_ep_create().  max_qp_wr/max_sge are signed in the FreeBSD
	 * ib_device_attr; clamp to >= 1 so a degenerate device report cannot
	 * size a zero-entry QP/CQ (mlx rejects those).  3b posts one SGE per
	 * recv (a single inline segment), so one recv SGE is sufficient.
	 */
	max_wr = SVC_RDMA_RECV_DEPTH;
	if (dev->attrs.max_qp_wr > 0 &&
	    (u32)dev->attrs.max_qp_wr < max_wr)
		max_wr = dev->attrs.max_qp_wr;
	max_sge = 1;
	if (dev->attrs.max_sge > 0 && (u32)dev->attrs.max_sge < max_sge)
		max_sge = dev->attrs.max_sge;

	conn->sc_pd = ib_alloc_pd(dev, 0);
	if (IS_ERR(conn->sc_pd)) {
		rc = -PTR_ERR(conn->sc_pd);
		conn->sc_pd = NULL;
		printf("nfsrdma: ib_alloc_pd failed: %d\n", rc);
		goto fail;
	}

	/*
	 * Separate send/recv CQs, each sized to its QP cap so it cannot
	 * overflow.  comp_vector 0 is the deliberate minimal choice (matching
	 * rpcrdma_ep_create; spreading vectors is a later perf task).  conn is
	 * the CQ context.  IB_POLL_WORKQUEUE dispatches completions from a
	 * workqueue thread (see svc_rdma_wc_recv()'s context note).
	 */
	conn->sc_scq = ib_alloc_cq(dev, conn, max_wr, 0, IB_POLL_WORKQUEUE);
	if (IS_ERR(conn->sc_scq)) {
		rc = -PTR_ERR(conn->sc_scq);
		conn->sc_scq = NULL;
		printf("nfsrdma: ib_alloc_cq (send) failed: %d\n", rc);
		goto fail;
	}
	conn->sc_rcq = ib_alloc_cq(dev, conn, max_wr, 0, IB_POLL_WORKQUEUE);
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
	qp_attr.cap.max_send_wr = max_wr;
	qp_attr.cap.max_recv_wr = max_wr;
	qp_attr.cap.max_send_sge = max_sge;
	qp_attr.cap.max_recv_sge = max_sge;
	qp_attr.cap.max_inline_data = 0;

	/*
	 * rdma_create_qp() records the QP in id->qp on success; on failure
	 * id->qp stays NULL, which is exactly what svc_rdma_conn_free_verbs()
	 * relies on to decide whether to rdma_destroy_qp().
	 */
	rc = rdma_create_qp(id, conn->sc_pd, &qp_attr);
	if (rc != 0) {
		printf("nfsrdma: rdma_create_qp failed: %d\n", rc);
		goto fail;
	}

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
	 * Conservative accept parameters (mirroring rpcrdma_ep_create's
	 * remote_cma): advertise responder_resources from the device's RDMA
	 * read/atomic depth (capped to the u8 field), initiate nothing, and
	 * leave RNR retry at 0 so any flow-control bug surfaces immediately
	 * rather than silently stalling.  retry_count is ignored when
	 * accepting.  No private data is exchanged.  Because a QP is already
	 * bound to the id, the qp_num/srq/qkey fields are ignored.
	 */
	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources =
	    min_t(u32, U8_MAX, (u32)dev->attrs.max_qp_rd_atom);
	conn_param.initiator_depth = 0;
	conn_param.flow_control = 0;
	conn_param.rnr_retry_count = 0;
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
 * (host-order) port.  Leak-free unwind: any failure destroys the cm_id we
 * created and leaves sl_id NULL.  Idempotent-safe against double start: a
 * second start while one is up is rejected (EBUSY) rather than leaking the
 * first cm_id.
 *
 * Returns a POSITIVE errno on failure.  The FreeBSD rdma_*() helpers return
 * NEGATIVE Linux errnos (rdma_bind_addr/rdma_listen, ib_cma.c), and
 * rdma_create_id reports via ERR_PTR; this function normalizes all of them to
 * positive so callers (the sysctl below, and the future SVCXPRT wiring) get a
 * conventional FreeBSD errno.
 */
int
svc_rdma_listen_start(uint16_t port)
{
	struct sockaddr_in sin;
	struct rdma_cm_id *id;
	int rc;

	if (port == 0)
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
		printf("nfsrdma: rdma_create_id failed: %d\n", rc);
		return (rc != 0 ? rc : EINVAL);
	}

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

	/*
	 * Modest backlog; this is just to observe inbound requests in 3a.  The
	 * value is tuned with the real accept path in a later increment.
	 */
	rc = rdma_listen(id, 8);
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
	svc_rdma_listener.sl_id = id;
	/* Publish the port under the same lock that guards sl_id (NIT). */
	svc_rdma_listen_port = port;
	mtx_unlock(&svc_rdma_listener.sl_lock);

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
 * Tear the listener down.  Safe vs an in-flight CONNECT_REQUEST: we detach the
 * stored pointer under the lock first, then rdma_destroy_id() the listener
 * outside the lock.  rdma_destroy_id() cancels in-flight asynchronous CM
 * operations associated with the id and does not return until the handler is
 * no longer running (verified in TASK_002), so no CONNECT_REQUEST can be in or
 * enter the handler for this listener after it returns.  Idempotent: a second
 * call (or unload after an explicit stop) finds sl_id NULL and does nothing.
 *
 * We must drop sl_lock before rdma_destroy_id(): the CM teardown can block, and
 * holding a non-sleepable mtx across it would be wrong; nothing else needs the
 * lock once we have unpublished the pointer.
 */
void
svc_rdma_listen_stop(void)
{
	struct rdma_cm_id *id;

	mtx_lock(&svc_rdma_listener.sl_lock);
	id = svc_rdma_listener.sl_id;
	svc_rdma_listener.sl_id = NULL;
	svc_rdma_listen_port = 0;	/* keep read-back in sync (NIT) */
	mtx_unlock(&svc_rdma_listener.sl_lock);

	if (id != NULL) {
		rdma_destroy_id(id);
		printf("nfsrdma: listener stopped\n");
	}
}

/*
 * ===========================================================================
 * TEMPORARY test scaffolding for TASK_003 (3a).
 *
 * vfs.nfsrdma.listen is an int knob: writing a nonzero value starts the
 * listener on that port; writing 0 stops it.  Reading reflects the port the
 * listener is up on (0 when down).  This exists ONLY to drive/observe the
 * listener by hand on the interop VM; it is to be REPLACED by the krpc
 * SVCXPRT + netconfig (rdma/rdma6) integration in TASK_003e and removed.
 * ===========================================================================
 */
static int
sysctl_nfsrdma_listen(SYSCTL_HANDLER_ARGS)
{
	int error, newport;

	/*
	 * Snapshot the current port under sl_lock so the read-back cannot be
	 * torn against a concurrent start/stop (NIT).  svc_rdma_listen_start()
	 * and svc_rdma_listen_stop() are the only writers and they keep the
	 * port in sync with sl_id under the same lock, so we do not write it
	 * here.
	 */
	mtx_lock(&svc_rdma_listener.sl_lock);
	newport = svc_rdma_listen_port;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	error = sysctl_handle_int(oidp, &newport, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	/* Reject out-of-range port values from userspace. */
	if (newport < 0 || newport > 65535)
		return (EINVAL);

	if (newport == 0) {
		svc_rdma_listen_stop();
		return (0);
	}

	return (svc_rdma_listen_start((uint16_t)newport));
}
SYSCTL_PROC(_vfs_nfsrdma, OID_AUTO, listen,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW, NULL, 0,
    sysctl_nfsrdma_listen, "I",
    "TEMP (3a): nonzero port starts the RDMA listener, 0 stops it");

/*
 * Stop the listener at module unload (and at kernel shutdown for a built-in
 * GENERIC-OFED), before the CM core can go away, so no dangling cm_id is left
 * for a later teardown to destroy through freed CM state.  Safe even if the
 * listener was never started (sl_id NULL -> no-op).
 *
 * Ordering is load-bearing.  The CM core registers its cleanup with
 *	module_exit_order(cma_cleanup, SI_ORDER_FOURTH)	(ib_cma.c:4702)
 * which expands to SYSUNINIT(cma_cleanup, SI_SUB_OFED_MODINIT,
 * SI_ORDER_FOURTH, ...) (linux/module.h).  SYSUNINITs run in DESCENDING
 * SI_ORDER within a subsystem, so to run our teardown BEFORE cma_cleanup we
 * need an SI_ORDER strictly GREATER than SI_ORDER_FOURTH(3).  We use
 * SI_ORDER_FIFTH(4): in reverse order FIFTH runs before FOURTH, so we destroy
 * the listening cm_id while the CM core (cma_wq, registered CM clients, the
 * cma_device list) is still fully alive.  THIS MUST STAY > cma_cleanup's
 * SI_ORDER_FOURTH; lowering it below FOURTH reintroduces a use-after-free,
 * because rdma_destroy_id() would then run after cma_cleanup() has torn the
 * CM core down.
 */
static void
svc_rdma_uninit(void *arg __unused)
{

	svc_rdma_listen_stop();
}
SYSUNINIT(svc_rdma_uninit, SI_SUB_OFED_MODINIT, SI_ORDER_FIFTH,
    svc_rdma_uninit, NULL);
