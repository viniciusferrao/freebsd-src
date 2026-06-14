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
#include <rdma/svc_rdma.h>	/* consumer upcall interface (TASK_003e-1) */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>		/* be32dec: endian- and alignment-safe word decode */
#include <sys/kernel.h>		/* SYSUNINIT, bootverbose */
#include <sys/lock.h>
#include <sys/malloc.h>		/* malloc/free, MALLOC_DEFINE */
#include <sys/mutex.h>
#include <sys/queue.h>		/* TAILQ: per-listener connection registry */
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
 *
 * sl_ops/sl_ctx (TASK_003e-1) are the consumer upcall table and its opaque
 * context, set once by svc_rdma_listen_start_ops() before the listener is
 * published and cleared on stop.  The sysctl self-test path passes
 * &svc_rdma_default_ops (and a NULL ctx), preserving the original accept ->
 * parse -> stub reply -> teardown behavior.  They are read under sl_lock at
 * accept time and COPIED onto each connection (sc_ops/sc_ctx), so completions
 * and the teardown task never chase the listener pointer (which may be torn
 * down out from under a live conn): a conn carries its own immutable copy for
 * its whole lifetime.  ops is a const function-pointer table the consumer owns
 * and must outlive the listener; ctx must outlive svc_rdma_listen_stop().
 */
struct svc_rdma_listener {
	struct mtx		 sl_lock;
	struct rdma_cm_id	*sl_id;
	const struct svc_rdma_ops *sl_ops;
	void			*sl_ctx;
};

static struct svc_rdma_listener svc_rdma_listener = {
	.sl_id = NULL,
	.sl_ops = NULL,
	.sl_ctx = NULL,
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
 *
 * SVC_RDMA_SEND_DEPTH is the size of the per-connection reply-send buffer pool
 * (3d).  It matches SVC_RDMA_RECV_DEPTH so we can have a reply in flight for
 * every recv we can be processing concurrently.  Like the recv depth it is
 * clamped down to the device-reported QP send cap at accept time, so the pool
 * can never exceed what the SQ can hold (and thus never outruns the send CQ,
 * which is sized max_wr + 1 for the ib_drain_qp SQ sentinel).
 */
#define	SVC_RDMA_INLINE		4096
#define	SVC_RDMA_RECV_DEPTH	8
#define	SVC_RDMA_SEND_DEPTH	SVC_RDMA_RECV_DEPTH

/*
 * Size of the inline RPC-over-RDMA v1 reply we marshal in 3d.  It is a fixed
 * local constant -- the 7-word (28-byte) RFC 8166 transport header followed by
 * a minimal 6-word (24-byte) ONC RPC MSG_ACCEPTED/SUCCESS reply body (RFC 5531)
 * -- so it is always well under SVC_RDMA_INLINE and cannot be influenced by any
 * peer-supplied length.  See svc_rdma_reply() for the exact word layout.
 */
#define	SVC_RDMA_REPLY_LEN	(RPCRDMA_HDR_MIN + 24)

/*
 * RFC 8166 (RPC-over-RDMA version 1) transport-header constants.
 *
 * The header that prefixes an inline RPC message is a sequence of big-endian
 * 32-bit XDR words:
 *   word0 rdma_xid, word1 rdma_vers(==1), word2 rdma_credit, word3 rdma_proc,
 *   then for RDMA_MSG/RDMA_NOMSG three chunk lists: word4 read_list,
 *   word5 write_list, word6 reply_chunk (each a present-flag here; 0 == empty).
 * For an inline RDMA_MSG with all three chunk lists empty the ONC RPC call
 * message starts at word7, i.e. byte offset RPCRDMA_HDR_MIN (28).
 *
 * RPCRDMA_HDR_MIN is the smallest header we will parse: 7 words = 28 bytes.
 * Words 4..6 are the three chunk-list optional-data/array discriminators; a
 * length of at least RPCRDMA_HDR_MIN therefore guarantees all of words 0..6 are
 * present, which is what lets svc_rdma_parse_header() read them after the single
 * len >= RPCRDMA_HDR_MIN gate.
 */
#define	RPCRDMA_VERSION		1
#define	RPCRDMA_HDR_MIN		28	/* xid,vers,credit,proc + 3 empty chunk-list words */

enum {
	RDMA_MSG	= 0,
	RDMA_NOMSG	= 1,
	RDMA_MSGP	= 2,	/* deprecated */
	RDMA_DONE	= 3,
	RDMA_ERROR	= 4
};

/*
 * ONC RPC (RFC 5531) reply-message constants for the minimal MSG_ACCEPTED/
 * SUCCESS body 3d marshals after the RPC-over-RDMA header.  This is exactly a
 * valid NFS NULL reply; the semantically-correct nfsd reply body is 3e.  These
 * are our own fixed constants -- nothing here is peer-derived except the echoed
 * opaque xid.
 */
enum {
	RPC_REPLY	= 1,	/* msg_type: REPLY */
	RPC_MSG_ACCEPTED = 0,	/* reply_stat: MSG_ACCEPTED */
	RPC_AUTH_NONE	= 0,	/* auth_flavor of the verifier */
	RPC_ACCEPT_SUCCESS = 0	/* accept_stat: SUCCESS */
};

/*
 * struct svc_rdma_msg (the parsed inline RPC-over-RDMA call) and the opaque
 * struct svc_rdma_conn forward declaration now live in <rdma/svc_rdma.h>, the
 * shared consumer contract included above; that definition is authoritative.
 * rpc/rpc_len point into the recv buffer (no copy); they are only valid while
 * that buffer is owned by the completion that produced them (and, for a
 * consumer, only for the duration of the sro_recv upcall).  3c only locates the
 * payload -- decoding the ONC RPC body is the krpc layer's job (3e).
 */

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
 * One reply-send buffer (3d).  The exact send-side mirror of svc_rdma_recv:
 * ss_cqe.done is the send completion the CQ core dispatches, and ss_wr.wr_cqe
 * aliases &ss_cqe so a completion lands in svc_rdma_wc_send() with this ss_*
 * recovered via container_of().  ss_buf is DMA-mapped DMA_TO_DEVICE once at
 * accept time and unmapped exactly once in the drained teardown (ss_mapped,
 * the analogue of rr_mapped).  ss_inuse, under sc_lock, makes the pool a simple
 * bounded free-list: a reply grabs a free buffer, the send completion frees it.
 */
struct svc_rdma_send {
	struct ib_cqe		 ss_cqe;
	struct svc_rdma_conn	*ss_conn;
	void			*ss_buf;	/* SVC_RDMA_INLINE bytes */
	u64			 ss_dma;	/* ib_dma_map_single() address */
	bool			 ss_mapped;	/* ss_dma is a live mapping */
	bool			 ss_inuse;	/* reserved for a reply (sc_lock) */
	struct ib_sge		 ss_sge;
	struct ib_send_wr	 ss_wr;
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
 * svc_rdma_wc_recv() (incremented while not SC_CLOSING, decremented after
 * ib_post_recv returns).  The teardown task waits for it to reach 0 BEFORE
 * ib_drain_qp(), so no late WR can be posted after the drain sentinel -- this is
 * the post-after-drain UAF barrier.
 *
 * sc_sends is the send-side mirror of sc_reposts (3d): it counts reply sends
 * currently in flight in svc_rdma_conn_send() (incremented while still SC_UP
 * under sc_lock, decremented after ib_post_send returns).  The teardown task
 * waits for sc_sends == 0 in the SAME barrier that waits for sc_reposts == 0,
 * BEFORE ib_drain_qp(), so no late SEND WR can be posted behind the SQ drain
 * sentinel -- the identical post-after-drain UAF barrier applied to the SQ.
 *
 * sc_upcalls (TASK_003e-1) extends that quiescence pattern to the CONSUMER
 * upcalls: it counts in-flight sro_newconn + sro_recv calls (incremented under
 * sc_lock at the SC_UP win / the SC_UP-and-newconn-done recv gate, decremented
 * after the upcall returns).  The teardown drains it in the SAME barrier, BEFORE
 * delivering sro_disconnect, so no sro_recv (or the sro_newconn) can overlap
 * sro_disconnect and the consumer may free its per-conn state inside disconnect.
 *
 * All three counters share ONE wakeup channel, &sc_upcalls: every decrement site
 * (repost, send, upcall) does wakeup(&sc_upcalls), and the teardown msleeps on
 * &sc_upcalls re-checking all three.  A single channel cannot lose a wakeup (any
 * decrement wakes the sleeper, which re-evaluates the full predicate) and cannot
 * self-deadlock (the teardown runs on taskqueue_thread; the decrementers run on
 * the CQ workqueue / CM contexts and only ever hold sc_lock briefly).
 */
struct svc_rdma_conn {
	struct rdma_cm_id	*sc_id;		/* child cm_id; QP is sc_id->qp */
	struct ib_pd		*sc_pd;
	struct ib_cq		*sc_scq;	/* send CQ */
	struct ib_cq		*sc_rcq;	/* recv CQ */
	struct svc_rdma_recv	*sc_recv;	/* sc_nrecv-element array */
	int			 sc_nrecv;
	struct svc_rdma_send	*sc_send;	/* sc_nsend-element pool (3d) */
	int			 sc_nsend;
	struct mtx		 sc_lock;
	enum {
		SC_CONNECTING = 0,
		SC_UP,
		SC_CLOSING
	}			 sc_state;
	int			 sc_reposts;	/* in-flight reposts (sc_lock) */
	int			 sc_sends;	/* in-flight reply sends (sc_lock) */
	struct task		 sc_teardown;	/* deferred (sleepable) unwind */
	TAILQ_ENTRY(svc_rdma_conn) sc_link;	/* registry (svc_rdma_conns_lock) */

	/*
	 * Consumer upcall binding (TASK_003e-1).  sc_ops/sc_ctx are the
	 * IMMUTABLE copy of the listener's sl_ops/sl_ctx taken at accept time,
	 * so a completion or the teardown task reaches the consumer without
	 * touching the listener (which can be stopped while this conn is still
	 * live).  Both are set once in svc_rdma_accept() before the conn goes
	 * live and never mutated, so they are read without sc_lock.
	 *
	 * sc_cctx is the consumer's OWN per-connection state, set/cleared by the
	 * consumer via svc_rdma_conn_set_ctx() (typically from sro_newconn) and
	 * read back via svc_rdma_conn_get_ctx().  The verbs layer never
	 * dereferences it; it is guarded by sc_lock only to give the set/get a
	 * defined memory ordering against the upcalls.
	 *
	 * The two upcall-lifecycle latches, both under sc_lock, distinguish the
	 * "about to call sro_newconn" instant from the "sro_newconn has returned"
	 * instant -- they are NOT redundant:
	 *   sc_newconn_fired is set in the SC_UP-winning section BEFORE sro_newconn
	 *     is called.  It is the DURABLE pairing token: the teardown delivers
	 *     sro_disconnect iff sc_newconn_fired, so a teardown that lands in the
	 *     post-sro_newconn / pre-sc_newconn_done window still pairs correctly
	 *     (the upcall ran; disconnect must follow).  Set once, never cleared.
	 *   sc_newconn_done is set STRICTLY AFTER sro_newconn returns.  It is the
	 *     recv DISPATCH gate: the recv path dispatches sro_recv only while
	 *     (SC_UP && sc_newconn_done), so no sro_recv can run before sro_newconn
	 *     has fully completed.
	 *
	 * sc_upcalls counts in-flight consumer upcalls (sro_newconn + sro_recv); see
	 * the quiescence-barrier note above.  The teardown drains it to 0 before
	 * sro_disconnect, so disconnect never overlaps another upcall.
	 */
	const struct svc_rdma_ops *sc_ops;	/* consumer upcalls (immutable) */
	void			*sc_ctx;	/* consumer listener ctx (immut.) */
	void			*sc_cctx;	/* consumer per-conn state (sc_lock) */
	bool			 sc_newconn_fired; /* sro_newconn entered (sc_lock) */
	bool			 sc_newconn_done; /* sro_newconn returned (sc_lock) */
	int			 sc_upcalls;	/* in-flight consumer upcalls (sc_lock) */
};

/*
 * Registry of every accepted connection that is currently "live" (made live in
 * svc_rdma_accept(), removed at the very end of svc_rdma_conn_destroy()).
 *
 * Without this list there was no way to reach an ESTABLISHED connection at
 * listener-stop / module-unload time: svc_rdma_listen_stop() destroyed only the
 * listening cm_id, leaving every accepted conn's QP/CQ/PD and posted recv
 * buffers alive -- and, fatally on unload, leaving its rr_cqe.done callbacks and
 * its queued sc_teardown task pointing into ibcore text that is about to be
 * freed (one more flush/frame -> panic or arbitrary kernel execution), plus an
 * unbounded resource leak for idle conns.  The registry lets stop/unload sweep
 * and drain every live conn before returning.
 *
 * Locking: svc_rdma_conns_lock guards the list head and every sc_link.  A conn
 * is INSERTED exactly once (in svc_rdma_accept, right after it is made live) and
 * REMOVED exactly once (at the end of svc_rdma_conn_destroy, just before the
 * conn is freed), so no double-insert / double-remove is possible.
 *
 * Lock order: svc_rdma_conns_lock -> sc_lock.  The sweep in
 * svc_rdma_listen_stop() holds svc_rdma_conns_lock and calls
 * svc_rdma_conn_close(), which takes sc_lock -- so the registry lock is the
 * OUTER lock.  The teardown's REMOVE takes ONLY svc_rdma_conns_lock (it holds no
 * sc_lock at that point), and no other path ever takes sc_lock and then
 * svc_rdma_conns_lock, so there is no lock-order reversal.
 */
static TAILQ_HEAD(svc_rdma_conn_list, svc_rdma_conn) svc_rdma_conns =
    TAILQ_HEAD_INITIALIZER(svc_rdma_conns);
static struct mtx svc_rdma_conns_lock;

/*
 * Initialize/destroy sl_lock and svc_rdma_conns_lock at module load/unload via
 * MTX_SYSINIT.  This file is linked into the ibcore KLD, so it has no module
 * event of its own; SYSINIT machinery is how an ibcore-internal source unit gets
 * init/teardown hooks.
 */
MTX_SYSINIT(svc_rdma_listener_lock, &svc_rdma_listener.sl_lock,
    "nfsrdma_listener", MTX_DEF);
MTX_SYSINIT(svc_rdma_conns_lock, &svc_rdma_conns_lock,
    "nfsrdma_conns", MTX_DEF);

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
static int svc_rdma_parse_header(const void *buf, uint32_t len,
    struct svc_rdma_msg *out);
static void svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_reply(struct svc_rdma_conn *conn, uint32_t xid);
static void svc_rdma_wc_send(struct ib_cq *cq, struct ib_wc *wc);

/*
 * Default consumer ops (TASK_003e-1) -- the in-tree self-test policy that
 * preserves the original sysctl behavior: ESTABLISHED logs, a parsed call gets
 * the fixed stub reply via svc_rdma_reply(), and teardown logs.  The plain
 * vfs.nfsrdma.listen sysctl binds these, so its observable behavior (accept ->
 * parse -> stub reply -> teardown, with every barrier/registry intact) is
 * unchanged from 3d.
 */
static void svc_rdma_default_newconn(void *ctx, struct svc_rdma_conn *conn);
static int svc_rdma_default_recv(void *ctx, struct svc_rdma_conn *conn,
    const struct svc_rdma_msg *msg);
static void svc_rdma_default_disconnect(void *ctx, struct svc_rdma_conn *conn);

static const struct svc_rdma_ops svc_rdma_default_ops = {
	.sro_newconn	= svc_rdma_default_newconn,
	.sro_recv	= svc_rdma_default_recv,
	.sro_disconnect	= svc_rdma_default_disconnect,
};

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
			 * sro_newconn (TASK_003e-1).  Recv buffers are posted
			 * before rdma_accept(), so the peer's first inline call can
			 * complete and reach svc_rdma_wc_recv() in the recv CQ
			 * context BEFORE this event runs -- but that recv path does
			 * NOT deliver newconn; it gates its sro_recv dispatch on
			 * (SC_UP && sc_newconn_done) and simply drops+reposts an
			 * early call until this handler has run.  Making ESTABLISHED
			 * the single deliverer removes every two-deliverer race.
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
			 * Publishing SC_UP here keeps the sysctl self-test behavior:
			 * SC_UP enables the repost/send paths even though the default
			 * ops' newconn is a no-op.
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
				if (--conn->sc_upcalls == 0)
					wakeup(&conn->sc_upcalls);
				mtx_unlock(&conn->sc_lock);
			}
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
 * Parse and validate the RFC 8166 RPC-over-RDMA version 1 transport header that
 * prefixes an inline RPC message, and locate the inline RPC payload.
 *
 * UNTRUSTED PEER.  buf/len describe bytes the remote (a possibly-hostile NFS/
 * RDMA client) sent into our recv buffer; len is wc->byte_len, already clamped
 * by the caller to <= SVC_RDMA_INLINE (the posted SGE length).  EVERY wire word
 * we read is gated by len BEFORE the read, so a short, truncated, or otherwise
 * malformed header can only produce a clean error return -- never an overread,
 * never a panic.
 *
 * Bounds model: the only words 3c needs are word0..word6 (xid, vers, credit,
 * proc, read_list, write_list, reply_chunk), occupying bytes [0, 28).  A single
 * up-front check, len >= RPCRDMA_HDR_MIN (28), proves the last byte we touch,
 * buf[27] (= the 4th byte of word6, read by be32dec(buf + 24)), is in range.
 * After that gate no further word read can exceed len.  We do NOT cast buf to
 * uint32_t* and dereference: the recv buffer is malloc'd (aligned) but be32dec()
 * is the correct portable choice -- it reads byte-by-byte (endian-safe, no
 * unaligned access assumption) per <sys/endian.h>.
 *
 * Returns 0 and fills *out for an inline RDMA_MSG with all chunk lists empty.
 * Returns a positive errno for anything we will not handle in 3c:
 *   EBADMSG   - too short, wrong version, or a non-RDMA_MSG proc (hard protocol
 *               violation; caller closes the connection).
 *   EOPNOTSUPP- well-formed RDMA_MSG but carrying read/write/reply chunks, which
 *               are 3f (caller closes the connection with a "not yet supported"
 *               note).
 * On any nonzero return *out is left untouched and no payload pointer escapes.
 */
static int
svc_rdma_parse_header(const void *buf, uint32_t len, struct svc_rdma_msg *out)
{
	uint32_t vers, proc, read_list, write_list, reply_chunk;

	/*
	 * Single bounds gate.  Reject anything that cannot contain the full
	 * 7-word (28-byte) fixed header.  This one check authorizes every
	 * be32dec() below (offsets 0,4,8,12,16,20,24 -- all < 28 <= len), so no
	 * individual word read can run past the received length.
	 */
	if (len < RPCRDMA_HDR_MIN)
		return (EBADMSG);

	/* word1: version MUST be 1 (RFC 8166 4.2). */
	vers = be32dec((const char *)buf + 4);
	if (vers != RPCRDMA_VERSION)
		return (EBADMSG);

	/* word3: 3c handles inline RDMA_MSG only; everything else -> close. */
	proc = be32dec((const char *)buf + 12);
	if (proc != RDMA_MSG)
		return (EBADMSG);

	/*
	 * words 4..6: the three chunk-list discriminators (read_list,
	 * write_list, reply_chunk).  0 == empty for each.  If ANY is nonzero the
	 * request carries chunks, which are out of scope until 3f; we do NOT
	 * attempt to walk the chunk segments here (that would read peer-counted
	 * lengths past word6).  Recognize and reject.
	 */
	read_list   = be32dec((const char *)buf + 16);
	write_list  = be32dec((const char *)buf + 20);
	reply_chunk = be32dec((const char *)buf + 24);
	if (read_list != 0 || write_list != 0 || reply_chunk != 0)
		return (EOPNOTSUPP);

	/*
	 * Inline RDMA_MSG, all chunk lists empty: the ONC RPC call message
	 * starts at word7 (offset 28).  len >= 28 guarantees buf + 28 is a valid
	 * pointer and len - 28 (>= 0) the exact remaining byte count -- which may
	 * legitimately be 0 (an empty body), still in bounds.
	 */
	out->xid     = be32dec((const char *)buf + 0);	/* word0 */
	out->credit  = be32dec((const char *)buf + 8);	/* word2 */
	out->rpc     = (const char *)buf + RPCRDMA_HDR_MIN;
	out->rpc_len = len - RPCRDMA_HDR_MIN;
	return (0);
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
 * 3c parses the RFC 8166 transport header on the success path:
 *   - a clean inline RDMA_MSG is logged (xid/credit/inline rpc bytes) and the
 *     recv buffer is reposted via the unchanged 3b SC_UP-gated barrier so the
 *     next call can arrive;
 *   - a hard protocol violation (too short, bad version, non-RDMA_MSG proc) or a
 *     chunk-carrying request (3f) is logged with its reason and the connection
 *     is closed via the 3b deferred teardown path -- we do NOT repost a
 *     connection we are tearing down.
 * The reply/send path, SVCXPRT dispatch, and chunk handling remain 3d..3f.
 */
static void
svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	struct svc_rdma_msg msg;
	const struct ib_recv_wr *bad_wr;
	uint32_t len;
	int rc;
	bool ready;

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

	rc = svc_rdma_parse_header(rr->rr_buf, len, &msg);
	if (rc != 0) {
		/*
		 * Protocol violation (EBADMSG: too short / bad version / not an
		 * inline RDMA_MSG) or a chunk-carrying request (EOPNOTSUPP: 3f).
		 * Log the reason (rate-limited -- the arrival rate is peer-
		 * controlled) and close the connection via the 3b deferred
		 * teardown path.  We deliberately do NOT repost: this connection
		 * is being torn down, and the SC_UP gate below would skip the
		 * repost once conn_close() publishes SC_CLOSING anyway.
		 */
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
			if (rc == EOPNOTSUPP)
				printf("nfsrdma: RPC-over-RDMA request carries "
				    "chunks; not yet supported (3f), closing "
				    "(%u bytes)\n", len);
			else
				printf("nfsrdma: malformed RPC-over-RDMA header "
				    "(%u bytes), closing\n", len);
		}
		svc_rdma_conn_close(conn);
		return;
	}

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: RPC-over-RDMA v1 RDMA_MSG xid=0x%08x credit=%u "
		    "inline rpc=%u bytes\n", msg.xid, msg.credit, msg.rpc_len);

	/*
	 * Readiness gate + upcall barrier (TASK_003e-1).  sro_newconn is delivered
	 * SOLELY by the ESTABLISHED CM handler, which sets sc_newconn_done strictly
	 * AFTER sro_newconn returns and only on the SC_CONNECTING -> SC_UP win.  This
	 * recv path never delivers newconn; it only DISPATCHES sro_recv, and must do
	 * so only once the consumer is ready.  In ONE sc_lock section capture
	 *   ready == (sc_state == SC_UP && sc_newconn_done)
	 * and, if ready, bump sc_upcalls (this sro_recv becomes an in-flight consumer
	 * upcall that the teardown drains before sro_disconnect -- the send-side
	 * mirror of the sc_reposts/sc_sends arm).  The two conjuncts guarantee (a)
	 * sro_newconn has fully completed and (b) the conn is SC_UP, so a synchronous
	 * svc_rdma_conn_send() from sro_recv does not hit the SC_UP gate's ENOTCONN.
	 *
	 * If not ready, skip the dispatch and fall through to the repost barrier.
	 * Two cases reach !ready, both benign:
	 *   - a rare recv that completed BEFORE the ESTABLISHED event (recv CQ and
	 *     CM work queue are independent contexts): SC_CONNECTING / not-yet-set
	 *     newconn -> drop this call and repost (the repost gate now admits
	 *     SC_CONNECTING, so the RQ does not deplete); the RC client retransmits
	 *     the RPC, and a later recv dispatches once ESTABLISHED has delivered
	 *     newconn and published SC_UP.  No reply is fabricated for an
	 *     undispatched call, so the client sees only a one-retransmit delay on
	 *     its very first op, then success.
	 *   - the conn is already SC_CLOSING (a disconnect/error raced this
	 *     completion): the repost barrier below sees SC_CLOSING and declines
	 *     the repost; the teardown reclaims the buffer.
	 */
	mtx_lock(&conn->sc_lock);
	ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
	if (ready)
		conn->sc_upcalls++;
	mtx_unlock(&conn->sc_lock);
	if (!ready)
		goto repost;

	/*
	 * Hand the parsed call to the consumer (TASK_003e-1).  This REPLACES the
	 * former direct svc_rdma_reply() call: the default ops' sro_recv is what
	 * now marshals and posts the stub reply (preserving 3d behavior), while a
	 * real consumer (krpc) enqueues the message and calls xprt_active().
	 *
	 * Contract honored here: the ready gate above guarantees sro_newconn has
	 * already COMPLETED for this conn and the conn is SC_UP, so a consumer's
	 * sro_recv may safely svc_rdma_conn_get_ctx() the state its sro_newconn
	 * attached, and a synchronous svc_rdma_conn_send() will not see ENOTCONN.
	 * sro_recv runs in THIS completion context and MUST NOT sleep; msg (and
	 * msg.rpc, which points into rr_buf) is valid only for the duration of this
	 * call -- we repost rr_buf right after, so a consumer that needs the bytes
	 * must copy them before returning.  A consumer may call svc_rdma_conn_send()
	 * synchronously from within sro_recv (the default ops does, exactly as the
	 * old code did).
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

	/*
	 * Repost the same buffer to keep the receive queue from starving --
	 * while the connection is NOT SC_CLOSING (admitting SC_CONNECTING as well
	 * as SC_UP), and under an in-flight repost refcount (sc_reposts) that the
	 * teardown task drains before it calls ib_drain_qp().  This closes a
	 * post-after-drain UAF: mlx5's ib_post_recv does NOT reject an ERR-state QP,
	 * so without the barrier a repost that sampled a non-closing state, dropped
	 * the lock, then lost the CPU could enqueue a WR AFTER the drain sentinel;
	 * that WR's flush completion would fire against an already-freed conn/recv.
	 *
	 * The gate is SC_CLOSING-based, not SC_UP-based (TASK_003e-1 SHOULD-FIX): a
	 * peer that sends an RPC before ESTABLISHED leaves the conn SC_CONNECTING,
	 * and the recv path drops+reposts that early call -- if the repost required
	 * SC_UP it would decline, depleting the RQ one buffer per early call until
	 * RNR.  Admitting SC_CONNECTING recycles the buffer so the RQ stays full.
	 * Post-after-drain safety is UNCHANGED: svc_rdma_conn_close() publishes
	 * SC_CLOSING under sc_lock BEFORE enqueuing the teardown, so once teardown
	 * is pending NO new repost passes the SC_CLOSING check (whether the conn was
	 * SC_CONNECTING or SC_UP when it closed); the task's barrier then waits only
	 * for already-counted reposts to finish their ib_post_recv and decrement.
	 * After the count hits 0 every posted WR is on the QP before ib_drain_qp(),
	 * so the drain catches them all and nothing posts afterward.
	 *
	 * Sequence: take sc_lock; if SC_CLOSING, bail (the teardown owns this buffer
	 * and reclaims it after ib_drain_qp(), so skipping the repost cannot leak).
	 * Otherwise bump sc_reposts and drop the lock before the (non-sleeping;
	 * mlx5_ib_post_recv only takes the RQ spinlock, mlx5_ib_qp.c:4211)
	 * ib_post_recv.  Reacquire, decrement, and wake the teardown (on the shared
	 * &sc_upcalls channel) if we were the last in-flight repost.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state == SC_CLOSING) {
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
 * svc_rdma_conn_send() -- copy a caller-marshalled inline reply into a free
 * send buffer and post it (TASK_003e-1).  This is the reusable send-pool path:
 * the former svc_rdma_reply() body, generalized so the bytes come from a caller
 * buffer (buf/len) instead of being built in-place from fixed constants.  Both
 * the in-tree default ops (via svc_rdma_reply) and an external consumer's
 * sro_recv post replies through here, so the SC_UP gate, bounded-pool free-list,
 * and sc_sends quiescence barrier are honored IDENTICALLY for every caller --
 * unchanged from 3d.
 *
 * PUBLIC entry point (declared in <rdma/svc_rdma.h>).  Context: callable from
 * the recv completion (IB_POLL_WORKQUEUE) -- it does NOT sleep and takes only
 * sc_lock briefly, exactly as before.  A consumer MAY call it synchronously from
 * within sro_recv (the default ops does).  It MUST NOT be called after this
 * conn's sro_disconnect has returned (the teardown owns the pool by then); the
 * SC_UP gate makes a stray late call a harmless drop rather than a UAF, but the
 * consumer must not rely on that.
 *
 * buf is caller-owned and only read here: we COPY len bytes into ss_buf (no
 * ownership transfer), so the caller may free/reuse buf the instant this
 * returns.  len must be <= SVC_RDMA_INLINE (the mapped buffer size); a longer
 * reply needs RDMA Write chunks (3f) and is rejected with EINVAL rather than
 * truncated.
 *
 * UNTRUSTED PEER.  This routine copies exactly the bytes the caller marshalled;
 * it trusts nothing from the wire itself.  The default ops echoes only the
 * 32-bit opaque xid into an otherwise-fixed reply (see svc_rdma_reply); a real
 * consumer is responsible for bounds-checking anything peer-derived BEFORE
 * handing the marshalled reply here.
 *
 * Bounded pool + send-quiescence barrier (the send-side mirror of the recv
 * repost barrier), UNCHANGED from 3d.  Under sc_lock, in one critical section:
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
	 * not peer-derived; a larger reply is a chunk path (3f), not a truncation.
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
 * Attach/retrieve the consumer's per-connection state (TASK_003e-1).  The verbs
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
 * Marshal and post the in-tree STUB inline RPC-over-RDMA version 1 reply (3d),
 * echoing the call's opaque xid.  This is now the DEFAULT-OPS reply policy: it
 * builds the fixed bytes and hands them to svc_rdma_conn_send() (the reusable
 * send-pool path), so its observable behavior is identical to 3d.  Called from
 * svc_rdma_default_recv() in the CQ workqueue context, so it must not sleep.
 *
 * UNTRUSTED PEER.  The ONLY peer-derived datum that enters the reply is the
 * 32-bit opaque xid, which we echo verbatim per RFC 5531 -- nothing else from
 * the call body or header is trusted.  Every other field is our own fixed
 * constant.  The credit we GRANT is conn->sc_nrecv -- the number of recv
 * buffers we actually posted -- NOT the client's offered credit and NOT the
 * SVC_RDMA_RECV_DEPTH constant (which can exceed what a small-cap device let us
 * post).  The reply is a fixed SVC_RDMA_REPLY_LEN bytes built into a local
 * stack buffer we own, well under SVC_RDMA_INLINE, so no peer length can size or
 * overflow it; svc_rdma_conn_send() copies it into the DMA buffer.
 *
 * A drop (pool exhausted / connection closing) returns from svc_rdma_conn_send()
 * with EBUSY/ENOTCONN; we rate-limit-log and ignore it -- the receive queue is
 * still reposted by the caller, so a dropped reply never starves the RQ, exactly
 * as in 3d.
 */
static void
svc_rdma_reply(struct svc_rdma_conn *conn, uint32_t xid)
{
	char reply[SVC_RDMA_REPLY_LEN];
	char *p = reply;
	int rc;

	/*
	 * Build the fixed reply with be32enc (endian- and alignment-safe; never
	 * cast-and-store).  Layout (all big-endian XDR words):
	 *   RFC 8166 transport header (7 words = RPCRDMA_HDR_MIN):
	 *     w0 rdma_xid    = echoed opaque xid (the ONLY peer-derived value)
	 *     w1 rdma_vers   = RPCRDMA_VERSION (1)
	 *     w2 rdma_credit = conn->sc_nrecv -- the credit we GRANT is exactly the
	 *                      number of recv buffers we actually posted (NOT the
	 *                      peer's offered credit, and NOT the SVC_RDMA_RECV_DEPTH
	 *                      constant: on a device whose max_qp_wr < the constant
	 *                      we posted fewer, so granting the constant would
	 *                      over-advertise and invite RNR/stall).  sc_nrecv is set
	 *                      once at accept time and never mutated, so reading it
	 *                      here without sc_lock is safe.
	 *     w3 rdma_proc   = RDMA_MSG (0)
	 *     w4 read_list   = 0 (empty)
	 *     w5 write_list  = 0 (empty)
	 *     w6 reply_chunk = 0 (empty)
	 *   ONC RPC reply body (RFC 5531, 6 words = 24 bytes):
	 *     w7  xid           = echoed opaque xid (RPC message xid)
	 *     w8  mtype         = RPC_REPLY (1)
	 *     w9  reply_stat    = RPC_MSG_ACCEPTED (0)
	 *     w10 verf.flavor   = RPC_AUTH_NONE (0)
	 *     w11 verf.length   = 0 (empty opaque body)
	 *     w12 accept_stat   = RPC_ACCEPT_SUCCESS (0)
	 * Total = RPCRDMA_HDR_MIN + 24 = SVC_RDMA_REPLY_LEN, fixed.
	 */
	be32enc(p +  0, xid);			/* w0  rdma_xid */
	be32enc(p +  4, RPCRDMA_VERSION);	/* w1  rdma_vers */
	be32enc(p +  8, (uint32_t)conn->sc_nrecv); /* w2 rdma_credit: posted depth */
	be32enc(p + 12, RDMA_MSG);		/* w3  rdma_proc */
	be32enc(p + 16, 0);			/* w4  read_list (empty) */
	be32enc(p + 20, 0);			/* w5  write_list (empty) */
	be32enc(p + 24, 0);			/* w6  reply_chunk (empty) */
	be32enc(p + 28, xid);			/* w7  RPC xid */
	be32enc(p + 32, RPC_REPLY);		/* w8  mtype = REPLY */
	be32enc(p + 36, RPC_MSG_ACCEPTED);	/* w9  reply_stat */
	be32enc(p + 40, RPC_AUTH_NONE);		/* w10 verf.flavor */
	be32enc(p + 44, 0);			/* w11 verf.length = 0 */
	be32enc(p + 48, RPC_ACCEPT_SUCCESS);	/* w12 accept_stat = SUCCESS */

	rc = svc_rdma_conn_send(conn, reply, SVC_RDMA_REPLY_LEN);
	if (rc != 0 && ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
		if (rc == EBUSY)
			printf("nfsrdma: send buffers exhausted, dropping "
			    "reply (xid=0x%08x)\n", xid);
		else if (rc == ENOTCONN)
			; /* connection tearing down; silent (expected) */
		else
			printf("nfsrdma: stub reply post failed: %d "
			    "(xid=0x%08x)\n", rc, xid);
	}
}

/*
 * Default consumer ops (TASK_003e-1) -- the in-tree self-test policy bound by
 * the plain vfs.nfsrdma.listen sysctl.  These preserve the exact 3d behavior so
 * the sysctl self-test path is unchanged when no external consumer is
 * registered.  ctx is always NULL for the default ops (the self-test carries no
 * consumer state).
 */
static void
svc_rdma_default_newconn(void *ctx __unused, struct svc_rdma_conn *conn __unused)
{

	/* Behavior-preserving: the original ESTABLISHED handler only logged,
	 * which the CM event path still does; nothing extra to do here. */
}

static int
svc_rdma_default_recv(void *ctx __unused, struct svc_rdma_conn *conn,
    const struct svc_rdma_msg *msg)
{

	/*
	 * The original recv path called svc_rdma_reply(conn, msg->xid) directly
	 * after a good parse.  Do exactly that here.  Return 0 so the verbs layer
	 * reposts the recv buffer and awaits the next call -- a dropped reply
	 * (pool exhausted / closing) is NOT a close, identical to 3d.
	 */
	svc_rdma_reply(conn, msg->xid);
	return (0);
}

static void
svc_rdma_default_disconnect(void *ctx __unused,
    struct svc_rdma_conn *conn __unused)
{

	/* Behavior-preserving: teardown already logs "connection torn down";
	 * the self-test has no per-conn consumer state to release. */
}

/*
 * Send completion (3d).  Dispatched by the CQ core in the same IB_POLL_WORKQUEUE
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

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: reply sent (send completion)\n");

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
 * buffer -> unmap+free each send buffer -> PD.  A CQ is never freed under a
 * live QP, and the PD (whose local_dma_lkey the recv and send SGEs both
 * reference) outlives every buffer that used it.  rdma_destroy_qp() is the
 * cm_id-paired QP destructor: it must only be called when a QP actually exists
 * (sc_id->qp != NULL), and it clears sc_id->qp itself, so we must not poke
 * sc_id->qp by hand.
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

	if (conn->sc_send != NULL) {
		/*
		 * Send-buffer pool (3d), the exact mirror of the recv unwind.
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
 *   1b. sro_disconnect (TASK_003e-1): delivered here, after the sc_upcalls drain (so
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
 *      CQs are FIFO, so when this returns EVERY earlier recv AND send completion
 *      -- including any flushed WRs and the now-quiesced reposts/sends from step
 *      1 -- has already run svc_rdma_wc_recv()/svc_rdma_wc_send() to completion.
 *      No completion can fire after this point.
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

	/*
	 * Step 1 (TASK_003e-1): unified quiescence barrier.  Drain in-flight recv
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
	 * Step 1b (TASK_003e-1): deliver sro_disconnect, exactly once, paired with
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

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
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
	 * Bind the consumer ops/ctx to this connection NOW (TASK_003e-1), reading
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
	 * Separate send/recv CQs, each sized to its QP cap PLUS ONE.  The +1 is
	 * drain-sentinel head-room: ib_drain_qp() (the teardown precondition)
	 * posts one extra sentinel WR per queue whose completion can coexist
	 * with up to max_wr flushed completions, so the CQ must hold max_wr + 1
	 * CQEs to honor that contract on an exact-fit provider (mlx5 happens to
	 * round entries up to a power of two, but we do not rely on that).
	 * comp_vector 0 is the deliberate minimal choice (matching
	 * rpcrdma_ep_create; spreading vectors is a later perf task).  conn is
	 * the CQ context.  IB_POLL_WORKQUEUE dispatches completions from a
	 * workqueue thread (see svc_rdma_wc_recv()'s context note).
	 */
	conn->sc_scq = ib_alloc_cq(dev, conn, max_wr + 1, 0, IB_POLL_WORKQUEUE);
	if (IS_ERR(conn->sc_scq)) {
		rc = -PTR_ERR(conn->sc_scq);
		conn->sc_scq = NULL;
		printf("nfsrdma: ib_alloc_cq (send) failed: %d\n", rc);
		goto fail;
	}
	conn->sc_rcq = ib_alloc_cq(dev, conn, max_wr + 1, 0, IB_POLL_WORKQUEUE);
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
		printf("nfsrdma: rdma_create_qp failed: %d\n", rc < 0 ? -rc : rc);
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
	 * Allocate and DMA-map (DMA_TO_DEVICE) the reply-send buffer pool (3d),
	 * the send-side mirror of the recv buffers.  Unlike recvs these are NOT
	 * posted now: a SEND WR is posted on demand by svc_rdma_reply() when a
	 * call arrives, drawing a free buffer from this bounded pool.  Each
	 * buffer is a fixed SVC_RDMA_INLINE-byte heap allocation (never stack/
	 * pageable); the reply we build occupies only the first SVC_RDMA_REPLY_LEN
	 * bytes, but we map the whole SVC_RDMA_INLINE so the map/unmap size is the
	 * symmetric mirror of the recv side.  ss_mapped is set true ONLY after a
	 * successful map so the teardown unmaps each slot exactly once.
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
 * (host-order) port, bound to the supplied consumer ops/ctx (TASK_003e-1).
 * Leak-free unwind: any failure destroys the cm_id we created and leaves sl_id
 * NULL (and sl_ops/sl_ctx NULL).  Idempotent-safe against double start: a second
 * start while one is up is rejected (EBUSY) rather than leaking the first cm_id.
 *
 * ops MUST be non-NULL (it is the consumer's upcall table; the sysctl path
 * passes &svc_rdma_default_ops).  ops and ctx are PUBLISHED with sl_id, in the
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
	struct sockaddr_in sin;
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
	/*
	 * Publish (id, ops, ctx) atomically under sl_lock so the accept path's
	 * snapshot is always consistent: no CONNECT_REQUEST can see sl_id set with
	 * a stale/NULL ops.  sl_ops/sl_ctx are cleared again in
	 * svc_rdma_listen_stop() alongside sl_id.
	 */
	svc_rdma_listener.sl_id = id;
	svc_rdma_listener.sl_ops = ops;
	svc_rdma_listener.sl_ctx = ctx;
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
 * Bring up the listener with the in-tree DEFAULT ops (the self-test policy).
 * This is the entry point the temporary vfs.nfsrdma.listen sysctl uses, so its
 * behavior is preserved: accept -> parse -> stub reply (svc_rdma_default_recv ->
 * svc_rdma_reply) -> teardown, with no external consumer.  ctx is NULL because
 * the default ops carries no consumer state.
 */
int
svc_rdma_listen_start(uint16_t port)
{

	return (svc_rdma_listen_start_ops(port, &svc_rdma_default_ops, NULL));
}

/*
 * Tear the listener down AND reclaim every connection it ever accepted.  Safe
 * vs an in-flight CONNECT_REQUEST: we detach the stored pointer under the lock
 * first, then rdma_destroy_id() the listener outside the lock.
 * rdma_destroy_id() cancels in-flight asynchronous CM operations associated with
 * the id and does not return until the handler is no longer running (verified in
 * TASK_002), so no CONNECT_REQUEST can be in or enter the handler for this
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
 *      unload path, where those callbacks live in ibcore text about to be freed.
 * After the drain the registry is empty.  The sweep runs unconditionally (even
 * when sl_id was already NULL): a connection established before an explicit
 * vfs.nfsrdma.listen=0 outlives the listener id, so unload must still reclaim it.
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
	svc_rdma_listen_port = 0;	/* keep read-back in sync (NIT) */
	mtx_unlock(&svc_rdma_listener.sl_lock);

	if (id != NULL) {
		rdma_destroy_id(id);
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
 * listener was never started (sl_id NULL -> no-op).  svc_rdma_listen_stop() now
 * also sweeps and drains every accepted connection, so the unload path inherits
 * full connection reclamation through this single call.
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
 *
 * The PER-CONNECTION drained teardown shares this exact ordering constraint.
 * The connection sweep here runs the registry's sc_teardown tasks SYNCHRONOUSLY
 * to completion (taskqueue_drain_all in svc_rdma_listen_stop returns only after
 * every one finishes), and each does rdma_disconnect/ib_drain_qp/rdma_destroy_id
 * on a child cm_id and its QP.  Those verbs/CM calls require the CM core and the
 * provider to still be alive, which is exactly what SI_ORDER_FIFTH-before-FOURTH
 * guarantees: at SI_ORDER_FIFTH cma_cleanup has not yet run, so every per-conn
 * drain/destroy completes against a live CM core.  Lowering this SI_ORDER below
 * FOURTH would tear the CM core down before these per-conn teardowns drain --
 * the same use-after-free as for the listener id, now multiplied across conns.
 */
static void
svc_rdma_uninit(void *arg __unused)
{

	svc_rdma_listen_stop();
}
SYSUNINIT(svc_rdma_uninit, SI_SUB_OFED_MODINIT, SI_ORDER_FIFTH,
    svc_rdma_uninit, NULL);

/*
 * ===========================================================================
 * Cross-module verbs-ops registration with the krpc layer (TASK_003e-2a).
 *
 * Module layering (docs/16-svcxprt-rdma-integration.md "Module layering").  The
 * SVCXPRT/krpc consumer lives in sys/rpc/svc_rdma.c, built INTO the kernel; the
 * verbs above live here in ibcore.  The krpc layer exports the built-in symbols
 * svc_rdma_register_verbs()/svc_rdma_unregister_verbs() (declared in
 * <rdma/svc_rdma.h>); a built-in kernel symbol is always resolvable from this
 * module, so no MODULE_DEPEND on krpc is needed (and on GENERIC-OFED, where
 * options OFED compiles this file INTO the kernel, both sides are in the same
 * image -- still a plain built-in-symbol call).  We hand krpc a table of our
 * verbs entry points at module load and revoke it at module unload; krpc reaches
 * the verbs ONLY through this table and refuses RDMA (ENXIO) when it is absent.
 *
 * ibcore_verbs_ops is a file-static const table -- it is the krpc registration's
 * "ops must outlive the registration window" object.  It is valid for the whole
 * lifetime of this module's text, and we svc_rdma_unregister_verbs() before that
 * text can go away (the SYSUNINIT below), so krpc never holds a dangling table.
 */
static const struct svc_rdma_verbs_ops ibcore_verbs_ops = {
	.svo_listen_start	= svc_rdma_listen_start_ops,
	.svo_listen_stop	= svc_rdma_listen_stop,
	.svo_conn_send		= svc_rdma_conn_send,
	.svo_conn_set_ctx	= svc_rdma_conn_set_ctx,
	.svo_conn_get_ctx	= svc_rdma_conn_get_ctx,
};

/*
 * Register the verbs-ops with krpc at module load.
 *
 * Ordering is load-bearing (the mirror image of svc_rdma_uninit's argument).
 * SYSINITs run in ASCENDING SI_ORDER, and the CM core comes up at
 *	module_init_order(cma_init, SI_ORDER_FOURTH)	(ib_cma.c:4701)
 * = SYSINIT(... SI_SUB_OFED_MODINIT, SI_ORDER_FOURTH ...).  We register at
 * SI_ORDER_FIFTH(4) so this runs strictly AFTER cma_init's FOURTH(3): by the
 * time krpc can be handed a verbs table, the ibcore/CM core it will drive is
 * already up.  (Registration itself only stores a pointer and does not touch the
 * CM core, but keeping it after cma_init matches the documented invariant and
 * leaves no window where a krpc listen could race a half-initialized core.)
 */
static void
svc_rdma_verbs_register(void *arg __unused)
{
	int rc;

	rc = svc_rdma_register_verbs(&ibcore_verbs_ops);
	if (rc != 0)
		printf("nfsrdma: svc_rdma_register_verbs failed: %d\n", rc);
}
SYSINIT(svc_rdma_verbs_register, SI_SUB_OFED_MODINIT, SI_ORDER_FIFTH,
    svc_rdma_verbs_register, NULL);

/*
 * Revoke the verbs-ops at module unload, BEFORE svc_rdma_uninit tears the
 * listener down.
 *
 * SYSUNINITs run in DESCENDING SI_ORDER.  svc_rdma_uninit (the listener/conn
 * teardown) is at SI_ORDER_FIFTH(4); we unregister at SI_ORDER_SIXTH(5) so this
 * runs FIRST on the unload path:
 *	SIXTH(5) unregister  ->  FIFTH(4) svc_rdma_uninit  ->  FOURTH(3) cma_cleanup
 * Why unregister must precede the teardown: once we return, krpc's table is NULL
 * and its bring-up sysctl returns ENXIO, so no NEW krpc-driven listen can start
 * against verbs whose module text is about to be freed.  And
 * svc_rdma_unregister_verbs() itself calls svo_listen_stop() (==
 * svc_rdma_listen_stop) on the outgoing table as a lifecycle safety net, so if a
 * krpc bring-up listener is still up it is torn down THROUGH the still-valid
 * verbs path now, not orphaned with rr_cqe.done/sc_teardown callbacks pointing
 * into freed ibcore text.  That svc_rdma_listen_stop() runs here at SIXTH(5),
 * still strictly before cma_cleanup's FOURTH(3), so it drains against a live CM
 * core -- the same constraint svc_rdma_uninit relies on.  The subsequent
 * svc_rdma_uninit's own svc_rdma_listen_stop() is then an idempotent no-op (sl_id
 * already NULL, registry already empty).
 *
 * OWNER-KEYED.  We pass &ibcore_verbs_ops -- the EXACT pointer this module's
 * svc_rdma_verbs_register() recorded -- so unregister revokes the global ONLY if
 * THIS module is the registered owner.  On GENERIC-OFED the in-kernel provider
 * owns the global and a duplicate kldload'd ibcore.ko was EBUSY'd at register;
 * that module's unload calls here with ITS OWN &ibcore_verbs_ops, which does not
 * match the in-kernel owner, so it is a no-op and cannot tear down the live
 * in-kernel listener.
 *
 * THIS MUST STAY > svc_rdma_uninit's SI_ORDER_FIFTH (so it runs before it) and,
 * transitively, > cma_cleanup's SI_ORDER_FOURTH; lowering it would let the
 * listener teardown (or the CM core) go away before the krpc consumer is cut
 * off, reintroducing exactly the dangling-callback hazard this ordering closes.
 */
static void
svc_rdma_verbs_unregister(void *arg __unused)
{

	svc_rdma_unregister_verbs(&ibcore_verbs_ops);
}
SYSUNINIT(svc_rdma_verbs_unregister, SI_SUB_OFED_MODINIT, SI_ORDER_SIXTH,
    svc_rdma_verbs_unregister, NULL);
