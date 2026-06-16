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
 * svc_rdma.c -- krpc-side (built into the kernel) NFS-over-RDMA SERVER
 * transport.  It turns each accepted RDMA connection (owned by the verbs layer
 * svc_verbs.c, in the ibcore module) into a krpc SVCXPRT so the EXISTING nfsd
 * serves NFS over RDMA.  This is the real SVCXPRT (TASK_003e-2b) plus the
 * nfsd-pool wiring (TASK_003e-2c); it replaces the 2a logging consumer.  It is
 * the RDMA analogue of sys/rpc/svc_vc.c (the TCP server transport) and mirrors
 * that file closely.
 *
 * SCOPE (hard boundary): INLINE RPC-over-RDMA v1 (RFC 8166) ONLY -- no RDMA
 * Read/Write chunks (that is TASK_003f).  A reply that does not fit the inline
 * send buffer is dropped-with-log here; the chunk data path is the follow-on
 * task.
 *
 * Module layering (docs/16-svcxprt-rdma-integration.md "Module layering").  The
 * verbs entry points (svc_rdma_listen_start_ops / svc_rdma_conn_send /
 * svc_rdma_conn_set_ctx / svc_rdma_conn_get_ctx, plus the private
 * svc_rdma_listen_stop) are DEFINED in the ibcore MODULE.  This file is built
 * INTO the kernel (rpc/svc_rdma.c is "optional ofed", and options OFED is in
 * GENERIC-OFED, so it is part of the kernel image whenever the verbs stack is
 * configured).  A kernel built-in cannot hard-link a loadable module's symbols,
 * so we never call the verbs entry points directly: this file EXPORTS the
 * built-in symbols svc_rdma_register_verbs()/svc_rdma_unregister_verbs(), ibcore
 * registers a function-pointer table at module load, and we reach the verbs only
 * through that table (svc_rdma_verbs).  With nothing registered (ibcore not
 * loaded) the listen hook returns ENXIO instead of dereferencing a NULL table.
 *
 * Lifecycle, mirroring svc_vc:
 *   sro_newconn  -> svc_xprt_alloc + xprt_register into the nfsd pool, attach
 *                   per-conn state, svc_rdma_conn_set_ctx(conn, xprt).  Sleepable
 *                   CM context (M_WAITOK ok), exactly where svc_vc_create_conn
 *                   runs.  This is the start of the xprt lifetime.
 *   sro_recv     -> copy the inline RPC bytes into an mbuf (NON-sleeping:
 *                   m_getm2(M_NOWAIT)+m_copyback), enqueue on the xprt's recv
 *                   queue under its leaf mtx, xprt_active(xprt) to wake a pool
 *                   thread.  This is the RDMA analogue of svc_vc_soupcall:
 *                   "recv completion" plays the role of the socket upcall.
 *   xp_recv      -> a pool thread dequeues one queued mbuf, xdr_callmsg-decodes
 *                   the ONC RPC call header into *msg, hands the remaining body
 *                   as an mbuf, returns the peer sockaddr.  Mirror svc_vc_recv's
 *                   tail (the xdrmbuf_create/xdr_callmsg/xdrmbuf_getall block).
 *   xp_reply     -> XDR-encode the ONC RPC reply header + chain the body, prepend
 *                   the RFC 8166 RPC-over-RDMA v1 reply transport header
 *                   (RDMA_MSG, empty chunk lists), linearize, svc_rdma_conn_send.
 *   sro_disconnect -> xprt_unregister + SVC_RELEASE the pool's reference so
 *                   xp_destroy runs.  Sleepable teardown context, drained after
 *                   every sro_recv has returned (see the header contract).
 *   xp_destroy   -> free the recv queue + the per-conn state.  (The verbs QP/CQ
 *                   teardown is separate, driven by the verbs layer after
 *                   sro_disconnect returns.)
 *
 * Untrusted peer (RFC 8166 5).  The RPC bytes are peer data.  The recv path
 * copies a length the VERBS layer already BOUNDED: for a pure-inline call that is
 * the recv buffer size (<= SVC_RDMA_INLINE); for an RDMA-Read-assembled body
 * (TASK_003f-3 -- NFS WRITE) it is the inline head plus the read data, which the
 * verbs layer caps at SVC_RDMA_INLINE + 1 MiB (its SVC_RDMA_MAX_READ
 * whole-request cap), still a fixed verbs-imposed bound, NEVER a raw peer length
 * into an allocation.  m_getm2() sizes the mbuf chain dynamically to that bounded
 * length, so the larger assembled body is handled the same way as an inline one.
 * The call header is decoded with the standard xdr_callmsg(), which is bounds-safe
 * on a short/malformed body (it returns FALSE, we drop).  The reply send buffer is
 * a fixed-size local buffer; an over-inline reply is dropped, never overflowed.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>		/* be32enc: alignment-safe XDR word store */
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/time.h>		/* ppsratecheck: rate-limit peer-driven logs */

#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/krpc.h>		/* clnt_bck_svccall + clnt_bck_rdma_send hook */

#include <rdma/svc_rdma.h>	/* the shared cross-module contract */

/*
 * SVC_RDMA_INLINE matches the verbs layer's receive-buffer size
 * (svc_verbs.c SVC_RDMA_INLINE == 4096).  It is the hard ceiling on an inline
 * reply: anything larger needs RDMA Write chunks (TASK_003f) and is dropped
 * here.  It is a fixed local constant, never peer-derived.
 */
#define	SVC_RDMA_INLINE		4096
/* Conservative RPC-over-RDMA v1 reply inline limit: the client posts recv
 * buffers of ~1KB for replies (no in-protocol inline negotiation in v1), so an
 * inline reply larger than this overflows the client recv buffer and is NAKd
 * REM_INV_REQ.  Larger replies must use the client-offered reply chunk. */
#define	SVC_RDMA_REPLY_INLINE	1024

/*
 * RFC 8166 (RPC-over-RDMA version 1) transport-header constants, identical to
 * the verbs layer's (svc_verbs.c).  The header that prefixes an inline RPC
 * message is a sequence of big-endian XDR words:
 *   w0 rdma_xid, w1 rdma_vers(==1), w2 rdma_credit, w3 rdma_proc,
 *   w4 read_list, w5 write_list, w6 reply_chunk (each 0 == empty here).
 * For an inline RDMA_MSG with all chunk lists empty the ONC RPC message starts
 * at byte offset RPCRDMA_HDR_MIN (28).
 */
#define	RPCRDMA_VERSION		1
#define	RPCRDMA_HDR_MIN		28	/* 7 words: xid,vers,credit,proc + 3 empty lists */
#define	RDMA_MSG		0	/* rdma_proc: inline RPC message follows */
/*
 * RFC 8166 4.4 RDMA_ERROR rdma_err code we ask the verbs layer to emit (through
 * the optional svo_conn_error op) when a reply cannot be placed into the client's
 * chunks (TASK_028).  We only ever request ERR_CHUNK here: the server has a known
 * xid but cannot place the reply (an over-inline reply with no usable reply
 * chunk; the write-list READ out-of-range fall-through).  ERR_VERS is diagnosed
 * and replied entirely inside the verbs layer (it owns the version check).  The
 * verbs layer builds the full RDMA_ERROR header; this file only names the error
 * kind.  ERR_CHUNK is a PER-REQUEST error -- the connection stays up and the
 * client may retry -- so the reply path returns FALSE (drop) after requesting it
 * and does NOT close.
 */
#define	RDMA_ERR_CHUNK		2	/* rdma_err: chunk lists unusable for reply */

/*
 * Fallback flow-control credit for a reply's w2 rdma_credit (SF1).  The primary
 * value is the verbs layer's REAL granted depth, read per-reply through
 * svo_conn_credits() (== conn->sc_nrecv, clamped to the device QP recv cap); see
 * svc_rdma_xprt_reply().  This constant is used only as a defensive non-zero
 * floor if the accessor ever returns 0 (it should not).  It matches the verbs
 * layer's nominal SVC_RDMA_RECV_DEPTH (64).
 */
#define	SVC_RDMA_CREDIT_GRANT	8

MALLOC_DEFINE(M_SVCRDMA, "svcrdma", "NFS over RDMA server SVCXPRT");

/* Forward declarations (definitions follow the consumer ops). */
static void	svc_rdma_conn_set_ctx_wrap(struct svc_rdma_conn *, void *);
static void	*svc_rdma_conn_get_ctx_wrap(struct svc_rdma_conn *);
static int	svc_rdma_krpc_listen_port;	/* last started port; 0 == down */

/*
 * The nfsd-pool listen hook, exported as a built-in kernel symbol and called
 * from nfsd (sys/fs/nfsserver/nfs_nfsdkrpc.c, guarded by options OFED).  The
 * prototype is declared in <rpc/svc.h>, included here and by nfsd via
 * <rpc/rpc.h>; that satisfies -Wmissing-prototypes for the non-static
 * definition below without a local extern in this file.
 */

/*
 * ===========================================================================
 * Cross-module verbs-ops registration (unchanged from TASK_003e-2a).
 *
 * The registered ibcore verbs-ops table, or NULL when ibcore is not loaded.
 * svc_rdma_verbs_lock serializes register/unregister against the listen-hook
 * reader so the hook never samples a half-published table and a verbs call is
 * never issued against a table unregister is concurrently clearing.  It is a
 * leaf mutex held only briefly; the blocking verbs calls are made with it
 * DROPPED, guarded by svc_rdma_verbs_inflight.
 *
 * svc_rdma_verbs_inflight counts threads that have snapshotted a non-NULL
 * svc_rdma_verbs and are about to call (or are calling) through it with the lock
 * DROPPED.  svc_rdma_unregister_verbs() waits for it to reach 0 before it lets
 * the table pointer go away, so when a truly modular ibcore.ko is unloaded no
 * listen-hook thread is still executing inside the ops it is about to revoke.
 *
 * svc_rdma_verbs_stopping (BLOCKER B2) gates NEW in-flight arms during unregister.
 * Unregister must run the outgoing table's svo_listen_stop() -- which sweeps live
 * connections and drives sro_disconnect upcalls THROUGH this very table (the ctx
 * wrappers below dereference svc_rdma_verbs) -- with the table STILL VALID, and
 * only THEN clear svc_rdma_verbs.  So it cannot NULL the pointer first.  Instead
 * it sets svc_rdma_verbs_stopping under the lock, drains the existing in-flight
 * callers, runs svo_listen_stop() with the table valid, and clears the pointer
 * afterward.  Every arm site (the sysctl and svc_rdma_nfsd_listen) arms only if
 * svc_rdma_verbs != NULL AND !svc_rdma_verbs_stopping, so no new caller enters
 * the ops while unregister is tearing them down.
 */
static struct mtx		 svc_rdma_verbs_lock;
static const struct svc_rdma_verbs_ops *svc_rdma_verbs;
static int			 svc_rdma_verbs_inflight;
static bool			 svc_rdma_verbs_stopping;

MTX_SYSINIT(svc_rdma_verbs_lock, &svc_rdma_verbs_lock, "svcrdma_verbs", MTX_DEF);

/* Rate limiter for peer-driven (remotely-triggerable) log lines. */
static struct timeval		 svc_rdma_log_last;
static int			 svc_rdma_log_pps;

/*
 * Monotonic generator for per-connection xp_sockref (SF2).  Incremented
 * atomically in sro_newconn; +1 at the use site guarantees the first sockref is
 * non-zero (0 is the "no socket" sentinel the DRC must not alias).
 */
static volatile uint64_t	 svc_rdma_sockref_gen;

/*
 * ===========================================================================
 * Listener and per-connection state.
 *
 * svc_rdma_listener is the consumer ctx handed to svo_listen_start() and back to
 * every upcall: it carries the SVCPOOL the accepted connections register into
 * (the nfsd pool, TASK_003e-2c).  It is allocated by the listen hook and lives
 * until svc_rdma_listen_stop() returns; the upcalls only READ sl_pool, which is
 * set once before the listener starts and never mutated.
 *
 * svc_rdma_xprt is the per-connection SVCXPRT private state, hung off
 * xprt->xp_p1.  It owns:
 *   - sx_conn: the opaque verbs connection handle (valid newconn..disconnect).
 *     Guarded by xr_lock; cleared to NULL by sro_disconnect so a pool thread
 *     racing in xp_reply after disconnect cannot post on a freed conn.
 *   - xr_mq:   the recv queue, an mbuf STAILQ of complete inline ONC RPC
 *     messages, each enqueued by sro_recv and dequeued by xp_recv.
 *   - xr_lock: a leaf mutex guarding xr_mq and sx_conn.  It is NEVER held across
 *     a krpc call that can take a pool/group lock (xprt_active is called with it
 *     dropped) and is taken only for brief list/pointer manipulation, so it
 *     cannot form a lock-order cycle with the krpc locks.
 */
struct svc_rdma_listener {
	SVCPOOL		*sl_pool;	/* pool accepted conns register into */
};

struct svc_rdma_qent {
	STAILQ_ENTRY(svc_rdma_qent) sq_link;
	struct mbuf	*sq_m;		/* one complete inline ONC RPC message */
	/*
	 * Reply-chunk carry (TASK_003f-4).  If the request that produced sq_m offered
	 * an RFC 8166 reply chunk (the client pre-registered memory for an over-inline
	 * reply -- e.g. the NFSv4 mount-handshake compound), the parsed-and-validated
	 * reply chunk is captured here by sro_recv (a pure value type, no pointers, so
	 * copying it is safe past the recv buffer's repost).  xp_recv moves it into the
	 * per-xprt pending table keyed by xid so xp_reply can RDMA-Write the reply into
	 * it.  sq_has_reply distinguishes "no reply chunk offered" from a zeroed one.
	 */
	bool		sq_has_reply;
	uint32_t	sq_xid;
	struct svc_rdma_write_chunk sq_reply;
	/*
	 * Write-list carry (write-list READ engine).  If the request offered an
	 * RFC 8166 WRITE list (a Linux NFS/RDMA client offers one for every READ,
	 * to receive the read data by DDP -- no reply chunk), the FIRST write chunk
	 * is captured here (RFC 8267 maps the single DDP-eligible READ result to one
	 * write chunk).  Like sq_reply it is a pure value type, safe to copy past
	 * the recv buffer's repost.  sq_has_writes distinguishes "no write list"
	 * from a zeroed chunk.  xp_recv moves it (and sq_xid) into the pending table
	 * so xp_reply can RDMA-Write the over-inline READ data into it.
	 */
	bool		sq_has_writes;
	struct svc_rdma_write_chunk sq_writes;
	uint32_t	sq_nwrites;	/* offered write-list chunk count */
};
STAILQ_HEAD(svc_rdma_qhead, svc_rdma_qent);

/*
 * Pending reply-chunk table (TASK_003f-4).  A reply chunk captured by sro_recv
 * must survive from xp_recv (where the request is dispatched) to xp_reply (where
 * the reply is marshalled), linked only by the ONC RPC xid.  We keep a small
 * fixed-size per-xprt table keyed by xid: xp_recv inserts the captured chunk,
 * xp_reply looks it up by msg->rm_xid and consumes it.  The table is bounded by
 * SVC_RDMA_REPLY_PEND (>= the verbs recv depth, so it cannot be outrun by the
 * number of concurrently-dispatchable requests); a full table or a missing entry
 * means "no reply chunk for this reply" -> the inline path (or drop) handles it,
 * never an over-write.  Guarded by xr_lock.
 */
#define	SVC_RDMA_REPLY_PEND	64
struct svc_rdma_reply_pend {
	bool		rp_valid;
	uint32_t	rp_xid;
	struct svc_rdma_write_chunk rp_reply;
	/*
	 * Write-list READ engine carry.  rp_has_writes + rp_writes hold the
	 * client's (single) write-list chunk for an over-inline READ reply.
	 * rp_has_ddp + rp_ddp_off/rp_ddp_len hold the DDP boundary the nfsd READ
	 * path supplied via SVC_CONTROL(SVCSET_READDDP) (offset of the read data
	 * within the reply BODY, and its unpadded length).  Both are filled at
	 * different times -- the write list in xp_recv from the qent, the DDP
	 * boundary later from xp_control on the SAME xid's request thread -- and
	 * both are consumed together by xp_reply.  rp_has_reply replaces the old
	 * implicit "rp_valid means a reply chunk is present" meaning so an entry can
	 * exist for a write-list-only READ.  All guarded by xr_lock.
	 */
	bool		rp_has_reply;
	bool		rp_has_writes;
	struct svc_rdma_write_chunk rp_writes;
	uint32_t	rp_nwrites;	/* offered write-list chunk count */
	bool		rp_has_ddp;
	uint32_t	rp_ddp_off;
	uint32_t	rp_ddp_len;
};

struct svc_rdma_xprt {
	struct svc_rdma_conn	*xr_conn;	/* verbs conn (NULL after disc.) */
	struct mtx		 xr_lock;	/* guards xr_mq + xr_conn + xr_seq */
	struct svc_rdma_qhead	 xr_mq;		/* queued recv messages */
	uint32_t		 xr_seq;	/* monotonic posted-reply counter */
	bool			 xr_died;	/* connection gone */
	struct svc_rdma_reply_pend xr_pend[SVC_RDMA_REPLY_PEND]; /* reply chunks */
};

/*
 * ===========================================================================
 * xp_ops: the SVCXPRT operations a pool thread drives.
 */
static bool_t svc_rdma_xprt_recv(SVCXPRT *, struct rpc_msg *,
    struct sockaddr **, struct mbuf **);
static enum xprt_stat svc_rdma_xprt_stat(SVCXPRT *);
static bool_t svc_rdma_xprt_ack(SVCXPRT *, uint32_t *);
static bool_t svc_rdma_xprt_reply(SVCXPRT *, struct rpc_msg *,
    struct sockaddr *, struct mbuf *, uint32_t *);
static void svc_rdma_xprt_destroy(SVCXPRT *);
static bool_t svc_rdma_xprt_control(SVCXPRT *, const u_int, void *);

static const struct xp_ops svc_rdma_xp_ops = {
	.xp_recv =	svc_rdma_xprt_recv,
	.xp_stat =	svc_rdma_xprt_stat,
	.xp_ack =	svc_rdma_xprt_ack,
	.xp_reply =	svc_rdma_xprt_reply,
	.xp_destroy =	svc_rdma_xprt_destroy,
	.xp_control =	svc_rdma_xprt_control,
};

/*
 * Free everything left on the recv queue.  Caller must NOT hold xr_lock
 * (m_freem may be lengthy and there is no reason to hold a leaf mutex over it);
 * called only from the destroy path when no other thread can reach the queue.
 */
static void
svc_rdma_drain_queue(struct svc_rdma_xprt *xr)
{
	struct svc_rdma_qent *q;

	while ((q = STAILQ_FIRST(&xr->xr_mq)) != NULL) {
		STAILQ_REMOVE_HEAD(&xr->xr_mq, sq_link);
		m_freem(q->sq_m);
		free(q, M_SVCRDMA);
	}
}

/*
 * Insert a captured reply chunk into the per-xprt pending table keyed by xid
 * (TASK_003f-4).  Called from xp_recv when a dispatched request offered a reply
 * chunk.  Picks the first free slot, or REUSES a slot already holding the same xid
 * (a client RC-retransmit of the same request re-offers its reply chunk -- the
 * latest wins).  If the table is full we silently drop the chunk: xp_reply then
 * finds no pending entry and falls back to the inline-or-drop path, which is
 * correct (never an over-write).  Guarded by xr_lock.
 */
static void
svc_rdma_reply_pend_insert(struct svc_rdma_xprt *xr, uint32_t xid,
    bool has_reply, const struct svc_rdma_write_chunk *reply,
    bool has_writes, const struct svc_rdma_write_chunk *writes,
    uint32_t nwrites)
{
	int i, free_slot = -1;

	mtx_lock(&xr->xr_lock);
	for (i = 0; i < SVC_RDMA_REPLY_PEND; i++) {
		if (xr->xr_pend[i].rp_valid && xr->xr_pend[i].rp_xid == xid) {
			free_slot = i;			/* overwrite same-xid slot */
			break;
		}
		if (!xr->xr_pend[i].rp_valid && free_slot < 0)
			free_slot = i;			/* remember first free */
	}
	if (free_slot >= 0) {
		struct svc_rdma_reply_pend *p = &xr->xr_pend[free_slot];

		p->rp_valid = true;
		p->rp_xid = xid;
		p->rp_has_reply = has_reply;
		if (has_reply)
			p->rp_reply = *reply;
		p->rp_has_writes = has_writes;
		if (has_writes)
			p->rp_writes = *writes;
		p->rp_nwrites = has_writes ? nwrites : 0;
		/*
		 * The DDP boundary is filled LATER by svc_rdma_readddp_set() (from
		 * xp_control on the request thread); start it cleared so a request
		 * with no READ-DDP op never carries a stale boundary into xp_reply.
		 */
		p->rp_has_ddp = false;
		p->rp_ddp_off = 0;
		p->rp_ddp_len = 0;
	}
	mtx_unlock(&xr->xr_lock);
}

/*
 * Record the DDP {off,len} boundary the nfsd READ path supplied via
 * SVC_CONTROL(SVCSET_READDDP) into this xid's pending entry (write-list READ
 * engine).  Runs on the request's pool thread between xp_recv (which inserted the
 * entry) and xp_reply (which consumes it).  Sets the boundary on the FIRST READ
 * for the xid only -- a COMPOUND with several DDP-eligible READs reduces just one
 * result (RFC 8267), so later READs are ignored and fall back to inline.  If no
 * pending entry exists (no write list was offered) this is a no-op: with no write
 * chunk there is nowhere to DDP, so the boundary is irrelevant.  Guarded by
 * xr_lock.
 */
static void
svc_rdma_readddp_set(struct svc_rdma_xprt *xr, uint32_t xid, uint32_t off,
    uint32_t len)
{
	int i;

	mtx_lock(&xr->xr_lock);
	for (i = 0; i < SVC_RDMA_REPLY_PEND; i++) {
		if (xr->xr_pend[i].rp_valid && xr->xr_pend[i].rp_xid == xid) {
			if (!xr->xr_pend[i].rp_has_ddp) {
				xr->xr_pend[i].rp_has_ddp = true;
				xr->xr_pend[i].rp_ddp_off = off;
				xr->xr_pend[i].rp_ddp_len = len;
			}
			break;
		}
	}
	mtx_unlock(&xr->xr_lock);
}

/*
 * Take (look up and remove) the pending reply chunk for xid, if any
 * (TASK_003f-4).  Called from xp_reply.  Returns true and fills *reply if a
 * pending entry existed (and clears the slot); false if none.  Guarded by
 * xr_lock.
 */
static bool
svc_rdma_reply_pend_take(struct svc_rdma_xprt *xr, uint32_t xid,
    struct svc_rdma_reply_pend *out)
{
	int i;
	bool found = false;

	mtx_lock(&xr->xr_lock);
	for (i = 0; i < SVC_RDMA_REPLY_PEND; i++) {
		if (xr->xr_pend[i].rp_valid && xr->xr_pend[i].rp_xid == xid) {
			*out = xr->xr_pend[i];	/* whole entry (value type) */
			xr->xr_pend[i].rp_valid = false;
			found = true;
			break;
		}
	}
	mtx_unlock(&xr->xr_lock);
	return (found);
}

/*
 * xp_recv: a pool thread (woken by xprt_active) pulls one queued inline message
 * off the recv queue and decodes its ONC RPC call header.  Mirrors the tail of
 * svc_vc_recv: xdrmbuf_create + xdr_callmsg + xdrmbuf_getall, with the body
 * handed back as an mbuf chain and the peer address taken from xp_rtaddr.
 *
 * Returns TRUE with msg, mp and addrp filled when a request was produced, FALSE
 * when the queue is empty or the message was malformed (dropped).  When we drain
 * the last message we call xprt_inactive_self() so the pool stops scheduling
 * this xprt until the next recv completion re-activates it -- exactly as
 * svc_vc_recv does when the socket has no more data.
 */
static bool_t
svc_rdma_xprt_recv(SVCXPRT *xprt, struct rpc_msg *msg,
    struct sockaddr **addrp, struct mbuf **mp)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	struct svc_rdma_qent *q;
	struct mbuf *m;
	XDR xdrs;
	bool_t empty;

	for (;;) {
		mtx_lock(&xr->xr_lock);
		q = STAILQ_FIRST(&xr->xr_mq);
		if (q != NULL)
			STAILQ_REMOVE_HEAD(&xr->xr_mq, sq_link);
		empty = STAILQ_EMPTY(&xr->xr_mq);
		/*
		 * Mark inactive while still holding xr_lock so we cannot race a
		 * concurrent sro_recv enqueue+xprt_active: if a message arrives
		 * after we sampled "empty", that enqueue path takes xr_lock to
		 * insert and then calls xprt_active() -- serialised behind us --
		 * so the transport is re-activated and the new message is not
		 * stranded.  (svc_vc_recv inactivates under the socket recvbuf
		 * lock for the same reason.)
		 */
		if (q == NULL || empty)
			xprt_inactive_self(xprt);
		mtx_unlock(&xr->xr_lock);

		if (q == NULL)
			return (FALSE);

		m = q->sq_m;

		/*
		 * Carry the reply chunk forward (TASK_003f-4).  If this request
		 * offered a reply chunk, record it in the per-xprt pending table
		 * keyed by xid so xp_reply can RDMA-Write the over-inline reply into
		 * it.  Done before freeing the qent.  A full table just means this
		 * reply falls back to the inline-or-drop path -- never an over-write.
		 */
		if (q->sq_has_reply || q->sq_has_writes)
			svc_rdma_reply_pend_insert(xr, q->sq_xid,
			    q->sq_has_reply, &q->sq_reply,
			    q->sq_has_writes, &q->sq_writes, q->sq_nwrites);
		free(q, M_SVCRDMA);

		/*
		 * Decode the ONC RPC call header.  xdr_callmsg is the standard
		 * bounds-safe decoder; on a short/malformed inline body it
		 * returns FALSE and we drop this message (the client retransmits
		 * or the connection is reset).  We never hand-parse peer bytes.
		 */
		xdrmbuf_create(&xdrs, m, XDR_DECODE);
		if (!xdr_callmsg(&xdrs, msg)) {
			XDR_DESTROY(&xdrs);
			if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps,
			    5))
				printf("svc_rdma: dropping malformed inline "
				    "RPC call\n");
			/* m was consumed into the XDR cursor; free the rest. */
			continue;
		}

		/*
		 * Peer address: copy from xp_rtaddr (set at newconn).  NFS uses
		 * svc_getrpccaller(), which falls back to &xp_rtaddr when
		 * rq_addr is NULL, so returning NULL here is also valid; we
		 * return NULL like svc_vc_recv does for a connected transport.
		 */
		*addrp = NULL;
		*mp = xdrmbuf_getall(&xdrs);
		XDR_DESTROY(&xdrs);
		return (TRUE);
	}
}

/*
 * xp_stat: report whether the pool should keep draining this transport.  Mirror
 * svc_vc_stat: DIED once the connection is gone, MOREREQS while the recv queue
 * is non-empty, else IDLE.
 */
static enum xprt_stat
svc_rdma_xprt_stat(SVCXPRT *xprt)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	enum xprt_stat stat;

	mtx_lock(&xr->xr_lock);
	if (xr->xr_died && STAILQ_EMPTY(&xr->xr_mq))
		stat = XPRT_DIED;
	else if (!STAILQ_EMPTY(&xr->xr_mq))
		stat = XPRT_MOREREQS;
	else
		stat = XPRT_IDLE;
	mtx_unlock(&xr->xr_lock);
	return (stat);
}

/*
 * xp_ack: report the reply "sent" high-water mark for the nfsd duplicate-request
 * cache (DRC).  nfsd keys the DRC ack list on xp_sockref and, for each cached
 * reply, records the xp_reply *seq; nfsrc_trimcache() confirms a cached reply as
 * delivered once this ack is SEQ_GEQ that recorded seq.  We return xr_seq, the
 * count of replies we have successfully posted (svc_rdma_conn_send returned 0).
 *
 * Inline-RDMA boundary: posting the SEND WR is as far as the krpc layer can
 * observe -- there is no krpc-visible send completion -- so "posted" is treated
 * as "sent".  That is the same delivery confidence as svc_vc gets from sosend()
 * returning success (the bytes are queued, not ACKed by the peer).  A non-NULL
 * xp_ack also makes SVC_ACK(xprt, NULL) return TRUE so nfsd records the reply in
 * the DRC at all (otherwise have_seq is false and the entry is left pending).
 */
static bool_t
svc_rdma_xprt_ack(SVCXPRT *xprt, uint32_t *ack)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	mtx_lock(&xr->xr_lock);
	*ack = xr->xr_seq;
	mtx_unlock(&xr->xr_lock);
	return (TRUE);
}

/*
 * xp_reply: marshal an RPC-over-RDMA v1 reply and post it -- inline when it fits,
 * or RDMA-Written into the client's reply chunk when it does not (TASK_003f-4).
 *
 * The ONC RPC reply (header + body) is built into an mbuf chain exactly as
 * svc_vc_reply does: xdr_replymsg() encodes the reply header, and on the
 * accepted/success path the caller's body mbuf m is appended via xdr_putmbuf().
 *
 * INLINE path (fits SVC_RDMA_REPLY_INLINE): PREPEND the 28-byte RFC 8166 transport
 * header (RDMA_MSG, all chunk lists empty), linearize, and hand to
 * svc_rdma_conn_send() (which copies it into the connection's DMA send buffer and
 * posts the SEND WR) -- unchanged from 3d/3e.
 *
 * REPLY-CHUNK path (TASK_003f-4): if the marshalled reply exceeds SVC_RDMA_REPLY_INLINE
 * AND the request offered a reply chunk (captured during sro_recv, looked up here
 * by xid), linearize the marshalled ONC RPC reply ALONE (no RFC 8166 header) and
 * hand it to svc_rdma_conn_reply_chunk(), which RDMA-Writes it into the client's
 * reply-chunk memory and SENDs an RDMA_NOMSG header reporting the length.  THIS is
 * what unblocks a usable NFSv4 mount: the mount-handshake compound reply is too big
 * for inline and the client always offers a reply chunk for it.
 *
 * If the reply is over-inline and NO reply chunk was offered (or the reply exceeds
 * the offered chunk's capacity), we drop-with-log and return FALSE rather than
 * overflow -- a drop is not fatal (the client's RC retransmit / a later op
 * proceeds; the recv side is unaffected).
 */

/*
 * Bound on zero-copy READ source pages: SVC_RDMA_MAX_WRITE (1 MiB) / PAGE_SIZE,
 * matching SVC_RDMA_MAX_WRITE_PAGES in svc_verbs.c (the engine re-checks it).
 */
#define	SVC_RDMA_RD_MAXPGS	((1U << 20) / PAGE_SIZE)

/*
 * Collect the M_EXTPG data pages for the read span [doff, doff+dlen) of the reply
 * mbuf chain (TASK_003f-19, Rick Macklem's enable_mextpg path), so the verbs
 * engine can RDMA-Write them directly instead of from a contigmalloc'd copy.
 * Returns the page count on success, or 0 to mean "not cleanly M_EXTPG -- use the
 * contigmalloc fallback".  Conservative by construction: it requires doff to land
 * exactly on an mbuf boundary, every mbuf in the span to be M_EXTPG with no
 * embedded TLS header/trailer and a page-aligned start (m_epg_1st_off == 0), and
 * the page count to fit pd[0..maxpd); any deviation returns 0.  Read-only walk; no
 * locks, no allocation, no ownership change.
 */
static int
svc_rdma_collect_extpg(struct mbuf *m, u_int doff, u_int dlen,
    struct svc_rdma_page *pd, int maxpd)
{
	u_int cum, need;
	int npd;

	cum = 0;
	while (m != NULL && cum + (u_int)m->m_len <= doff) {
		cum += m->m_len;
		m = m->m_next;
	}
	if (m == NULL || cum != doff)
		return (0);		/* doff not on an mbuf boundary */

	npd = 0;
	need = dlen;
	while (need > 0) {
		int pg;

		if (m == NULL || (m->m_flags & M_EXTPG) == 0 ||
		    m->m_epg_hdrlen != 0 || m->m_epg_trllen != 0 ||
		    m->m_epg_1st_off != 0)
			return (0);	/* not a clean page-aligned EXTPG data mbuf */
		for (pg = 0; pg < m->m_epg_npgs && need > 0; pg++) {
			u_int plen = m_epg_pagelen(m, pg, 0);

			if (plen > need)
				plen = need;	/* trim the final (padded) page to dlen */
			if (npd >= maxpd)
				return (0);	/* more pages than the engine can take */
			pd[npd].pg_pa = m->m_epg_pa[pg];
			pd[npd].pg_off = 0;
			pd[npd].pg_len = plen;
			npd++;
			need -= plen;
		}
		m = m->m_next;
	}
	return (npd);
}

static bool_t
svc_rdma_xprt_reply(SVCXPRT *xprt, struct rpc_msg *msg,
    struct sockaddr *addr, struct mbuf *m, uint32_t *seq)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	struct svc_rdma_conn *conn;
	struct svc_rdma_reply_pend pend;
	struct mbuf *mrep;
	char *buf;
	XDR xdrs;
	uint32_t hdr[7];
	uint32_t seqval = 0;
	u_int rlen, total;
	u_int nfsreply_len = 0;
	int rc;
	bool_t stat = TRUE;
	bool have_pend;

	/*
	 * Pre-allocate this pool thread's linuxkpi `current` shadow OFF-LOCK (#59)
	 * before any of the post sites below run ib_post_send under xr_lock: the
	 * first mlx5_ib_post_send on a fresh krpc thread would otherwise do that
	 * M_WAITOK alloc while holding the leaf mutex (WITNESS warns).  Optional op,
	 * NULL on an older ibcore.  Snapshot svc_rdma_verbs into a local so the
	 * NULL-check and the call use the SAME pointer (no TOCTOU on the global, and
	 * the snapshot targets the never-freed registered table).
	 */
	{
		const struct svc_rdma_verbs_ops *vops = svc_rdma_verbs;

		if (vops != NULL && vops->svo_thread_setup != NULL)
			vops->svo_thread_setup();
	}

	/*
	 * Build the ONC RPC reply into a fresh pkthdr mbuf, mirroring
	 * svc_vc_reply (minus the record-mark reservation: the RDMA transport
	 * header is prepended after marshalling, not in-band).
	 */
	mrep = m_gethdr(M_WAITOK, MT_DATA);
	xdrmbuf_create(&xdrs, mrep, XDR_ENCODE);

	if (msg->rm_reply.rp_stat == MSG_ACCEPTED &&
	    msg->rm_reply.rp_acpt.ar_stat == SUCCESS) {
		if (!xdr_replymsg(&xdrs, msg)) {
			stat = FALSE;
		} else {
			/*
			 * Capture the NFS reply body length BEFORE it is consumed
			 * into the reply chain (write-list READ engine).  xdr_putmbuf
			 * (xdrmbuf_putmbuf) tail-links the body verbatim, so the RPC
			 * reply-header length is (rlen - nfsreply_len) and the DDP
			 * read-data offset within the marshalled reply is that header
			 * length + the body-relative offset nfsd recorded.
			 */
			nfsreply_len = m_length(m, NULL);
			(void)xdr_putmbuf(&xdrs, m);
			m = NULL;	/* body now owned by the reply chain */
		}
	} else {
		stat = xdr_replymsg(&xdrs, msg);
	}

	if (!stat) {
		XDR_DESTROY(&xdrs);
		m_freem(mrep);
		if (m != NULL)
			m_freem(m);
		return (FALSE);
	}

	m_fixhdr(mrep);
	XDR_DESTROY(&xdrs);

	/*
	 * On the non-success (error reply) path xdr_replymsg encodes just the
	 * reply header and the body mbuf m is not part of the reply; free it so
	 * it is not leaked (on the success path m was consumed and is NULL).
	 */
	if (m != NULL) {
		m_freem(m);
		m = NULL;
	}

	rlen = mrep->m_pkthdr.len;
	total = RPCRDMA_HDR_MIN + rlen;

	/*
	 * Take this xid's pending reply chunk (TASK_003f-4), if the request offered
	 * one.  We take it unconditionally (so the slot is always reclaimed) and use it
	 * only on the over-inline path below; if the reply fits inline we simply drop
	 * the (taken) chunk and reply inline, which RFC 8166 permits.
	 */
	have_pend = svc_rdma_reply_pend_take(xr, msg->rm_xid, &pend);

	/*
	 * INLINE bound.  RPCRDMA_HDR_MIN + reply must fit one inline send buffer.  A
	 * larger reply (big READDIR/READLINK/READ, or the NFSv4 mount-handshake
	 * compound) is the RDMA Write engine's job (TASK_003f-4): if the client offered
	 * a reply chunk, RDMA-Write the marshalled ONC RPC reply into it and SEND an
	 * RDMA_NOMSG header reporting the length.  With no reply chunk offered we cannot
	 * deliver an over-inline reply -- drop-with-log (never overflow the send
	 * buffer); the verbs layer's reply_chunk also returns EMSGSIZE if the reply
	 * exceeds the offered chunk, which we treat as the same drop.
	 */
	if (total > SVC_RDMA_REPLY_INLINE) {
		/*
		 * Multi-chunk write list (RFC 8166 3.4.2): a COMPOUND that offered more
		 * than one write chunk (i.e. >1 DDP-eligible READ).  The reduction
		 * engine maps a SINGLE DDP result to one write chunk (RFC 8267) and
		 * echoes a one-chunk reply write list, so it cannot place a multi-chunk
		 * reply.  Rather than send a non-conformant single-chunk reply or drop
		 * silently, answer with a per-request RDMA_ERROR/ERR_CHUNK keyed by the
		 * KNOWN xid (RFC 8166 4.4/5): the client learns this request could not
		 * be placed and may retry (e.g. without DDP), and the connection STAYS
		 * UP.  Only matters over-inline; an inline reply simply leaves every
		 * offered write chunk empty, which is always conformant.
		 */
		if (have_pend && pend.rp_has_writes && pend.rp_nwrites > 1) {
			m_freem(mrep);
			mtx_lock(&xr->xr_lock);
			conn = xr->xr_conn;
			if (conn != NULL && svc_rdma_verbs != NULL &&
			    svc_rdma_verbs->svo_conn_error != NULL)
				(void)svc_rdma_verbs->svo_conn_error(conn,
				    msg->rm_xid, RDMA_ERR_CHUNK);
			mtx_unlock(&xr->xr_lock);
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("svc_rdma: multi-chunk write list (%u "
				    "chunks) not reducible, replying ERR_CHUNK "
				    "(xid=0x%08x)\n", pend.rp_nwrites,
				    msg->rm_xid);
			return (FALSE);
		}
		/*
		 * Write-list READ engine (RFC 8166 reduction).  An over-inline READ
		 * whose data is DDP-eligible into the client's write list: the request
		 * offered a SINGLE write chunk (captured at recv; multi-chunk handled
		 * above) AND the nfsd READ path stamped the DDP boundary {off,len} via
		 * SVCSET_READDDP.  RDMA-Write the read data into the write list and
		 * SEND a reduced RDMA_MSG instead of dropping.  The data sits at
		 * rpchdr + ddp_off within mrep, where rpchdr = rlen - nfsreply_len.
		 * The read data mbuf was XDR round-up padded by nfsvno_read
		 * (NFSM_RNDUP(cnt)), so the inline reduced body must excise the PADDED
		 * span [doff, doff+padded) while the write list receives exactly
		 * ddp_len (unpadded) bytes (RFC 8166 3.4.5).  Bounds-check the padded
		 * window against the marshalled reply before trusting it; a failed
		 * bound falls through to the existing reply-chunk / drop path.
		 * Strictly prefer this over the reply-chunk path: a READ never offers a
		 * reply chunk.
		 */
		if (have_pend && pend.rp_has_writes && pend.rp_nwrites == 1 &&
		    pend.rp_has_ddp && pend.rp_ddp_len > 0 && svc_rdma_verbs != NULL &&
		    svc_rdma_verbs->svo_conn_write_list != NULL) {
			u_int hdrbytes = rlen - nfsreply_len;
			u_int doff = hdrbytes + pend.rp_ddp_off;
			u_int dlen = pend.rp_ddp_len;
			u_int padded = (dlen + 3u) & ~3u;
			u_int reducedlen;
			char *reduced;
			void *src;
			struct svc_rdma_page *pgs;
			int npg;

			if (nfsreply_len <= rlen && padded <= rlen &&
			    doff <= rlen - padded) {
				/*
				 * reduced: the inline body with [doff, doff+padded)
				 * removed (the read data AND its XDR pad) -- head
				 * [0,doff) ++ tail [doff+padded,rlen).  Built off the
				 * xr_lock either way.
				 */
				reducedlen = rlen - padded;
				reduced = malloc(reducedlen, M_SVCRDMA, M_WAITOK);
				if (doff > 0)
					m_copydata(mrep, 0, doff, reduced);
				if (rlen > doff + padded)
					m_copydata(mrep, doff + padded,
					    rlen - (doff + padded),
					    reduced + doff);

				/*
				 * ZERO-COPY (TASK_003f-19): if the engine offers the
				 * page entry point and the read data is a clean M_EXTPG
				 * page chain, RDMA-Write those pages DIRECTLY -- no
				 * contigmalloc, no per-READ m_copydata of the data (the
				 * old read ceiling).  svc_rdma_collect_extpg returns 0
				 * to fall back to the contiguous copy.  pgs is heap
				 * (~4 KiB) to stay off the kernel stack.
				 */
				pgs = malloc(SVC_RDMA_RD_MAXPGS * sizeof(*pgs),
				    M_SVCRDMA, M_WAITOK);
				npg = (svc_rdma_verbs->svo_conn_write_list_pages !=
				    NULL) ? svc_rdma_collect_extpg(mrep, doff, dlen,
				    pgs, SVC_RDMA_RD_MAXPGS) : 0;
				if (npg == 0) {
					/*
					 * Fallback: copy the unpadded read data into a
					 * contiguous DMA source OFF the lock and hand it
					 * to the contig engine (which owns src).
					 */
					src = contigmalloc(dlen, M_NFSRDMA, M_WAITOK,
					    0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
					m_copydata(mrep, doff, dlen, src);
				} else
					src = NULL;

				mtx_lock(&xr->xr_lock);
				conn = xr->xr_conn;
				if (conn == NULL) {
					rc = ENOTCONN;
					if (npg == 0)
						free(src, M_NFSRDMA);	/* never handed off */
				} else if (npg > 0) {
					rc = svc_rdma_verbs->svo_conn_write_list_pages(
					    conn, msg->rm_xid, &pend.rp_writes, mrep,
					    pgs, npg, dlen, reduced, reducedlen);
					/*
					 * The engine OWNS mrep on EVERY return (0 or
					 * errno: it frees mrep at badm, through
					 * svc_rdma_write_free, or at drain on a committed
					 * partial post), so drop our reference here
					 * UNCONDITIONALLY -- never m_freem() it below.
					 */
					mrep = NULL;
					if (rc == 0)
						seqval = ++xr->xr_seq;
				} else {
					rc = svc_rdma_verbs->svo_conn_write_list(
					    conn, msg->rm_xid, &pend.rp_writes,
					    src, dlen, reduced, reducedlen);
					if (rc == 0)
						seqval = ++xr->xr_seq;
					/* svo_conn_write_list OWNS src on every return. */
				}
				mtx_unlock(&xr->xr_lock);

				free(pgs, M_SVCRDMA);
				free(reduced, M_SVCRDMA);
				if (mrep != NULL)
					m_freem(mrep);	/* fallback/error: engine didn't take it */

				if (rc != 0) {
					if (rc != ENOTCONN &&
					    ppsratecheck(&svc_rdma_log_last,
					    &svc_rdma_log_pps, 5))
						printf("svc_rdma: write-list "
						    "READ post failed: %d "
						    "(xid=0x%08x, %u bytes)\n",
						    rc, msg->rm_xid, dlen);
					return (FALSE);
				}
				if (seq != NULL)
					*seq = seqval;
				return (TRUE);
			}
			/*
			 * boundary out of range: fall through to the reply-chunk /
			 * ERR_CHUNK path below.  A READ never offers a reply chunk, so
			 * an out-of-range write-list boundary lands on the ERR_CHUNK
			 * drop (RFC 8166 4.4/5), not on a reply-chunk send.
			 */
		}
		if (have_pend && pend.rp_has_reply) {
			/*
			 * Linearize the marshalled ONC RPC reply ALONE (no RFC 8166
			 * header -- the verbs layer builds the RDMA_NOMSG header).  Post
			 * under xr_lock so we observe a stable live xr_conn (SF1/SF2
			 * race window, identical to the inline path below).
			 */
			buf = malloc(rlen, M_SVCRDMA, M_WAITOK);
			m_copydata(mrep, 0, rlen, buf);
			m_freem(mrep);

			mtx_lock(&xr->xr_lock);
			conn = xr->xr_conn;
			if (conn != NULL && svc_rdma_verbs != NULL &&
			    svc_rdma_verbs->svo_conn_reply_chunk != NULL) {
				rc = svc_rdma_verbs->svo_conn_reply_chunk(conn,
				    msg->rm_xid, &pend.rp_reply, buf, rlen);
				if (rc == 0)
					seqval = ++xr->xr_seq;
			} else
				rc = ENOTCONN;
			mtx_unlock(&xr->xr_lock);

			free(buf, M_SVCRDMA);

			if (rc != 0) {
				if (rc != ENOTCONN &&
				    ppsratecheck(&svc_rdma_log_last,
				    &svc_rdma_log_pps, 5))
					printf("svc_rdma: reply-chunk post failed: "
					    "%d (xid=0x%08x, %u bytes)\n", rc,
					    msg->rm_xid, rlen);
				return (FALSE);
			}
			if (seq != NULL)
				*seq = seqval;
			return (TRUE);
		}
		m_freem(mrep);
		/*
		 * (B) ERR_CHUNK (RFC 8166 4.4/5, TASK_028).  We could not place this
		 * reply: it is over-inline and either no reply chunk was offered, or a
		 * write-list read's DDP boundary was out of range and fell through to
		 * here.  Rather than drop silently, report RDMA_ERROR/ERR_CHUNK keyed
		 * by the request's KNOWN xid (msg->rm_xid, decoded by xdr_callmsg) so
		 * the client learns this specific request failed and can retry -- the
		 * connection STAYS UP (a per-request error).  Post under xr_lock so we
		 * observe a stable live xr_conn (the same SF1/SF2 window as the inline
		 * and reply-chunk paths above), and only when the verbs layer supplies
		 * the OPTIONAL svo_conn_error (an older ibcore without it falls back to
		 * the plain drop).  mrep was freed above and is not touched here.  We
		 * still return FALSE: no inline reply was sent.
		 */
		mtx_lock(&xr->xr_lock);
		conn = xr->xr_conn;
		if (conn != NULL && svc_rdma_verbs != NULL &&
		    svc_rdma_verbs->svo_conn_error != NULL)
			(void)svc_rdma_verbs->svo_conn_error(conn, msg->rm_xid,
			    RDMA_ERR_CHUNK);
		mtx_unlock(&xr->xr_lock);
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("svc_rdma: over-inline reply (%u > %u) with no reply "
			    "chunk, replying ERR_CHUNK (xid=0x%08x)\n", total,
			    SVC_RDMA_REPLY_INLINE, msg->rm_xid);
		return (FALSE);
	}

	/*
	 * Linearize [RFC 8166 header | ONC RPC reply] into one contiguous buffer
	 * for svc_rdma_conn_send().  All header words except the credit are fixed
	 * local data (only the echoed xid is peer-derived); the credit (w2) is
	 * the verbs layer's real posted recv depth and is filled inside the lock
	 * below, once we have confirmed a live conn to read it from (SF1).
	 */
	hdr[0] = htonl(msg->rm_xid);		/* w0 rdma_xid */
	hdr[1] = htonl(RPCRDMA_VERSION);	/* w1 rdma_vers */
	hdr[2] = htonl(SVC_RDMA_CREDIT_GRANT);	/* w2 rdma_credit (fallback) */
	hdr[3] = htonl(RDMA_MSG);		/* w3 rdma_proc */
	hdr[4] = 0;				/* w4 read_list (empty) */
	hdr[5] = 0;				/* w5 write_list (empty) */
	hdr[6] = 0;				/* w6 reply_chunk (empty) */

	buf = malloc(total, M_SVCRDMA, M_WAITOK);
	memcpy(buf, hdr, RPCRDMA_HDR_MIN);
	m_copydata(mrep, 0, rlen, buf + RPCRDMA_HDR_MIN);
	m_freem(mrep);

	/*
	 * Post under xr_lock so we observe a stable xr_conn: sro_disconnect
	 * NULLs xr_conn under the same lock after draining all sro_recv, so if
	 * we win the race we hold a live conn for the duration of the (non-
	 * sleeping) svc_rdma_conn_send; if we lose it, conn is NULL and we drop.
	 * svc_rdma_conn_send does not sleep and is documented safe to call
	 * holding a leaf mutex.  While we hold the live conn we also read its
	 * real granted credit (svo_conn_credits == conn->sc_nrecv, SF1) and write
	 * it into w2 -- exactly what the verbs layer would grant -- and, on a
	 * successful post, advance xr_seq and report it as *seq for the DRC (SF2).
	 */
	mtx_lock(&xr->xr_lock);
	conn = xr->xr_conn;
	if (conn != NULL && svc_rdma_verbs != NULL) {
		uint32_t credit = svc_rdma_verbs->svo_conn_credits(conn);

		if (credit == 0)		/* defensive: never advertise 0 */
			credit = SVC_RDMA_CREDIT_GRANT;
		be32enc(buf + 8, credit);	/* w2 rdma_credit: real depth */
		rc = svc_rdma_verbs->svo_conn_send(conn, buf, total);
		if (rc == 0)
			seqval = ++xr->xr_seq;
	} else
		rc = ENOTCONN;
	mtx_unlock(&xr->xr_lock);

	free(buf, M_SVCRDMA);

	if (rc != 0) {
		if (rc != ENOTCONN && ppsratecheck(&svc_rdma_log_last,
		    &svc_rdma_log_pps, 5))
			printf("svc_rdma: reply post failed: %d "
			    "(xid=0x%08x)\n", rc, msg->rm_xid);
		return (FALSE);
	}

	if (seq != NULL)
		*seq = seqval;
	return (TRUE);
}

/*
 * svc_rdma_bck_send: send one NFSv4.1 backchannel CB RPC CALL (server->client
 * callback, e.g. CB_NULL) over the SAME established RDMA QP, in the reverse
 * direction of the forward NFS stream.  Reached only through the link-safe
 * clnt_bck_rdma_send hook from clnt_bck_call (xp_socket == NULL).  mreq is the
 * marshalled ONC RPC CALL whose first XDR word is the already-network-order
 * xid (clnt_bck_call wrote htonl(xid) there and, on the RDMA path, prepended no
 * TCP record mark); it is consumed (m_freem) here.
 *
 * This is the inline reply-send path of svc_rdma_xprt_reply above with a CALL
 * body instead of a REPLY body: build the 7-word RFC 8166 RDMA_MSG transport
 * header (w0 = the echoed ONC xid so the client's RPC-over-RDMA layer mirrors
 * it and the clnt_bck_call reply matcher keys on the same value; w1 =
 * RPCRDMA_VERSION; w2 = the real granted credit read from the live conn under
 * xr_lock; w3 = RDMA_MSG; w4/w5/w6 = empty chunk lists -- a CB_NULL CALL is
 * pure-inline), prepend it, then post under xr_lock against a stable xr_conn --
 * the identical SF1 discipline as the forward reply (sro_disconnect NULLs
 * xr_conn under the same lock after draining recv; svo_conn_send does not sleep
 * and is safe under a leaf mutex).  Lock order xr_lock -> sc_lock is the
 * existing forward-reply order; ct_lock is never held here (clnt_bck_call drops
 * it before the send block), so no new lock order is introduced.  Returns 0, or
 * ENOTCONN/EBUSY/EINVAL which clnt_bck_call maps to RPC_CANTSEND.
 */
static int
svc_rdma_bck_send(SVCXPRT *xprt, struct mbuf *mreq)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	struct svc_rdma_conn *conn;
	uint32_t hdr[7];
	uint32_t netxid;
	char *buf;
	u_int rlen, total;
	int rc;

	/* Pre-warm the linuxkpi `current` shadow off-lock before the post (#59);
	 * snapshot the global so the NULL-check and call use one pointer. */
	{
		const struct svc_rdma_verbs_ops *vops = svc_rdma_verbs;

		if (vops != NULL && vops->svo_thread_setup != NULL)
			vops->svo_thread_setup();
	}

	rlen = m_length(mreq, NULL);
	total = RPCRDMA_HDR_MIN + rlen;
	if (total > SVC_RDMA_INLINE) {
		m_freem(mreq);
		return (EINVAL);		/* CB_NULL is tiny; never trips */
	}

	/* The ONC xid is word0 of mreq, already in network byte order. */
	m_copydata(mreq, 0, sizeof(netxid), (caddr_t)&netxid);
	hdr[0] = netxid;			/* w0 rdma_xid (echo, net order) */
	hdr[1] = htonl(RPCRDMA_VERSION);	/* w1 rdma_vers */
	hdr[2] = htonl(SVC_RDMA_CREDIT_GRANT);	/* w2 rdma_credit (fallback) */
	hdr[3] = htonl(RDMA_MSG);		/* w3 rdma_proc */
	hdr[4] = 0;				/* w4 read_list (empty) */
	hdr[5] = 0;				/* w5 write_list (empty) */
	hdr[6] = 0;				/* w6 reply_chunk (empty) */

	buf = malloc(total, M_SVCRDMA, M_WAITOK);
	memcpy(buf, hdr, RPCRDMA_HDR_MIN);
	m_copydata(mreq, 0, rlen, buf + RPCRDMA_HDR_MIN);
	m_freem(mreq);

	mtx_lock(&xr->xr_lock);
	conn = xr->xr_conn;
	if (conn != NULL && svc_rdma_verbs != NULL) {
		uint32_t credit = svc_rdma_verbs->svo_conn_credits(conn);

		if (credit == 0)		/* defensive: never advertise 0 */
			credit = SVC_RDMA_CREDIT_GRANT;
		be32enc(buf + 8, credit);	/* w2 rdma_credit: real depth */
		rc = svc_rdma_verbs->svo_conn_send(conn, buf, total);
	} else
		rc = ENOTCONN;
	mtx_unlock(&xr->xr_lock);

	free(buf, M_SVCRDMA);

	if (rc != 0 && rc != ENOTCONN && ppsratecheck(&svc_rdma_log_last,
	    &svc_rdma_log_pps, 5))
		printf("svc_rdma: backchannel CALL post failed: %d "
		    "(xid=0x%08x)\n", rc, ntohl(netxid));
	return (rc);
}

static bool_t
svc_rdma_xprt_control(SVCXPRT *xprt, const u_int rq, void *in)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	const struct svcxprt_readddp *rd;

	switch (rq) {
	case SVCSET_READDDP:
		/*
		 * The nfsd READ path located the DDP-eligible read data within the
		 * reply body it is building (write-list READ engine).  Stamp the
		 * {off,len} onto this xid's pending entry (created at recv when a
		 * write list was offered); xp_reply consumes it to RDMA-Write the
		 * data into the client's write chunk and send a reduced reply.  No
		 * write list -> no pending entry -> silent no-op (the reply falls
		 * back to inline / drop).  Unknown commands keep the FALSE no-op.
		 */
		if (xr == NULL || in == NULL)
			return (FALSE);
		rd = (const struct svcxprt_readddp *)in;
		if (rd->rd_len == 0)
			return (FALSE);
		svc_rdma_readddp_set(xr, rd->rd_xid, rd->rd_off, rd->rd_len);
		return (TRUE);
	default:
		return (FALSE);
	}
}

/*
 * xp_destroy: the final SVC_RELEASE dropped the last reference, so no pool
 * thread holds this xprt.  Free the recv queue and the per-conn state.  The
 * verbs connection itself is torn down separately by the verbs layer after
 * sro_disconnect returned; we must not touch xr_conn here.
 */
static void
svc_rdma_xprt_destroy(SVCXPRT *xprt)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	if (xr != NULL) {
		svc_rdma_drain_queue(xr);
		mtx_destroy(&xr->xr_lock);
		free(xr, M_SVCRDMA);
		xprt->xp_p1 = NULL;
	}
	/*
	 * Release the NFSv4.1 backchannel CLIENT bound at CREATE_SESSION
	 * (nfs_nfsdstate.c:840 CLNT_ACQUIRE'd nr_client into xp_p2).  Runs on the
	 * last SVC_RELEASE, after every recv completion has drained and after
	 * sro_disconnect already CLNT_CLOSE'd it, so no clnt_bck_svccall can
	 * still reference it.  Mirrors svc_vc_destroy (svc_vc.c:539,550).  The
	 * session's own xprt reference is released separately by
	 * nfsrv_freesession via SVC_RELEASE, so this is a distinct refcount and
	 * not a double free.
	 */
	if (xprt->xp_p2 != NULL) {
		CLNT_RELEASE((CLIENT *)xprt->xp_p2);
		xprt->xp_p2 = NULL;
	}
	sx_destroy(&xprt->xp_lock);
	svc_xprt_free(xprt);
}

/*
 * ===========================================================================
 * Consumer upcalls (struct svc_rdma_ops) driven by the verbs layer.
 */

/*
 * sro_newconn: an RDMA connection reached ESTABLISHED.  Sleepable CM context
 * (M_WAITOK ok), guaranteed before any sro_recv for this conn.  Allocate and
 * register the SVCXPRT into the pool and bind it to the conn -- the RDMA
 * analogue of svc_vc_create_conn.
 *
 * We do NOT call svc_reg(NFS_PROG,...) per-connection here, and deliberately so:
 * svc_reg attaches a (prog,vers)->dispatch callout to the POOL (sp_callouts),
 * not to the xprt, and nfsd already populated those callouts for its pool when
 * its first (TCP/UDP) transport came up (nfsrvd_addsock).  xprt_register alone
 * is therefore enough for svc_executereq to dispatch NFS on this transport --
 * exactly as svc_vc leaves svc_reg to its caller (nfsrvd_addsock), not to the
 * transport.  We DO call svc_rdma_conn_set_ctx so our recv/disconnect upcalls
 * recover the xprt from the conn.
 */
static void
svc_rdma_sro_newconn(void *ctx, struct svc_rdma_conn *conn)
{
	struct svc_rdma_listener *sl = ctx;
	struct svc_rdma_xprt *xr;
	SVCXPRT *xprt;

	xr = malloc(sizeof(*xr), M_SVCRDMA, M_WAITOK | M_ZERO);
	mtx_init(&xr->xr_lock, "svcrdma_xr", NULL, MTX_DEF);
	STAILQ_INIT(&xr->xr_mq);
	xr->xr_conn = conn;
	xr->xr_died = false;

	xprt = svc_xprt_alloc();
	sx_init(&xprt->xp_lock, "xprt->xp_lock");
	xprt->xp_pool = sl->sl_pool;
	xprt->xp_socket = NULL;		/* no socket: gates soshutdown/DDP paths */
	xprt->xp_p1 = xr;
	xprt->xp_p2 = NULL;
	xprt->xp_ops = &svc_rdma_xp_ops;
	xprt->xp_extpg = true;		/* TASK_003f-19: nfsd may build M_EXTPG READ
					 * replies for this xprt; the verbs engine
					 * RDMA-Writes the data pages directly. */
	/*
	 * No xp_idletimeout: the idle reaper (svc_checkidle) calls
	 * soshutdown(xp_socket,...) unconditionally on a timed-out xprt, which
	 * would NULL-deref here.  RDMA connection lifetime is driven by the
	 * verbs CM (sro_disconnect), not by the krpc idle timer, so we leave
	 * xp_idletimeout == 0 (reaper skips us).
	 */

	/*
	 * Give the transport a unique non-zero xp_sockref so the nfsd duplicate-
	 * request cache (DRC) can key its per-transport ack list on it (SF2):
	 * nfsd records each reply under xp_sockref + the xp_reply *seq, and
	 * nfsrc_trimcache() confirms cached replies for this sockref once xp_ack
	 * reports a SEQ_GEQ value.  A zero sockref would alias the "no socket"
	 * sentinel and collide across connections, so we allocate from a process-
	 * wide monotonic counter (atomic; wrap is astronomically distant and would
	 * at worst momentarily share a DRC bucket, never corrupt it).
	 *
	 * Peer address (TASK_003f-6): surface the RDMA-CM resolved client
	 * sockaddr into xp_rtaddr so NFS export-address checks
	 * (svc_getrpccaller -> xp_rtaddr) match the client against -network/-host
	 * exports, exactly as svc_vc does for a TCP peer.  If the verbs layer
	 * cannot supply it (older provider, or an unknown address family) it stays
	 * AF_UNSPEC and only unrestricted exports match -- the prior behavior.
	 * The DRC is keyed on xp_sockref (below), independent of the peer address.
	 */
	xprt->xp_sockref = atomic_fetchadd_64(&svc_rdma_sockref_gen, 1) + 1;

	if (svc_rdma_verbs != NULL && svc_rdma_verbs->svo_conn_peeraddr != NULL) {
		struct sockaddr_storage ss;

		svc_rdma_verbs->svo_conn_peeraddr(conn, &ss);
		if (ss.ss_family != AF_UNSPEC && ss.ss_len != 0 &&
		    ss.ss_len <= sizeof(xprt->xp_rtaddr))
			memcpy(&xprt->xp_rtaddr, &ss, ss.ss_len);
	}

	xprt_register(xprt);
	svc_rdma_conn_set_ctx_wrap(conn, xprt);

	/*
	 * Drop the svc_xprt_alloc() reference (xp_refs was 1; xprt_register
	 * bumped it to 2).  After this the pool holds the SOLE reference, so the
	 * transport is destroyed via SVC_DESTROY -> svc_rdma_xprt_destroy on the
	 * last release (sro_disconnect's xprt_unregister, or a pool thread seeing
	 * XPRT_DIED) -- not leaked.  This mirrors svc_vc.c:477, which does
	 * SVC_RELEASE(new_xprt) right after svc_vc_create_conn.  The release MUST
	 * come AFTER svc_rdma_conn_set_ctx_wrap: while we still held the alloc
	 * reference no pool thread could destroy the xprt mid-setup (a recv that
	 * raced in would xprt_active it, but destroy cannot run until refs hit 0,
	 * which only this release allows).  We MUST NOT touch xprt after this.
	 */
	SVC_RELEASE(xprt);
}

/*
 * sro_recv: a good inline RDMA_MSG call completed.  recv-completion
 * (IB_POLL_WORKQUEUE) context: *** MUST NOT SLEEP ***.  Copy the inline RPC
 * bytes into an mbuf (the verbs recv buffer is reposted the instant we return,
 * so we must copy), enqueue, and xprt_active() to wake a pool thread.  This is
 * the RDMA analogue of svc_vc_soupcall: the recv completion is the "data ready"
 * signal.
 *
 * Non-sleeping allocation: m_getm2(M_NOWAIT) pre-sizes a chain large enough for
 * rpc_len so the subsequent m_copyback does not extend (and thus does not sleep
 * or allocate).  On alloc failure we DROP (return 0 so the verbs layer reposts);
 * the RC client retransmits.  We never block a completion thread.
 *
 * msg->rpc_len was bounded by the verbs layer: <= SVC_RDMA_INLINE for a pure-
 * inline call, or <= SVC_RDMA_INLINE + 1 MiB for an RDMA-Read-assembled NFS WRITE
 * body (TASK_003f-3); either way a fixed verbs-imposed bound, not a peer-supplied
 * length into an allocation.  m_getm2 sizes the chain to it dynamically.
 */
static int
svc_rdma_sro_recv(void *ctx, struct svc_rdma_conn *conn,
    const struct svc_rdma_msg *msg)
{
	SVCXPRT *xprt = svc_rdma_conn_get_ctx_wrap(conn);
	struct svc_rdma_xprt *xr;
	struct svc_rdma_qent *q;
	struct mbuf *m;

	if (xprt == NULL)	/* newconn must have run first (header contract) */
		return (0);
	xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	if (msg->rpc_len == 0)
		return (0);	/* nothing to dispatch; repost */

	/*
	 * NFSv4.1 backchannel REPLY demux.  Forward NFS CALLs and the client's
	 * server-originated callback (CB) REPLYs both arrive as inline RDMA_MSG
	 * SENDs on this one recv ring; the RPC-over-RDMA transport header carries
	 * no direction, so the direction lives in the INNER ONC RPC header at
	 * word1 (offset +4 of the inline body; the xid is at +0): CALL == 0,
	 * REPLY == 1 (rpc_msg.h).  When a backchannel CLIENT is bound
	 * (xp_p2 != NULL) and this is a REPLY, route it to the krpc reply matcher
	 * (clnt_bck_svccall) instead of dispatching it as a forward call -- the
	 * RDMA analogue of svc_vc_recv's TCP demux, but here on the recv-
	 * completion workqueue (an independent context from the nfsd pool thread
	 * blocked in clnt_bck_call awaiting this reply), which guarantees the
	 * reply's wakeup always has a runnable context and cannot deadlock on
	 * pool-thread occupancy.
	 *
	 * MUST copy the bytes NOW: msg->rpc points into the verbs recv buffer,
	 * which is reposted the instant this function returns, so an mbuf is
	 * built with M_NOWAIT (we are in IB_POLL_WORKQUEUE context and MUST NOT
	 * SLEEP) before the call.  clnt_bck_svccall takes only ct_lock + wakeup
	 * (no sleep, no XDR decode, and it m_freem's an unmatched/late reply and
	 * honors ct_closing itself), so it is safe here.  On copy-alloc failure
	 * we drop and repost; the client/session layer retransmits.  We return
	 * WITHOUT enqueueing to xr_mq or calling xprt_active -- a diverted reply
	 * is never a forward call.  Use the symbolic REPLY enum, never a literal.
	 */
	if (msg->rpc_len >= 8 && xprt->xp_p2 != NULL &&
	    be32dec((const char *)msg->rpc + 4) == REPLY) {
		struct mbuf *rm;

		rm = m_getm2(NULL, msg->rpc_len, M_NOWAIT, MT_DATA, M_PKTHDR);
		if (rm == NULL)
			return (0);	/* drop; client retransmits the CB */
		m_copyback(rm, 0, msg->rpc_len, msg->rpc);
		rm->m_pkthdr.len = msg->rpc_len;
		clnt_bck_svccall(xprt->xp_p2, rm,
		    be32dec((const char *)msg->rpc));
		return (0);	/* matched (or freed) by the CB client; repost */
	}

	q = malloc(sizeof(*q), M_SVCRDMA, M_NOWAIT);
	if (q == NULL)
		return (0);	/* drop; client retransmits */

	m = m_getm2(NULL, msg->rpc_len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		free(q, M_SVCRDMA);
		return (0);	/* drop; client retransmits */
	}
	m_copyback(m, 0, msg->rpc_len, msg->rpc);
	m->m_pkthdr.len = msg->rpc_len;
	q->sq_m = m;

	/*
	 * Capture the reply chunk (TASK_003f-4) if the client offered one for this
	 * request: the whole RPC reply will be too large for inline and must be
	 * RDMA-Written into the client's reply-chunk memory.  msg->reply is a pure
	 * value type (a fixed-size validated segment array, no pointers), so copying it
	 * here is safe even though msg itself is valid only for this call.  We key it on
	 * the ONC RPC xid so xp_reply (a later pool thread) can find it.
	 */
	q->sq_has_reply = msg->reply_present;
	/*
	 * Capture the FIRST write-list chunk too (write-list READ engine): a READ
	 * offers a write list (not a reply chunk) to receive its data by DDP.
	 * msg->writes is a pure value type, safe to copy here.  RFC 8267 maps the
	 * single DDP-eligible READ result to one write chunk, so we carry
	 * writes[0] only -- but ALSO carry the offered chunk count so xp_reply can
	 * tell a single-chunk READ (reduced) from a multi-chunk write list (a
	 * COMPOUND with >1 DDP-eligible READ), which the engine does not reduce and
	 * must answer with a conformant ERR_CHUNK rather than a single-chunk reply.
	 * sq_xid is set whenever EITHER list is present.
	 */
	q->sq_has_writes = (msg->wr_nchunks > 0);
	q->sq_nwrites = msg->wr_nchunks;
	if (msg->reply_present || q->sq_has_writes)
		q->sq_xid = msg->xid;
	if (msg->reply_present)
		q->sq_reply = msg->reply;
	if (q->sq_has_writes)
		q->sq_writes = msg->writes[0];

	mtx_lock(&xr->xr_lock);
	STAILQ_INSERT_TAIL(&xr->xr_mq, q, sq_link);
	mtx_unlock(&xr->xr_lock);

	/*
	 * Wake a pool thread.  xprt_active is the krpc wakeup primitive (the
	 * same call svc_vc_soupcall makes); it takes the group lock internally.
	 * We call it with xr_lock DROPPED to avoid any lock-order coupling
	 * between our leaf mutex and the krpc group lock.
	 */
	xprt_active(xprt);
	return (0);
}

/*
 * sro_recv_mbuf: zero-copy variant of sro_recv for the RDMA-Read-assembled NFS
 * WRITE path (TASK_003f-3).  Same IB_POLL_WORKQUEUE context and MUST-NOT-SLEEP
 * rule as sro_recv, same sro_newconn-happened-before guarantee.  m is a COMPLETE
 * ONC RPC call already assembled by the verbs layer as an mbuf chain (small head
 * fragments bracketing one EXT_DISPOSABLE segment over the DMA'd read sink); we
 * enqueue it with NO copy (no m_getm2/m_copyback of the body).  On return 0
 * ownership of m transfers to us (drained via xr_mq / svc_rdma_drain_queue);
 * on any drop we m_freem(m) here, which runs the verbs-layer ext_free and
 * releases the read sink.  reply is a pure value type captured iff has_reply.
 */
static int
svc_rdma_sro_recv_mbuf(void *ctx, struct svc_rdma_conn *conn, struct mbuf *m,
    uint32_t xid, bool has_reply, const struct svc_rdma_write_chunk *reply)
{
	SVCXPRT *xprt = svc_rdma_conn_get_ctx_wrap(conn);
	struct svc_rdma_xprt *xr;
	struct svc_rdma_qent *q;

	if (xprt == NULL) {	/* newconn must have run first (header contract) */
		m_freem(m);	/* runs ext_free -> releases the read sink */
		return (0);
	}
	xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	if (m->m_pkthdr.len == 0) {
		m_freem(m);
		return (0);	/* nothing to dispatch; repost */
	}

	q = malloc(sizeof(*q), M_SVCRDMA, M_NOWAIT);
	if (q == NULL) {
		m_freem(m);	/* drop; client retransmits */
		return (0);
	}
	q->sq_m = m;		/* OWNERSHIP TRANSFERS; no m_getm2/m_copyback */

	/*
	 * Capture the reply chunk if the client offered one (same rationale as
	 * sro_recv: msg->reply is a pure value type, safe to copy by value).
	 */
	q->sq_has_reply = has_reply;
	/*
	 * The RDMA-Read-assembled NFS WRITE path has no outbound write list to
	 * carry (the read list it consumed is inbound), so there is nothing to
	 * capture for the write-list READ engine.  q is M_NOWAIT (not M_ZERO), so
	 * sq_has_writes MUST be explicitly cleared here.
	 */
	q->sq_has_writes = false;
	q->sq_nwrites = 0;
	if (has_reply) {
		q->sq_xid = xid;
		q->sq_reply = *reply;
	}

	mtx_lock(&xr->xr_lock);
	STAILQ_INSERT_TAIL(&xr->xr_mq, q, sq_link);
	mtx_unlock(&xr->xr_lock);

	xprt_active(xprt);	/* xr_lock dropped (same discipline as sro_recv) */
	return (0);
}

/*
 * sro_disconnect: the connection is going away.  Sleepable teardown context,
 * delivered ONCE and paired with newconn, AFTER every sro_recv has returned (the
 * verbs layer drains in-flight upcalls first), so no sro_recv runs concurrently.
 *
 * Mirror svc_vc's destroy refcounting: xprt_unregister() removes the transport
 * from the pool and drops the pool's reference (the matching SVC_ACQUIRE done by
 * xprt_register).  Any pool thread still mid-xp_recv holds its OWN reference, so
 * xp_destroy runs only after that thread releases -- our state is not freed from
 * under it.  We NULL xr_conn under xr_lock first so a pool thread that reaches
 * xp_reply after this returns finds conn == NULL and drops instead of posting on
 * a conn the verbs layer is about to free.
 */
static void
svc_rdma_sro_disconnect(void *ctx, struct svc_rdma_conn *conn)
{
	SVCXPRT *xprt = svc_rdma_conn_get_ctx_wrap(conn);
	struct svc_rdma_xprt *xr;

	if (xprt == NULL)
		return;
	xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	/*
	 * Stop any future xp_reply from touching the conn the verbs layer is
	 * about to free, and mark the transport dead so xp_stat reports
	 * XPRT_DIED once the queue drains (which makes svc_getreq call
	 * xprt_unregister too -- idempotent with ours).
	 */
	mtx_lock(&xr->xr_lock);
	xr->xr_conn = NULL;
	xr->xr_died = true;
	mtx_unlock(&xr->xr_lock);

	/*
	 * Quiesce the NFSv4.1 backchannel CLIENT (if one is bound) AFTER xr_conn
	 * is NULL: an in-flight CB send now drops with ENOTCONN, and CLNT_CLOSE
	 * (clnt_bck_close) sets ct_closing so any late CB REPLY still arriving on
	 * the draining recv ring hits the ct_closing guard in clnt_bck_svccall
	 * and is m_freem'd rather than matched against state about to be freed.
	 * Do NOT release or NULL xp_p2 here -- svc_rdma_xprt_destroy holds the
	 * single CLNT_RELEASE, on the last SVC_RELEASE after all recv completions
	 * have drained.  This runs in the sleepable deferred-teardown context
	 * (svo_listen_stop / CM), so clnt_bck_close's msleep is legal.
	 */
	if (xprt->xp_p2 != NULL)
		CLNT_CLOSE((CLIENT *)xprt->xp_p2);

	/* Detach our back-pointer; conn is freed by the verbs layer after we
	 * return, and must not be dereferenced again. */
	svc_rdma_conn_set_ctx_wrap(conn, NULL);

	/*
	 * Drop the pool's reference.  xprt_unregister is a no-op if a pool
	 * thread (via svc_getreq seeing XPRT_DIED) already unregistered; the
	 * SVC_RELEASE it performs balances xprt_register's SVC_ACQUIRE.  When
	 * the last reference goes the xp_destroy op frees xr and the xprt.
	 * xp_socket is NULL so xprt_unregister's soshutdown() is skipped.
	 */
	xprt_unregister(xprt);
}

static const struct svc_rdma_ops svc_rdma_consumer_ops = {
	.sro_newconn	= svc_rdma_sro_newconn,
	.sro_recv	= svc_rdma_sro_recv,
	.sro_recv_mbuf	= svc_rdma_sro_recv_mbuf,
	.sro_disconnect	= svc_rdma_sro_disconnect,
};

/*
 * Thin wrappers over the registered verbs table for conn ctx get/set, so the
 * upcalls above read like svc_vc (direct calls) while still routing through the
 * cross-module function-pointer table.  svc_rdma_verbs is guaranteed non-NULL
 * for the whole window these run: newconn/recv are delivered only by a running
 * listener (which holds the table live), and sro_disconnect is driven either by
 * a live listener or by unregister's svo_listen_stop() -- which now runs with the
 * table STILL VALID and only clears it afterward (BLOCKER B2).  So the KASSERTs
 * are a defensive net, never the expected path.
 */
static void
svc_rdma_conn_set_ctx_wrap(struct svc_rdma_conn *conn, void *cctx)
{

	KASSERT(svc_rdma_verbs != NULL,
	    ("svc_rdma: conn_set_ctx with no verbs registered"));
	svc_rdma_verbs->svo_conn_set_ctx(conn, cctx);
}

static void *
svc_rdma_conn_get_ctx_wrap(struct svc_rdma_conn *conn)
{

	KASSERT(svc_rdma_verbs != NULL,
	    ("svc_rdma: conn_get_ctx with no verbs registered"));
	return (svc_rdma_verbs->svo_conn_get_ctx(conn));
}

/*
 * ===========================================================================
 * Cross-module verbs-ops registration (called from ibcore at load/unload).
 * Owner-keyed, with the modular-build UAF guard; the unregister path now runs
 * svo_listen_stop() with the table still valid (BLOCKER B2, see below).
 */
int
svc_rdma_register_verbs(const struct svc_rdma_verbs_ops *ops)
{

	if (ops == NULL || ops->svo_listen_start == NULL ||
	    ops->svo_listen_stop == NULL || ops->svo_conn_send == NULL ||
	    ops->svo_conn_reply_chunk == NULL ||
	    ops->svo_conn_set_ctx == NULL || ops->svo_conn_get_ctx == NULL ||
	    ops->svo_conn_credits == NULL)
		return (EINVAL);

	mtx_lock(&svc_rdma_verbs_lock);
	if (svc_rdma_verbs != NULL) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return (EBUSY);
	}
	svc_rdma_verbs = ops;
	/*
	 * Arm the link-safe backchannel send hook (rpc/krpc.h, defined NULL in
	 * rpc/clnt_bck.c) atomically with the verbs table under this lock, so
	 * clnt_bck_call can drive an NFSv4.1 callback over an RDMA xprt only when
	 * the OFED verbs table is live.  clnt_bck_call reaches svc_rdma_bck_send
	 * solely through this pointer, so the always-compiled krpc never names an
	 * OFED symbol.
	 */
	clnt_bck_rdma_send = svc_rdma_bck_send;
	mtx_unlock(&svc_rdma_verbs_lock);

	printf("svc_rdma(krpc): ibcore verbs registered\n");
	return (0);
}

void
svc_rdma_unregister_verbs(const struct svc_rdma_verbs_ops *ops)
{

	mtx_lock(&svc_rdma_verbs_lock);

	/* Owner-keyed: only the registration that owns the global may revoke
	 * it (so an EBUSY'd duplicate ibcore.ko unload is a strict no-op). */
	if (ops == NULL || svc_rdma_verbs != ops) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return;
	}

	/*
	 * BLOCKER B2: run svo_listen_stop() with the table STILL VALID.
	 *
	 * svo_listen_stop() (svc_verbs.c svc_rdma_listen_stop) sweeps every live
	 * connection and delivers sro_disconnect for each; our sro_disconnect ->
	 * svc_rdma_conn_get_ctx_wrap / svc_rdma_conn_set_ctx_wrap dereference
	 * svc_rdma_verbs.  If we NULLed the table first (as 2a did) those wrappers
	 * would hit a NULL function-pointer table -- a deterministic panic on
	 * kldunload ibcore (or GENERIC-OFED shutdown) with a live NFS-over-RDMA
	 * connection.  So:
	 *   1. mark stopping so no NEW in-flight arm enters the ops (the arm sites
	 *      check svc_rdma_verbs != NULL && !svc_rdma_verbs_stopping);
	 *   2. drain the in-flight callers already inside the lock-dropped ops;
	 *   3. drop the lock and call svo_listen_stop() -- svc_rdma_verbs is still
	 *      the live, owner table, so every sro_disconnect upcall it drives
	 *      resolves through it correctly;
	 *   4. retake the lock and only NOW clear svc_rdma_verbs.
	 * msleep here is legal: unregister runs in ibcore's SYSUNINIT/unload
	 * context, which is sleepable.
	 */
	svc_rdma_verbs_stopping = true;
	svc_rdma_krpc_listen_port = 0;
	while (svc_rdma_verbs_inflight != 0)
		msleep(&svc_rdma_verbs_inflight, &svc_rdma_verbs_lock, 0,
		    "svcrdvu", 0);
	mtx_unlock(&svc_rdma_verbs_lock);

	/* Table still valid: sro_disconnect upcalls driven by this resolve OK. */
	ops->svo_listen_stop();

	mtx_lock(&svc_rdma_verbs_lock);
	svc_rdma_verbs = NULL;
	/*
	 * Disarm the backchannel send hook atomically with the verbs table.
	 * svo_listen_stop() above already delivered sro_disconnect for every
	 * live conn (NULLing each xr_conn and CLNT_CLOSE'ing each xp_p2), so no
	 * clnt_bck_call can still be mid-send; any future socket-less send now
	 * falls back to ENOTCONN -> RPC_CANTSEND, and no stale pointer into this
	 * (about-to-unload) module remains.
	 */
	clnt_bck_rdma_send = NULL;
	svc_rdma_verbs_stopping = false;
	mtx_unlock(&svc_rdma_verbs_lock);

	printf("svc_rdma(krpc): ibcore verbs unregistered\n");
}

/*
 * ===========================================================================
 * nfsd-pool listen hook (TASK_003e-2c).
 *
 * svc_rdma_nfsd_listen() is the built-in kernel symbol nfsd (nfs_nfsdkrpc.c)
 * calls to start/stop the RDMA listener bound to its SVCPOOL -- the FreeBSD
 * analogue of Linux's `echo "rdma 20049" > /proc/fs/nfsd/portlist`.  nfsd passes
 * VNET(nfsrvd_pool) and the host-order port; we stash the pool in a listener ctx
 * and drive the registered verbs' svo_listen_start() with our SVCXPRT consumer
 * ops, so accepted connections svc_xprt_alloc + xprt_register into nfsd's pool.
 *
 * port != 0 starts; port == 0 stops.  Returns 0 on success, ENXIO if ibcore is
 * not loaded (no verbs registered), EBUSY if a listener is already up, EINVAL
 * for a bad port, or the verbs bring-up errno.
 *
 * Single global listener (one verbs CM listener exists), so a single static
 * listener ctx suffices; it is published before start and only read by upcalls.
 */
static struct svc_rdma_listener svc_rdma_the_listener;

int
svc_rdma_nfsd_listen(SVCPOOL *pool, int port)
{
	const struct svc_rdma_verbs_ops *ops;
	int error;

	if (port < 0 || port > 65535)
		return (EINVAL);
	if (port != 0 && pool == NULL)
		return (EINVAL);

	/*
	 * Snapshot the verbs table and arm the in-flight refcount under the
	 * lock (the modular-build UAF guard, identical to the 2a sysctl), then
	 * issue the blocking verbs call with the lock dropped.  Refuse to arm
	 * while unregister is stopping the table (B2): treat an in-progress
	 * unregister as "ibcore going away" and return ENXIO.
	 */
	mtx_lock(&svc_rdma_verbs_lock);
	ops = svc_rdma_verbs;
	if (ops == NULL || svc_rdma_verbs_stopping) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return (ENXIO);
	}
	svc_rdma_verbs_inflight++;
	mtx_unlock(&svc_rdma_verbs_lock);

	if (port == 0) {
		ops->svo_listen_stop();
		error = 0;
	} else {
		svc_rdma_the_listener.sl_pool = pool;
		error = ops->svo_listen_start((uint16_t)port,
		    &svc_rdma_consumer_ops, &svc_rdma_the_listener);
	}

	mtx_lock(&svc_rdma_verbs_lock);
	if (error == 0)
		svc_rdma_krpc_listen_port = port;
	if (--svc_rdma_verbs_inflight == 0)
		wakeup(&svc_rdma_verbs_inflight);
	mtx_unlock(&svc_rdma_verbs_lock);

	return (error);
}

/*
 * ===========================================================================
 * TEMPORARY bring-up sysctl (kept from TASK_003e-2a, now wired to the real
 * SVCXPRT consumer).  vfs.nfsrdma_krpc.listen with a nonzero port starts the
 * listener using a STANDALONE test pool (svc_reg of NFS_PROG is NOT done here --
 * this knob is for verbs/SVCXPRT bring-up without nfsd).  A real mount uses the
 * nfsd hook (svc_rdma_nfsd_listen, driven from nfs_nfsdkrpc.c) instead.
 *
 * To keep this self-contained and not require nfsd, the sysctl creates a private
 * SVCPOOL on first start and tears it down on stop.  This proves the SVCXPRT
 * lifecycle end to end (newconn->register, recv->enqueue/active, xp_recv/decode)
 * even on a kernel where nfsd is not running.
 */
SYSCTL_NODE(_vfs, OID_AUTO, nfsrdma_krpc, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "NFS over RDMA server (krpc layer)");

static SVCPOOL		*svc_rdma_test_pool;	/* under svc_rdma_verbs_lock */

static int
sysctl_nfsrdma_krpc_listen(SYSCTL_HANDLER_ARGS)
{
	SVCPOOL *pool, *oldpool;
	int error, newport;

	mtx_lock(&svc_rdma_verbs_lock);
	newport = svc_rdma_krpc_listen_port;
	mtx_unlock(&svc_rdma_verbs_lock);

	error = sysctl_handle_int(oidp, &newport, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (newport < 0 || newport > 65535)
		return (EINVAL);

	if (newport == 0) {
		error = svc_rdma_nfsd_listen(NULL, 0);
		mtx_lock(&svc_rdma_verbs_lock);
		oldpool = svc_rdma_test_pool;
		svc_rdma_test_pool = NULL;
		mtx_unlock(&svc_rdma_verbs_lock);
		if (oldpool != NULL)
			svcpool_destroy(oldpool);
		return (error);
	}

	/*
	 * Create the private test pool before starting the listener so
	 * sro_newconn (which can fire as soon as the listener is up) has a pool
	 * to register into.  If a pool already exists, reuse it.
	 */
	mtx_lock(&svc_rdma_verbs_lock);
	pool = svc_rdma_test_pool;
	mtx_unlock(&svc_rdma_verbs_lock);
	if (pool == NULL) {
		pool = svcpool_create("nfsrdma_test",
		    SYSCTL_STATIC_CHILDREN(_vfs_nfsrdma_krpc));
		mtx_lock(&svc_rdma_verbs_lock);
		if (svc_rdma_test_pool == NULL) {
			svc_rdma_test_pool = pool;
			oldpool = NULL;
		} else {
			oldpool = pool;		/* lost a race; use existing */
			pool = svc_rdma_test_pool;
		}
		mtx_unlock(&svc_rdma_verbs_lock);
		if (oldpool != NULL)
			svcpool_destroy(oldpool);
	}

	error = svc_rdma_nfsd_listen(pool, newport);
	if (error != 0) {
		/* Start failed: drop the test pool we just created. */
		mtx_lock(&svc_rdma_verbs_lock);
		oldpool = svc_rdma_test_pool;
		svc_rdma_test_pool = NULL;
		mtx_unlock(&svc_rdma_verbs_lock);
		if (oldpool != NULL)
			svcpool_destroy(oldpool);
	}
	return (error);
}
SYSCTL_PROC(_vfs_nfsrdma_krpc, OID_AUTO, listen,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW, NULL, 0,
    sysctl_nfsrdma_krpc_listen, "I",
    "TEMP: nonzero port starts the krpc RDMA listener on a private test pool, "
    "0 stops it; ENXIO if ibcore is not loaded");
