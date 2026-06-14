/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
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

#include <rdma/svc_rdma.h>	/* the shared cross-module contract */

/*
 * SVC_RDMA_INLINE matches the verbs layer's receive-buffer size
 * (svc_verbs.c SVC_RDMA_INLINE == 4096).  It is the hard ceiling on an inline
 * reply: anything larger needs RDMA Write chunks (TASK_003f) and is dropped
 * here.  It is a fixed local constant, never peer-derived.
 */
#define	SVC_RDMA_INLINE		4096

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
 * Fallback flow-control credit for a reply's w2 rdma_credit (SF1).  The primary
 * value is the verbs layer's REAL granted depth, read per-reply through
 * svo_conn_credits() (== conn->sc_nrecv, clamped to the device QP recv cap); see
 * svc_rdma_xprt_reply().  This constant is used only as a defensive non-zero
 * floor if the accessor ever returns 0 (it should not).  It matches the verbs
 * layer's nominal SVC_RDMA_RECV_DEPTH (8).
 */
#define	SVC_RDMA_CREDIT_GRANT	8

MALLOC_DEFINE(M_SVCRDMA, "svcrdma", "NFS over RDMA server SVCXPRT");

/* Forward declarations (definitions follow the consumer ops). */
static void	svc_rdma_conn_set_ctx_wrap(struct svc_rdma_conn *, void *);
static void	*svc_rdma_conn_get_ctx_wrap(struct svc_rdma_conn *);
static int	svc_rdma_krpc_listen_port;	/* last started port; 0 == down */

/*
 * The nfsd-pool listen hook, exported as a built-in kernel symbol and called
 * from nfsd (sys/fs/nfsserver/nfs_nfsdkrpc.c, guarded by options OFED).  A
 * prototype here both satisfies -Wmissing-prototypes for the non-static
 * definition and documents the contract that nfsd's matching extern relies on.
 */
int	svc_rdma_nfsd_listen(SVCPOOL *pool, int port);

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
};
STAILQ_HEAD(svc_rdma_qhead, svc_rdma_qent);

struct svc_rdma_xprt {
	struct svc_rdma_conn	*xr_conn;	/* verbs conn (NULL after disc.) */
	struct mtx		 xr_lock;	/* guards xr_mq + xr_conn + xr_seq */
	struct svc_rdma_qhead	 xr_mq;		/* queued recv messages */
	uint32_t		 xr_seq;	/* monotonic posted-reply counter */
	bool			 xr_died;	/* connection gone */
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
 * xp_reply: marshal an inline RPC-over-RDMA v1 reply and post it.
 *
 * The ONC RPC reply (header + body) is built into an mbuf chain exactly as
 * svc_vc_reply does: xdr_replymsg() encodes the reply header, and on the
 * accepted/success path the caller's body mbuf m is appended via xdr_putmbuf().
 * Instead of a TCP record marker we then PREPEND the 28-byte RFC 8166 transport
 * header (RDMA_MSG, all chunk lists empty), linearize the whole chain into one
 * contiguous local buffer, and hand it to svc_rdma_conn_send() (which copies it
 * into the connection's DMA send buffer and posts the SEND WR).
 *
 * INLINE ONLY: if the marshalled reply exceeds SVC_RDMA_INLINE it needs RDMA
 * Write chunks (TASK_003f); we drop-with-log and return FALSE rather than
 * overflow the bounded send buffer.  A drop is not fatal -- the client's RC
 * retransmit / a later op proceeds; the recv side is unaffected.
 */
static bool_t
svc_rdma_xprt_reply(SVCXPRT *xprt, struct rpc_msg *msg,
    struct sockaddr *addr, struct mbuf *m, uint32_t *seq)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	struct svc_rdma_conn *conn;
	struct mbuf *mrep;
	char *buf;
	XDR xdrs;
	uint32_t hdr[7];
	uint32_t seqval = 0;
	u_int rlen, total;
	int rc;
	bool_t stat = TRUE;

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
	 * INLINE bound.  RPCRDMA_HDR_MIN + reply must fit one inline send
	 * buffer.  Larger replies (big READDIR/READLINK/READ) require RDMA Write
	 * chunks -- TASK_003f.  Drop-with-log; never overflow the send buffer.
	 */
	if (total > SVC_RDMA_INLINE) {
		m_freem(mrep);
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("svc_rdma: inline reply too large (%u > %u), "
			    "dropping (xid=0x%08x); needs RDMA Write chunks "
			    "(TASK_003f)\n", total, SVC_RDMA_INLINE,
			    msg->rm_xid);
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

static bool_t
svc_rdma_xprt_control(SVCXPRT *xprt, const u_int rq, void *in)
{

	return (FALSE);
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
	 * Known boundary for inline NFS-over-RDMA: xp_rtaddr is left zeroed
	 * (AF_UNSPEC) -- the verbs layer does not yet surface the peer sockaddr
	 * through the consumer header, so svc_getrpccaller() returns an unspec
	 * address and NFS export-address checks that need the real client address
	 * are a follow-on.  Inline bring-up (NULL/GETATTR/LOOKUP) does not depend
	 * on it.  The DRC itself is keyed on xp_sockref (above), not on the peer
	 * address, so it is unaffected.
	 */
	xprt->xp_sockref = atomic_fetchadd_64(&svc_rdma_sockref_gen, 1) + 1;

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
	    ops->svo_conn_set_ctx == NULL || ops->svo_conn_get_ctx == NULL ||
	    ops->svo_conn_credits == NULL)
		return (EINVAL);

	mtx_lock(&svc_rdma_verbs_lock);
	if (svc_rdma_verbs != NULL) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return (EBUSY);
	}
	svc_rdma_verbs = ops;
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
