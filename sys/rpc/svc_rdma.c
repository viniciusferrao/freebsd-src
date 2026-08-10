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
 * krpc side of the NFS-over-RDMA server transport, implementing RPC-over-RDMA
 * version 1 (RFC 8166).  It turns each connection the verbs layer accepts into
 * an SVCXPRT, and is the RDMA analogue of svc_vc.c.  The verbs layer drives the
 * Read and Write engines; this file marshals the transport header, captures
 * the chunks the client offered, and hands over-inline replies and
 * DDP-eligible READ data to the engine.
 *
 * This is built into the kernel while the verbs live in nfsrdma, and a
 * built-in cannot link against a module, so the module registers a table of
 * entry points at load.  With nothing registered the listen hook returns ENXIO.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/krpc.h>

#include <rpc/svc_rdma.h>

SYSCTL_DECL(_vfs_nfsd);

/*
 * vfs.nfsd.rdma_listen: the listener port, 0 for none.  The sysctl exists only
 * while the module is loaded, but nfsd keeps the port, so it can bring the
 * listener back on restart.
 */
VNET_DECLARE(SVCPOOL *, nfsrvd_pool);

static int
sysctl_nfsd_rdma_listen(SYSCTL_HANDLER_ARGS)
{
	int error, port;

	port = nfsrvd_rdma_port;
	error = sysctl_handle_int(oidp, &port, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (port < 0 || port > 65535)
		return (EINVAL);

	/*
	 * A configuration knob, not a live control: the port is read when nfsd
	 * starts, so setting it under a running server would not take effect
	 * until the next one.  Refuse rather than appear to have worked.
	 */
	if (port != 0 && newnfs_numnfsd > 0)
		return (ENXIO);

	nfsrvd_rdma_port = port;
	return (0);
}
SYSCTL_PROC(_vfs_nfsd, OID_AUTO, rdma_listen,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW, NULL, 0,
    sysctl_nfsd_rdma_listen, "I",
    "RDMA port for the NFS server, read when nfsd starts; 0 disables RDMA. "
    "ENXIO if nfsd is already running");

/*
 * Publish or withdraw the listen hook nfsd calls, from the module event
 * handler, so nfsd can reach the listener exactly while the module is loaded.
 */
void
svc_rdma_publish_listen(bool publish)
{

	svc_rdma_listen = publish ? svc_rdma_nfsd_listen : NULL;
}

/*
 * True while nfsd has threads running.  The verbs module refuses to unload in
 * that window: the SVCXPRT ops those threads drive live in its text.
 */
bool
svc_rdma_nfsd_running(void)
{

	return (newnfs_numnfsd != 0);
}

/*
 * The verbs layer's receive-buffer size, bounding an inbound call and an
 * outbound backchannel call.  Replies use the smaller ceiling below.
 */
#define	SVC_RDMA_INLINE		4096
/*
 * Version 1 has no inline negotiation and clients post roughly 1 KB recv
 * buffers for replies, so a larger inline reply overflows the client buffer
 * and is NAKed.  Anything bigger goes in the offered reply chunk.
 */
#define	SVC_RDMA_REPLY_INLINE	1024

/*
 * The transport header, big-endian: xid, vers, credit, proc, then the read
 * list, write list and reply chunk, zero when empty.
 */
#define	RPCRDMA_VERSION		1
#define	RPCRDMA_HDR_MIN		28
#define	RDMA_MSG		0	/* rdma_proc: inline RPC message follows */
/*
 * Requested when a reply cannot be placed in the client's chunks.  ERR_VERS
 * belongs to the verbs layer, which owns the version check.
 */
#define	RDMA_ERR_CHUNK		2	/* rdma_err: chunk lists unusable for reply */

/*
 * Fallback credit for a reply's rdma_credit word.  The real value comes from
 * the verbs layer per reply; this is only a non-zero floor for the case where
 * that accessor returns 0.
 */
#define	SVC_RDMA_CREDIT_GRANT	8

MALLOC_DEFINE(M_SVCRDMA, "svcrdma", "NFS over RDMA server SVCXPRT");
/* M_NFSRDMA is defined here (base kernel / krpc) so both svc_rdma.c and the
 * nfsrdma module (svc_verbs.c) share the tag without a KLD→base linker dep. */
MALLOC_DEFINE(M_NFSRDMA, "nfsrdma", "NFS over RDMA server");

/* Forward declarations (definitions follow the consumer ops). */
static void	svc_rdma_conn_set_ctx_wrap(struct svc_rdma_conn *, void *);
static void	*svc_rdma_conn_get_ctx_wrap(struct svc_rdma_conn *);
static int	svc_rdma_krpc_listen_port;	/* last started port; 0 == down */

/* Returns ENXIO until the module registers a verbs provider. */

/*
 * svc_rdma_verbs is the registered nfsrdma table, NULL when the module is not
 * loaded, under the leaf mutex svc_rdma_verbs_lock.  Blocking verbs calls run
 * with it dropped, so svc_rdma_verbs_inflight counts the threads inside them
 * and unregister waits for zero.  Unregister cannot just clear the pointer: it
 * must run the outgoing table's svo_listen_stop(), which drives sro_disconnect
 * back through that same table, so it marks stopping, drains, stops the
 * listener, and clears afterwards.
 */
static struct mtx		 svc_rdma_verbs_lock;
static const struct svc_rdma_verbs_ops *svc_rdma_verbs;
static int			 svc_rdma_verbs_inflight;
static bool			 svc_rdma_verbs_stopping;

MTX_SYSINIT(svc_rdma_verbs_lock, &svc_rdma_verbs_lock, "svcrdma_verbs", MTX_DEF);

/*
 * Hold the verbs table across a call that drops svc_rdma_verbs_lock, so
 * unregister cannot free the module's text under a caller inside the ops.
 * NULL when nothing is registered or unregister is stopping; the caller must
 * then neither dereference the table nor unhold.
 */
static const struct svc_rdma_verbs_ops *
svc_rdma_verbs_hold(void)
{
	const struct svc_rdma_verbs_ops *ops;

	mtx_lock(&svc_rdma_verbs_lock);
	ops = svc_rdma_verbs;
	if (ops == NULL || svc_rdma_verbs_stopping) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return (NULL);
	}
	svc_rdma_verbs_inflight++;
	mtx_unlock(&svc_rdma_verbs_lock);
	return (ops);
}

static void
svc_rdma_verbs_unhold(void)
{
	mtx_lock(&svc_rdma_verbs_lock);
	if (--svc_rdma_verbs_inflight == 0)
		wakeup(&svc_rdma_verbs_inflight);
	mtx_unlock(&svc_rdma_verbs_lock);
}

/* Rate limiter for peer-driven (remotely-triggerable) log lines. */
static struct timeval		 svc_rdma_log_last;
static int			 svc_rdma_log_pps;

/*
 * Source of per-connection xp_sockref values.  The use site adds one, so the
 * first is non-zero: 0 is the no-socket sentinel the DRC must not alias.
 */
static volatile uint64_t	 svc_rdma_sockref_gen;

/*
 * svc_rdma_listener is the consumer ctx handed to svo_listen_start() and back
 * to every upcall, carrying the SVCPOOL accepted connections register into.
 * svc_rdma_xprt is the per-connection state hung off xp_p1; its xr_lock is a
 * leaf mutex over xr_mq and xr_conn, never held across a krpc call that can
 * take a pool or group lock, xprt_active() included.  sro_disconnect clears
 * xr_conn under it, so a pool thread reaching xp_reply afterwards cannot post
 * on a freed connection.
 */
struct svc_rdma_listener {
	SVCPOOL		*sl_pool;	/* pool accepted conns register into */
};

struct svc_rdma_qent {
	STAILQ_ENTRY(svc_rdma_qent) sq_link;
	struct mbuf	*sq_m;		/* one complete inline ONC RPC message */
	/*
	 * The offered reply chunk, a value type with no pointers, so it
	 * outlives the recv buffer's repost.  sq_has_reply distinguishes none
	 * offered from a zeroed one.
	 */
	bool		sq_has_reply;
	uint32_t	sq_xid;
	struct svc_rdma_write_chunk sq_reply;
	/*
	 * The first offered write chunk, for a READ taking its data by DDP;
	 * RFC 8267 maps the single DDP-eligible result to one chunk.
	 */
	bool		sq_has_writes;
	struct svc_rdma_write_chunk sq_writes;
	uint32_t	sq_nwrites;	/* offered write-list chunk count */
};
STAILQ_HEAD(svc_rdma_qhead, svc_rdma_qent);

/*
 * A captured chunk must survive from xp_recv to xp_reply with only the xid
 * linking them, so this fixed table under xr_lock holds it.  Sized at or above
 * the verbs recv depth, so requests cannot outrun it; a missing entry just
 * means no chunk for that reply.
 */
#define	SVC_RDMA_REPLY_PEND	64
struct svc_rdma_reply_pend {
	bool		rp_valid;
	uint32_t	rp_xid;
	struct svc_rdma_write_chunk rp_reply;
	/*
	 * The chunk is filled in xp_recv and the read-data boundary later from
	 * xp_control on the same thread, then both are consumed by xp_reply.
	 * rp_has_reply is separate so an entry can exist for a write-list-only
	 * READ.  All under xr_lock.
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
 * Insert a captured chunk keyed by xid, reusing a slot already holding that
 * xid so a retransmit's re-offered chunk wins.  A full table drops it and
 * xp_reply falls back to inline-or-drop.  Under xr_lock.
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
		 * The boundary is filled later by svc_rdma_readddp_set(), so
		 * start it cleared: a request with no READ-DDP op must not
		 * carry a stale one into xp_reply.
		 */
		p->rp_has_ddp = false;
		p->rp_ddp_off = 0;
		p->rp_ddp_len = 0;
	}
	mtx_unlock(&xr->xr_lock);
	if (free_slot < 0 &&
	    ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("svc_rdma: reply-pend table full (xid=0x%08x): "
		    "reply chunk dropped, client may stall\n", xid);
}

/*
 * Record the DDP boundary from SVCSET_READDDP into this xid's entry, between
 * xp_recv and xp_reply on the request's pool thread.  Only the first READ for
 * an xid takes it, RFC 8267 reducing one result.  Under xr_lock.
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

/* Look up and remove the pending chunk for xid.  Under xr_lock. */
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
 * xp_recv: take one queued message and decode its call header, mirroring the
 * tail of svc_vc_recv.  Draining the last one calls xprt_inactive_self(), so
 * the pool stops scheduling this transport until a completion reactivates it.
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
		 * Mark inactive while still holding xr_lock: a message arriving
		 * after we sampled empty takes the same lock to enqueue and
		 * calls xprt_active() behind us, so it is not stranded.
		 */
		if (q == NULL || empty)
			xprt_inactive_self(xprt);
		mtx_unlock(&xr->xr_lock);

		if (q == NULL)
			return (FALSE);

		m = q->sq_m;

		/*
		 * Record any offered chunk in the pending table before the
		 * queue entry is freed, so xp_reply can find it by xid.  A
		 * full table just means this reply goes inline or is dropped.
		 */
		if (q->sq_has_reply || q->sq_has_writes)
			svc_rdma_reply_pend_insert(xr, q->sq_xid,
			    q->sq_has_reply, &q->sq_reply,
			    q->sq_has_writes, &q->sq_writes, q->sq_nwrites);
		free(q, M_SVCRDMA);

		/*
		 * xdr_callmsg() is the standard decoder and returns FALSE on a
		 * short or malformed body, which drops the message; peer bytes
		 * are never hand-parsed here.
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
		 * svc_getrpccaller() falls back to xp_rtaddr when rq_addr is
		 * NULL, so NULL is correct here, as it is in svc_vc_recv for a
		 * connected transport.
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
 * xp_ack: the reply high-water mark for the duplicate-request cache.  There is
 * no krpc-visible send completion, so posted counts as sent, the same
 * confidence svc_vc takes from a successful sosend().
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
 * xp_reply: marshal a reply and post it, inline when it fits or RDMA-Written
 * into the chunk captured during sro_recv and looked up here by xid.
 * Over-inline with no usable chunk, or past the offered capacity, is answered
 * with ERR_CHUNK and a FALSE return; the connection stays up.
 */

/*
 * Bound on zero-copy READ source pages: SVC_RDMA_MAX_WRITE (1 MiB) / PAGE_SIZE,
 * matching SVC_RDMA_MAX_WRITE_PAGES in svc_verbs.c (the engine re-checks it).
 */
#define	SVC_RDMA_RD_MAXPGS	((1U << 20) / PAGE_SIZE)

/*
 * Collect the M_EXTPG pages for the read span so the engine can write them
 * without a copy.  Requires doff on an mbuf boundary and every mbuf
 * page-aligned with no header or trailer; anything else returns 0 for the
 * copy path.
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
		return (0);

	npd = 0;
	need = dlen;
	while (need > 0) {
		int pg;

		if (m == NULL || (m->m_flags & M_EXTPG) == 0 ||
		    m->m_epg_hdrlen != 0 || m->m_epg_trllen != 0 ||
		    m->m_epg_1st_off != 0)
			return (0);
		for (pg = 0; pg < m->m_epg_npgs && need > 0; pg++) {
			u_int plen = m_epg_pagelen(m, pg, 0);

			/* trim the final (padded) page to dlen */
			plen = MIN(plen, need);
			if (npd >= maxpd)
				return (0);
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

static bool_t svc_rdma_do_reply(SVCXPRT *, struct rpc_msg *,
    struct sockaddr *, struct mbuf *, uint32_t *,
    const struct svc_rdma_verbs_ops *);

static bool_t
svc_rdma_xprt_reply(SVCXPRT *xprt, struct rpc_msg *msg,
    struct sockaddr *addr, struct mbuf *m, uint32_t *seq)
{
	const struct svc_rdma_verbs_ops *vops;
	bool_t stat;

	/*
	 * Hold the verbs table across the whole reply, which calls through it
	 * with xr_lock dropped, so an unload cannot free that text mid-reply.
	 */
	vops = svc_rdma_verbs_hold();
	stat = svc_rdma_do_reply(xprt, msg, addr, m, seq, vops);
	if (vops != NULL)
		svc_rdma_verbs_unhold();
	return (stat);
}

static bool_t
svc_rdma_do_reply(SVCXPRT *xprt, struct rpc_msg *msg,
    struct sockaddr *addr, struct mbuf *m, uint32_t *seq,
    const struct svc_rdma_verbs_ops *vops)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	struct svc_rdma_conn *conn;
	struct svc_rdma_reply_pend pend;
	struct mbuf *mrep;
	char *buf;
	XDR xdrs;
	uint32_t seqval = 0;
	u_int rlen, total;
	u_int nfsreply_len = 0;
	int rc;
	bool_t stat = TRUE;
	bool have_pend;

	/*
	 * Pre-allocate this thread's linuxkpi current shadow off-lock: the
	 * first post on a fresh thread would otherwise allocate it under
	 * xr_lock.  Optional, so NULL on an older module.
	 */
	if (vops != NULL && vops->svo_thread_setup != NULL)
		vops->svo_thread_setup();

	/*
	 * Build the reply into a fresh pkthdr mbuf as svc_vc_reply does, with
	 * no record mark: the transport header is prepended after marshalling.
	 */
	mrep = m_gethdr(M_WAITOK, MT_DATA);
	xdrmbuf_create(&xdrs, mrep, XDR_ENCODE);

	if (msg->rm_reply.rp_stat == MSG_ACCEPTED &&
	    msg->rm_reply.rp_acpt.ar_stat == SUCCESS) {
		if (!xdr_replymsg(&xdrs, msg)) {
			stat = FALSE;
		} else {
			/*
			 * Take the body length before the chain consumes it:
			 * xdr_putmbuf() tail-links it as is, so the header is
			 * rlen - nfsreply_len and the read data sits at that
			 * plus the offset nfsd recorded.
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
	 * On the error path xdr_replymsg() encodes only the header and the body
	 * is not part of the reply, so free it; on success it is already NULL.
	 */
	if (m != NULL) {
		m_freem(m);
		m = NULL;
	}

	rlen = mrep->m_pkthdr.len;
	total = RPCRDMA_HDR_MIN + rlen;

	/*
	 * Take this xid's pending chunk unconditionally, so the slot is always
	 * reclaimed, and use it only on the over-inline path below.  Replying
	 * inline and dropping a taken chunk is permitted.
	 */
	have_pend = svc_rdma_reply_pend_take(xr, msg->rm_xid, &pend);

	/*
	 * Header plus reply must fit one send buffer.  A larger reply is
	 * written into the offered reply chunk with an RDMA_NOMSG header
	 * reporting the length; with no chunk, or one too small, the answer is
	 * ERR_CHUNK rather than an overflowed send buffer.
	 */
	if (total > SVC_RDMA_REPLY_INLINE) {
		/*
		 * A compound offering more than one write chunk cannot be
		 * reduced: the engine maps a single DDP result to one chunk
		 * (RFC 8267) and echoes a one-chunk write list, so ERR_CHUNK by
		 * xid is conformant where a single-chunk reply would not be.
		 * Inline replies leave every chunk empty and are unaffected.
		 */
		if (have_pend && pend.rp_has_writes && pend.rp_nwrites > 1) {
			m_freem(mrep);
			mtx_lock(&xr->xr_lock);
			conn = xr->xr_conn;
			if (conn != NULL && vops != NULL &&
			    vops->svo_conn_error != NULL)
				(void)vops->svo_conn_error(conn,
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
		 * An over-inline READ whose data is DDP-eligible: the data goes
		 * into the offered write chunk and a reduced RDMA_MSG is sent.
		 * The data was XDR round-up padded, so the reduced body excises
		 * the padded span while the chunk receives exactly the unpadded
		 * length (RFC 8166 3.4.5).
		 */
		if (have_pend && pend.rp_has_writes && pend.rp_nwrites == 1 &&
		    pend.rp_has_ddp && pend.rp_ddp_len > 0 && vops != NULL &&
		    vops->svo_conn_write_list != NULL) {
			u_int hdrbytes = rlen - nfsreply_len;
			u_int doff = hdrbytes + pend.rp_ddp_off;
			u_int dlen = pend.rp_ddp_len;
			u_int padded = roundup2(dlen, 4);
			u_int reducedlen;
			char *reduced;
			void *src;
			bool src_pooled;
			struct svc_rdma_page *pgs;
			int npg;

			if (nfsreply_len <= rlen && padded <= rlen &&
			    doff <= rlen - padded) {
				/*
				 * The reduced body is head [0,doff) followed by
				 * tail [doff+padded,rlen), excising the read
				 * data and its XDR pad.  Built off xr_lock.
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
				 * With the page entry point and a clean M_EXTPG
				 * chain, write those pages directly, with no
				 * allocation and no copy; a 0 from
				 * svc_rdma_collect_extpg() means the copy path.
				 * pgs is heap to keep it off the stack.
				 */
				pgs = malloc(SVC_RDMA_RD_MAXPGS * sizeof(*pgs),
				    M_SVCRDMA, M_WAITOK);
				npg = (vops->svo_conn_write_list_pages !=
				    NULL) ? svc_rdma_collect_extpg(mrep, doff, dlen,
				    pgs, SVC_RDMA_RD_MAXPGS) : 0;
				if (npg == 0) {
					/*
					 * Otherwise copy the unpadded data into
					 * a contiguous source off the lock,
					 * which the engine owns.  The recycle
					 * pool is preferred, since allocating
					 * per operation costs a shootdown.
					 */
					src = NULL;
					if (vops->svo_sink_get != NULL) {
						src = vops->svo_sink_get();
						src_pooled = true;
					}
					/* sink_get may fail; use WAITOK */
					if (src == NULL) {
						src = contigmalloc(dlen, M_NFSRDMA,
						    M_WAITOK, 0, ~(vm_paddr_t)0,
						    PAGE_SIZE, 0);
						src_pooled = false;
					}
					if (src == NULL) {
						/* contig WAITOK can fail */
						free(pgs, M_SVCRDMA);
						free(reduced, M_SVCRDMA);
						m_freem(mrep);
						return (FALSE);
					}
					m_copydata(mrep, doff, dlen, src);
				} else
					src = NULL;

				mtx_lock(&xr->xr_lock);
				conn = xr->xr_conn;
				if (conn == NULL) {
					rc = ENOTCONN;
					if (npg == 0) {
						if (src_pooled)
							vops->svo_sink_put(src);
						else
							free(src, M_NFSRDMA);
					}
				} else if (npg > 0) {
					rc = vops->svo_conn_write_list_pages(
					    conn, msg->rm_xid, &pend.rp_writes, mrep,
					    pgs, npg, dlen, reduced, reducedlen);
					/*
					 * The engine owns mrep on every return,
					 * so the reference is dropped here and
					 * it is never freed below.
					 */
					mrep = NULL;
					if (rc == 0)
						seqval = ++xr->xr_seq;
				} else {
					rc = vops->svo_conn_write_list(
					    conn, msg->rm_xid, &pend.rp_writes,
					    src, dlen, reduced, reducedlen,
					    src_pooled);
					if (rc == 0)
						seqval = ++xr->xr_seq;
				}
				mtx_unlock(&xr->xr_lock);

				free(pgs, M_SVCRDMA);
				free(reduced, M_SVCRDMA);
				if (mrep != NULL)
					m_freem(mrep);

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
			 * An out-of-range boundary falls through below, and
			 * since a READ never offers a reply chunk it lands on
			 * ERR_CHUNK rather than a reply-chunk send.
			 */
		}
		if (have_pend && pend.rp_has_reply) {
			/*
			 * Linearize the reply on its own; the verbs layer
			 * builds the RDMA_NOMSG header.  Post under xr_lock to
			 * observe a stable xr_conn, as the inline path does.
			 */
			buf = malloc(rlen, M_SVCRDMA, M_WAITOK);
			m_copydata(mrep, 0, rlen, buf);
			m_freem(mrep);

			mtx_lock(&xr->xr_lock);
			conn = xr->xr_conn;
			if (conn != NULL && vops != NULL &&
			    vops->svo_conn_reply_chunk != NULL) {
				rc = vops->svo_conn_reply_chunk(conn,
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
		 * Over-inline with no usable chunk, either none offered or a
		 * write-list boundary out of range.  ERR_CHUNK by xid lets the
		 * client retry instead of dropping silently, posted under
		 * xr_lock for a stable xr_conn and only when the optional op
		 * exists.  The return is still FALSE, no inline reply having
		 * been sent.
		 */
		mtx_lock(&xr->xr_lock);
		conn = xr->xr_conn;
		if (conn != NULL && vops != NULL &&
		    vops->svo_conn_error != NULL)
			(void)vops->svo_conn_error(conn, msg->rm_xid,
			    RDMA_ERR_CHUNK);
		mtx_unlock(&xr->xr_lock);
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("svc_rdma: over-inline reply (%u > %u) with no reply "
			    "chunk, replying ERR_CHUNK (xid=0x%08x)\n", total,
			    SVC_RDMA_REPLY_INLINE, msg->rm_xid);
		return (FALSE);
	}

	/*
	 * Linearize the header and reply into one buffer.  Every header word is
	 * local except the echoed xid, and the credit is filled inside the lock
	 * below, once there is a live connection to read it from.
	 */
	buf = malloc(total, M_SVCRDMA, M_WAITOK);
	be32enc(buf + 0, msg->rm_xid);
	be32enc(buf + 4, RPCRDMA_VERSION);
	be32enc(buf + 8, SVC_RDMA_CREDIT_GRANT);
	be32enc(buf + 12, RDMA_MSG);
	be32enc(buf + 16, 0);
	be32enc(buf + 20, 0);
	be32enc(buf + 24, 0);
	m_copydata(mrep, 0, rlen, buf + RPCRDMA_HDR_MIN);
	m_freem(mrep);

	/*
	 * Post under xr_lock to observe a stable xr_conn: sro_disconnect NULLs
	 * it under the same lock after draining every sro_recv, so either the
	 * conn is live for the whole of the non-sleeping send or it is NULL and
	 * this drops.  The granted credit is read from the same live conn.
	 */
	mtx_lock(&xr->xr_lock);
	conn = xr->xr_conn;
	if (conn != NULL && vops != NULL) {
		uint32_t credit = vops->svo_conn_credits(conn);

		if (credit == 0)
			credit = SVC_RDMA_CREDIT_GRANT;
		be32enc(buf + 8, credit);
		rc = vops->svo_conn_send(conn, buf, total);
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
 * Send one NFSv4.1 backchannel call over the established QP, in the reverse
 * direction of the forward stream.  mreq is the marshalled call, whose first
 * XDR word is the already network-order xid, and it is consumed here.  This is
 * the forward reply's inline send path with a call body instead, posting under
 * xr_lock against a stable xr_conn; the order xr_lock before sc_lock is the
 * forward-reply order and ct_lock is not held, so nothing new is introduced.
 */
static int svc_rdma_do_bck_send(SVCXPRT *, struct mbuf *,
    const struct svc_rdma_verbs_ops *);

static int
svc_rdma_bck_send(SVCXPRT *xprt, struct mbuf *mreq)
{
	const struct svc_rdma_verbs_ops *vops;
	int rc;

	/*
	 * Hold the verbs table across the backchannel send, which calls through
	 * it with xr_lock dropped, so a concurrent unload cannot free that text
	 * mid-call on the modular build.
	 */
	vops = svc_rdma_verbs_hold();
	rc = svc_rdma_do_bck_send(xprt, mreq, vops);
	if (vops != NULL)
		svc_rdma_verbs_unhold();
	return (rc);
}

static int
svc_rdma_do_bck_send(SVCXPRT *xprt, struct mbuf *mreq,
    const struct svc_rdma_verbs_ops *vops)
{
	struct svc_rdma_xprt *xr = (struct svc_rdma_xprt *)xprt->xp_p1;
	struct svc_rdma_conn *conn;
	uint32_t netxid;
	char *buf;
	u_int rlen, total;
	int rc;

	/* Pre-warm the linuxkpi current shadow off-lock before the post. */
	if (vops != NULL && vops->svo_thread_setup != NULL)
		vops->svo_thread_setup();

	rlen = m_length(mreq, NULL);
	total = RPCRDMA_HDR_MIN + rlen;
	if (total > SVC_RDMA_INLINE) {
		m_freem(mreq);
		return (EINVAL);
	}

	/* The ONC xid is word0 of mreq, already in network byte order. */
	m_copydata(mreq, 0, sizeof(netxid), (caddr_t)&netxid);
	buf = malloc(total, M_SVCRDMA, M_WAITOK);
	be32enc(buf + 0, ntohl(netxid));
	be32enc(buf + 4, RPCRDMA_VERSION);
	be32enc(buf + 8, SVC_RDMA_CREDIT_GRANT);
	be32enc(buf + 12, RDMA_MSG);
	be32enc(buf + 16, 0);
	be32enc(buf + 20, 0);
	be32enc(buf + 24, 0);
	m_copydata(mreq, 0, rlen, buf + RPCRDMA_HDR_MIN);
	m_freem(mreq);

	mtx_lock(&xr->xr_lock);
	conn = xr->xr_conn;
	if (conn != NULL && vops != NULL) {
		uint32_t credit = vops->svo_conn_credits(conn);

		if (credit == 0)
			credit = SVC_RDMA_CREDIT_GRANT;
		be32enc(buf + 8, credit);
		rc = vops->svo_conn_send(conn, buf, total);
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
		 * The READ path has located the DDP-eligible data in the reply
		 * body, so stamp the boundary onto this xid's entry for
		 * xp_reply.  With no write list there is no entry and this is a
		 * no-op.
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
 * xp_destroy: the last reference is gone, so free the queue and the
 * per-connection state.  The verbs connection is torn down separately after
 * sro_disconnect returned, so xr_conn must not be touched here.
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
	 * Release the backchannel client bound at CREATE_SESSION, as
	 * svc_vc_destroy does.  This runs on the last release, after the recv
	 * completions drained and sro_disconnect closed it.  The session's own
	 * transport reference is a separate refcount.
	 */
	if (xprt->xp_p2 != NULL) {
		CLNT_RELEASE((CLIENT *)xprt->xp_p2);
		xprt->xp_p2 = NULL;
	}
	sx_destroy(&xprt->xp_lock);
	svc_xprt_free(xprt);
}

/*
 * Consumer upcalls driven by the verbs layer.
 */

/*
 * sro_newconn: allocate and register the SVCXPRT and bind it to the
 * connection, as svc_vc_create_conn does.  Sleepable and guaranteed before any
 * recv upcall.
 *
 * svc_reg() is deliberately not called per connection: it attaches the
 * dispatch callouts to the pool, not the transport, and nfsd populated those
 * when its first transport came up.
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
	 * nfsd may build M_EXTPG READ replies for this transport; the verbs
	 * engine RDMA-Writes those data pages directly.
	 */
	xprt->xp_extpg = true;
	/*
	 * xp_idletimeout stays 0, so the reaper skips this transport: it calls
	 * soshutdown() unconditionally on a timed-out one, and there is no
	 * socket here.  Connection lifetime comes from the CM instead.
	 */

	/*
	 * xp_sockref keys the duplicate-request cache per transport.  Zero
	 * would alias the no-socket sentinel and collide across connections, so
	 * it comes from a monotonic counter; a wrap at worst shares a bucket.
	 *
	 * xp_rtaddr carries the CM-resolved client sockaddr, so export address
	 * checks match -network/-host as they do for a TCP peer.  Without one
	 * it stays AF_UNSPEC and only unrestricted exports match.
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
	 * Drop the allocation reference so the pool holds the only one and the
	 * transport is destroyed on the last release, as svc_vc does.  It must
	 * come after the connection is bound: until then that reference is what
	 * stops a pool thread destroying the transport mid-setup, and xprt must
	 * not be touched afterwards.
	 */
	SVC_RELEASE(xprt);
}

/*
 * sro_recv: an inline call completed.  The analogue of svc_vc_soupcall, with
 * the completion as the data-ready signal.  Runs in the recv completion and
 * must not sleep, so m_getm2() pre-sizes the chain with M_NOWAIT and a failed
 * allocation drops the call for the client to retransmit.  rpc_len was
 * bounded by the verbs layer, so the chain is never sized from a peer length.
 */
static int
svc_rdma_sro_recv(void *ctx, struct svc_rdma_conn *conn,
    const struct svc_rdma_msg *msg)
{
	SVCXPRT *xprt = svc_rdma_conn_get_ctx_wrap(conn);
	struct svc_rdma_xprt *xr;
	struct svc_rdma_qent *q;
	struct mbuf *m;

	if (xprt == NULL)
		return (0);
	xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	if (msg->rpc_len == 0)
		return (0);

	/*
	 * Forward calls and callback replies share the recv ring and the
	 * transport header carries no direction, so it comes from the inner ONC
	 * header at word1.  A reply goes to clnt_bck_svccall(); this runs on
	 * the completion workqueue, independent of the pool thread waiting in
	 * clnt_bck_call, so the wakeup always has a runnable context.  The
	 * bytes are copied now with M_NOWAIT, since msg->rpc points into the
	 * recv buffer and this cannot sleep.
	 */
	if (msg->rpc_len >= 8 && xprt->xp_p2 != NULL &&
	    be32dec((const char *)msg->rpc + 4) == REPLY) {
		struct mbuf *rm;

		rm = m_getm2(NULL, msg->rpc_len, M_NOWAIT, MT_DATA, M_PKTHDR);
		if (rm == NULL)
			return (0);
		m_copyback(rm, 0, msg->rpc_len, msg->rpc);
		rm->m_pkthdr.len = msg->rpc_len;
		clnt_bck_svccall(xprt->xp_p2, rm,
		    be32dec((const char *)msg->rpc));
		return (0);
	}

	q = malloc(sizeof(*q), M_SVCRDMA, M_NOWAIT);
	if (q == NULL)
		return (0);	/* drop; client retransmits */

	m = m_getm2(NULL, msg->rpc_len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		free(q, M_SVCRDMA);
		return (0);
	}
	m_copyback(m, 0, msg->rpc_len, msg->rpc);
	m->m_pkthdr.len = msg->rpc_len;
	q->sq_m = m;

	/*
	 * Capture any offered reply chunk, for a reply too large to go inline.
	 * msg->reply is a value type with no pointers, so the copy outlives msg
	 * itself, keyed on the xid for xp_reply.
	 */
	q->sq_has_reply = msg->reply_present;
	/*
	 * Capture the first write-list chunk too, a READ offering a write list
	 * rather than a reply chunk.  RFC 8267 maps one DDP result to one
	 * chunk, so only writes[0] is carried, but the offered count comes with
	 * it: xp_reply needs that to tell a single-chunk READ from a compound
	 * with several, which it answers with ERR_CHUNK.
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
	 * Wake a pool thread with xr_lock dropped: xprt_active() takes the
	 * group lock internally, and our leaf mutex must not couple to it.
	 */
	xprt_active(xprt);
	return (0);
}

/*
 * sro_recv_mbuf: the assembled-body form of sro_recv, same context and
 * no-sleep rule.  m is head fragments bracketing one EXT_DISPOSABLE segment
 * over the read sink, so it is queued without copying.  Ownership transfers on
 * a 0 return; a drop frees it here, running the ext_free that releases the
 * sink.
 */
static int
svc_rdma_sro_recv_mbuf(void *ctx, struct svc_rdma_conn *conn, struct mbuf *m,
    uint32_t xid, bool has_reply, const struct svc_rdma_write_chunk *reply)
{
	SVCXPRT *xprt = svc_rdma_conn_get_ctx_wrap(conn);
	struct svc_rdma_xprt *xr;
	struct svc_rdma_qent *q;

	if (xprt == NULL) {
		m_freem(m);
		return (0);
	}
	xr = (struct svc_rdma_xprt *)xprt->xp_p1;

	if (m->m_pkthdr.len == 0) {
		m_freem(m);
		return (0);
	}

	q = malloc(sizeof(*q), M_SVCRDMA, M_NOWAIT);
	if (q == NULL) {
		m_freem(m);
		return (0);
	}
	q->sq_m = m;		/* ownership passes to the queue */

	/*
	 * Capture the reply chunk if the client offered one (same rationale as
	 * sro_recv: msg->reply is a pure value type, safe to copy by value).
	 */
	q->sq_has_reply = has_reply;
	/*
	 * This path consumed an inbound read list and has no outbound write
	 * list to carry.  q is not zeroed on allocation, so clear it here.
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

	xprt_active(xprt);
	return (0);
}

/*
 * sro_disconnect: the connection is going away.  Sleepable, delivered once and
 * paired with newconn, after every recv upcall has returned.
 *
 * Refcounting follows svc_vc: xprt_unregister() drops the pool's reference
 * while a pool thread still in xp_recv holds its own, so xp_destroy runs only
 * once that thread releases.  xr_conn is cleared under xr_lock first, so a
 * thread reaching xp_reply afterwards drops the reply.
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
	 * Stop any later xp_reply touching the connection, and mark the
	 * transport dead so xp_stat reports XPRT_DIED once the queue drains.
	 */
	mtx_lock(&xr->xr_lock);
	xr->xr_conn = NULL;
	xr->xr_died = true;
	mtx_unlock(&xr->xr_lock);

	/*
	 * Quiesce the backchannel client after xr_conn is NULL, so an in-flight
	 * send drops with ENOTCONN and a late reply is freed rather than
	 * matched against state about to go away.  xp_p2 is not released here;
	 * xp_destroy holds the single release.  The close may sleep.
	 */
	if (xprt->xp_p2 != NULL)
		CLNT_CLOSE((CLIENT *)xprt->xp_p2);

	/* Detach our back-pointer; conn is freed by the verbs layer after we
	 * return, and must not be dereferenced again. */
	svc_rdma_conn_set_ctx_wrap(conn, NULL);

	/*
	 * Drop the pool's reference.  xprt_unregister() is a no-op if a pool
	 * thread already unregistered, and balances the xprt_register()
	 * acquire.  xp_socket is NULL, so its soshutdown() is skipped.
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
 * Wrappers over the registered table, so the upcalls above read like direct
 * calls.  The table is live for their whole window: newconn and recv come only
 * from a running listener, and sro_disconnect from one or from unregister,
 * which runs svo_listen_stop() before clearing.  The assertions are a net.
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
 * Cross-module verbs ops registration, called from the nfsrdma module at load
 * and unload.  Owner-keyed, and unregister runs svo_listen_stop() with the
 * table still valid.
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
	 * Arm the backchannel send hook under this lock, so a callback goes
	 * over RDMA only while the table is live.  clnt_bck_call reaches the
	 * send only through this pointer, so the always-compiled krpc never
	 * names an OFED symbol.
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

	/* Only the registration owning the global may revoke it. */
	if (ops == NULL || svc_rdma_verbs != ops) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return;
	}

	/*
	 * svo_listen_stop() must run while the table is valid: it delivers
	 * sro_disconnect for every live connection and those upcalls resolve
	 * through the table, so clearing it first would leave them on NULL.
	 * Mark stopping, drain the callers already inside, stop the listener,
	 * then clear.  The wait may sleep, which unload allows.
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
	 * Disarm the backchannel hook with the table.  The stop above delivered
	 * sro_disconnect for every connection, so nothing is mid-send, a later
	 * send falls back to ENOTCONN, and no pointer into this module is left.
	 */
	clnt_bck_rdma_send = NULL;
	svc_rdma_verbs_stopping = false;
	mtx_unlock(&svc_rdma_verbs_lock);

	printf("svc_rdma(krpc): ibcore verbs unregistered\n");
}

/*
 * The hook nfsd calls to start and stop the listener bound to its pool.  A
 * non-zero port starts, 0 stops.  There is one global listener, so one static
 * ctx suffices; it is published before the start and only read by the upcalls.
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
	 * Snapshot the table and arm the in-flight count under the lock, then
	 * make the blocking call with it dropped.  Arming is refused while
	 * unregister is stopping the table, which returns ENXIO.
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


