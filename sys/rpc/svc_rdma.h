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
 * Consumer interface to the NFS-over-RDMA server verbs layer, which lives in
 * the nfsrdma module and knows nothing of krpc.  A kernel built-in cannot
 * link against a module, so the module registers the table below at load and
 * krpc calls through the function pointers.
 */

#ifndef _RDMA_SVC_RDMA_H
#define _RDMA_SVC_RDMA_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/malloc.h>

/* The engine frees the write-list source buffer, so allocate it with this. */
MALLOC_DECLARE(M_NFSRDMA);

struct mbuf;

/*
 * One page of an M_EXTPG READ reply, written without a copy.  pg_pa is
 * physical: the engine maps PHYS_TO_DMAP(pg_pa) + pg_off, never a vm_page_t,
 * since some EXTPG pages are unmanaged.
 */
struct svc_rdma_page {
	vm_paddr_t	pg_pa;
	uint32_t	pg_off;
	uint32_t	pg_len;
};

/* Opaque; valid from sro_newconn to sro_disconnect. */
struct svc_rdma_conn;
struct svc_rdma_write_state;

/* sro_recv_mbuf's chain has an EXT_DISPOSABLE segment with a verbs ext_free. */
struct mbuf;

/*
 * RFC 8166 chunk metadata.  Every field is peer-supplied; the parser enforces
 * these caps, a per-segment length in (0, SVC_RDMA_MAX_SEG_LEN], and a total
 * that cannot overflow.  A peer declaring more is rejected, not sized for.
 */
#define	SVC_RDMA_MAX_SEGS	16	/* max rdma_segments in one chunk */
#define	SVC_RDMA_MAX_CHUNKS	8	/* max chunks in read/write list */
#define	SVC_RDMA_MAX_SEG_LEN	(1U << 30)	/* sane per-segment length cap */
/*
 * Capped apart from SVC_RDMA_MAX_CHUNKS since an NFS WRITE arrives as many
 * segments of one chunk.  64 covers 1 MiB down to 16 KiB segments and keeps
 * struct svc_rdma_msg under 4 KiB.  One segment is one WR, so this also
 * bounds the SQ head room reserved at accept.
 */
#define	SVC_RDMA_MAX_READ_SEGS	64	/* max segments in the read list */

/* One RFC 8166 rdma_segment, 4 XDR words. */
struct svc_rdma_segment {
	uint32_t	 rs_handle;	/* registered memory handle (rkey) */
	uint32_t	 rs_length;	/* segment length in bytes (validated) */
	uint64_t	 rs_offset;	/* segment virtual address */
};

/* The parser flattens the RFC 8166 1/0-terminated chain into these. */
struct svc_rdma_read_chunk {
	uint32_t	 rc_position;	/* position in the XDR stream */
	struct svc_rdma_segment rc_seg;	/* the single target segment */
};

/* A write chunk, and the shape of the reply chunk too. */
struct svc_rdma_write_chunk {
	uint32_t	 wc_nsegs;	/* number of valid wc_segs (<= cap) */
	uint32_t	 wc_total;	/* sum of segment lengths (validated) */
	struct svc_rdma_segment wc_segs[SVC_RDMA_MAX_SEGS];
};

/*
 * A parsed inline call.  rpc points into the verbs layer's recv buffer with
 * no copy, so it is valid only for the duration of the upcall.
 */
struct svc_rdma_msg {
	uint32_t	 xid;		/* word0, echoed opaque */
	uint32_t	 credit;	/* word2, flow control */
	uint32_t	 rdma_proc;	/* word3, RDMA_MSG / RDMA_NOMSG */
	const void	*rpc;		/* inline RPC payload (buf + header) */
	uint32_t	 rpc_len;	/* payload length */

	uint32_t	 rd_nchunks;	/* valid entries in reads[] */
	uint32_t	 wr_nchunks;	/* valid entries in writes[] (<= cap) */
	bool		 reply_present;	/* a reply chunk was encoded */
	struct svc_rdma_read_chunk  reads[SVC_RDMA_MAX_READ_SEGS];
	struct svc_rdma_write_chunk writes[SVC_RDMA_MAX_CHUNKS];
	struct svc_rdma_write_chunk reply;
};

/*
 * Consumer upcall table.  ctx is the value given to
 * svc_rdma_listen_start_ops() and handed back to every upcall.
 *
 * sro_newconn runs from the sleepable CM handler, once, before any recv for
 * that connection, and is where the consumer attaches its state.  sro_recv
 * runs from the recv completion and must not sleep; msg and msg->rpc die when
 * it returns, since the buffer is reposted at once.  sro_disconnect runs from
 * the sleepable teardown task, only if sro_newconn fired, with the in-flight
 * upcalls already drained; conn is dead after it returns.
 */
struct svc_rdma_ops {
	void	(*sro_newconn)(void *ctx, struct svc_rdma_conn *conn);
	int	(*sro_recv)(void *ctx, struct svc_rdma_conn *conn,
		    const struct svc_rdma_msg *msg);
	void	(*sro_disconnect)(void *ctx, struct svc_rdma_conn *conn);
	/*
	 * Assembled-body form of sro_recv, same context and no-sleep rule.
	 * Ownership of m passes to the callee on a 0 return only.
	 */
	int	(*sro_recv_mbuf)(void *ctx, struct svc_rdma_conn *conn,
		    struct mbuf *m, uint32_t xid, bool has_reply,
		    const struct svc_rdma_write_chunk *reply);
};

/*
 * Listen on the wildcard address of each compiled-in family, host-order port.
 * ops must outlive the listener and ctx svc_rdma_listen_stop().  Returns a
 * positive errno.
 */
int	svc_rdma_listen_start_ops(uint16_t port, const struct svc_rdma_ops *ops,
	    void *ctx);

/* Attach consumer state; the verbs layer stores it and never frees it. */
void	svc_rdma_conn_set_ctx(struct svc_rdma_conn *conn, void *cctx);

/* Retrieve the state set by svc_rdma_conn_set_ctx(), or NULL. */
void	*svc_rdma_conn_get_ctx(struct svc_rdma_conn *conn);

/*
 * Post an inline reply.  buf is copied, so it can be freed on return.
 * Callable from sro_recv and does not sleep.  EBUSY leaves buf untouched;
 * a sleepable caller must retain it and retry, rechecking connection lifetime
 * after each wait.  A caller that cannot retry must close the connection.
 *
 * conn is valid only between sro_newconn and sro_disconnect, so a caller
 * posting from outside an upcall must hold something that keeps it alive:
 * in krpc, the per-connection lock under which sro_disconnect clears its
 * handle.
 */
int	svc_rdma_conn_send(struct svc_rdma_conn *conn, const void *buf,
	    uint32_t len);

/*
 * Post an RDMA_ERROR reply (RFC 8166 4.4).  The xid must come from a request
 * whose header parsed.  ERR_CHUNK normally leaves the connection up to be
 * retried; send-buffer exhaustion closes it so the caller can reconnect.
 * Same context and lifetime rules as svc_rdma_conn_send().
 */
int	svc_rdma_conn_error(struct svc_rdma_conn *conn, uint32_t xid,
	    uint32_t errcode);

/*
 * Prepare a write state and its SEND buffer in a sleepable caller, before
 * acquiring the connection's lifetime lock.  A non-NULL reply is copied into
 * a contiguous source for a reply chunk; otherwise replylen must be zero and
 * reducedlen is the inline body length for a write-list reply.
 *
 * No connection or DMA resources are accessed.  On success the caller owns
 * *wsp until it passes it to a posting function, which consumes it on every
 * return, or calls svc_rdma_write_free() after a disconnect.  On failure
 * *wsp is NULL.  Hold the verbs provider throughout preparation and posting.
 */
int	svc_rdma_write_alloc(uint32_t nsegs, uint32_t reducedlen,
	    const void *reply, uint32_t replylen,
	    struct svc_rdma_write_state **wsp);
void	svc_rdma_write_free(struct svc_rdma_write_state *ws);

/*
 * Write an over-inline reply into the client's reply chunk, then SEND an
 * RDMA_NOMSG header with the length written (RFC 8166 4.3).  The ONC
 * RPC body is copied by svc_rdma_write_alloc() before this call.
 *
 * reply is peer-supplied and re-validated here against the caps and against
 * len, so an oversized reply returns EMSGSIZE rather than overrunning the
 * chunk.  Does not sleep; same lifetime rule as svc_rdma_conn_send().  Each
 * posting function consumes the prepared state on every return.  A partially
 * posted chain is reclaimed only after completion or drain.
 */
int	svc_rdma_conn_reply_chunk(struct svc_rdma_conn *conn, uint32_t xid,
	    const struct svc_rdma_write_chunk *reply,
	    struct svc_rdma_write_state *ws, uint32_t len);

/*
 * Write a DDP-eligible READ's data into the client's write-list chunk, then
 * SEND the reduced RDMA_MSG (RFC 8166 3.5.3).  The chunk receives exactly
 * datalen unpadded bytes; header plus reduced body must fit one send buffer.
 * Same rules as svc_rdma_conn_reply_chunk().
 */
int	svc_rdma_conn_write_list(struct svc_rdma_conn *conn, uint32_t xid,
	    const struct svc_rdma_write_chunk *write, void *src,
	    uint32_t datalen, const void *reduced, uint32_t reducedlen,
	    bool src_pooled, struct svc_rdma_write_state *ws);

/*
 * Zero-copy form, sourced from the reply's M_EXTPG pages.  The engine owns
 * mrep on every return and frees it.
 */
int	svc_rdma_conn_write_list_pages(struct svc_rdma_conn *conn, uint32_t xid,
	    const struct svc_rdma_write_chunk *write, struct mbuf *mrep,
	    const struct svc_rdma_page *pages, uint32_t npages,
	    uint32_t datalen, const void *reduced, uint32_t reducedlen,
	    struct svc_rdma_write_state *ws);

/*
 * Recv buffers actually posted, which is what a reply advertises in
 * rdma_credit (RFC 8166 3.3.1).  Set at accept and never mutated.
 */
uint32_t svc_rdma_conn_credits(struct svc_rdma_conn *conn);

/*
 * Pre-allocate this thread's linuxkpi current shadow off-lock, so a later
 * post under xr_lock does not hit the M_WAITOK inside mlx5_ib_post_send().
 */
void	svc_rdma_thread_setup(void);

/*
 * The verbs table nfsrdma registers at load.  It must outlive every call krpc
 * can make through it, so the module passes a static one and unregisters
 * before its text goes away; only one provider at a time.  Missing core
 * entries are rejected, while optional entries are NULL-checked at the call
 * site.  Changes to this private table require rebuilding both the consumer
 * and provider.
 */
struct svc_rdma_verbs_ops {
	int	(*svo_listen_start)(uint16_t port,
		    const struct svc_rdma_ops *ops, void *ctx);
	void	(*svo_listen_stop)(void);
	int	(*svo_conn_send)(struct svc_rdma_conn *conn, const void *buf,
		    uint32_t len);
	int	(*svo_conn_reply_chunk)(struct svc_rdma_conn *conn, uint32_t xid,
		    const struct svc_rdma_write_chunk *reply,
		    struct svc_rdma_write_state *ws,
		    uint32_t len);
	/* Optional; without it over-inline READs fall back to the drop. */
	int	(*svo_conn_write_list)(struct svc_rdma_conn *conn, uint32_t xid,
		    const struct svc_rdma_write_chunk *write, void *src,
		    uint32_t datalen, const void *reduced, uint32_t reducedlen,
		    bool src_pooled, struct svc_rdma_write_state *ws);
	/* Optional; without it the consumer stays on the copy path. */
	int	(*svo_conn_write_list_pages)(struct svc_rdma_conn *conn, uint32_t xid,
		    const struct svc_rdma_write_chunk *write, struct mbuf *mrep,
		    const struct svc_rdma_page *pages, uint32_t npages,
		    uint32_t datalen, const void *reduced, uint32_t reducedlen,
		    struct svc_rdma_write_state *ws);
	void	(*svo_conn_set_ctx)(struct svc_rdma_conn *conn, void *cctx);
	void	*(*svo_conn_get_ctx)(struct svc_rdma_conn *conn);
	uint32_t (*svo_conn_credits)(struct svc_rdma_conn *conn);
	void	(*svo_conn_peeraddr)(struct svc_rdma_conn *conn,
		    struct sockaddr_storage *ss);
	/* Optional; without it an unplaceable reply is dropped. */
	int	(*svo_conn_error)(struct svc_rdma_conn *conn, uint32_t xid,
		    uint32_t errcode);
	/* Optional; see svc_rdma_thread_setup(). */
	void	(*svo_thread_setup)(void);
	/*
	 * Recycle the write-list fallback buffer instead of allocating and
	 * freeing per operation, which is what keeps the copy path off the TLB
	 * shootdown.  Optional; when present the consumer passes src_pooled.
	 */
	void	*(*svo_sink_get)(void);
	void	(*svo_sink_put)(void *buf);
	int	(*svo_write_alloc)(uint32_t nsegs, uint32_t reducedlen,
		    const void *reply, uint32_t replylen,
		    struct svc_rdma_write_state **wsp);
	void	(*svo_write_free)(struct svc_rdma_write_state *ws);
};

/*
 * Called from the module at load and unload.  Unregister is idempotent and
 * keyed on the ops pointer, so it only revokes the table that owns the
 * global.
 */
void	svc_rdma_publish_listen(bool publish);
bool	svc_rdma_nfsd_running(void);
int	svc_rdma_register_verbs(const struct svc_rdma_verbs_ops *ops);
void	svc_rdma_unregister_verbs(const struct svc_rdma_verbs_ops *ops);

/*
 * SVCSET_READDDP tells the transport where the read data sits in the NFS
 * reply body, for RFC 8166 reduction.  `in' points at a rpcrdma_reduce.
 */

#endif	/* _RDMA_SVC_RDMA_H */
