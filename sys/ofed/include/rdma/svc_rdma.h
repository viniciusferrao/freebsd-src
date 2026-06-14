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
 * svc_rdma.h -- consumer upcall interface for the NFS-over-RDMA server verbs
 * layer (svc_verbs.c, in the ibcore module).
 *
 * TASK_003e-1 scope: decouple the verbs layer from the RPC policy.  svc_verbs.c
 * owns the RDMA-CM listener, the per-connection QP/CQ/PD, the recv/send buffer
 * pools, and the drained-teardown lifecycle.  It does NOT know anything about
 * krpc/SVCXPRT/nfsd.  A consumer (TASK_003e-2's krpc SVCXPRT in
 * sys/rpc/svc_rdma.c) registers a struct svc_rdma_ops upcall table plus an
 * opaque ctx with svc_rdma_listen_start_ops(); the verbs layer then calls back
 * into the consumer at the three lifecycle points (newconn / recv / disconnect)
 * and exposes svc_rdma_conn_send() so the consumer can post a marshalled reply.
 *
 * Module layering (docs/16-svcxprt-rdma-integration.md "Module layering"): the
 * verbs live in the ibcore module; the SVCXPRT/xp_ops live in the krpc layer
 * built into the kernel.  A kernel built-in cannot hard-link a loadable module's
 * symbols, so the consumer does NOT call these entry points directly at link
 * time -- ibcore registers this ops surface with krpc at module load and krpc
 * invokes it through function pointers.  This header is the shared contract for
 * that registration; it declares only what a consumer needs and keeps every
 * verbs-internal detail (recv/send descriptors, the registry, the barriers)
 * private to svc_verbs.c.
 *
 * NOTE: the additive sysctl self-test in svc_verbs.c uses an internal DEFAULT
 * ops table (accept -> parse -> stub reply -> teardown) and does not go through
 * this header.  These declarations exist for the external consumer.
 */

#ifndef _RDMA_SVC_RDMA_H
#define _RDMA_SVC_RDMA_H

#include <sys/types.h>

/*
 * Opaque per-accepted-connection handle.  The concrete struct svc_rdma_conn is
 * defined privately in svc_verbs.c (it carries the cm_id, QP/CQ/PD, buffer
 * pools, state machine, and registry linkage).  A consumer only ever holds the
 * pointer the verbs layer hands it in the upcalls below and passes it back to
 * svc_rdma_conn_send() / svc_rdma_conn_set_ctx().  Its lifetime is bounded by
 * the sro_newconn .. sro_disconnect upcall pair (see the ops contract below).
 */
struct svc_rdma_conn;

/*
 * RFC 8166 chunk metadata, decoded and BOUNDS-VALIDATED by svc_verbs.c
 * (TASK_003f-1) into the fixed-capacity structures below.  These describe the
 * peer-registered memory regions a later increment (3f-3 RDMA Read / 3f-4 RDMA
 * Write) will operate on; 3f-1 only DECODES and VALIDATES them -- no verbs are
 * posted from the parser.
 *
 * EVERY field here is peer-supplied and therefore UNTRUSTED, but by the time a
 * consumer sees them the parser has already enforced: a per-message segment cap
 * (SVC_RDMA_MAX_SEGS) and chunk cap (SVC_RDMA_MAX_CHUNKS) -- so the arrays are
 * FIXED-SIZE and a hostile peer can never drive an allocation or an array index
 * past these bounds; a nonzero, sane per-segment length (0 < length <=
 * SVC_RDMA_MAX_SEG_LEN); and a running total that cannot overflow uint32_t.  A
 * message that violates any of these is REJECTED by the parser and never
 * reaches the consumer.  The caps are deliberately small fixed constants, not
 * peer counts: if the peer declares more it is a clean reject, not a larger
 * struct.
 */
#define	SVC_RDMA_MAX_SEGS	16	/* max rdma_segments in one chunk */
#define	SVC_RDMA_MAX_CHUNKS	8	/* max chunks in read/write list */
#define	SVC_RDMA_MAX_SEG_LEN	(1U << 30)	/* sane per-segment length cap */

/*
 * One RFC 8166 rdma_segment: { handle (rkey), length, offset (virtual addr) }.
 * 4 XDR words = 16 wire bytes.  rs_length is already validated 0 < len <=
 * SVC_RDMA_MAX_SEG_LEN by the parser.
 */
struct svc_rdma_segment {
	uint32_t	 rs_handle;	/* registered memory handle (rkey) */
	uint32_t	 rs_length;	/* segment length in bytes (validated) */
	uint64_t	 rs_offset;	/* segment virtual address */
};

/*
 * One read-list entry: an rdma_position plus a single rdma_segment.  The read
 * list is a flat array of these (the parser flattens the RFC 8166 1/0-terminated
 * chain into rd_nchunks entries, capped at SVC_RDMA_MAX_CHUNKS).
 */
struct svc_rdma_read_chunk {
	uint32_t	 rc_position;	/* position in the XDR stream */
	struct svc_rdma_segment rc_seg;	/* the single target segment */
};

/*
 * One write chunk (also the shape of the reply chunk): a COUNTED array of
 * rdma_segments, capped at SVC_RDMA_MAX_SEGS.  wc_total is the validated sum of
 * the segment lengths (cannot overflow uint32_t).
 */
struct svc_rdma_write_chunk {
	uint32_t	 wc_nsegs;	/* number of valid wc_segs (<= cap) */
	uint32_t	 wc_total;	/* sum of segment lengths (validated) */
	struct svc_rdma_segment wc_segs[SVC_RDMA_MAX_SEGS];
};

/*
 * A parsed inline RPC-over-RDMA v1 (RFC 8166) call, handed to the consumer's
 * sro_recv upcall.  This mirrors the verbs-internal definition in svc_verbs.c
 * (which stays authoritative); it exposes exactly what a consumer needs to
 * dispatch the call:
 *   xid     - word0, the echoed opaque transaction id (the only field a stub
 *             reply needs).
 *   credit  - word2, the peer's offered flow-control credit.
 *   rpc     - pointer to the inline ONC RPC payload (recv buffer + 28-byte
 *             RFC 8166 header).  NO COPY: this points directly into the verbs
 *             layer's recv buffer and is valid ONLY for the duration of the
 *             sro_recv call (see the lifetime rule below).
 *   rpc_len - length in bytes of the inline RPC payload (may be 0).
 *
 * Chunk metadata (TASK_003f-1).  rdma_proc is word3, distinguishing RDMA_MSG
 * (inline body follows the chunk lists) from RDMA_NOMSG (no inline body; the
 * whole call/reply travels by chunk).  The three chunk descriptions are decoded
 * from the read list / write list / reply chunk that follow word3, each into a
 * fixed-capacity holder above:
 *   reads        - rd_nchunks read-list entries (each position + one segment).
 *   writes       - wr_nchunks write-list chunks (each a counted segment array).
 *   reply        - the optional reply chunk; reply_present says whether it was
 *                  encoded by the peer.
 * For a pure inline call (all three lists empty -- the only shape pre-3f) all
 * counts are 0, reply_present is false, and rpc/rpc_len locate the inline body
 * exactly as before.  Consumers that do not yet handle chunks (3f-1 itself)
 * MUST treat any nonzero count / present reply as "not yet served".
 */
struct svc_rdma_msg {
	uint32_t	 xid;		/* word0, echoed opaque */
	uint32_t	 credit;	/* word2, flow control */
	uint32_t	 rdma_proc;	/* word3, RDMA_MSG / RDMA_NOMSG */
	const void	*rpc;		/* inline RPC payload (buf + header) */
	uint32_t	 rpc_len;	/* payload length */

	uint32_t	 rd_nchunks;	/* valid entries in reads[] (<= cap) */
	uint32_t	 wr_nchunks;	/* valid entries in writes[] (<= cap) */
	bool		 reply_present;	/* a reply chunk was encoded */
	struct svc_rdma_read_chunk  reads[SVC_RDMA_MAX_CHUNKS];
	struct svc_rdma_write_chunk writes[SVC_RDMA_MAX_CHUNKS];
	struct svc_rdma_write_chunk reply;
};

/*
 * Consumer upcall table.  ctx is the opaque value the consumer passed to
 * svc_rdma_listen_start_ops(); it is handed back to every upcall so the
 * consumer can recover its listener-scoped state (e.g. the SVCPOOL).  All three
 * upcalls run in the verbs layer's own contexts; the consumer MUST honor the
 * context rules:
 *
 *   sro_newconn(ctx, conn)
 *       Called exactly once per accepted connection, from the ESTABLISHED CM
 *       event handler (the rdma_cm work context, which is sleepable), and ALWAYS
 *       BEFORE any sro_recv is dispatched for that connection.  The consumer
 *       attaches its per-conn state via svc_rdma_conn_set_ctx() here, and -- since
 *       this runs in a sleepable context -- MAY do blocking setup such as
 *       xprt_register / SVCXPRT allocation inline; an M_WAITOK allocation is
 *       acceptable.  MUST NOT call back into the verbs layer destroy path.  This
 *       is the start of conn's lifetime as seen by the consumer.
 *
 *       Ordering vs. recv: receive buffers are posted before the connection is
 *       accepted, so the peer's first inline call can complete and reach the
 *       verbs layer BEFORE this ESTABLISHED event.  The verbs layer does NOT
 *       dispatch sro_recv for such an early call -- it drops it and reposts the
 *       buffer; the RC client retransmits the RPC, and a later recv is dispatched
 *       once this sro_newconn has completed and the connection is up.  So the
 *       consumer never sees an sro_recv before sro_newconn has returned; the only
 *       visible effect of the race is a one-retransmit delay on the very first op.
 *
 *   sro_recv(ctx, conn, msg)  -> 0 to continue, nonzero to drop+close
 *       Called once per successfully-parsed inline RDMA_MSG call, from the recv
 *       completion (IB_POLL_WORKQUEUE context).  *** MUST NOT SLEEP. ***  It is
 *       GUARANTEED that sro_newconn for this conn has already completed before
 *       the first sro_recv, so svc_rdma_conn_get_ctx() returns the state that
 *       sro_newconn attached.  The krpc consumer enqueues the message and calls
 *       xprt_active() -- it does NOT block a pool thread here.  msg (and
 *       msg->rpc) are valid ONLY for the duration of this call; the underlying
 *       recv buffer is reposted to the QP as soon as sro_recv returns, so a
 *       consumer that needs the bytes past the call MUST copy them (e.g. into an
 *       mbuf chain) before returning.  The consumer MAY call svc_rdma_conn_send()
 *       synchronously from within sro_recv (the stub does); that is supported in
 *       this context.  Returning nonzero asks the verbs layer to close the
 *       connection (the consumer rejected the call); returning 0 lets the verbs
 *       layer repost and await the next call.
 *
 *   sro_disconnect(ctx, conn)
 *       Delivered EXACTLY ONCE, and PAIRED with sro_newconn: it fires if and only
 *       if sro_newconn fired for this conn (a connection that never reached
 *       ESTABLISHED gets neither).  Runs from the deferred teardown task
 *       (taskqueue_thread, a sleepable context) -- NOT from a completion or the
 *       CM callback.
 *
 *       It is delivered ONLY AFTER all sro_recv upcalls for this conn (and the
 *       sro_newconn) have returned: the verbs layer drains its in-flight consumer
 *       upcalls before calling sro_disconnect, so no sro_recv can be running
 *       concurrently.  The consumer may therefore safely tear down and FREE its
 *       per-conn state here (e.g. xprt_unregister and release its SVCXPRT
 *       reference, and free whatever it attached with svc_rdma_conn_set_ctx()).
 *       After this returns the verbs layer finishes draining the QP and frees
 *       conn; the consumer MUST NOT touch conn (or call svc_rdma_conn_send() on
 *       it) afterward.
 */
struct svc_rdma_ops {
	void	(*sro_newconn)(void *ctx, struct svc_rdma_conn *conn);
	int	(*sro_recv)(void *ctx, struct svc_rdma_conn *conn,
		    const struct svc_rdma_msg *msg);
	void	(*sro_disconnect)(void *ctx, struct svc_rdma_conn *conn);
};

/*
 * Start the passive RDMA-CM listener on the wildcard address and the given
 * (host-order) port, driving the supplied consumer ops with the supplied ctx.
 * ops and ctx are stored on the listener and copied onto each accepted
 * connection at accept time, so every completion/teardown can reach them.
 *
 * Returns 0 on success or a positive FreeBSD errno on failure (EINVAL for a
 * zero port or NULL ops, EBUSY if a listener is already up, or the normalized
 * errno from the rdma_*() bring-up).  ops MUST outlive the listener (it is a
 * function-pointer table the consumer owns; typically a static const in the
 * krpc module), as MUST ctx until svc_rdma_listen_stop() has returned.
 */
int	svc_rdma_listen_start_ops(uint16_t port, const struct svc_rdma_ops *ops,
	    void *ctx);

/*
 * Attach consumer per-connection state to conn.  Intended to be called from
 * sro_newconn (or from within sro_recv).  The verbs layer stores the pointer
 * opaquely and does not interpret or free it; the consumer reclaims it from
 * sro_disconnect.  Safe to call from the upcall contexts above.
 */
void	svc_rdma_conn_set_ctx(struct svc_rdma_conn *conn, void *cctx);

/*
 * Retrieve the consumer per-connection state previously set with
 * svc_rdma_conn_set_ctx() (NULL if never set).  Convenience for the consumer's
 * own upcalls.
 */
void	*svc_rdma_conn_get_ctx(struct svc_rdma_conn *conn);

/*
 * Marshal-and-post an inline reply on conn: copy len bytes from buf into a free
 * send buffer from the connection's bounded pool and post a SEND WR for them.
 * buf is a caller-owned, already-marshalled RPC-over-RDMA reply (transport
 * header + ONC RPC body); the verbs layer copies it (no ownership transfer) and
 * the caller may free/reuse buf as soon as this returns.
 *
 * Context: safe to call from sro_recv (the recv completion / workqueue context)
 * -- it does NOT sleep.  It is gated by the connection still being up and by the
 * bounded send pool: if the connection is tearing down or the pool is exhausted
 * the reply is dropped (this is not an error the caller must recover from -- the
 * peer will retransmit / the conn is going away).
 *
 * Returns 0 if the SEND WR was posted, EINVAL if len exceeds the inline reply
 * capacity, EBUSY if the pool was exhausted, ENOTCONN if the connection is no
 * longer up, or the posted error otherwise.  MUST NOT be called after
 * sro_disconnect for this conn has returned.
 *
 * Caller-reference rule (the consumer's responsibility): conn is owned by the
 * verbs layer and is valid only for the sro_newconn..sro_disconnect window.  A
 * caller that invokes svc_rdma_conn_send() OUTSIDE an active upcall (e.g. a krpc
 * pool thread marshalling a reply asynchronously) MUST hold a reference that
 * keeps conn alive across the call -- in the krpc consumer this is the per-conn
 * lock under which sro_disconnect clears its conn handle, so a post either sees
 * a live conn or is dropped, never racing the verbs layer's free of conn.  The
 * verbs layer's own SC_UP/in-flight-send gate then makes the post itself safe.
 */
int	svc_rdma_conn_send(struct svc_rdma_conn *conn, const void *buf,
	    uint32_t len);

/*
 * Report the flow-control credit the verbs layer GRANTED this connection: the
 * number of receive buffers (and thus recv WRs) it actually posted, which is the
 * value a reply's RPC-over-RDMA header should advertise in rdma_credit (RFC 8166
 * 3.3.1).  The verbs layer clamps the posted depth to the device's QP recv cap,
 * so this is the true depth, not a nominal constant -- granting it avoids both
 * over-advertising (RNR/stall on a small HCA) and under-advertising (needless
 * round trips).  Set once at accept time and never mutated, so it is safe to read
 * from any upcall or from a pool thread holding a reference to conn.
 */
uint32_t svc_rdma_conn_credits(struct svc_rdma_conn *conn);

/*
 * ===========================================================================
 * Cross-module verbs-ops registration (TASK_003e-2a).
 *
 * Module layering (docs/16-svcxprt-rdma-integration.md "Module layering"): the
 * verbs entry points above (svc_rdma_listen_start_ops / svc_rdma_conn_send /
 * svc_rdma_conn_set_ctx / svc_rdma_conn_get_ctx) are DEFINED in the ibcore
 * module (svc_verbs.c).  The SVCXPRT/krpc consumer (sys/rpc/svc_rdma.c) is built
 * INTO the kernel, and a kernel built-in cannot hard-link a loadable module's
 * symbols.  So the call direction is inverted at link time: the krpc layer
 * EXPORTS the two registration entry points below as built-in kernel symbols,
 * and ibcore -- which CAN resolve a built-in kernel symbol -- calls
 * svc_rdma_register_verbs() at module load to hand krpc a table of the verbs
 * entry points (svc_rdma_verbs_ops).  krpc thereafter reaches the verbs only
 * through that registered table; with no table registered (ibcore not loaded)
 * krpc refuses to create an RDMA transport (returns ENXIO) instead of chasing a
 * NULL or an unresolved symbol.
 *
 * struct svc_rdma_verbs_ops mirrors the verbs entry points one-for-one:
 *   svo_listen_start  -> svc_rdma_listen_start_ops
 *   svo_listen_stop   -> svc_rdma_listen_stop
 *   svo_conn_send     -> svc_rdma_conn_send
 *   svo_conn_set_ctx  -> svc_rdma_conn_set_ctx
 *   svo_conn_get_ctx  -> svc_rdma_conn_get_ctx
 *   svo_conn_credits  -> svc_rdma_conn_credits
 * (svc_rdma_listen_stop() is declared privately in svc_verbs.c, not in this
 * consumer header, because a consumer never calls it directly -- it reaches it
 * only through svo_listen_stop.  The signature here matches it.)
 *
 * The ops table the caller passes MUST outlive every call krpc can make through
 * it: ibcore passes a static const table and must svc_rdma_unregister_verbs()
 * before that table (its module text) can go away.  Registration is single-
 * provider: a second svc_rdma_register_verbs() while one is registered is
 * rejected.  All entries are required (krpc rejects a partial table with EINVAL).
 */
struct svc_rdma_verbs_ops {
	int	(*svo_listen_start)(uint16_t port,
		    const struct svc_rdma_ops *ops, void *ctx);
	void	(*svo_listen_stop)(void);
	int	(*svo_conn_send)(struct svc_rdma_conn *conn, const void *buf,
		    uint32_t len);
	void	(*svo_conn_set_ctx)(struct svc_rdma_conn *conn, void *cctx);
	void	*(*svo_conn_get_ctx)(struct svc_rdma_conn *conn);
	uint32_t (*svo_conn_credits)(struct svc_rdma_conn *conn);
};

/*
 * Register / unregister the ibcore verbs-ops table with the krpc layer.  These
 * are DEFINED in sys/rpc/svc_rdma.c (built into the kernel) and CALLED from
 * ibcore (svc_verbs.c) at module load / unload.  register returns 0 on success
 * or EBUSY if a table is already registered (or EINVAL for a NULL/incomplete
 * table); unregister is idempotent.  ops MUST outlive the registration window
 * (register .. unregister).
 *
 * Registration is OWNER-KEYED.  svc_rdma_unregister_verbs() takes the SAME ops
 * pointer that the matching svc_rdma_register_verbs() recorded, and is a no-op
 * unless that pointer is the one currently registered.  This is load-bearing in
 * the shipping GENERIC-OFED config: options OFED compiles the provider IN-KERNEL
 * (which registers at boot) AND also builds ibcore.ko carrying a DUPLICATE
 * register/unregister pair over its OWN &ibcore_verbs_ops.  A kldload ibcore on
 * such a kernel finds a provider already registered and gets EBUSY (its
 * &ibcore_verbs_ops never becomes the owner); a later kldunload must then NOT
 * tear down the in-kernel provider's live listener.  Owner-keying guarantees
 * exactly that: the module's unregister(&module_ibcore_verbs_ops) does not match
 * the in-kernel owner and returns without touching the global or the listener.
 */
int	svc_rdma_register_verbs(const struct svc_rdma_verbs_ops *ops);
void	svc_rdma_unregister_verbs(const struct svc_rdma_verbs_ops *ops);

#endif	/* _RDMA_SVC_RDMA_H */
