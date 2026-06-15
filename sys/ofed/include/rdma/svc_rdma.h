/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (c) 2014-2017 Oracle.  All rights reserved.
 * Copyright (c) 2003-2007 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include <sys/socket.h>

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
 * Opaque mbuf handle.  Used only by the zero-copy sro_recv_mbuf op below, which
 * hands the consumer an already-assembled ONC RPC call as an mbuf chain whose
 * large middle segment is EXT_DISPOSABLE external storage over a DMA'd RDMA-Read
 * sink (verbs-layer-owned ext_free); the consumer treats the chain as opaque.
 */
struct mbuf;

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
 * SVC_RDMA_MAX_READ_SEGS caps the read list SPECIFICALLY (decoupled from
 * SVC_RDMA_MAX_CHUNKS, TASK_003f-10).  An NFS WRITE's read list is many segments
 * of ONE logical chunk (one rdma_position), and a real Linux NFS/RDMA client
 * splits a 1 MiB WRITE into ~16 segments of ~64 KiB (the HCA's FRWR granularity)
 * -- far more than the 8-chunk write-list cap.  Sizing the read list at 8 made
 * the server reject every >~0.5 MiB WRITE ("exceeds chunk/segment caps") and
 * was the wall that pinned the negotiated wsize at 128 KiB.  64 covers a 1 MiB
 * request down to 16 KiB segments (4x the observed fragmentation) while the
 * reads[] array still leaves struct svc_rdma_msg under the 4 KiB budget.  It is
 * a FIXED LOCAL constant: a peer declaring more read segments is a clean reject,
 * never a larger allocation.  Each read segment is one RDMA Read WR / SQ slot,
 * so this also bounds the SQ head-room reserved at accept (see max_send_wr).
 */
#define	SVC_RDMA_MAX_READ_SEGS	64	/* max segments in the read list */

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
 * chain into rd_nchunks entries, capped at SVC_RDMA_MAX_READ_SEGS).
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
	struct svc_rdma_read_chunk  reads[SVC_RDMA_MAX_READ_SEGS];
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
	/*
	 * sro_recv_mbuf(ctx, conn, m, xid, has_reply, reply) -> 0 cont /
	 * nonzero drop+close.  Same IB_POLL_WORKQUEUE context and *** MUST NOT
	 * SLEEP *** rule as sro_recv, same sro_newconn-happened-before
	 * guarantee.  m is a COMPLETE ONC RPC call body already assembled
	 * (head ++ read-data ++ head-tail) as an mbuf chain whose large middle
	 * segment is EXT_DISPOSABLE external storage over a DMA'd read sink with
	 * its OWN ext_free callback (verbs-layer-owned; the krpc treats m as
	 * opaque).  OWNERSHIP OF m TRANSFERS to the callee on return 0 (it
	 * m_freem()s it via the recv queue / drain).  On nonzero the CALLER
	 * still owns m and m_freem()s it.  reply is a pure value type, captured
	 * iff has_reply.
	 */
	int	(*sro_recv_mbuf)(void *ctx, struct svc_rdma_conn *conn,
		    struct mbuf *m, uint32_t xid, bool has_reply,
		    const struct svc_rdma_write_chunk *reply);
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
 * RDMA-Write a too-large-for-inline reply into the client's reply chunk, then
 * SEND a small RDMA_NOMSG transport header reporting the bytes written
 * (TASK_003f-4).  This is the OUTBOUND data path for the RFC 8166 §4.3 reply
 * chunk: the whole marshalled ONC RPC reply does not fit the inline send buffer,
 * so the client pre-registered reply-chunk memory and the server RDMA-Writes the
 * reply into it and reports the length in the RDMA_NOMSG header's reply chunk.
 *
 * buf/len are the marshalled ONC RPC reply BODY ONLY (NO RFC 8166 header -- the
 * verbs layer builds the RDMA_NOMSG header itself).  buf is caller-owned and only
 * read here: the verbs layer copies len bytes into its own DMA-mapped source
 * buffer (no ownership transfer), so the caller may free/reuse buf the instant
 * this returns.
 *
 * reply is the parsed-and-validated reply chunk the client offered, captured by
 * the consumer during sro_recv (it is a pure value type -- a fixed-size segment
 * array, no pointers -- so the consumer copies it and hands it back here).  EVERY
 * field is UNTRUSTED and is RE-VALIDATED at post time: the segment count <= cap,
 * each segment length in (0, cap], the running total >= len (the client must have
 * offered at least as much reply-chunk space as the reply needs -- if not, the
 * reply does not fit the client's chunk and EMSGSIZE is returned, NOT an
 * over-write of the client's memory).  The client {rkey, addr} are passed
 * VERBATIM to the HCA, which enforces them; a bad one fails the WR -> clean close.
 *
 * xid is the echoed opaque transaction id for the RDMA_NOMSG header (word0).
 *
 * Context: callable from a krpc pool thread (xp_reply) under the consumer's
 * per-conn lock (the same caller-reference rule as svc_rdma_conn_send: the lock
 * keeps conn alive across the call).  It does NOT sleep.  It is gated by the
 * connection still being up and by the bounded send pool (the RDMA_NOMSG header
 * SEND draws one buffer); a tearing-down conn or exhausted pool drops the reply.
 *
 * Returns 0 if the RDMA Write chain + header SEND were posted, EINVAL for a
 * len/segment violation, EMSGSIZE if the reply exceeds the client's reply-chunk
 * capacity, ENOMEM on allocation failure, EBUSY if the send pool was exhausted,
 * ENOTCONN if the connection is no longer up, or the posted errno otherwise.  On
 * a nonzero return the verbs layer has released everything it allocated for a
 * never-posted attempt (a posted-but-failed chain is reclaimed by the drained
 * teardown -- the partial-post discipline, see svc_verbs.c).
 */
int	svc_rdma_conn_reply_chunk(struct svc_rdma_conn *conn, uint32_t xid,
	    const struct svc_rdma_write_chunk *reply, const void *buf,
	    uint32_t len);

/*
 * RDMA-Write a DDP-eligible NFS READ's data into the client's write-list chunk,
 * then SEND a REDUCED RDMA_MSG (RFC 8166 3.5.3 / 4.2 "reduction"): the ONC RPC
 * reply with the read data removed, carrying a write list that echoes the chunk
 * with the per-segment lengths ACTUALLY written.  OUTBOUND data path for the
 * write list (vs. svc_rdma_conn_reply_chunk's reply chunk): the read data does
 * not fit inline, so the client pre-registered write-list memory and the server
 * RDMA-Writes the data into it and reports the lengths in the header.
 *
 * `write' is the parsed-and-validated single write chunk the client offered for
 * this READ (a pure value type the consumer captured during sro_recv).  EVERY
 * field is UNTRUSTED and RE-VALIDATED at post time exactly as the reply-chunk
 * engine does: segment count <= cap, each length in (0, cap], the running total
 * (offered capacity) computed with no uint32 overflow >= datalen, else EMSGSIZE
 * and NOTHING is written.  data/datalen are the read data bytes (server-known,
 * bounded by SVC_RDMA_MAX_WRITE); the chunk receives exactly datalen UNPADDED
 * bytes (RFC 8166 3.4.5).  reduced/reducedlen are the reduced inline ONC RPC
 * body the verbs layer SENDs after the RDMA_MSG header (header + body must fit
 * one inline send buffer; else EMSGSIZE).  {rkey,addr} go VERBATIM to the HCA,
 * which enforces them.  data and reduced are caller-owned and only read here
 * (both copied into DMA-mapped verbs-owned buffers), so the caller may free them
 * the instant this returns.  xid is the echoed transaction id (RDMA_MSG word0).
 *
 * Same context, lifetime, completion and partial-post rules as
 * svc_rdma_conn_reply_chunk.  Returns 0, EINVAL for a len/segment violation,
 * EMSGSIZE if the data exceeds the client's write chunk or the reduced reply
 * exceeds the inline send buffer, ENOMEM, EBUSY, ENOTCONN, or the posted errno.
 */
int	svc_rdma_conn_write_list(struct svc_rdma_conn *conn, uint32_t xid,
	    const struct svc_rdma_write_chunk *write, const void *data,
	    uint32_t datalen, const void *reduced, uint32_t reducedlen);

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
 *   svo_conn_reply_chunk -> svc_rdma_conn_reply_chunk (TASK_003f-4)
 *   svo_conn_set_ctx  -> svc_rdma_conn_set_ctx
 *   svo_conn_get_ctx  -> svc_rdma_conn_get_ctx
 *   svo_conn_credits  -> svc_rdma_conn_credits
 *   svo_conn_peeraddr -> svc_rdma_conn_peeraddr (TASK_003f-6)
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
	int	(*svo_conn_reply_chunk)(struct svc_rdma_conn *conn, uint32_t xid,
		    const struct svc_rdma_write_chunk *reply, const void *buf,
		    uint32_t len);
	/*
	 * svo_conn_write_list -> svc_rdma_conn_write_list (write-list READ
	 * engine).  OPTIONAL: krpc NULL-checks it at the call site (like
	 * svo_conn_peeraddr) and svc_rdma_register_verbs does NOT require it, so
	 * an older ibcore predating the engine still registers and over-inline
	 * READs simply fall back to the existing drop.
	 */
	int	(*svo_conn_write_list)(struct svc_rdma_conn *conn, uint32_t xid,
		    const struct svc_rdma_write_chunk *write, const void *data,
		    uint32_t datalen, const void *reduced, uint32_t reducedlen);
	void	(*svo_conn_set_ctx)(struct svc_rdma_conn *conn, void *cctx);
	void	*(*svo_conn_get_ctx)(struct svc_rdma_conn *conn);
	uint32_t (*svo_conn_credits)(struct svc_rdma_conn *conn);
	void	(*svo_conn_peeraddr)(struct svc_rdma_conn *conn,
		    struct sockaddr_storage *ss);
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
