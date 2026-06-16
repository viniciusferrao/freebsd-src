// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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
 * Provenance: this server-side RPC-over-RDMA verbs layer was derived from the
 * Linux kernel svcrdma transport -- net/sunrpc/xprtrdma/svc_rdma_transport.c,
 * svc_rdma_recvfrom.c, svc_rdma_sendto.c, svc_rdma_rw.c (Tom Tucker, Chuck
 * Lever) -- and ported to the FreeBSD OFED/LinuxKPI verbs stack.  The dual
 * GPL-2.0/BSD-3-Clause copyrights above are retained per the BSD-3-Clause
 * terms, under which FreeBSD uses this file.
 */

/*
 * svc_verbs.c -- server-side RDMA-CM listener for NFS-over-RDMA.
 *
 * This is the passive (server) counterpart to the active-connect substrate in
 * xprt_verbs.c, loosely based on net/sunrpc/xprtrdma/svc_rdma_transport.c in
 * Linux.  It is significantly different, due to FreeBSD's rdma_XXX() functions
 * having different arguments (e.g. rdma_create_id() takes a leading
 * struct vnet *), and due to the FreeBSD rdma_cm_event carrying no ->id member
 * (the child cm_id of a CONNECT_REQUEST is delivered as the handler's id
 * argument, not via event->id as on Linux).
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
 *
 * TASK_003 (3f-2) scope (this increment): the FRWR (Fast Registration Work
 * Request) memory-registration SUBSTRATE that the RDMA Read (3f-3) and RDMA
 * Write (3f-4) data engines will build on.  Each accepted connection gains a
 * small bounded pool of fast-registration memory regions (ib_alloc_mr with
 * IB_MR_TYPE_MEM_REG); a register helper maps a SERVER-allocated buffer's
 * scatter/gather list into an MR (ib_map_mr_sg), rotates the registration key
 * (ib_update_fast_reg_key), and builds an IB_WR_REG_MR work request whose rkey/
 * lkey the caller (3f-3/3f-4) will use as the local MR for an RDMA Read/Write.
 * A tiny accept-time self-test posts REG_MR + LOCAL_INV (chained, one signaled
 * completion) over one of the server's own buffers to prove the registration/
 * invalidation completion path end-to-end; that single completion is accounted
 * in the EXISTING send-side quiescence barrier (sc_sends) so the drained
 * teardown waits it out before ib_drain_qp()/ib_dereg_mr().  NO RDMA Read/Write
 * (IB_WR_RDMA_READ/WRITE) and NO peer-chunk consumption here -- only the
 * registration substrate and its per-connection lifecycle.  The MR pool's
 * lifetime mirrors the recv/send buffer pools EXACTLY: allocated at accept,
 * deregistered in the drained teardown after ib_drain_qp() so no completion can
 * race the free.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>	/* SI_SUB_OFED_MODINIT */
#include <linux/netdevice.h>	/* init_net */
#include <linux/dma-mapping.h>	/* DMA_FROM_DEVICE */
#include <linux/scatterlist.h>	/* sg_init_one for the FRWR map (TASK_003f-2) */
#include <linux/sched.h>	/* linux_set_current for the krpc post threads (#59) */
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/svc_rdma.h>	/* consumer upcall interface (TASK_003e-1) */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>		/* be32dec: endian- and alignment-safe word decode */
#include <sys/kernel.h>		/* SYSUNINIT, bootverbose */
#include <sys/lock.h>
#include <sys/malloc.h>		/* malloc/free, MALLOC_DEFINE */
#include <sys/mbuf.h>		/* zero-copy read-sink mbuf assembly (TASK_003f-3) */
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
#define	SVC_RDMA_RECV_DEPTH	64
#define	SVC_RDMA_SEND_DEPTH	SVC_RDMA_RECV_DEPTH

/*
 * FRWR memory-registration pool sizing (TASK_003f-2).
 *
 * SVC_RDMA_MR_DEPTH is how many fast-registration MRs we pre-allocate per
 * connection.  It is SVC_RDMA_MAX_CHUNKS (the RFC 8166 chunk cap from 3f-1, in
 * <rdma/svc_rdma.h>): the data engine (3f-3/3f-4) registers at most one MR per
 * chunk it serves concurrently, and the parser already rejects any request that
 * declares more than SVC_RDMA_MAX_CHUNKS chunks, so this depth can never be
 * outrun by a (validated) peer request.  It is a fixed LOCAL constant, never a
 * peer-supplied count.
 *
 * SVC_RDMA_MR_PAGES is the maximum number of device pages a single MR can map
 * (the max_num_sg passed to ib_alloc_mr).  It bounds the page-list length so a
 * future multi-page server buffer registers within one MR.  It is clamped DOWN
 * at accept time to the device-reported dev->attrs.max_fast_reg_page_list_len
 * (the per-MR fast-reg page-list cap), so the MR is never asked to hold more
 * pages than the HCA supports.  Today the only buffer we register is the
 * SVC_RDMA_INLINE-byte (one-page) self-test buffer, so one page would suffice;
 * we size for a small multi-page window now so 3f-3/3f-4 need not resize the
 * pool.  Like every other size here it is a fixed local constant, NOT a
 * peer-driven length (3f-2 registers only server-allocated buffers).
 */
#define	SVC_RDMA_MR_DEPTH	SVC_RDMA_MAX_CHUNKS
#define	SVC_RDMA_MR_PAGES	256

/*
 * RDMA Read engine sizing (TASK_003f-3).
 *
 * SVC_RDMA_MAX_READ is the hard cap on the total inbound length we will pull
 * from a peer's read-list chunks into a single server destination buffer.  It is
 * a FIXED LOCAL constant, NEVER a peer sum: a request whose summed read-list
 * length exceeds it is a clean close, not a larger allocation.  1 MiB covers the
 * common NFS WRITE rsize/wsize (up to 1 MiB) while bounding what one hostile call
 * can make us malloc.  The 3f-1 parser already overflow-checks each per-segment
 * length (<= SVC_RDMA_MAX_SEG_LEN) and the per-chunk total; this is an additional
 * whole-request cap re-asserted at post time.
 *
 * SVC_RDMA_MAX_READ_SEGS (defined in <rdma/svc_rdma.h>, == 64) is the cap on how
 * many RDMA Read WRs we will chain for one request.  It bounds the read list,
 * the rs_wr[]/rs_sge[] arrays, and the SQ read head-room reserved at accept.  It
 * is DECOUPLED from SVC_RDMA_MAX_CHUNKS (the write-list cap): an NFS WRITE's read
 * list is many single-segment entries of one position, and a real client splits
 * 1 MiB into ~16 of them, so the read list needs far more entries than the
 * 8-chunk write list (TASK_003f-10).  Each WR consumes one SQ slot, so the value
 * must fit the SQ head-room reserved at accept time (see max_send_wr).
 */
#define	SVC_RDMA_MAX_READ	(1U << 20)	/* 1 MiB whole-request cap */
/* SVC_RDMA_MAX_READ_SEGS now lives in <rdma/svc_rdma.h> (sizes reads[] there). */

/*
 * RDMA Write engine sizing (TASK_003f-4) -- the OUTBOUND data path.
 *
 * SVC_RDMA_MAX_WRITE is the hard cap on the total length we will RDMA-Write into
 * a client's reply-chunk (or write-list) segments for one reply.  Like
 * SVC_RDMA_MAX_READ it is a FIXED LOCAL constant, never a peer sum: the source is
 * the server's own marshalled reply, whose length we KNOW, and we refuse to size
 * a transfer past this cap.  1 MiB covers a large NFS READ result / READDIR reply
 * while bounding one transfer.  The source buffer is sized by the SERVER-KNOWN
 * reply length (bounded by this), never by a raw peer field.
 *
 * SVC_RDMA_MAX_WRITE_SEGS is the cap on how many IB_WR_RDMA_WRITE WRs we chain for
 * one reply.  A reply chunk / write chunk carries up to SVC_RDMA_MAX_SEGS segments
 * (the parser cap); we write the reply across at most that many segments, so this
 * is that same fixed cap.  Each WR consumes one SQ slot, so it must fit the SQ
 * head-room reserved at accept time (see max_send_wr).
 */
#define	SVC_RDMA_MAX_WRITE	(1U << 20)	/* 1 MiB whole-reply cap */
#define	SVC_RDMA_MAX_WRITE_SEGS	SVC_RDMA_MAX_SEGS
/*
 * Zero-copy outbound-READ page-gather bounds (TASK_003f-19).  The M_EXTPG read
 * source is up to SVC_RDMA_MAX_WRITE bytes of page-aligned data = MAX_WRITE_PAGES
 * page SGEs.  Each RDMA Write WR gathers up to MAX_SEND_SGE pages (one fully
 * packed M_EXTPG mbuf), and a WR never crosses a write-list segment (distinct
 * rkey/remote_addr), so the WR count is bounded by pages/SGE + one partial WR per
 * segment.  The krpc collect helper rejects (=> contigmalloc fallback) anything
 * that would exceed MAX_WRITE_PAGES, so these arrays never overflow.
 */
#define	SVC_RDMA_MAX_SEND_SGE	MBUF_PEXT_MAX_PGS	/* 8 on amd64: pages per M_EXTPG mbuf */
#define	SVC_RDMA_MAX_WRITE_PAGES (SVC_RDMA_MAX_WRITE / PAGE_SIZE)	/* 256 */
#define	SVC_RDMA_MAX_WRITE_WRS	(SVC_RDMA_MAX_WRITE_PAGES / SVC_RDMA_MAX_SEND_SGE + \
				 SVC_RDMA_MAX_WRITE_SEGS)	/* 32 + 16 */
/* Total SGEs: one per page, plus one extra each time a non-page-aligned segment
 * boundary splits a page across two WRs (<= SEGS such splits). */
#define	SVC_RDMA_MAX_WRITE_SGE	(SVC_RDMA_MAX_WRITE_PAGES + SVC_RDMA_MAX_WRITE_SEGS)	/* 272 */

/*
 * Per-connection pool of pre-allocated, pre-DMA-mapped CONTIGUOUS RDMA-Read
 * sink buffers (TASK_003f-8).  Each is SVC_RDMA_MAX_READ bytes (the per-request
 * read cap) and mapped DMA_FROM_DEVICE ONCE at accept, so the NFS-WRITE hot path
 * grabs a ready buffer instead of contigmalloc+map per write (which serializes
 * on the global physical-page allocator and caps WRITE throughput).  Capped at
 * the recv depth; a read that finds the pool empty falls back to the per-read
 * contigmalloc path.  16 * 1 MiB = 16 MiB/conn (benchmark-tuned).
 */
#define	SVC_RDMA_READBUF_POOL	16

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
 * The header is a sequence of big-endian 32-bit XDR words.  The FIXED prefix is
 * four words (16 bytes):
 *   word0 rdma_xid, word1 rdma_vers(==1), word2 rdma_credit, word3 rdma_proc.
 * For RDMA_MSG/RDMA_NOMSG three chunk lists follow, IN ORDER and VARIABLE in
 * length (RFC 8166 4.3):
 *   1. read list   - a chain of read chunks, each preceded by a "1" (more)
 *                    discriminator and holding { rdma_position, rdma_segment },
 *                    terminated by a "0".  rdma_segment = { handle, length,
 *                    offset(64) } = 4 words.  So an empty read list is one word
 *                    (the "0").
 *   2. write list  - a chain of write chunks, each preceded by a "1" and holding
 *                    a COUNTED array { nsegs, rdma_segment[nsegs] }, terminated
 *                    by a "0".  Empty = one word.
 *   3. reply chunk - optional-data: a "1" then ONE counted write chunk, or a "0"
 *                    if absent.  Absent = one word.
 *
 * RPCRDMA_HDR_FIXED is the fixed four-word prefix (16 bytes).  RPCRDMA_HDR_MIN
 * (28) is the smallest POSSIBLE well-formed header: the fixed prefix plus the
 * three single-word empty-list/absent markers.  Beyond the fixed prefix the
 * parser uses a byte cursor that checks remaining length BEFORE every word it
 * reads, so a chunk-bearing header of any (peer-claimed) shape can only decode
 * within len or return a clean error -- never overread.
 */
#define	RPCRDMA_VERSION		1
#define	RPCRDMA_WORD		4	/* one big-endian XDR word, bytes */
#define	RPCRDMA_HDR_FIXED	16	/* xid,vers,credit,proc -- fixed prefix */
#define	RPCRDMA_HDR_MIN		28	/* fixed prefix + 3 empty chunk-list words */
#define	RPCRDMA_SEG_WORDS	4	/* rdma_segment: handle,length,offset(64) */

enum {
	RDMA_MSG	= 0,
	RDMA_NOMSG	= 1,
	RDMA_MSGP	= 2,	/* deprecated */
	RDMA_DONE	= 3,
	RDMA_ERROR	= 4
};

/*
 * RFC 8166 4.4 rdma_err discriminator carried in word4 of an RDMA_ERROR reply.
 * These are the only two recoverable faults this server diagnoses with a KNOWN
 * xid and reports rather than silently resetting the connection:
 *   ERR_VERS  - the call's rdma_vers is not one we support; the reply appends
 *               the inclusive [vers_low, vers_high] range we DO support (here
 *               exactly [1,1]).  The recv path sends this then closes the
 *               mismatched connection (a version cannot change on a live RC
 *               connection, so closing is correct -- the reply is a courtesy so
 *               the client learns the reason rather than seeing only a reset).
 *   ERR_CHUNK - the chunk lists could not be used to place the reply (an
 *               over-inline reply with no usable reply chunk, or a write-list
 *               read whose DDP boundary is out of range and fell through).  No
 *               extra words follow; the connection STAYS UP -- a per-request
 *               error, and the client may retry.
 * Both are built by svc_rdma_send_error() / svc_rdma_conn_error() from a KNOWN
 * xid only -- we NEVER fabricate an RDMA_ERROR from an unparseable header.
 */
enum {
	ERR_VERS	= 1,	/* unsupported rdma_vers; vers range follows */
	ERR_CHUNK	= 2	/* chunk lists unusable for this reply */
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
	RPC_MSG_ACCEPTED= 0,	/* reply_stat: MSG_ACCEPTED */
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
 *
 * Budget guard (TASK_003f-3).  We keep a DURABLE per-recv copy of this struct
 * (rr_rs.rs_msg below) so the parsed chunk arrays survive past the recv handler
 * until the async RDMA Read completes.  Assert its size stays within a sane
 * budget so a future grow of the fixed-capacity chunk arrays cannot silently
 * bloat per-recv (or per-conn) memory.  4 KiB comfortably holds the layout
 * (reads[64] read segments + writes[8] x 16 segs + reply ~= 3.7 KiB) with
 * head-room; the CTASSERT below is the hard guard if a future grow exceeds it.
 */
CTASSERT(sizeof(struct svc_rdma_msg) <= 4096);

/*
 * One pre-allocated, pre-DMA-mapped contiguous RDMA-Read sink buffer from the
 * per-connection read-buffer pool (TASK_003f-8).
 *
 * rb_buf is contigmalloc'd SVC_RDMA_MAX_READ bytes (physically contiguous) and
 * rb_dma is its permanent DMA_FROM_DEVICE mapping, established ONCE at accept
 * and torn down ONCE in the drained teardown.  rb_inuse (sc_lock) is the
 * bounded-free-list token: a read that borrows the buffer sets it true and
 * rs_rb records the borrow; svc_rdma_read_free returns the buffer (rb_inuse
 * <- false, rs_rb <- NULL) instead of unmapping/freeing.  rb_mapped mirrors
 * the rr_mapped / ss_mapped pattern: set only after a successful map so a
 * partial-build teardown skips the unmap for an unmapped slot.
 */
struct svc_rdma_readbuf {
	void	*rb_buf;	/* contigmalloc'd SVC_RDMA_MAX_READ bytes (contiguous) */
	u64	 rb_dma;	/* ib_dma_map_single DMA_FROM_DEVICE, mapped once */
	bool	 rb_mapped;	/* rb_dma is a live mapping */
	bool	 rb_inuse;	/* lent to an in-flight read (sc_lock) */
};

/*
 * Durable inbound-read state (TASK_003f-3), embedded in each recv descriptor.
 *
 * THE LIFETIME FIX.  The 3f-1 parser fills a struct svc_rdma_msg whose rpc/
 * segment pointers reference rr_buf, and 3b reposts rr_buf the instant the recv
 * handler returns.  An RDMA Read completes LATER (async on the SQ), so both the
 * chunk metadata AND the inline head bytes the read splices into must outlive the
 * recv handler.  This struct provides that durable storage: when a request bears
 * a read list we COPY the parsed msg (rs_msg -- the bounded chunk arrays) and the
 * inline head (rs_head, the bytes before the read-list splice point) into here,
 * post the read into rs_buf, and DO NOT repost rr_buf until the read completes and
 * the assembled body has been dispatched.  Nothing here points into rr_buf after
 * the recv handler returns.
 *
 *   rs_cqe   - completion callback for the read WRs (aliased by every WR in the
 *              chain's wr_cqe; the chain is signaled only on the LAST WR, so a
 *              single completion lands in svc_rdma_wc_rdma_read with this rs_* via
 *              container_of on the owning rr).
 *   rs_msg   - the durable COPY of the parsed call (chunk arrays + xid/credit/
 *              proc).  rs_msg.rpc is re-pointed at the ASSEMBLED body (rs_buf-
 *              based) before dispatch, never at rr_buf.
 *   rs_head  - a copy of the inline head: the inline bytes that precede the
 *              read-list splice position (rc_position), capped at SVC_RDMA_INLINE.
 *   rs_headlen - valid bytes in rs_head.
 *   rs_buf   - the server destination buffer the read pulls into (malloc'd, size
 *              rs_total), or the assembled body buffer; freed exactly once.
 *   rs_total - summed read-list length, re-bounded <= SVC_RDMA_MAX_READ.
 *   rs_dma   - ib_dma_map_single address of rs_buf (DMA_FROM_DEVICE; the device
 *              WRITES the read data into it).
 *   rs_mapped - DMA-map idempotency token (sc_lock): guards the single
 *              ib_dma_unmap_single in svc_rdma_read_free; set right after a
 *              successful map (BEFORE the SC_UP post gate), cleared on unmap.
 *   rs_active - the COMPLETION ONE-SHOT guard (sc_lock): set before the post,
 *              test-and-cleared at the top of svc_rdma_wc_rdma_read so exactly the
 *              FIRST of possibly-several completions (a chained/partially-committed
 *              post can flush multiple unsignaled prefix WRs) does the
 *              dispatch+free+repost; later completions no-op.  It does NOT gate
 *              reclaim (rs_mapped/rs_buf do) -- the drained teardown reclaims a
 *              never-completed read regardless of rs_active.
 *   rs_nwr   - number of chained read WRs (== rd_nchunks, <= SVC_RDMA_MAX_READ_SEGS).
 *   rs_wr/rs_sge - the per-segment RDMA Read WR + its one SGE (sg into rs_buf).
 */
struct svc_rdma_read_state {
	struct ib_cqe		 rs_cqe;
	struct svc_rdma_msg	 rs_msg;
	char			*rs_head;	/* inline head copy (<= INLINE) */
	uint32_t		 rs_headlen;
	void			*rs_buf;	/* read destination / assembled body */
	uint32_t		 rs_total;	/* summed read length (bounded) */
	u64			 rs_dma;	/* rs_buf DMA map (DMA_FROM_DEVICE) */
	bool			 rs_mapped;	/* rs_dma is a live mapping (sc_lock) */
	struct svc_rdma_readbuf	*rs_rb;		/* borrowed pool buffer; NULL => fallback alloc */
	bool			 rs_active;	/* completion one-shot guard (sc_lock) */
	int			 rs_nwr;
	struct ib_rdma_wr	 rs_wr[SVC_RDMA_MAX_READ_SEGS];
	struct ib_sge		 rs_sge[SVC_RDMA_MAX_READ_SEGS];
};

/*
 * mbuf ext_free for the read sink (TASK_003f-3).  The mbuf carries the sink
 * buffer pointer DIRECTLY as ext_arg1; this callback runs at refcount->0
 * (EXT_DISPOSABLE -> fires exactly once) and frees ONLY that PLAIN CPU MEMORY.
 *
 * CRITICAL: the sink mbuf is nfsd-owned and OUTLIVES the conn -- it can be freed
 * long after svc_rdma_conn_free_verbs has run rdma_destroy_id(sc_id), which
 * RELEASES the ib_device.  Therefore this callback MUST NOT touch the device:
 * the DMA mapping is torn down in svc_rdma_wc_rdma_read (Review fix (b)), while
 * the conn and device are provably alive (the completion runs on this conn's CQ),
 * leaving the mbuf owning plain memory only.  No ib_device, no dma cookie here ->
 * no device use-after-free on DEVICE_REMOVAL / HCA kldunload.  free() never
 * sleeps or takes sc_lock/xr_lock, so the callback adds no lock-order edge and
 * cannot deadlock the teardown.
 */
static void
svc_rdma_read_extfree(struct mbuf *m)
{
	void *buf = m->m_ext.ext_arg1;

	if (buf != NULL)
		free(buf, M_NFSRDMA);
}

/*
 * Durable outbound-write state (TASK_003f-4) -- the OUTBOUND data path's analogue
 * of svc_rdma_read_state.
 *
 * THE LIFETIME FIX (mirroring 3f-3).  A reply-chunk RDMA Write originates from the
 * consumer's xp_reply (a krpc pool thread), not from a recv buffer, so this state
 * has no natural durable home like rr_rs.  It is malloc'd on demand by
 * svc_rdma_conn_reply_chunk() and THREADED on the per-conn sc_writes list so the
 * drained teardown can reclaim a write still in flight at close.  The RDMA Write
 * chain + the header SEND complete LATER (async on the SQ), so the source bytes
 * (the marshalled reply) and the header bytes must outlive the xp_reply call:
 * both are COPIED into ws_src / ws_hdr here, never aliasing the caller's buffer.
 *
 *   ws_link  - sc_writes registry linkage (sc_lock); inserted at post, removed on
 *              the first completion (or by the drained teardown).
 *   ws_cqe   - completion callback for the chain.  ONLY the signaled tail SEND
 *              aliases &ws_cqe; the unsignaled RDMA Write WRs route to the per-conn
 *              sink cqe (TASK_003f-20), so svc_rdma_wc_rdma_write runs EXACTLY ONCE
 *              per ws (recovered via container_of), with no duplicate flush CQE.
 *   ws_src   - the source buffer the RDMA Writes read FROM (the marshalled ONC RPC
 *              reply), malloc'd ws_srclen bytes, DMA-mapped DMA_TO_DEVICE.
 *   ws_srclen- the reply length (server-known, bounded <= SVC_RDMA_MAX_WRITE).
 *   ws_src_dma / ws_src_mapped - ws_src DMA map + its idempotency token (sc_lock).
 *   ws_hdr   - the RDMA_NOMSG transport-header SEND buffer, malloc'd, DMA-mapped
 *              DMA_TO_DEVICE; carries the reply-chunk list with the actual length.
 *   ws_hdrlen- valid header bytes.
 *   ws_hdr_dma / ws_hdr_mapped - ws_hdr DMA map + its idempotency token (sc_lock).
 *   ws_active- the COMPLETION ONE-SHOT guard (sc_lock): set before the post,
 *              test-and-cleared at the top of svc_rdma_wc_rdma_write so exactly the
 *              FIRST of possibly-several completions (a partially-committed chained
 *              post can flush multiple WRs) does the free; later completions no-op.
 *              It does NOT gate reclaim (ws_*_mapped/ws_src/ws_hdr do).
 *   ws_nwr   - number of chained RDMA Write WRs (<= SVC_RDMA_MAX_WRITE_SEGS).
 *   ws_wr/ws_sge - the per-segment RDMA Write WR + its one SGE (into ws_src).
 *   ws_sndwr/ws_sndsge - the tail header SEND WR + its SGE (into ws_hdr).
 */
struct svc_rdma_write_state {
	TAILQ_ENTRY(svc_rdma_write_state) ws_link;
	struct ib_cqe		 ws_cqe;
	struct svc_rdma_conn	*ws_conn;
	void			*ws_src;	/* RDMA Write source (reply bytes) */
	uint32_t		 ws_srclen;
	u64			 ws_src_dma;
	bool			 ws_src_mapped;
	void			*ws_hdr;	/* RDMA_NOMSG header SEND buffer */
	uint32_t		 ws_hdrlen;
	u64			 ws_hdr_dma;
	bool			 ws_hdr_mapped;
	bool			 ws_active;	/* completion one-shot guard (sc_lock) */
	int			 ws_nwr;
	/*
	 * Zero-copy M_EXTPG page source (TASK_003f-19), used ONLY by
	 * svc_rdma_conn_write_list_pages; M_ZERO-clear on every other path so the
	 * write_free unmap/free is a no-op for reply_chunk and the contig write_list.
	 *   ws_npgs/ws_pg_dma/ws_pg_len - the per-page DMA maps of the read data;
	 *     ws_pages_mapped gates the unmap, which iterates ws_npgs (PAGES) and
	 *     NEVER ws_nwr (a WR may gather several pages).
	 *   ws_keepm - the source M_EXTPG mbuf chain; the engine owns it and
	 *     m_freem()s it in svc_rdma_write_free (the pages must outlive the Write).
	 */
	uint32_t		 ws_npgs;
	bool			 ws_pages_mapped;
	struct mbuf		*ws_keepm;
	u64			 ws_pg_dma[SVC_RDMA_MAX_WRITE_PAGES];
	uint32_t		 ws_pg_len[SVC_RDMA_MAX_WRITE_PAGES];
	struct ib_rdma_wr	 ws_wr[SVC_RDMA_MAX_WRITE_WRS];
	struct ib_sge		 ws_sge[SVC_RDMA_MAX_WRITE_SGE];
	struct ib_send_wr	 ws_sndwr;
	struct ib_sge		 ws_sndsge;
};

/*
 * One posted receive buffer.  rr_cqe.done is the completion callback the CQ
 * core dispatches (ib_cq.c: wc->wr_cqe->done(cq, wc)); rr_wr.wr_cqe aliases
 * &rr_cqe in the ib_recv_wr union, so a completion for this WR lands in
 * svc_rdma_wc_recv() with this exact rr_* in hand via container_of.
 *
 * rr_rs (TASK_003f-3) is this recv's durable inbound-read state.  At most ONE
 * RDMA Read is in flight per recv buffer at a time: the recv buffer is NOT
 * reposted while its read is outstanding (rr_rs.rs_active), so the read engine
 * never reuses rr_rs under a live read.  rr_rs.rs_cqe.rr is recovered by
 * container_of from rr_rs back to rr (see svc_rdma_wc_rdma_read).
 */
struct svc_rdma_recv {
	struct ib_cqe		 rr_cqe;
	struct svc_rdma_conn	*rr_conn;
	void			*rr_buf;	/* SVC_RDMA_INLINE bytes */
	u64			 rr_dma;	/* ib_dma_map_single() address */
	bool			 rr_mapped;	/* rr_dma is a live mapping */
	struct ib_sge		 rr_sge;
	struct ib_recv_wr	 rr_wr;
	struct svc_rdma_read_state rr_rs;	/* durable inbound-read state */
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
 * One fast-registration memory region from the per-connection FRWR pool
 * (TASK_003f-2).  This is the local MR the RDMA Read (3f-3) / RDMA Write (3f-4)
 * engines will fast-register over a SERVER buffer's scatter/gather list and use
 * as the lkey/rkey of the data transfer, then invalidate.
 *
 * sm_mr is the kernel fast-reg MR (ib_alloc_mr(IB_MR_TYPE_MEM_REG, max_pages));
 * its lifetime is the exact mirror of a recv/send buffer's: created at accept
 * time and ib_dereg_mr()'d in the drained teardown AFTER ib_drain_qp(), so no
 * REG_MR/LOCAL_INV completion can race the free.
 *
 * sm_cqe.done is the completion callback the CQ core dispatches for a REG_MR/
 * LOCAL_INV WR posted with this descriptor; sm_regwr.wr.wr_cqe / sm_invwr.wr_cqe
 * alias &sm_cqe so a completion lands in svc_rdma_wc_reg() with this sm_* in hand
 * via container_of().  sm_regwr is the prebuilt IB_WR_REG_MR work request the
 * register helper fills; sm_invwr is the IB_WR_LOCAL_INV that invalidates the
 * same MR (the FRWR reg+inv pair).
 *
 * sm_sg is a ONE-entry scatterlist describing the (contiguous, server-allocated)
 * buffer being registered; ib_map_mr_sg() turns it into the MR's page vector.
 * sm_sg_mapped tracks whether sm_sg currently holds a live ib_dma_map_sg()
 * mapping -- the MR-vs-DMA lifetime token: the DMA mapping that ib_map_mr_sg()
 * consumed MUST stay mapped until the MR is invalidated (LOCAL_INV completes) or
 * the connection is torn down, and is unmapped exactly once (on the LOCAL_INV
 * completion that releases the slot, or in the drained teardown for a slot still
 * mapped at close).  sm_inuse, under sc_lock, makes the pool a bounded free-list
 * exactly like ss_inuse.  sm_key is the rolling registration-key nibble
 * ib_update_fast_reg_key() rotates on every (re)registration so a stale rkey can
 * never be reused.
 */
struct svc_rdma_mr {
	struct ib_cqe		 sm_cqe;
	struct svc_rdma_conn	*sm_conn;
	struct ib_mr		*sm_mr;		/* fast-reg MR (max sm_pages) */
	struct scatterlist	 sm_sg[1];	/* one contiguous server buffer */
	bool			 sm_sg_mapped;	/* sm_sg holds a live DMA map */
	bool			 sm_inuse;	/* reserved from the pool (sc_lock) */
	u8			 sm_key;	/* rolling fast-reg key nibble */
	struct ib_reg_wr	 sm_regwr;	/* prebuilt IB_WR_REG_MR */
	struct ib_send_wr	 sm_invwr;	/* prebuilt IB_WR_LOCAL_INV */
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
 * The FRWR self-test (3f-2) posts its REG_MR+LOCAL_INV chain through the EXACT
 * same sc_sends arm (svc_rdma_mr_selftest increments sc_sends under SC_UP and
 * decrements after ib_post_send), so those SQ WRs are drained by this same
 * barrier before ib_drain_qp()/ib_dereg_mr() -- no separate accounting, no new
 * completion-vs-teardown race.
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
	struct svc_rdma_mr	*sc_mr;		/* sc_nmr FRWR pool (3f-2) */
	int			 sc_nmr;
	struct svc_rdma_readbuf	*sc_rbpool;	/* sc_nrbpool-element read-buffer pool */
	int			 sc_nrbpool;
	void			*sc_selftest_buf; /* private FRWR self-test buffer */
	u32			 sc_mr_pages;	/* per-MR page cap (device-bounded) */
	struct mtx		 sc_lock;
	enum {
		SC_CONNECTING = 0,
		SC_UP,
		SC_CLOSING
	}			 sc_state;
	int			 sc_reposts;	/* in-flight reposts (sc_lock) */
	int			 sc_sends;	/* in-flight reply sends (sc_lock) */
	/*
	 * Outbound RDMA Write state registry (TASK_003f-4).  A reply-chunk write is
	 * malloc'd on demand (it has no recv-buffer home) and threaded here under
	 * sc_lock so the drained teardown can reclaim a write still in flight at
	 * close -- the exact analogue of how rr_rs lets the teardown reclaim an
	 * in-flight read.  sc_sends accounts only the POST CALL (incremented before
	 * ib_post_send, decremented right after it RETURNS), NOT the async WR, so it
	 * is NOT the barrier that drains in-flight write WRs -- ib_drain_qp() is.
	 * This list owns the EXACTLY-ONCE free of a write's source/header buffers +
	 * DMA maps + the write state itself: by its completion if one runs, else by
	 * the post-drain teardown.
	 */
	TAILQ_HEAD(, svc_rdma_write_state) sc_writes;	/* in-flight writes (sc_lock) */
	/*
	 * Sink completion for the UNSIGNALED RDMA Write WRs of a chain (TASK_003f-20).
	 * On QP error every WR of a chain flushes, signaled or not; if the writes
	 * aliased &ws->ws_cqe (as the signaled tail SEND does) they would deliver
	 * DUPLICATE completions for one ws, and the first completion's free-then-
	 * recycle of the ws ADDRESS let a trailing duplicate re-match a recycled live
	 * ws and free it mid-post (ABA GPF under ~256 concurrent reads).  Routing the
	 * unsignaled writes to this per-conn sink instead means svc_rdma_wc_rdma_write
	 * runs EXACTLY ONCE per ws (only the signaled SEND), so no stale completion can
	 * ever alias a freed/recycled ws -- the write path is now ABA-immune like the
	 * recv/send pools.  Set once at accept, never freed until the drained teardown.
	 * The two counters are touched only by the (single-threaded) send-CQ workqueue.
	 */
	struct ib_cqe		 sc_write_sink_cqe;	/* unsignaled-write flush sink */
	uint64_t		 sc_write_sink_flushes;	/* write WRs flushed to sink */
	uint64_t		 sc_write_sink_errs;	/* non-flush write WR errors */
	uint32_t		 sc_max_send_sge;	/* granted send-SGE cap (3f-19) */
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
 * Rotating completion-vector assignment (TASK_003f-9 fix #2).  comp_vector
 * selects which device completion vector (MSI-X / per-core ib-comp workqueue)
 * a CQ's completions steer to.  Pinning every CQ to vector 0 funnels all RDMA
 * completion processing onto one core (the ~99%-idle/concurrency-1 symptom in
 * the WRITE benchmark); rotating per-connection, and putting a connection's send
 * and recv CQ on adjacent vectors, fans completion work across cores.  This is
 * ONLY a vector (steering) change -- each CQ still uses IB_POLL_WORKQUEUE with
 * one work item per CQ, so the per-CQ completion serialization the lockless
 * counters / teardown barrier rely on is unchanged.
 */
static volatile u_int svc_rdma_cqv;

/*
 * Last requested listen port; 0 means stopped.  This is the value the sysctl
 * read-back reports.  It is kept in sync with svc_rdma_listener.sl_id and is
 * read/written ONLY under sl_lock so the read-back can never be stale or
 * mismatched against the actual listener state (including when the CM core
 * destroys the id from under us on DEVICE_REMOVAL).
 */
static int svc_rdma_listen_port;

int svc_rdma_listen_start(uint16_t port);
void svc_rdma_listen_stop(void);

static int svc_rdma_accept(struct rdma_cm_id *id);
static void svc_rdma_conn_free_verbs(struct svc_rdma_conn *conn);
static void svc_rdma_conn_destroy(void *arg, int pending);
static void svc_rdma_conn_close(struct svc_rdma_conn *conn);
static int svc_rdma_parse_header(const void *buf, uint32_t len,
    struct svc_rdma_msg *out);
static void svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_reply(struct svc_rdma_conn *conn, uint32_t xid);
static int svc_rdma_send_error(struct svc_rdma_conn *conn, uint32_t xid,
    uint32_t errcode);
static void svc_rdma_wc_send(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_conn_peeraddr(struct svc_rdma_conn *conn,
    struct sockaddr_storage *ss);
static int svc_rdma_mr_reg(struct svc_rdma_conn *conn, struct svc_rdma_mr *sm,
    void *buf, uint32_t len, int access, uint32_t *rkeyp);
static void svc_rdma_mr_unmap(struct svc_rdma_conn *conn, struct svc_rdma_mr *sm);
static void svc_rdma_wc_reg(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_mr_selftest(struct svc_rdma_conn *conn);
static int svc_rdma_read_start(struct svc_rdma_conn *conn,
    struct svc_rdma_recv *rr, const struct svc_rdma_msg *msg, uint32_t len);
static void svc_rdma_wc_rdma_read(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_read_free(struct svc_rdma_conn *conn,
    struct svc_rdma_recv *rr);
static void svc_rdma_repost(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr);
static void svc_rdma_wc_rdma_write(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_wc_write_sink(struct ib_cq *cq, struct ib_wc *wc);
static void svc_rdma_write_free(struct svc_rdma_write_state *ws);
int svc_rdma_conn_write_list(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *write, void *src,
    uint32_t datalen, const void *reduced, uint32_t reducedlen);

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

				/*
				 * FRWR substrate self-test (TASK_003f-2).  Now
				 * that the conn is SC_UP, exercise the register/
				 * invalidate completion path once: post REG_MR +
				 * LOCAL_INV over a server buffer and let the
				 * send-side barrier (sc_sends) drain the single
				 * completion at teardown.  Only the SC_UP winner
				 * runs it, so it fires exactly once per conn.  It
				 * proves the 3f-3/3f-4 posting path works against
				 * the EXISTING teardown discipline without adding a
				 * new completion-vs-teardown race.  Run with the
				 * lock dropped (it claims sc_lock briefly itself);
				 * a failure only logs / closes via the shared path.
				 */
				svc_rdma_mr_selftest(conn);
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
 * ===========================================================================
 * RFC 8166 chunk-list decoder (TASK_003f-1).  UNTRUSTED-PEER PARSER.
 *
 * THE most security-critical code in the server: buf/len are bytes a hostile
 * NFS/RDMA client put in our recv buffer.  The decode is driven by a byte
 * cursor, *offp, that NEVER advances until the bytes it is about to read are
 * proven in range by svc_rdma_need().  Every be32dec/be64dec is preceded by a
 * need() check; a read that would pass len returns EBADMSG.  The chunk and
 * segment COUNTS are bounded by fixed caps (SVC_RDMA_MAX_CHUNKS /
 * SVC_RDMA_MAX_SEGS), NOT by any peer count, so no peer value drives an
 * allocation or an array index.  Per-segment length is range-checked
 * (0 < len <= SVC_RDMA_MAX_SEG_LEN) and the running per-chunk total is
 * overflow-checked against UINT32_MAX.  There is no malloc here at all: every
 * result lands in the fixed-size svc_rdma_msg the caller owns on the stack.
 * ===========================================================================
 */

/*
 * Cursor bound check: are there at least `need` more bytes at *offp within the
 * `len`-byte buffer?  All arithmetic in uint64_t so off + need cannot wrap
 * (off and need are each <= UINT32_MAX, so the sum fits in 64 bits and the
 * comparison is exact).  Returns true iff the read is in range.
 */
static __inline bool
svc_rdma_need(uint32_t off, uint32_t need, uint32_t len)
{

	return ((uint64_t)off + (uint64_t)need <= (uint64_t)len);
}

/*
 * Decode one RFC 8166 rdma_segment (4 words = 16 bytes): handle, length,
 * offset(64).  Advances *offp only after the whole segment is proven in range.
 * Validates the segment length is nonzero and within SVC_RDMA_MAX_SEG_LEN (a
 * zero-length segment is malformed; an absurd length is a hostile/overflowing
 * value).  Returns 0 or EBADMSG.
 */
static int
svc_rdma_decode_segment(const void *buf, uint32_t len, uint32_t *offp,
    struct svc_rdma_segment *seg)
{
	uint32_t off = *offp;

	if (!svc_rdma_need(off, RPCRDMA_SEG_WORDS * RPCRDMA_WORD, len))
		return (EBADMSG);

	seg->rs_handle = be32dec((const char *)buf + off);
	seg->rs_length = be32dec((const char *)buf + off + 4);
	seg->rs_offset = be64dec((const char *)buf + off + 8);
	off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;

	/* Reject a 0-length or oversized segment (untrusted length). */
	if (seg->rs_length == 0 || seg->rs_length > SVC_RDMA_MAX_SEG_LEN)
		return (EBADMSG);

	*offp = off;
	return (0);
}

/*
 * Decode the RFC 8166 read list: a chain where each entry is preceded by a
 * "1" (more) word, then { rdma_position, rdma_segment }, terminated by a "0".
 * Flattens into out->reads[], capping at SVC_RDMA_MAX_READ_SEGS.  A "more" word
 * that is neither 0 nor 1 is malformed.  Returns 0 or a positive errno.
 *
 * SINGLE rdma_position constraint (TASK_003f-3, NIT).  RFC 8166 4.3 permits a
 * read list whose segments carry DIFFERING rdma_position values (data spliced
 * into the XDR stream at several offsets).  The 3f-3 RDMA Read engine assembles
 * the read data as ONE contiguous run spliced at a SINGLE position
 * (reads[0].rc_position), so a multi-position read list would be mis-assembled.
 * We therefore REJECT (EOPNOTSUPP -- well-formed but not served) any read list
 * whose entries do not all share reads[0].rc_position.  This is the safe choice
 * the reviewer preferred over silently assuming a single position; a Linux NFS/
 * RDMA client always sends a single position for an NFS WRITE, so this rejects
 * only genuinely multi-position lists we do not yet handle.
 */
static int
svc_rdma_decode_read_list(const void *buf, uint32_t len, uint32_t *offp,
    struct svc_rdma_msg *out)
{
	uint32_t off = *offp;
	uint32_t more, position;
	int rc;

	out->rd_nchunks = 0;
	for (;;) {
		/* The 1/0 "more" discriminator. */
		if (!svc_rdma_need(off, RPCRDMA_WORD, len))
			return (EBADMSG);
		more = be32dec((const char *)buf + off);
		off += RPCRDMA_WORD;

		if (more == 0)			/* end of read list */
			break;
		if (more != 1)			/* only 0/1 are valid */
			return (EBADMSG);

		/* Fixed cap: more read segments than we will serve -> reject. */
		if (out->rd_nchunks >= SVC_RDMA_MAX_READ_SEGS)
			return (EOPNOTSUPP);

		/* rdma_position (1 word) + rdma_segment (4 words). */
		if (!svc_rdma_need(off, RPCRDMA_WORD, len))
			return (EBADMSG);
		position = be32dec((const char *)buf + off);
		off += RPCRDMA_WORD;

		/*
		 * Enforce the single-position constraint: every entry must repeat
		 * reads[0].rc_position.  A differing position is a well-formed list
		 * the single-splice assembler cannot serve -> EOPNOTSUPP.
		 */
		if (out->rd_nchunks != 0 &&
		    position != out->reads[0].rc_position)
			return (EOPNOTSUPP);
		out->reads[out->rd_nchunks].rc_position = position;

		rc = svc_rdma_decode_segment(buf, len, &off,
		    &out->reads[out->rd_nchunks].rc_seg);
		if (rc != 0)
			return (rc);

		out->rd_nchunks++;
	}

	*offp = off;
	return (0);
}

/*
 * Decode one RFC 8166 write chunk: a COUNTED segment array { nsegs,
 * rdma_segment[nsegs] }.  nsegs is peer-supplied -> capped at
 * SVC_RDMA_MAX_SEGS (a larger count is rejected, never used to size anything).
 * Accumulates the segment lengths into wc_total, rejecting a uint32_t overflow.
 * Returns 0 or a positive errno.
 */
static int
svc_rdma_decode_write_chunk(const void *buf, uint32_t len, uint32_t *offp,
    struct svc_rdma_write_chunk *wc)
{
	uint32_t off = *offp;
	uint32_t nsegs, i;
	int rc;

	/* nsegs (1 word). */
	if (!svc_rdma_need(off, RPCRDMA_WORD, len))
		return (EBADMSG);
	nsegs = be32dec((const char *)buf + off);
	off += RPCRDMA_WORD;

	/* Fixed cap: a peer count over the cap is rejected, not allocated. */
	if (nsegs == 0 || nsegs > SVC_RDMA_MAX_SEGS)
		return (EOPNOTSUPP);

	wc->wc_nsegs = 0;
	wc->wc_total = 0;
	for (i = 0; i < nsegs; i++) {
		rc = svc_rdma_decode_segment(buf, len, &off, &wc->wc_segs[i]);
		if (rc != 0)
			return (rc);

		/*
		 * Overflow-checked running total.  Each rs_length is already
		 * <= SVC_RDMA_MAX_SEG_LEN (1<<30); reject if adding it would
		 * exceed UINT32_MAX so wc_total is always exact.
		 */
		if (wc->wc_segs[i].rs_length > UINT32_MAX - wc->wc_total)
			return (EBADMSG);
		wc->wc_total += wc->wc_segs[i].rs_length;
		wc->wc_nsegs++;
	}

	*offp = off;
	return (0);
}

/*
 * Decode the RFC 8166 write list: a chain where each entry is preceded by a
 * "1", then one counted write chunk, terminated by a "0".  Caps at
 * SVC_RDMA_MAX_CHUNKS.  Returns 0 or a positive errno.
 */
static int
svc_rdma_decode_write_list(const void *buf, uint32_t len, uint32_t *offp,
    struct svc_rdma_msg *out)
{
	uint32_t off = *offp;
	uint32_t more;
	int rc;

	out->wr_nchunks = 0;
	for (;;) {
		if (!svc_rdma_need(off, RPCRDMA_WORD, len))
			return (EBADMSG);
		more = be32dec((const char *)buf + off);
		off += RPCRDMA_WORD;

		if (more == 0)			/* end of write list */
			break;
		if (more != 1)
			return (EBADMSG);

		if (out->wr_nchunks >= SVC_RDMA_MAX_CHUNKS)
			return (EOPNOTSUPP);

		rc = svc_rdma_decode_write_chunk(buf, len, &off,
		    &out->writes[out->wr_nchunks]);
		if (rc != 0)
			return (rc);

		out->wr_nchunks++;
	}

	*offp = off;
	return (0);
}

/*
 * Decode the RFC 8166 reply chunk: optional-data -- a "1" then ONE counted
 * write chunk, or a "0" if absent.  Returns 0 or a positive errno.
 */
static int
svc_rdma_decode_reply_chunk(const void *buf, uint32_t len, uint32_t *offp,
    struct svc_rdma_msg *out)
{
	uint32_t off = *offp;
	uint32_t present;
	int rc;

	out->reply_present = false;

	if (!svc_rdma_need(off, RPCRDMA_WORD, len))
		return (EBADMSG);
	present = be32dec((const char *)buf + off);
	off += RPCRDMA_WORD;

	if (present == 0) {			/* no reply chunk */
		*offp = off;
		return (0);
	}
	if (present != 1)
		return (EBADMSG);

	rc = svc_rdma_decode_write_chunk(buf, len, &off, &out->reply);
	if (rc != 0)
		return (rc);

	out->reply_present = true;
	*offp = off;
	return (0);
}

/*
 * Parse and validate the RFC 8166 RPC-over-RDMA version 1 transport header that
 * prefixes a call, decode any chunk lists into the bounded svc_rdma_msg, and
 * locate the inline RPC payload.
 *
 * UNTRUSTED PEER.  buf/len describe bytes the remote (a possibly-hostile NFS/
 * RDMA client) sent into our recv buffer; len is wc->byte_len, already clamped
 * by the caller to <= SVC_RDMA_INLINE (the posted SGE length).  EVERY wire word
 * we read is gated by len BEFORE the read (svc_rdma_need + the cursor model
 * above), so a short, truncated, oversized, or otherwise malformed header can
 * only produce a clean error return -- never an overread, never a panic, never
 * a peer-count-driven allocation.
 *
 * Bounds model: the FIXED prefix is word0..word3 (bytes [0,16)); one up-front
 * len >= RPCRDMA_HDR_FIXED gate authorizes those four be32dec()s.  Everything
 * after word3 is variable-length and is walked by the byte cursor `off`, which
 * each sub-decoder advances ONLY after svc_rdma_need() proves the next read is
 * in range.  We do NOT cast buf to uint32_t*: be32dec/be64dec read byte-by-byte
 * (endian- and alignment-safe) per <sys/endian.h>.
 *
 * Returns 0 and fills *out for any well-formed RDMA_MSG/RDMA_NOMSG, including
 * one bearing valid (bounded) read/write/reply chunks.  For RDMA_MSG the inline
 * body is whatever bytes remain after the chunk lists (out->rpc/rpc_len); for
 * RDMA_NOMSG there is no inline body and rpc_len is 0.  Returns a positive errno
 * for anything malformed or out of our caps:
 *   EBADMSG   - too short / truncated, wrong version, a non-MSG/NOMSG proc, a
 *               bad discriminator, a 0/oversized segment, or a length overflow.
 *   EOPNOTSUPP- well-formed but exceeding a fixed cap (too many chunks, too many
 *               segments in a chunk) -- a request we will not serve.
 * On any nonzero return *out must be treated as undefined and no pointer into
 * buf escapes.
 */
static int
svc_rdma_parse_header(const void *buf, uint32_t len, struct svc_rdma_msg *out)
{
	uint32_t vers, proc, off;
	int rc;

	/*
	 * Fixed-prefix gate.  Reject anything that cannot contain the four-word
	 * (16-byte) fixed header.  This one check authorizes the be32dec()s at
	 * offsets 0,4,8,12 (all < 16 <= len).  Past word3 every read is gated by
	 * the cursor.
	 */
	if (len < RPCRDMA_HDR_FIXED)
		return (EBADMSG);

	/*
	 * word1: version MUST be 1 (RFC 8166 4.2).  A mismatch is DISTINGUISHED
	 * from generic malformation: the fixed-prefix gate above proved len >=
	 * RPCRDMA_HDR_FIXED, so word0 (rdma_xid) is in range and READABLE even
	 * though we decode nothing else.  Stamp out->xid from word0 (the init
	 * block below, which normally sets it, is reached only on the success
	 * path) and return a DISTINCT code -- EPROTONOSUPPORT, not EBADMSG -- so
	 * the recv path can reply RDMA_ERROR/ERR_VERS keyed by that real xid
	 * before closing the mismatched connection (RFC 8166 4.4/5).  On this
	 * return only out->xid is defined; every other out field is undefined and
	 * the caller touches only out->xid.
	 */
	vers = be32dec((const char *)buf + 4);
	if (vers != RPCRDMA_VERSION) {
		out->xid = be32dec((const char *)buf + 0);	/* word0 */
		return (EPROTONOSUPPORT);
	}

	/*
	 * word3: rdma_proc.  We decode chunk lists for RDMA_MSG and RDMA_NOMSG
	 * (both carry the read/write/reply lists, RFC 8166 4.3); any other proc
	 * (RDMA_MSGP/RDMA_DONE/RDMA_ERROR/unknown) is well-formed but not served:
	 * EOPNOTSUPP -> close (RDMA_DONE belongs to the deprecated read-read model;
	 * RDMA_ERROR is a server->client reply; none are valid client->server v1).
	 */
	proc = be32dec((const char *)buf + 12);
	if (proc != RDMA_MSG && proc != RDMA_NOMSG)
		return (EOPNOTSUPP);	/* well-formed v1 header, proc not served (RFC 8166) */

	/* Initialize the bounded output; sub-decoders fill the counts. */
	out->xid     = be32dec((const char *)buf + 0);	/* word0 */
	out->credit  = be32dec((const char *)buf + 8);	/* word2 */
	out->rdma_proc = proc;
	out->rd_nchunks = 0;
	out->wr_nchunks = 0;
	out->reply_present = false;
	out->rpc = NULL;
	out->rpc_len = 0;

	/*
	 * Walk the three chunk lists IN ORDER from just past word3.  Each
	 * sub-decoder advances `off` only across bytes it proved in range.
	 */
	off = RPCRDMA_HDR_FIXED;
	rc = svc_rdma_decode_read_list(buf, len, &off, out);
	if (rc != 0)
		return (rc);
	rc = svc_rdma_decode_write_list(buf, len, &off, out);
	if (rc != 0)
		return (rc);
	rc = svc_rdma_decode_reply_chunk(buf, len, &off, out);
	if (rc != 0)
		return (rc);

	/*
	 * After the chunk lists, what remains is the inline body.  For RDMA_MSG
	 * that is the inline ONC RPC message (may be 0 bytes -- still in range
	 * because `off` never passed len).  For RDMA_NOMSG there is no inline
	 * body; leave rpc_len 0.  off <= len is guaranteed by the cursor, so
	 * len - off does not underflow.
	 */
	if (proc == RDMA_MSG) {
		out->rpc = (const char *)buf + off;
		out->rpc_len = len - off;
	}
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
 * The success path parses the RFC 8166 transport header (3c) and decodes any
 * read/write/reply chunk lists into the bounded svc_rdma_msg (3f-1):
 *   - a clean PURE-INLINE RDMA_MSG (no chunks) is logged (xid/credit/inline rpc
 *     bytes), dispatched to the consumer, and the recv buffer reposted via the
 *     unchanged 3b SC_UP-gated barrier -- the pre-3f behavior, unchanged;
 *   - a well-formed CHUNK-BEARING request decodes its chunk metadata into bounded
 *     structs, is LOGGED with its read/write/reply segment counts, and -- because
 *     the RDMA Read/Write data engine is 3f-3/3f-4, not yet present -- is closed
 *     cleanly as "decoded but not yet served" (we must NOT hand it to the inline
 *     stub, which would fabricate an inline reply ignoring the chunks);
 *   - a hard protocol violation (too short/truncated, bad version, unsupported
 *     proc, bad discriminator, 0/oversized segment, overflow) or a request over a
 *     fixed cap is logged with its reason and the connection closed via the 3b
 *     deferred teardown path -- we do NOT repost a connection we are tearing down.
 * The RDMA Read/Write data path (acting on the decoded chunks) is 3f-3..3f-5.
 */
static void
svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	struct svc_rdma_msg msg;
	uint32_t len;
	int rc;
	bool ready;

	/*
	 * Invariant guard (review N2): this handler -- and the sc_lock-protected
	 * quiescence counters sc_reposts/sc_sends/sc_upcalls it drives -- relies on
	 * IB_POLL_WORKQUEUE for its completion model.  Each CQ is polled by its own
	 * workqueue work item, and a work_struct cannot run concurrently with itself,
	 * so completions ON ONE CQ are serialized (the send CQ and recv CQ are
	 * distinct work items and MAY run concurrently on two CPUs; the counters are
	 * therefore maintained under sc_lock, and the teardown waits them out under
	 * sc_lock -- it is sc_lock, not a single per-conn thread, that serializes the
	 * counter updates).  If a future change allocated the CQ with
	 * IB_POLL_DIRECT/SOFTIRQ the completion would run in an unexpected context and
	 * reopen a completion-vs-teardown hazard; assert the context so that mistake
	 * trips INVARIANTS here instead of failing silently.
	 */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

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
		 * Parse rejected the message (UNTRUSTED-PEER reject path):
		 *   EBADMSG    - too short/truncated, bad version, unsupported
		 *                proc, bad chunk discriminator, a 0/oversized
		 *                segment, or a length overflow.
		 *   EOPNOTSUPP - well-formed but over a FIXED CAP (too many chunks
		 *                or too many segments in a chunk) -- not served.
		 * Log the reason (rate-limited -- the arrival rate is peer-
		 * controlled) and close the connection via the 3b deferred
		 * teardown path.  We deliberately do NOT repost: this connection
		 * is being torn down, and the SC_CLOSING gate below would skip the
		 * repost once conn_close() publishes SC_CLOSING anyway.
		 */
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
			if (rc == EPROTONOSUPPORT)
				printf("nfsrdma: RPC-over-RDMA version unsupported "
				    "xid=0x%08x, replying ERR_VERS and closing\n",
				    msg.xid);
			else if (rc == EOPNOTSUPP)
				printf("nfsrdma: unsupported RPC-over-RDMA "
				    "request (proc or over fixed cap), closing "
				    "(%u bytes)\n", len);
			else
				printf("nfsrdma: malformed RPC-over-RDMA header "
				    "(%u bytes), closing\n", len);
		}
		/*
		 * (A) ERR_VERS (RFC 8166 4.4/5).  ONLY the version-mismatch return
		 * (EPROTONOSUPPORT) leaves a trustworthy xid: parse_header proved the
		 * fixed prefix was present and stamped msg.xid before bailing.  Reply
		 * RDMA_ERROR/ERR_VERS carrying our supported version range on the
		 * still-SC_UP conn, THEN close.  The SEND is posted through the same
		 * SC_UP-gated, sc_sends-counted bounded pool as every reply, so
		 * posting it BEFORE svc_rdma_conn_close() publishes SC_CLOSING is
		 * safe: the in-flight WR is drained by the close's sc_sends barrier
		 * ahead of ib_drain_qp(), and a racing close makes the post a benign
		 * ENOTCONN drop.  Every other rc (EBADMSG/EOPNOTSUPP) has NO
		 * guaranteed-readable xid (the header may be too short), so we MUST
		 * NOT fabricate an RDMA_ERROR -- we just close, exactly as before.
		 */
		if (rc == EPROTONOSUPPORT)
			svc_rdma_send_error(conn, msg.xid, ERR_VERS);
		svc_rdma_conn_close(conn);
		return;
	}

	/*
	 * Well-formed and within caps.  Route by chunk shape:
	 *
	 *   - A request bearing a WRITE list or a REPLY chunk (NFS READ result /
	 *     large reply), or RDMA_NOMSG whose whole call travels by chunk with NO
	 *     read list to pull, is the RDMA Write engine's job (3f-4) -- still
	 *     decoded-but-not-served here.  Closing cleanly is correct: the inline
	 *     stub would fabricate an inline reply and ignore the client's chunks.
	 *
	 *   - A request bearing a READ list (NFS WRITE / large call argument) and NO
	 *     write list / reply chunk is the RDMA Read engine's job (3f-3, THIS
	 *     increment).  We must NOT repost rr_buf yet and must NOT dispatch inline:
	 *     the call body is not fully in our memory until the async RDMA Read
	 *     completes.  Hand off to svc_rdma_read_start(), which copies the chunk
	 *     metadata + inline head into the recv's DURABLE rr_rs (so nothing points
	 *     into rr_buf once we return), allocates+maps a server buffer, and posts
	 *     the read chain.  The read completion (svc_rdma_wc_rdma_read) assembles
	 *     the body, dispatches sro_recv, frees the buffer, and reposts rr_buf.
	 *     On a start error we close; on success we return WITHOUT reposting (the
	 *     read owns rr_buf until completion).
	 */
	/*
	 * A WRITE list (the client's destination for an NFS READ result) still
	 * needs the write-list RDMA Write case -- deferred; close cleanly.  An
	 * RDMA_NOMSG with no read list has no inline call body to serve.  Every
	 * other request with an inline call body (RDMA_MSG) IS served now,
	 * INCLUDING one that offers a REPLY chunk for an over-inline reply: the
	 * body is inline, so we dispatch it exactly like any inline call (below);
	 * the parsed reply chunk travels to the consumer in msg.reply, and the
	 * consumer's xp_reply replies inline when it fits or RDMA-Writes the reply
	 * into the reply chunk (TASK_003f-4) when it does not.  A request that ALSO
	 * carries a read list is handled by the RDMA Read engine below, which
	 * copies the whole parsed msg -- reply chunk included -- into rs_msg, so
	 * the post-read dispatch carries the reply chunk too (TASK_003f-5).
	 */
	/*
	 * Only a bodyless RDMA_NOMSG with no read list is unserveable (there is no
	 * inline call body and no read chunk to assemble one) -- close it.  A
	 * request that carries a WRITE list (the client's destination for an NFS
	 * READ result) is now DISPATCHED: its call body is inline, so we serve it
	 * like any inline call and reply inline when the result fits.  The write
	 * list itself is not yet used to RDMA-Write a large result into the client
	 * (that is the write-list data path, a separate increment); a result too
	 * large for the inline reply is dropped by xp_reply with no reply chunk,
	 * exactly as before -- but small reads (and the mount's own ops) succeed.
	 */
	if (msg.rdma_proc == RDMA_NOMSG && msg.rd_nchunks == 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: RPC-over-RDMA v1 RDMA_NOMSG xid=0x%08x "
			    "credit=%u no read list (bodyless), closing\n",
			    msg.xid, msg.credit);
		svc_rdma_conn_close(conn);
		return;
	}

	if (msg.rd_nchunks != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: RPC-over-RDMA v1 %s xid=0x%08x credit=%u "
			    "read_list=%u segs inline head=%u bytes (RDMA Read)\n",
			    msg.rdma_proc == RDMA_NOMSG ? "RDMA_NOMSG" :
			    "RDMA_MSG", msg.xid, msg.credit, msg.rd_nchunks,
			    msg.rpc_len);
		rc = svc_rdma_read_start(conn, rr, &msg, len);
		if (rc != 0)
			svc_rdma_conn_close(conn);
		/*
		 * On success the read owns rr_buf until svc_rdma_wc_rdma_read
		 * reposts it; on failure the conn is closing and the teardown
		 * reclaims rr_buf.  Either way: do NOT repost here.
		 */
		return;
	}

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: RPC-over-RDMA v1 RDMA_MSG xid=0x%08x credit=%u "
		    "inline rpc=%u bytes reply_chunk=%u (dispatching)\n",
		    msg.xid, msg.credit, msg.rpc_len,
		    msg.reply_present ? msg.reply.wc_nsegs : 0);

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
	svc_rdma_repost(conn, rr);
}

/*
 * Repost one recv buffer to keep the receive queue from starving -- while the
 * connection is NOT SC_CLOSING (admitting SC_CONNECTING as well as SC_UP), and
 * under an in-flight repost refcount (sc_reposts) that the teardown task drains
 * before it calls ib_drain_qp().  This closes a post-after-drain UAF: mlx5's
 * ib_post_recv does NOT reject an ERR-state QP, so without the barrier a repost
 * that sampled a non-closing state, dropped the lock, then lost the CPU could
 * enqueue a WR AFTER the drain sentinel; that WR's flush completion would fire
 * against an already-freed conn/recv.
 *
 * Factored out of svc_rdma_wc_recv (TASK_003f-3) so the RDMA Read completion can
 * repost the SAME recv buffer once it has consumed the inbound data -- a recv
 * whose request bore a read list is NOT reposted by the recv handler; the read
 * completion reposts it here after the assembled body is dispatched.  Behavior is
 * byte-for-byte the former inline repost block.
 *
 * The gate is SC_CLOSING-based, not SC_UP-based (TASK_003e-1 SHOULD-FIX): a peer
 * that sends an RPC before ESTABLISHED leaves the conn SC_CONNECTING, and the
 * recv path drops+reposts that early call -- if the repost required SC_UP it
 * would decline, depleting the RQ one buffer per early call until RNR.  Admitting
 * SC_CONNECTING recycles the buffer so the RQ stays full.  Post-after-drain
 * safety is UNCHANGED: svc_rdma_conn_close() publishes SC_CLOSING under sc_lock
 * BEFORE enqueuing the teardown, so once teardown is pending NO new repost passes
 * the SC_CLOSING check; the task's barrier then waits only for already-counted
 * reposts to finish their ib_post_recv and decrement.  After the count hits 0
 * every posted WR is on the QP before ib_drain_qp(), so the drain catches them
 * all and nothing posts afterward.
 *
 * Sequence: take sc_lock; if SC_CLOSING, bail (the teardown owns this buffer and
 * reclaims it after ib_drain_qp(), so skipping the repost cannot leak).
 * Otherwise bump sc_reposts and drop the lock before the (non-sleeping;
 * mlx5_ib_post_recv only takes the RQ spinlock) ib_post_recv.  Reacquire,
 * decrement, and wake the teardown (on the shared &sc_upcalls channel) if we
 * were the last in-flight repost.
 */
static void
svc_rdma_repost(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr)
{
	const struct ib_recv_wr *bad_wr;
	int rc;

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
 * ===========================================================================
 * RDMA Read engine -- inbound NFS WRITE / large-call data (TASK_003f-3).
 *
 * For a request bearing a read list, the CLIENT has registered memory it wants
 * us to RDMA-READ FROM (the data of an NFS WRITE, or a large call argument).
 * Each read-list segment is a peer-supplied { rs_handle(rkey), rs_offset(remote
 * virtual address), rs_length }.  We pull every segment into one contiguous
 * server destination buffer, splice it together with the inline head at the
 * read list's rdma_position (RFC 8166 4.3), and hand the assembled call body to
 * the consumer's sro_recv -- so nfsd sees the full NFS WRITE.
 *
 * UNTRUSTED PEER (RFC 8166 5) -- re-validated AT POST TIME, not trusted from the
 * parse:
 *   - every rs_length re-checked in (0, SVC_RDMA_MAX_SEG_LEN];
 *   - the segment/WR count re-checked <= SVC_RDMA_MAX_READ_SEGS;
 *   - the running SUM re-checked against SVC_RDMA_MAX_READ (1 MiB) with no
 *     uint32 overflow -- the server buffer is sized by THIS bounded sum, never
 *     by an unbounded peer total;
 *   - rs_handle(rkey) and rs_offset are passed VERBATIM to the HCA: the hardware
 *     enforces the rkey against the client's MR, so a bad rkey/addr fails the WR
 *     with an error completion, which we handle by CLOSING -- never by trusting.
 * A read that fails for any reason is a clean close, never a panic/overread.
 *
 * COMPLETION-vs-TEARDOWN lifetime (the #1 hazard), mirroring 3f-2 exactly:
 *   - the read WR chain is accounted in sc_sends (armed only under SC_UP), so the
 *     drained teardown's barrier waits it out before ib_drain_qp();
 *   - the server destination buffer + its DMA mapping live in the recv's DURABLE
 *     rr_rs and are freed/unmapped EXACTLY ONCE -- on the read completion, or by
 *     the teardown for a read still in flight at close (rs_active/rs_mapped
 *     idempotency, the sm_sg_mapped pattern);
 *   - svc_rdma_conn_close() publishes SC_CLOSING before enqueuing the teardown,
 *     so once teardown is pending no new read passes the SC_UP gate.
 * ===========================================================================
 */

/*
 * Kick off the RDMA Read for a request whose read list we just parsed.  Called
 * from the recv completion (IB_POLL_WORKQUEUE) with the parsed msg still pointing
 * into rr_buf; len is the clamped recv byte length.  On success a read chain is
 * on the SQ, accounted in sc_sends, and rr_buf is OWNED by the read until the
 * completion reposts it -- the caller must NOT repost.  Returns 0 on success or a
 * positive errno (the caller closes the conn on error; this routine has already
 * released everything it allocated before returning nonzero).
 *
 * Durability: BEFORE posting, copy the parsed msg (the bounded chunk arrays) and
 * the inline head bytes into the recv's durable rr_rs, so nothing the read or its
 * completion touches points into rr_buf (which 3b reposts as soon as a recv
 * handler returns -- but here we do not repost, and the durable copy means even a
 * future repost cannot corrupt the read state).
 */
static int
svc_rdma_read_start(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr,
    const struct svc_rdma_msg *msg, uint32_t len)
{
	struct svc_rdma_read_state *rs = &rr->rr_rs;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t total;
	uint32_t i, n;
	int rc;

	n = msg->rd_nchunks;

	/*
	 * Re-validate the read-list SHAPE at post time (untrusted peer).  The
	 * parser already enforced n <= SVC_RDMA_MAX_READ_SEGS and each rs_length in
	 * (0, SVC_RDMA_MAX_SEG_LEN]; re-assert here so this engine is correct
	 * independent of the parser's caps and so a future parser change cannot
	 * silently let an over-cap request reach the HCA.
	 */
	if (n == 0 || n > SVC_RDMA_MAX_READ_SEGS)
		return (EINVAL);

	/*
	 * Re-compute and re-bound the TOTAL inbound length.  uint64 accumulation
	 * cannot wrap (each rs_length <= 1<<30, n <= SVC_RDMA_MAX_READ_SEGS (64) ->
	 * at most 2^36, far under UINT64_MAX).  Reject 0 (a read list of
	 * only zero-length segments is malformed -- though the parser already
	 * rejects a 0-length segment) and anything over the whole-request cap.  The
	 * server buffer is sized by THIS value, never by a raw peer field.
	 */
	total = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = msg->reads[i].rc_seg.rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN)
			return (EINVAL);
		total += slen;
	}
	if (total == 0 || total > SVC_RDMA_MAX_READ)
		return (EMSGSIZE);

	/*
	 * Copy the parsed call + inline head into the DURABLE rr_rs.  After this no
	 * field the read or its completion uses points into rr_buf.  rs_head holds
	 * the inline bytes (the head the read data splices into at rdma_position);
	 * cap the copy at SVC_RDMA_INLINE (len is already clamped to it).
	 */
	rs->rs_msg = *msg;			/* durable copy of chunk arrays */
	rs->rs_total = (uint32_t)total;
	rs->rs_headlen = msg->rpc_len;
	/*
	 * Defense in depth: rpc_len is (len - chunk-list bytes) and so already
	 * <= len <= SVC_RDMA_INLINE, but clamp explicitly to the received byte
	 * count and the buffer size so a malformed rpc_len can never drive a copy
	 * past the bytes that actually landed in rr_buf.
	 */
	if (rs->rs_headlen > len)
		rs->rs_headlen = len;
	if (rs->rs_headlen > SVC_RDMA_INLINE)
		rs->rs_headlen = SVC_RDMA_INLINE;
	rs->rs_head = malloc(SVC_RDMA_INLINE, M_NFSRDMA, M_NOWAIT);
	if (rs->rs_head == NULL)
		return (ENOMEM);
	if (rs->rs_headlen != 0)
		memcpy(rs->rs_head, msg->rpc, rs->rs_headlen);

	/*
	 * Grab a pre-mapped pool buffer if one is free (TASK_003f-8 fast path):
	 * no per-write contigmalloc/map.  rs_rb records the borrow; rs_mapped stays
	 * FALSE (the pool owns the permanent mapping -- it must NOT be unmapped per
	 * read).  Fall back to a per-read contigmalloc+map if the pool is empty.
	 *
	 * contigmalloc: rs_buf must be PHYSICALLY contiguous -- ib_dma_map_single maps
	 * one contiguous region (vtophys of the first page); a scattered multi-page
	 * malloc buffer would land the RDMA-Read data in the wrong physical pages
	 * (TASK_003f-3 data-corruption fix).  Freed with free() (contigfree deprecated).
	 */
	rs->rs_rb = NULL;
	mtx_lock(&conn->sc_lock);
	{
		int rbk;
		for (rbk = 0; rbk < conn->sc_nrbpool; rbk++) {
			if (!conn->sc_rbpool[rbk].rb_inuse) {
				conn->sc_rbpool[rbk].rb_inuse = true;
				rs->rs_rb = &conn->sc_rbpool[rbk];
				break;
			}
		}
	}
	mtx_unlock(&conn->sc_lock);
	/*
	 * RE-STOCK an evacuated slot (TASK_003f-3, Edit 7).  A prior zero-copy
	 * detach handed this slot's buffer to an mbuf and left rb_buf == NULL
	 * (rb_mapped == false).  Re-stock it lazily here -- OFF the latency path
	 * (the read that evacuated it already completed) and OUTSIDE sc_lock so the
	 * contigmalloc/map does not nest the DMA lock under sc_lock (the same
	 * lock-order discipline svc_rdma_read_free relies on).  On failure, return
	 * the slot to the pool and fall through to the per-read fallback alloc.
	 */
	if (rs->rs_rb != NULL && rs->rs_rb->rb_buf == NULL) {
		struct svc_rdma_readbuf *rb = rs->rs_rb;
		void *nbuf;
		u64 ndma;

		nbuf = contigmalloc(SVC_RDMA_MAX_READ, M_NFSRDMA, M_NOWAIT, 0,
		    ~(vm_paddr_t)0, PAGE_SIZE, 0);
		if (nbuf != NULL) {
			ndma = ib_dma_map_single(dev, nbuf, SVC_RDMA_MAX_READ,
			    DMA_FROM_DEVICE);
			if (ib_dma_mapping_error(dev, ndma)) {
				free(nbuf, M_NFSRDMA);
				nbuf = NULL;
			}
		}
		if (nbuf == NULL) {
			/* Re-stock failed: release the slot, take the fallback. */
			mtx_lock(&conn->sc_lock);
			rb->rb_inuse = false;
			mtx_unlock(&conn->sc_lock);
			rs->rs_rb = NULL;
		} else {
			rb->rb_buf = nbuf;
			rb->rb_dma = ndma;
			rb->rb_mapped = true;
		}
	}
	if (rs->rs_rb != NULL) {
		rs->rs_buf = rs->rs_rb->rb_buf;
		rs->rs_dma = rs->rs_rb->rb_dma;
		rs->rs_mapped = false;	/* pool owns the mapping; not per-read */
		/* Hand the buffer to the device for this read (DMA_FROM_DEVICE). */
		ib_dma_sync_single_for_device(dev, rs->rs_dma, rs->rs_total,
		    DMA_FROM_DEVICE);
	} else {
		/* Fallback: per-read contigmalloc + map (the original path). */
		rs->rs_buf = contigmalloc(rs->rs_total, M_NFSRDMA, M_NOWAIT, 0,
		    ~(vm_paddr_t)0, PAGE_SIZE, 0);
		if (rs->rs_buf == NULL) {
			free(rs->rs_head, M_NFSRDMA);
			rs->rs_head = NULL;
			return (ENOMEM);
		}
		rs->rs_dma = ib_dma_map_single(dev, rs->rs_buf, rs->rs_total,
		    DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(dev, rs->rs_dma)) {
			free(rs->rs_buf, M_NFSRDMA);
			rs->rs_buf = NULL;
			free(rs->rs_head, M_NFSRDMA);
			rs->rs_head = NULL;
			return (EIO);
		}
		/*
		 * BLOCKER 1 fix: mark the mapping live IMMEDIATELY after a successful
		 * map, BEFORE the SC_UP check below.  svc_rdma_read_free unmaps iff
		 * rs_mapped, so any reclaim after this point (the SC_UP-lost-race
		 * early-out, or the drained teardown) unmaps exactly once.  Setting
		 * it only inside the SC_UP branch left a window where a teardown
		 * racing between the map and the lock would free() rs_buf with the DMA
		 * mapping still live (leaked mapping + device translation onto freed
		 * memory) -- remotely triggerable by a mid-flight disconnect.  It is
		 * plain memory the recv owns until the post, so setting it before
		 * taking sc_lock is safe (no completion can reach rr_rs yet: nothing
		 * is posted).
		 */
		rs->rs_mapped = true;	/* fallback mapping; read_free unmaps it */
	}

	/*
	 * Build the RDMA Read WR chain: one IB_WR_RDMA_READ per read segment, each
	 * with a single local SGE pointing at the running offset within rs_buf
	 * (lkey = the PD's local_dma_lkey -- the server dest is local memory, no
	 * FRWR registration needed for the SINK of a read), and the peer's
	 * { rkey, remote_addr } passed VERBATIM as wr.rdma.{rkey, remote_addr}.
	 * Chain them next->next and SIGNAL ONLY THE LAST so a single completion
	 * fires for the whole chain.  rs_cqe.done routes that completion to
	 * svc_rdma_wc_rdma_read; every WR's wr_cqe aliases &rs_cqe so the (last)
	 * completion recovers rs via container_of.
	 */
	{
		uint32_t off = 0;

		rs->rs_nwr = n;
		rs->rs_cqe.done = svc_rdma_wc_rdma_read;
		for (i = 0; i < n; i++) {
			const struct svc_rdma_segment *seg =
			    &msg->reads[i].rc_seg;
			uint32_t slen = seg->rs_length;

			rs->rs_sge[i].addr = rs->rs_dma + off;
			rs->rs_sge[i].length = slen;
			rs->rs_sge[i].lkey = conn->sc_pd->local_dma_lkey;

			memset(&rs->rs_wr[i], 0, sizeof(rs->rs_wr[i]));
			rs->rs_wr[i].wr.wr_cqe = &rs->rs_cqe;
			rs->rs_wr[i].wr.sg_list = &rs->rs_sge[i];
			rs->rs_wr[i].wr.num_sge = 1;
			rs->rs_wr[i].wr.opcode = IB_WR_RDMA_READ;
			rs->rs_wr[i].wr.send_flags = 0;
			rs->rs_wr[i].remote_addr = seg->rs_offset;
			rs->rs_wr[i].rkey = seg->rs_handle;
			rs->rs_wr[i].wr.next = (i + 1 < n) ?
			    &rs->rs_wr[i + 1].wr : NULL;
			off += slen;	/* bounded by rs_total, no overflow */
		}
		/* Signal only the tail -- one completion for the whole chain. */
		rs->rs_wr[n - 1].wr.send_flags = IB_SEND_SIGNALED;
	}

	/*
	 * Arm the send-side teardown barrier and post, IDENTICALLY to
	 * svc_rdma_conn_send()/the FRWR self-test: in one sc_lock section verify
	 * SC_UP, mark this read in flight on the recv (rs_active -- with rs_mapped
	 * already set after the map), and bump sc_sends; then ib_post_send with the
	 * lock dropped; then reacquire, decrement sc_sends, and wake the teardown if
	 * we were the last in-flight SQ WR.  Because conn_close() publishes SC_CLOSING
	 * before enqueuing the teardown, once teardown is pending this post cannot
	 * pass the SC_UP gate, and the barrier waits only for an already-counted post
	 * to finish.  After sc_sends hits 0 the chain is on the SQ before
	 * ib_drain_qp(), so the SQ drain sentinel catches it (its flush completion
	 * reaches svc_rdma_wc_rdma_read with a live conn) and nothing posts afterward.
	 *
	 * rs_active is set BEFORE the post (the one-shot completion token): a chained
	 * post that partially commits (see the failure handling below) generates flush
	 * completions for the committed prefix, which must find rs_active set so the
	 * one-shot guard in svc_rdma_wc_rdma_read claims reclaim ownership correctly.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		/*
		 * Tearing down before we posted anything: no WR reached the SQ, so
		 * no completion will ever fire for this read.  Reclaim inline
		 * (svc_rdma_read_free unmaps via the now-early rs_mapped) and let
		 * the caller close.  This is the ONLY inline-reclaim path left --
		 * it is safe precisely because nothing was posted.
		 */
		svc_rdma_read_free(conn, rr);
		return (ENOTCONN);
	}
	rs->rs_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp, &rs->rs_wr[0].wr, &bad_wr);

	/*
	 * BLOCKER 2 fix: a CHAINED ib_post_send can PARTIALLY commit.  mlx5's
	 * mlx5_ib_post_send builds WQEs one WR at a time and, on a mid-chain
	 * begin_wqe/mlx5_wq_overflow failure, `goto out` where `if (likely(nreq))`
	 * RINGS THE DOORBELL for the already-built prefix while returning -ENOMEM
	 * (mlx5_ib_qp.c:3952-3958 begin_wqe failure -> :4178-4200 out:).  So on rc
	 * != 0 we must assume the worst: some prefix RDMA Reads are LIVE on the HCA
	 * and will DMA-write rs_buf, and their completions (flush on QP->ERR, or an
	 * error CQE) will run svc_rdma_wc_rdma_read via container_of on rr_rs.  We
	 * therefore do NOT reclaim inline (no svc_rdma_read_free, no repost): freeing
	 * rs_buf here would be a DMA-after-free, and the SINGLE post-drain reclaimer
	 * (svc_rdma_conn_free_verbs -> svc_rdma_read_free, after ib_drain_qp) frees it
	 * exactly once.  We DO still decrement sc_sends (the POSTING operation has
	 * finished, success or fail) so the teardown's barrier can reach 0 and proceed
	 * to drain the committed prefix -- leaving rs_active/rs_mapped/rs_buf intact
	 * for that drained reclaim.  Then conn_close and return nonzero; the caller's
	 * close is idempotent with ours.
	 */
	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (RDMA Read) failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);
}

/*
 * Hand the read sink to the zero-copy mbuf (TASK_003f-3).  Transfers ownership of
 * the DMA'd destination buffer + its mapping out of rr_rs and into the bufp/dmap
 * out-params; the caller unmaps it (in the completion, device alive) and wraps the
 * resulting plain-memory buffer in an EXT_DISPOSABLE mbuf.  *maplenp returns the
 * length the buffer was MAPPED at, so the caller's ib_dma_unmap_single matches the
 * original map exactly: SVC_RDMA_MAX_READ for a POOLED buffer (the pool maps every
 * slot at SVC_RDMA_MAX_READ at accept time), rs_total for the per-read FALLBACK
 * buffer (mapped at rs_total in read_start).  For a POOLED sink the slot is
 * EVACUATED (rb_buf=NULL, rb_dma=0, rb_mapped=false, rb_inuse=false, rs_rb=NULL)
 * so the pool no longer owns that buffer; svc_rdma_read_start re-stocks the empty
 * slot lazily (Edit 7).  rs_buf/rs_dma/rs_mapped are cleared unconditionally, so
 * the subsequent svc_rdma_read_free becomes a no-op for the SINK (it still frees
 * rs_head).  Done under sc_lock so the slot/rr_rs fields flip atomically against a
 * concurrent read_free / teardown.  Caller holds NO lock.
 */
static void
svc_rdma_read_sink_detach(struct svc_rdma_conn *conn,
    struct svc_rdma_read_state *rs, void **bufp, u64 *dmap, uint32_t *maplenp)
{
	mtx_lock(&conn->sc_lock);
	if (rs->rs_rb != NULL) {
		*bufp = rs->rs_rb->rb_buf;
		*dmap = rs->rs_rb->rb_dma;
		*maplenp = SVC_RDMA_MAX_READ;	/* pool slot mapped at MAX_READ */
		rs->rs_rb->rb_buf = NULL;	/* evacuated: pool no longer owns it */
		rs->rs_rb->rb_dma = 0;
		rs->rs_rb->rb_mapped = false;
		rs->rs_rb->rb_inuse = false;	/* slot free to be re-stocked */
		rs->rs_rb = NULL;
	} else {
		*bufp = rs->rs_buf;
		*dmap = rs->rs_dma;
		*maplenp = rs->rs_total;	/* fallback mapped at rs_total */
	}
	rs->rs_buf = NULL;
	rs->rs_dma = 0;
	rs->rs_mapped = false;		/* read_free now unmaps/frees nothing for the sink */
	mtx_unlock(&conn->sc_lock);
}

/*
 * Alloc-failure unwind for a DETACHED sink that no mbuf took ownership of.  The
 * caller already unmapped the sink (in svc_rdma_wc_rdma_read, right after detach
 * and BEFORE the extref/mbuf alloc), so this is now plain CPU memory: just free
 * it, exactly once.  No device touch here (and none possible -- the mapping is
 * already gone), matching svc_rdma_read_extfree.
 */
static void
svc_rdma_read_sink_free_detached(void *buf)
{
	if (buf != NULL)
		free(buf, M_NFSRDMA);
}

/*
 * Release the durable read state for a recv: unmap+free the server destination
 * buffer and free the inline-head copy, EXACTLY ONCE.  RECLAIM IS DRIVEN BY THE
 * idempotent rs_mapped (unmap) and rs_buf/rs_head != NULL (free) tokens -- the
 * sm_sg_mapped pattern -- NOT by rs_active (which is the completion one-shot
 * guard, a separate concern this routine merely clears defensively).  So the two
 * legitimate reclaimers -- the first read completion (success or assemble-alloc
 * drop), and the drained teardown (svc_rdma_conn_free_verbs) -- can each call this
 * and the SECOND is a harmless no-op (all tokens already cleared/NULL).  Call it
 * WITHOUT sc_lock held: it calls ib_dma_unmap_single, which takes DMA_PRIV_LOCK
 * (so it is not lock-free), though it never sleeps.  All callers comply -- the
 * read completion and the drained teardown both drop sc_lock before calling.
 *
 * The DMA / read-vs-teardown rule: the server buffer's DMA mapping MUST stay live
 * until the device is done writing into it (the read completion) or the QP is
 * drained AND the recv CQ freed (teardown).  ib_drain_qp() drains the QP, but the
 * recv buffers (and this read state) are reclaimed only AFTER ib_free_cq(), whose
 * flush_work() is the barrier that quiesces the completion workqueue; so by the
 * time the teardown calls this no read completion can be touching rs_buf/rs_dma.
 */
static void
svc_rdma_read_free(struct svc_rdma_conn *conn, struct svc_rdma_recv *rr)
{
	struct svc_rdma_read_state *rs = &rr->rr_rs;
	struct ib_device *dev;

	/*
	 * Pooled buffer (TASK_003f-8): return it to the free-list; do NOT unmap or
	 * free it (the pool owns the permanent mapping and the memory).  Idempotent
	 * via rs_rb: the read completion and the drained teardown may both call this,
	 * but only the one that finds rs_rb != NULL returns the buffer.  Done under
	 * sc_lock so rb_inuse + rs_rb flip atomically.  sc_lock is dropped BEFORE the
	 * ib_dma_unmap_single below (which takes DMA_PRIV_LOCK) -- no lock nesting.
	 */
	mtx_lock(&conn->sc_lock);
	if (rs->rs_rb != NULL) {
		rs->rs_rb->rb_inuse = false;
		rs->rs_rb = NULL;
		rs->rs_buf = NULL;	/* belongs to the pool; do not free below */
		rs->rs_dma = 0;
		rs->rs_mapped = false;
	}
	mtx_unlock(&conn->sc_lock);

	/* Fallback buffer: unmap + free exactly once (idempotent via rs_mapped/rs_buf). */
	if (rs->rs_mapped) {
		dev = (conn->sc_id != NULL) ? conn->sc_id->device : NULL;
		if (dev != NULL)
			ib_dma_unmap_single(dev, rs->rs_dma, rs->rs_total,
			    DMA_FROM_DEVICE);
		rs->rs_mapped = false;
	}
	if (rs->rs_buf != NULL) {
		free(rs->rs_buf, M_NFSRDMA);
		rs->rs_buf = NULL;
	}
	if (rs->rs_head != NULL) {
		free(rs->rs_head, M_NFSRDMA);
		rs->rs_head = NULL;
	}
	rs->rs_active = false;
}

/*
 * RDMA Read completion (TASK_003f-3).  Dispatched by the CQ core in the same
 * IB_POLL_WORKQUEUE context as the send/recv handlers; keep it short, take no
 * sleepable lock, start no blocking teardown.  The signaled tail WR's wr_cqe
 * aliases &rs->rs_cqe, so container_of recovers the read state, then the recv
 * descriptor and the owning conn.
 *
 * ONE-SHOT (the multi-completion guard).  A chained post can deliver MORE THAN
 * ONE completion for a single read: only the tail WR is signaled, but flush
 * (QP->ERR) and error CQEs are reported for UNSIGNALED prefix WRs too, and a
 * partially-committed failed post (see svc_rdma_read_start's BLOCKER 2 fix) can
 * leave a committed prefix that flushes.  So this handler can be invoked >1x for
 * one rr_rs.  rs_active is the one-shot token: at the top, under sc_lock,
 * test-and-clear it; if it was already clear this is a DUPLICATE completion and
 * we return immediately (the first invocation, or the drained teardown, owns
 * reclaim).  Only the FIRST completion proceeds.  sc_sends is NOT touched here --
 * it is decremented exactly once at the POSTING site (svc_rdma_read_start), so no
 * completion path can double-decrement it.
 *
 * SUCCESS (first completion): rs_buf holds the inbound data the peer registered.
 * Assemble the full call body = head[0, pos) ++ read_data ++ head[pos, headlen)
 * where pos is the read list's rdma_position (RFC 8166 4.3); the parser already
 * rejected a read list whose segments carry DIFFERING positions, so a single
 * reads[0].rc_position describes the whole splice (clamped to headlen).  For the
 * common NFS WRITE pos == headlen, so the read data appends after the inline
 * head.  Dispatch via sro_recv under the same readiness gate + sc_upcalls barrier
 * the inline path uses, then free the read state and repost rr_buf.
 *
 * ERROR/FLUSH (first completion): a bad rkey/addr/length fails the WR (the HCA
 * enforced the rkey), or the chain flushed during teardown.  We clear rs_active
 * (one-shot) but do NOT free rr_rs -- the DRAINED teardown is the single reclaimer
 * for a closing conn, gated by the idempotent rs_mapped/rs_buf tokens (NOT
 * rs_active), so leaving them set is correct and reclaim happens exactly once
 * after ib_drain_qp().  IB_WC_WR_FLUSH_ERR is swallowed; any other status closes.
 * rr_buf is NOT reposted (the teardown owns it).  This mirrors the recv/send flush
 * handling exactly.
 *
 * Serialization (the true model): completions on ONE CQ are serialized because a
 * CQ's IB_POLL_WORKQUEUE work item cannot run concurrently with itself -- and
 * every completion this RDMA Read can produce lands on the SEND CQ, so they are
 * serialized with each other (the recv CQ is a separate work item and may run
 * concurrently, but the recv that owns rr_rs is single-owner: never reposted while
 * rs_active, so no recv completion races this read's rr_rs).  ib_drain_qp() is
 * FIFO, so every completion this read can ever produce has run before the teardown
 * frees conn/rr.  The rs_active one-shot then makes the >1-completion case safe:
 * exactly one invocation does the work, the rest no-op.
 */
static void
svc_rdma_wc_rdma_read(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_read_state *rs;
	struct svc_rdma_recv *rr;
	struct svc_rdma_conn *conn;
	uint32_t pos, bodylen;
	int rc;
	bool ready, first;

	/* Same single-workqueue-thread invariant as the other wc handlers (N2). */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	rs = container_of(wc->wr_cqe, struct svc_rdma_read_state, rs_cqe);
	rr = container_of(rs, struct svc_rdma_recv, rr_rs);
	conn = rr->rr_conn;

	/*
	 * One-shot test-and-clear: only the FIRST completion for this read proceeds;
	 * any duplicate (a prefix flush after the tail already ran, a second flush)
	 * finds rs_active already false and returns.  This makes dispatch+free+repost
	 * (and the close) happen at most once per read.
	 */
	mtx_lock(&conn->sc_lock);
	first = rs->rs_active;
	rs->rs_active = false;
	mtx_unlock(&conn->sc_lock);
	if (!first)
		return;

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * Flushed during teardown: expected; the DRAINED teardown reclaims
		 * rr_rs after ib_drain_qp() via the idempotent rs_mapped/rs_buf
		 * tokens, so leave them set and touch nothing else.  Any other
		 * status (including the error a bad peer rkey/addr/length produces)
		 * is a real fault -> close; again do NOT free rr_rs here (the conn
		 * is closing and the teardown is the single reclaimer), and do NOT
		 * repost rr_buf (the teardown owns it).
		 */
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: RDMA Read completion error %u "
				    "(bad rkey/addr/len or fault), closing\n",
				    wc->status);
			svc_rdma_conn_close(conn);
		}
		return;
	}

	/*
	 * Splice point: the position in the XDR stream where the read data belongs.
	 * Clamp to the inline head length so a peer-supplied position can never
	 * index past the head we copied (defense in depth -- pos beyond headlen just
	 * appends).  bodylen = head + read data; both bounded (headlen <=
	 * SVC_RDMA_INLINE, rs_total <= SVC_RDMA_MAX_READ), so the sum cannot
	 * overflow uint32.
	 */
	pos = rs->rs_msg.reads[0].rc_position;
	if (pos > rs->rs_headlen)
		pos = rs->rs_headlen;
	bodylen = rs->rs_headlen + rs->rs_total;

	/*
	 * DMA sync the read sink before the CPU reads it (TASK_003f-3 corruption
	 * fix).  rs_buf is a malloc'd, physically-scattered buffer, so
	 * ib_dma_map_single may bounce it; the RDMA-Read data is only guaranteed
	 * visible to the CPU after a DMA_FROM_DEVICE sync_for_cpu.  Without it a
	 * bounced read leaves stale (uninitialized) rs_buf bytes in the assembled
	 * body -- intermittent NFS-WRITE data corruption under load.
	 */
	ib_dma_sync_single_for_cpu(conn->sc_id->device, rs->rs_dma,
	    rs->rs_total, DMA_FROM_DEVICE);

	/*
	 * ZERO-COPY ASSEMBLE (TASK_003f-3).  rs_buf (the read sink) holds [read_data]
	 * of rs_total bytes, already DMA-synced for the CPU above.  Instead of
	 * malloc(bodylen) + 3 memcpy + a second copy in sro_recv, build an mbuf chain
	 *     mhead(head[0,pos)) -> mext(EXT_DISPOSABLE sink) -> [mt(head[pos,headlen))]
	 * where mext wraps the DMA'd sink as external storage owned by its own
	 * ext_free (svc_rdma_read_extfree); only the two small (<=4 KiB) head fragments
	 * are copied.  Ownership of the sink TRANSFERS to mext via m_extadd, so after
	 * detach the verbs teardown never touches it (see svc_rdma_read_sink_detach).
	 *
	 * All allocations are M_NOWAIT (completion context); on ANY failure we drop the
	 * call (the RC client retransmits) and free EXACTLY the sink/chain we hold --
	 * never twice, never zero.  m_getm2 pre-sizes each head fragment so the
	 * internally-M_NOWAIT m_copyback cannot SILENTLY TRUNCATE on extend.
	 */
	{
		struct mbuf *mhead, *mext, *mt;
		struct svc_rdma_write_chunk reply = { 0 };
		void *sinkbuf;
		u64 sinkdma;
		uint32_t sinkmaplen, xid = 0;
		bool has_reply = false;

		/*
		 * Take the sink out of rr_rs (locals only from here), then UNMAP it
		 * IMMEDIATELY while conn + device are provably alive (this completion
		 * runs on this conn's CQ).  The data is already CPU-coherent from the
		 * ib_dma_sync_single_for_cpu above, so after the unmap the sink is plain
		 * CPU memory.  Review fix (b): the mbuf must own NO device handle -- it
		 * outlives the conn, and a later ext_free touching a device released by
		 * rdma_destroy_id() at teardown would be a use-after-free.  Unmap LENGTH
		 * = sinkmaplen, the length the buffer was originally mapped at.
		 */
		svc_rdma_read_sink_detach(conn, rs, &sinkbuf, &sinkdma, &sinkmaplen);
		ib_dma_unmap_single(conn->sc_id->device, sinkdma, sinkmaplen,
		    DMA_FROM_DEVICE);

		/* The EXT segment over the (now plain-memory) sink. */
		mext = m_get(M_NOWAIT, MT_DATA);
		if (mext == NULL) {
			/* No mbuf took the sink yet: free the plain buffer, once. */
			svc_rdma_read_sink_free_detached(sinkbuf);
			svc_rdma_read_free(conn, rr);	/* frees rs_head */
			svc_rdma_repost(conn, rr);
			return;
		}

		/*
		 * EXT_DISPOSABLE wraps the plain sink buffer as external storage; the
		 * buffer pointer is carried DIRECTLY as ext_arg1 and svc_rdma_read_extfree
		 * frees it.  flags=0: EXT_DISPOSABLE already selects the embedded-refcount
		 * branch internally (so ext_free fires EXACTLY ONCE at refcount->0, even
		 * if nfsd m_copym's the chain -- m_dupcl shadows the EMBREF), and passing
		 * EXT_FLAG_EMBREF in `flags` would wrongly OR a bit into m_flags.  From
		 * this point the sink is owned by mext; freeing mext (directly or via
		 * m_freem of any chain containing it) releases the sink via ext_free.
		 */
		m_extadd(mext, (char *)sinkbuf, rs->rs_total,
		    svc_rdma_read_extfree, sinkbuf, NULL, 0, EXT_DISPOSABLE);
		mext->m_len = rs->rs_total;

		/*
		 * head[0,pos): the chain head, carries the pkthdr.  Pre-size with
		 * m_getm2 (>= pos bytes, never less than a pkthdr mbuf) so m_copyback
		 * cannot truncate the <=4 KiB head copy.
		 */
		mhead = m_getm2(NULL, pos, M_NOWAIT, MT_DATA, M_PKTHDR);
		if (mhead == NULL) {
			m_freem(mext);		/* releases sink via ext_free, once */
			svc_rdma_read_free(conn, rr);
			svc_rdma_repost(conn, rr);
			return;
		}
		if (pos != 0)
			m_copyback(mhead, 0, pos, rs->rs_head);
		mhead->m_next = mext;

		/* head[pos,headlen): the post-splice tail, if any. */
		if (rs->rs_headlen > pos) {
			uint32_t tlen = rs->rs_headlen - pos;

			mt = m_getm2(NULL, tlen, M_NOWAIT, MT_DATA, 0);
			if (mt == NULL) {
				/* mhead owns mext (and thus the sink): one m_freem. */
				m_freem(mhead);
				svc_rdma_read_free(conn, rr);
				svc_rdma_repost(conn, rr);
				return;
			}
			m_copyback(mt, 0, tlen, rs->rs_head + pos);
			mext->m_next = mt;
		}
		mhead->m_pkthdr.len = bodylen;

		/*
		 * Capture the reply-chunk identity into LOCALS BEFORE read_free
		 * (stale-read hardening, review NIT): rs_msg is durable storage in rr
		 * that read_free does not currently touch, but reading it after the
		 * reclaim is fragile -- snapshot it now and pass the locals below.
		 */
		xid = rs->rs_msg.xid;
		has_reply = rs->rs_msg.reply_present;
		if (has_reply)
			reply = rs->rs_msg.reply;	/* pure value copy */

		/* rs_head is copied into the small mbufs; the sink already detached. */
		svc_rdma_read_free(conn, rr);

		/*
		 * Dispatch the assembled chain under the SAME readiness gate +
		 * sc_upcalls barrier as the inline path.  EVERY branch that did
		 * sc_upcalls++ balances it with --sc_upcalls + wakeup under sc_lock
		 * (a leak hangs teardown forever), and the chain is freed EXACTLY
		 * once: sro_recv_mbuf takes ownership on return 0 (we must NOT free),
		 * and on every other outcome we m_freem(mhead) ourselves.
		 *
		 * REPOST AT COMPLETION (the original placement -- Edit 6 reverted).
		 * rr_buf is NOT reposted until this completion fully returns, so the
		 * single-owner rr_rs invariant holds (svc_verbs.c "One posted receive
		 * buffer" note): no new call can land on rr_buf or touch rr_rs while a
		 * read is in flight.  We repost on the normal-completion exits
		 * (dispatch-success AND not-ready/no-consumer), but NOT on the
		 * consumer-reject path (it closes the conn; the teardown owns rr_buf).
		 */
		mtx_lock(&conn->sc_lock);
		ready = (conn->sc_state == SC_UP && conn->sc_newconn_done);
		if (ready)
			conn->sc_upcalls++;
		mtx_unlock(&conn->sc_lock);

		if (ready && conn->sc_ops != NULL &&
		    conn->sc_ops->sro_recv_mbuf != NULL) {
			rc = conn->sc_ops->sro_recv_mbuf(conn->sc_ctx, conn,
			    mhead, xid, has_reply, &reply);
			mtx_lock(&conn->sc_lock);
			if (--conn->sc_upcalls == 0)
				wakeup(&conn->sc_upcalls);
			mtx_unlock(&conn->sc_lock);
			if (rc != 0) {
				/* Consumer rejected: it did NOT take the chain. */
				m_freem(mhead);
				svc_rdma_conn_close(conn);
				return;		/* closing: do NOT repost */
			}
			/* On rc == 0 the consumer owns mhead; do not touch it. */
		} else {
			/* Not ready / no consumer: we still own the chain. */
			m_freem(mhead);
			if (ready) {
				mtx_lock(&conn->sc_lock);
				if (--conn->sc_upcalls == 0)
					wakeup(&conn->sc_upcalls);
				mtx_unlock(&conn->sc_lock);
			}
		}

		/* Normal completion: repost rr_buf for the next call (original). */
		svc_rdma_repost(conn, rr);
		return;
	}
}

/*
 * ===========================================================================
 * RDMA Write engine -- outbound NFS READ result / large reply (TASK_003f-4).
 *
 * For a reply that does not fit the inline send buffer, the CLIENT pre-registered
 * memory it wants us to RDMA-WRITE INTO: a REPLY CHUNK (the whole RPC reply, the
 * NFSv4 mount-handshake case -- THIS increment) or a WRITE LIST (NFS READ data).
 * Each segment is a peer-supplied { rs_handle(rkey), rs_offset(remote virtual
 * address), rs_length }.  We push the server's marshalled reply OUT into those
 * segments and then SEND a small RPC-over-RDMA header reporting the lengths
 * written: RDMA_NOMSG + the reply-chunk list for a reply chunk (RFC 8166 4.3).
 *
 * UNTRUSTED PEER (RFC 8166 5) -- re-validated AT POST TIME, not trusted from the
 * parse, and the source is SERVER-KNOWN so we NEVER write more than the client
 * offered:
 *   - every rs_length re-checked in (0, SVC_RDMA_MAX_SEG_LEN];
 *   - the segment/WR count re-checked <= SVC_RDMA_MAX_WRITE_SEGS;
 *   - the running SUM of segment lengths (the client's offered capacity) computed
 *     with no uint32 overflow; the reply length (our own, bounded by
 *     SVC_RDMA_MAX_WRITE) must be <= that capacity -- if the reply is LARGER than
 *     the client's reply chunk we return EMSGSIZE and write NOTHING, never an
 *     over-write of the client's memory;
 *   - we write at most rs_length bytes into each segment (min(remaining, len)),
 *     so a segment is never over-written even if a later segment is short;
 *   - rs_handle(rkey) and rs_offset are passed VERBATIM to the HCA: the hardware
 *     enforces the rkey against the client's MR, so a bad rkey/addr fails the WR
 *     with an error completion, which we handle by CLOSING -- never by trusting.
 *
 * COMPLETION-vs-TEARDOWN lifetime (the #1 hazard), mirroring 3f-3 EXACTLY:
 *   - sc_sends accounts only the POST CALL (incremented under SC_UP, decremented
 *     right after ib_post_send returns), NOT the async WRs; ib_drain_qp() -- not
 *     the sc_sends barrier -- is what quiesces the in-flight write/SEND WRs before
 *     the teardown reclaims;
 *   - the write state (source + header buffers + DMA maps) lives in a malloc'd
 *     svc_rdma_write_state threaded on conn->sc_writes and is freed/unmapped
 *     EXACTLY ONCE -- on the (tail-SEND) completion, or by the teardown for a write
 *     still in flight at close (ws_active one-shot + ws_*_mapped idempotency, the
 *     sm_sg_mapped pattern);
 *   - svc_rdma_conn_close() publishes SC_CLOSING before enqueuing the teardown, so
 *     once teardown is pending no new write passes the SC_UP gate.
 *
 * PARTIAL-POST rule (mlx5 commits prefix WQEs even on -ENOMEM): on ib_post_send
 * rc != 0 we do NOT reclaim inline -- a committed prefix is live and will flush; we
 * leave the write state on sc_writes for the drained teardown to reclaim, exactly
 * as svc_rdma_read_start does (BLOCKER 2 there).
 * ===========================================================================
 */

/*
 * Release one outbound write state: remove it from the registry, unmap+free the
 * source and header buffers, EXACTLY ONCE.  RECLAIM IS DRIVEN BY the idempotent
 * ws_src_mapped/ws_hdr_mapped (unmap) and ws_src/ws_hdr != NULL (free) tokens --
 * NOT by ws_active (the completion one-shot, a separate concern this routine
 * merely clears defensively).  The two legitimate reclaimers -- the first
 * completion and the drained teardown -- can each call this and the SECOND is a
 * harmless no-op.  Callable WITHOUT sc_lock (the first completion) or WITH the
 * registry already emptied by the teardown loop; it only ib_dma_unmap_single /
 * free, neither sleeps.  The caller has already detached ws from sc_writes (or is
 * the teardown draining the whole list), so this never touches the list itself --
 * the detach is done at the call site under sc_lock to keep the registry coherent.
 *
 * The DMA / write-vs-teardown rule: the source mapping MUST stay live until the
 * device is done READING it (the write completion) or the QP is drained AND the
 * send CQ freed (teardown).  The teardown reclaims write state only AFTER
 * ib_free_cq(), whose flush_work() quiesces the completion workqueue (ib_drain_qp()
 * alone does not -- a dispatched-but-unrun SEND completion may remain), so the
 * teardown calling this for a write that never completed is safe.
 */
static void
svc_rdma_write_free(struct svc_rdma_write_state *ws)
{
	struct svc_rdma_conn *conn = ws->ws_conn;
	struct ib_device *dev;

	dev = (conn != NULL && conn->sc_id != NULL) ? conn->sc_id->device : NULL;

	/*
	 * Detach-before-free contract -- the cornerstone of the ABA
	 * safety argued in svc_rdma_wc_rdma_write.  Every caller (the
	 * completion one-shot, the pre-insert error paths, the drained
	 * teardown) has already removed ws from sc_writes -- or never
	 * inserted it -- and cleared ws_active before reaching here, so a
	 * freed write is never on the registry for a stale or duplicate
	 * completion to re-find.  A still-active (hence possibly still-
	 * registered) write must never be freed.
	 */
	MPASS(!ws->ws_active);

	/*
	 * Zero-copy M_EXTPG page source (TASK_003f-19): unmap EACH mapped page.
	 * Drive the loop off ws_npgs (PAGES), never ws_nwr (a WR gathers several
	 * pages, so coalescing by WR would leak).  ws_pages_mapped is the idempotent
	 * token; ws_npgs is bumped incrementally as pages map, so a mid-map failure
	 * unmaps exactly the mapped prefix.  ws_npgs==0 on every non-page path.
	 */
	if (ws->ws_pages_mapped) {
		uint32_t p;

		for (p = 0; p < ws->ws_npgs; p++)
			if (dev != NULL)
				ib_dma_unmap_single(dev, ws->ws_pg_dma[p],
				    ws->ws_pg_len[p], DMA_TO_DEVICE);
		ws->ws_pages_mapped = false;
	}

	if (ws->ws_src_mapped) {
		if (dev != NULL)
			ib_dma_unmap_single(dev, ws->ws_src_dma, ws->ws_srclen,
			    DMA_TO_DEVICE);
		ws->ws_src_mapped = false;
	}
	if (ws->ws_hdr_mapped) {
		if (dev != NULL)
			ib_dma_unmap_single(dev, ws->ws_hdr_dma, ws->ws_hdrlen,
			    DMA_TO_DEVICE);
		ws->ws_hdr_mapped = false;
	}
	if (ws->ws_src != NULL) {
		free(ws->ws_src, M_NFSRDMA);
		ws->ws_src = NULL;
	}
	if (ws->ws_hdr != NULL) {
		free(ws->ws_hdr, M_NFSRDMA);
		ws->ws_hdr = NULL;
	}
	/*
	 * Free the source M_EXTPG mbuf chain LAST (TASK_003f-19): the device read
	 * the data pages out of it, so it had to outlive the RDMA Write; this is the
	 * sole reference drop.  ws_keepm is NULL on every non-page path.
	 */
	if (ws->ws_keepm != NULL) {
		m_freem(ws->ws_keepm);
		ws->ws_keepm = NULL;
	}
	ws->ws_active = false;
	free(ws, M_NFSRDMA);
}

/*
 * RDMA-Write a too-large-for-inline reply into the client's reply chunk and SEND
 * the RDMA_NOMSG header reporting the bytes written (TASK_003f-4).  PUBLIC entry
 * point (declared in <rdma/svc_rdma.h>); the krpc consumer's xp_reply calls it
 * when a marshalled reply exceeds the inline size and the request carried a reply
 * chunk.  Context: a krpc pool thread under the consumer's per-conn lock (the
 * caller-reference rule that keeps conn alive, identical to svc_rdma_conn_send);
 * it does NOT sleep.
 *
 * buf/len are the marshalled ONC RPC reply BODY ONLY; reply is the parsed,
 * validated reply chunk the client offered (a pure value type the consumer
 * captured during sro_recv).  On success an RDMA Write chain + the header SEND are
 * on the SQ and the write state is on sc_writes until the tail-SEND completion (or
 * the drained teardown) frees it.  Returns 0 or a positive errno; on nonzero it
 * has already released everything it allocated for a NEVER-posted attempt (a
 * posted-but-failed chain is left for the drained teardown -- the partial-post
 * rule).
 */
int
svc_rdma_conn_reply_chunk(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *reply, const void *buf, uint32_t len)
{
	struct svc_rdma_write_state *ws;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t capacity;
	uint32_t i, n, off, remaining, hdrlen;
	char *h;
	int rc;

	/*
	 * Validate the reply LENGTH (server-known, bounded).  A 0-length reply is a
	 * caller bug; a reply over the whole-reply cap is refused rather than written
	 * (we never size a transfer past SVC_RDMA_MAX_WRITE).  len is the server's own
	 * marshalled reply size, NOT a peer field.
	 */
	if (len == 0 || len > SVC_RDMA_MAX_WRITE)
		return (EINVAL);

	/*
	 * Re-validate the reply-chunk SHAPE at post time (untrusted peer).  The parser
	 * already enforced wc_nsegs <= SVC_RDMA_MAX_SEGS and each rs_length in
	 * (0, SVC_RDMA_MAX_SEG_LEN]; re-assert here so this engine is correct
	 * independent of the parser and so a future parser change cannot let an
	 * over-cap reply chunk reach the HCA.
	 */
	n = reply->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS)
		return (EINVAL);

	/*
	 * Compute the client's offered CAPACITY (sum of segment lengths) with no
	 * uint32 overflow, re-checking each length.  The reply must FIT: len <=
	 * capacity, else the client did not offer enough reply-chunk space -> EMSGSIZE
	 * and we write nothing.  This is the never-over-write invariant: we will write
	 * exactly len bytes, spread across segments, each capped at its own rs_length.
	 */
	capacity = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN)
			return (EINVAL);
		capacity += slen;
	}
	if ((uint64_t)len > capacity)
		return (EMSGSIZE);

	/*
	 * Allocate the durable write state (it outlives this call -- the writes and the
	 * header SEND complete async).  M_NOWAIT: xp_reply may run under the consumer's
	 * leaf mutex, so do not block.  Zeroed so every token starts false/NULL.
	 */
	ws = malloc(sizeof(*ws), M_NFSRDMA, M_NOWAIT | M_ZERO);
	if (ws == NULL)
		return (ENOMEM);
	ws->ws_conn = conn;

	/*
	 * Copy the reply bytes into the DMA source buffer and map it DMA_TO_DEVICE (the
	 * HCA READS this buffer to push it into the client).  Sized by the SERVER-KNOWN
	 * len (bounded by SVC_RDMA_MAX_WRITE), never a raw peer field.
	 */
	ws->ws_srclen = len;
	/* contigmalloc: ws_src is the RDMA-Write SOURCE for the reply chunk; like the
	 * read sink it must be physically contiguous for ib_dma_map_single (a
	 * multi-page reply -- e.g. a large READDIR -- otherwise sources wrong
	 * physical pages and the write fails REM_INV_REQ).  Same fix as rs_buf. */
	ws->ws_src = contigmalloc(len, M_NFSRDMA, M_NOWAIT, 0, ~(vm_paddr_t)0,
	    PAGE_SIZE, 0);
	if (ws->ws_src == NULL) {
		free(ws, M_NFSRDMA);
		return (ENOMEM);
	}
	memcpy(ws->ws_src, buf, len);
	ws->ws_src_dma = ib_dma_map_single(dev, ws->ws_src, len, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_src_dma)) {
		free(ws->ws_src, M_NFSRDMA);
		free(ws, M_NFSRDMA);
		return (EIO);
	}
	ws->ws_src_mapped = true;	/* mark live IMMEDIATELY (BLOCKER 1 rule) */

	/*
	 * Build the RDMA_NOMSG transport header: the fixed 4-word prefix, two empty
	 * lists (read list, write list), then the reply chunk present marker + the
	 * counted write chunk whose segments echo the client's { handle, offset } with
	 * the LENGTH updated to the bytes we actually wrote into each segment.  Layout
	 * (big-endian XDR words, RFC 8166 4.3):
	 *   w0 rdma_xid, w1 rdma_vers(1), w2 rdma_credit, w3 rdma_proc(RDMA_NOMSG),
	 *   w4 read_list=0, w5 write_list=0,
	 *   w6 reply_chunk_present=1, w7 nsegs,
	 *   then nsegs * { handle, length(written), offset(64) } (4 words each).
	 * The header is a fixed local size (<= a few hundred bytes for <= 16 segs), so
	 * we size it exactly and it can never be driven past SVC_RDMA_INLINE by a peer.
	 */
	hdrlen = RPCRDMA_HDR_FIXED + 2 * RPCRDMA_WORD +	/* prefix + 2 empty lists */
	    2 * RPCRDMA_WORD +				/* present + nsegs */
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD);	/* the segments */
	ws->ws_hdrlen = hdrlen;
	ws->ws_hdr = malloc(hdrlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees ws */
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);				/* w0  rdma_xid */
	be32enc(h +  4, RPCRDMA_VERSION);		/* w1  rdma_vers */
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);	/* w2  rdma_credit (granted) */
	be32enc(h + 12, RDMA_NOMSG);			/* w3  rdma_proc */
	be32enc(h + 16, 0);				/* w4  read_list (empty) */
	be32enc(h + 20, 0);				/* w5  write_list (empty) */
	be32enc(h + 24, 1);				/* w6  reply chunk present */
	be32enc(h + 28, n);				/* w7  nsegs */
	off = 32;
	remaining = len;
	for (i = 0; i < n; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;

		be32enc(h + off + 0, reply->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);		/* bytes written into this seg */
		be64enc(h + off + 8, reply->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, hdrlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees both + ws */
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Build the RDMA Write WR chain: one IB_WR_RDMA_WRITE per segment that carries
	 * bytes, each with a single local SGE into ws_src at the running source offset
	 * (lkey = the PD's local_dma_lkey -- the source is local memory, no FRWR
	 * registration needed for the SOURCE of a write), and the peer's { rkey,
	 * remote_addr } passed VERBATIM.  Chain them next->next; all UNSIGNALED.  Then
	 * chain the header SEND last and SIGNAL ONLY IT, so a single completion fires
	 * for the whole chain.  The SEND's wr_cqe aliases &ws_cqe (-> ws); the
	 * UNSIGNALED write WRs route to the per-conn sink cqe instead, so a flushed
	 * write never delivers a duplicate completion for this ws (TASK_003f-20).
	 *
	 * We emit a WR only for a segment that actually carries bytes (wlen > 0); once
	 * the reply is exhausted, trailing client segments get length 0 in the header
	 * and no WR (we never write 0 bytes nor over-write a spare segment).
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	off = 0;			/* source offset within ws_src */
	remaining = len;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = reply->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;
		int k = ws->ws_nwr;

		ws->ws_sge[k].addr = ws->ws_src_dma + off;
		ws->ws_sge[k].length = wlen;
		ws->ws_sge[k].lkey = conn->sc_pd->local_dma_lkey;

		memset(&ws->ws_wr[k], 0, sizeof(ws->ws_wr[k]));
		ws->ws_wr[k].wr.wr_cqe = &conn->sc_write_sink_cqe;	/* 3f-20 */
		ws->ws_wr[k].wr.sg_list = &ws->ws_sge[k];
		ws->ws_wr[k].wr.num_sge = 1;
		ws->ws_wr[k].wr.opcode = IB_WR_RDMA_WRITE;
		ws->ws_wr[k].wr.send_flags = 0;		/* unsignaled */
		ws->ws_wr[k].remote_addr = reply->wc_segs[i].rs_offset;
		ws->ws_wr[k].rkey = reply->wc_segs[i].rs_handle;
		ws->ws_nwr++;
		off += wlen;		/* bounded by len, no overflow */
		remaining -= wlen;
	}

	/* The tail header SEND, signaled -- one completion for the whole chain. */
	ws->ws_sndsge.addr = ws->ws_hdr_dma;
	ws->ws_sndsge.length = hdrlen;
	ws->ws_sndsge.lkey = conn->sc_pd->local_dma_lkey;
	memset(&ws->ws_sndwr, 0, sizeof(ws->ws_sndwr));
	ws->ws_sndwr.wr_cqe = &ws->ws_cqe;
	ws->ws_sndwr.sg_list = &ws->ws_sndsge;
	ws->ws_sndwr.num_sge = 1;
	ws->ws_sndwr.opcode = IB_WR_SEND;
	ws->ws_sndwr.send_flags = IB_SEND_SIGNALED;
	ws->ws_sndwr.next = NULL;

	/* Link writes -> ... -> header SEND. */
	for (i = 0; i + 1 < (uint32_t)ws->ws_nwr; i++)
		ws->ws_wr[i].wr.next = &ws->ws_wr[i + 1].wr;
	if (ws->ws_nwr > 0)
		ws->ws_wr[ws->ws_nwr - 1].wr.next = &ws->ws_sndwr;

	/*
	 * Arm the send-side teardown barrier and post, IDENTICALLY to
	 * svc_rdma_read_start / svc_rdma_conn_send: in one sc_lock section verify
	 * SC_UP, register the write on sc_writes, mark it in flight (ws_active -- with
	 * ws_*_mapped already set after the maps), and bump sc_sends; then ib_post_send
	 * with the lock dropped; then reacquire, decrement sc_sends, wake the teardown
	 * if last.  ws_active is set BEFORE the post (the one-shot token): a partially-
	 * committed chained post flushes its prefix, whose completions must find
	 * ws_active set so the one-shot guard claims reclaim correctly.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		/*
		 * Tearing down before we posted anything: no WR reached the SQ, so no
		 * completion will fire.  Reclaim inline (it is not yet on sc_writes) and
		 * return ENOTCONN.  Safe precisely because nothing was posted.
		 */
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * Post the chain (RDMA Writes... + header SEND).  If ws_nwr == 0 (degenerate:
	 * a 0-length reply was rejected above, so this cannot happen for len > 0), the
	 * head is the SEND itself.  bad_wr MUST be passed (mlx5 dereferences it on an
	 * immediate error).
	 */
	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	/*
	 * PARTIAL-POST rule (mlx5 commits the built prefix on a mid-chain failure while
	 * returning -ENOMEM): on rc != 0 do NOT reclaim inline -- a committed prefix is
	 * live.  A committed unsignaled write WR flushes to the per-conn sink cqe (not to
	 * svc_rdma_wc_rdma_write); a committed tail SEND flushes to svc_rdma_wc_rdma_write
	 * and frees ws; if the SEND was NOT reached, no completion frees ws, so the
	 * DRAINED teardown (svc_rdma_conn_free_verbs, after ib_drain_qp) is the single
	 * reclaimer.  Leave ws on sc_writes with ws_active/ws_*_mapped intact.  We DO
	 * still decrement sc_sends (the posting op finished); ib_drain_qp then quiesces
	 * the committed prefix before the teardown reclaims, then close.
	 */
	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (RDMA Write) failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);
}

/*
 * Sink completion for the UNSIGNALED RDMA Write WRs of a chain (TASK_003f-20).
 * Dispatched on the SAME SEND-CQ IB_POLL_WORKQUEUE context as the real write/send
 * handlers.  An unsignaled WR raises NO completion on success, so this is reached
 * ONLY when the QP is in error and the WR flushes (IB_WC_WR_FLUSH_ERR), or in the
 * rare case the HCA reports a per-WR fault (bad rkey/addr/len) on the write itself.
 * It must touch NO ws: the write states are owned and freed via the signaled tail
 * SEND's svc_rdma_wc_rdma_write, and a flushed write WR carries this shared per-conn
 * cqe, not any ws_cqe.  Recover conn from cq->cq_context (== conn) and do O(1) work:
 * count the event, and on a non-flush fault close the connection (idempotent) so a
 * bad client rkey surfaces promptly instead of waiting for the trailing SEND flush.
 * The counters are read/written only by this single-threaded workqueue, so they
 * need no lock.
 */
static void
svc_rdma_wc_write_sink(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_conn *conn = cq->cq_context;

	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	if (wc->status == IB_WC_SUCCESS)
		return;				/* unsignaled: not expected, ignore */
	if (wc->status == IB_WC_WR_FLUSH_ERR) {
		conn->sc_write_sink_flushes++;	/* QP draining: the SEND closes */
		return;
	}
	conn->sc_write_sink_errs++;
	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: RDMA Write WR error %u (bad rkey/addr/len), "
		    "closing\n", wc->status);
	svc_rdma_conn_close(conn);
}

/*
 * RDMA Write completion (TASK_003f-4).  Dispatched by the CQ core in the same
 * IB_POLL_WORKQUEUE context as the read/send handlers; keep it short, take no
 * sleepable lock, start no blocking teardown.  ONLY the signaled tail SEND of a
 * write chain carries &ws->ws_cqe (the unsignaled write WRs carry the per-conn
 * sink cqe -- TASK_003f-20), so container_of recovers the write state, then conn,
 * and this handler runs EXACTLY ONCE per ws: once on the SEND's success, or once
 * on the SEND's flush when the QP went to error.  There is therefore NO duplicate
 * completion for a ws and NO stale CQE can alias a freed/recycled ws address --
 * the prior design aliased every WR to &ws_cqe, so a flush storm delivered a
 * duplicate per unsignaled WR and the first completion's free-then-recycle of the
 * ws ADDRESS let a trailing duplicate re-match a recycled live ws and free it
 * mid-ib_post_send (the 256-concurrent-read ABA GPF).
 *
 * The sc_writes membership search is retained as DEFENSE IN DEPTH: recover conn
 * from cq->cq_context WITHOUT touching ws, then under sc_lock confirm ws is still
 * ON the list (and ws_active) before dereferencing it.  The only way it is absent
 * is a SEND completion that races the drained teardown after the teardown already
 * detached+freed it (the teardown runs only after ib_drain_qp(), which is FIFO on
 * this same CQ, so in practice the SEND completion precedes it); the search makes
 * that benign rather than a UAF.  sc_sends is NOT touched here (it is decremented
 * once at the post site; it accounts the post CALL, not the async WR).
 *
 * SUCCESS: the reply was RDMA-Written into the client's chunk and the header SEND
 * transmitted, so the device is done reading ws_src/ws_hdr -- free the write state.
 *
 * FLUSH/ERROR: the chain flushed (the QP is going down -- a bad rkey on a write
 * reaches the sink, or a teardown drain).  Close on ANY non-success before the
 * free (idempotent); the write state is freed here since we removed it from the
 * registry.  The teardown walks sc_writes only AFTER ib_free_cq() has flush_work()ed
 * this CQ, so no completion for a ws is still in flight when it does.
 */
static void
svc_rdma_wc_rdma_write(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_write_state *cand, *ws;
	struct svc_rdma_conn *conn;

	/* Same single-workqueue-thread invariant as the other wc handlers (N2). */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	/*
	 * Recover conn from the CQ context (NOT from the candidate ws -- ws may have
	 * been freed by a prior completion).  cand is only an ADDRESS to match against
	 * the registry; we do not dereference it until proven still-live below.
	 */
	conn = cq->cq_context;
	cand = container_of(wc->wr_cqe, struct svc_rdma_write_state, ws_cqe);

	/*
	 * Prove ownership: search sc_writes for the exact cand pointer.  If present and
	 * still active, this is the FIRST completion -- remove it (clearing ws_active)
	 * and we own the free.  If absent, this is a DUPLICATE (the first completion, or
	 * the drained teardown, already removed+freed it); return having dereferenced
	 * nothing.  Detaching here keeps the registry coherent and makes ownership
	 * unambiguous: whoever removes ws from the list owns its free.
	 */
	ws = NULL;
	mtx_lock(&conn->sc_lock);
	{
		struct svc_rdma_write_state *p;

		TAILQ_FOREACH(p, &conn->sc_writes, ws_link) {
			if (p == cand && p->ws_active) {
				p->ws_active = false;
				TAILQ_REMOVE(&conn->sc_writes, p, ws_link);
				ws = p;
				break;
			}
		}
	}
	mtx_unlock(&conn->sc_lock);
	if (ws == NULL)
		return;

	/*
	 * Registry coherence (defense in depth): the write we matched on
	 * sc_writes was created for THIS conn (whose CQ delivered this
	 * completion), so ws_conn must point back at conn.  A mismatch
	 * would mean a clobbered ws_cqe/ws_conn or a cross-conn alias --
	 * trip loudly under INVARIANTS rather than free the wrong state.
	 */
	MPASS(ws->ws_conn == conn);

	if (wc->status != IB_WC_SUCCESS) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: RDMA Write completion error %u "
				    "(bad rkey/addr/len or fault), closing\n",
				    wc->status);
		}
		/*
		 * Close on ANY non-success completion -- INCLUDING flush -- BEFORE the
		 * free, so SC_CLOSING is published first.  This closes an ABA window the
		 * one-shot essay above relies on NOT existing: a single bad/stale client
		 * rkey faults one RDMA-Write WR, which puts the whole QP in ERR and
		 * FLUSHES every other in-flight write, raising a storm of
		 * IB_WC_WR_FLUSH_ERR completions ahead of the one error CQE.  The old
		 * code closed only on the NON-flush sub-case, so the first flush freed
		 * its ws while the conn was still SC_UP; a krpc pool thread then passed
		 * the SC_UP insert gate, malloc recycled that exact address as a NEW
		 * live ws and posted it, and a trailing duplicate flush matched the new
		 * ws by address and freed it mid-post -> corrupted num_sge at
		 * ib_post_send + a use-after-free deref of ws_cqe in the completion
		 * workqueue (GPF), reproducible under ~256 concurrent small reads.
		 * Closing here publishes SC_CLOSING on the FIRST flush, so the SC_UP
		 * gate refuses every recycled insert while duplicate flushes drain.  A
		 * flush means the QP is already in ERR (the connection is going down
		 * regardless), so closing is correct; svc_rdma_conn_close is idempotent,
		 * so a normal drained-teardown flush remains a no-op.
		 */
		svc_rdma_conn_close(conn);
		svc_rdma_write_free(ws);
		return;
	}

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: reply chunk written + RDMA_NOMSG header sent "
		    "(%u bytes)\n", ws->ws_srclen);

	svc_rdma_write_free(ws);
}

/*
 * RDMA-Write a DDP-eligible NFS READ's data into the client's write-list chunk
 * and SEND a REDUCED RDMA_MSG reporting the bytes written (write-list READ
 * engine).  PUBLIC entry point (declared in <rdma/svc_rdma.h>); the krpc
 * consumer's xp_reply calls it when an over-inline READ reply carries a write
 * list.  It is the OUTBOUND-write twin of svc_rdma_conn_reply_chunk and reuses
 * its svc_rdma_write_state, svc_rdma_write_free, and svc_rdma_wc_rdma_write
 * completion VERBATIM.  The ONLY structural differences from reply_chunk:
 *   - the RDMA Write SOURCE is the READ DATA (data/datalen), not a reply body;
 *   - the tail SEND carries a REDUCED RDMA_MSG = [transport header with the
 *     echoed write list] ++ [reduced inline ONC RPC body], not a bodyless
 *     RDMA_NOMSG header.  ws_hdr therefore holds header + reduced body and the
 *     SEND covers both.
 *
 * UNTRUSTED PEER -- re-validated at post time, never trusted from the parse, and
 * the source is SERVER-KNOWN so we never write more than the client offered:
 *   - datalen re-checked in (0, SVC_RDMA_MAX_WRITE];
 *   - the write chunk's segment count re-checked <= SVC_RDMA_MAX_WRITE_SEGS;
 *   - each rs_length re-checked in (0, SVC_RDMA_MAX_SEG_LEN] and SUMMED with no
 *     uint32 overflow; datalen must be <= that capacity (else EMSGSIZE, write
 *     NOTHING);
 *   - at most rs_length bytes into each segment (min(remaining, rs_length));
 *   - rs_handle(rkey)/rs_offset passed VERBATIM to the HCA, which enforces them.
 * reducedlen is server-known; header + reduced body must fit one inline send
 * buffer (SVC_RDMA_INLINE) or EMSGSIZE.
 *
 * COMPLETION-vs-TEARDOWN lifetime, PARTIAL-POST, and ws one-shot are IDENTICAL
 * to svc_rdma_conn_reply_chunk (same sc_writes registry, same ws_active guard,
 * same svc_rdma_wc_rdma_write).  Context: a krpc pool thread under the
 * consumer's per-conn lock; does NOT sleep.
 */
int
svc_rdma_conn_write_list(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *write, void *src,
    uint32_t datalen, const void *reduced, uint32_t reducedlen)
{
	struct svc_rdma_write_state *ws;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t capacity;
	uint32_t i, n, off, remaining, hdrlen, sendlen;
	char *h;
	int rc;

	/*
	 * Validate the DATA length (server-known, bounded).  A 0-length read does
	 * not reach here (the consumer skips DDP for cnt == 0); a read over the
	 * whole-transfer cap is refused rather than written.
	 */
	if (datalen == 0 || datalen > SVC_RDMA_MAX_WRITE) {
		rc = EINVAL;
		goto badsrc;
	}

	/*
	 * Re-validate the write chunk SHAPE at post time (untrusted peer), exactly
	 * as reply_chunk re-validates the reply chunk.
	 */
	n = write->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS) {
		rc = EINVAL;
		goto badsrc;
	}

	/*
	 * Offered CAPACITY (sum of segment lengths) with no uint32 overflow,
	 * re-checking each length.  The data must FIT: datalen <= capacity, else
	 * EMSGSIZE and we write nothing (never-over-write invariant).
	 */
	capacity = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN) {
			rc = EINVAL;
			goto badsrc;
		}
		capacity += slen;
	}
	if ((uint64_t)datalen > capacity) {
		rc = EMSGSIZE;
		goto badsrc;
	}

	/*
	 * The reduced RDMA_MSG SEND = transport header (with the echoed write
	 * list) + the reduced inline body.  Header layout (big-endian XDR words,
	 * RFC 8166 4.3, write-list form):
	 *   w0 rdma_xid, w1 rdma_vers(1), w2 rdma_credit, w3 rdma_proc(RDMA_MSG),
	 *   w4 read_list = 0,
	 *   w5 = 1 (write list: one chunk present), w6 nsegs,
	 *     then nsegs * { handle, length(written), offset(64) } (4 words each),
	 *   w  = 0 (write list terminator),
	 *   w  = 0 (reply chunk: absent),
	 *   then the reduced inline ONC RPC body.
	 * The header is a fixed local size (bounded by n <= SVC_RDMA_MAX_WRITE_SEGS
	 * and cannot be driven past the cap by a peer); with the reduced body it
	 * must fit one inline send buffer (SVC_RDMA_INLINE -- the receive-buffer
	 * size, the bound svc_rdma_conn_send also uses), else EMSGSIZE -> the
	 * caller drops, exactly as the pre-engine over-inline path did.
	 */
	hdrlen = RPCRDMA_HDR_FIXED +			/* prefix */
	    RPCRDMA_WORD +				/* read list = 0 */
	    2 * RPCRDMA_WORD +				/* write list: present + nsegs */
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD) +	/* the segments */
	    RPCRDMA_WORD +				/* write list terminator */
	    RPCRDMA_WORD;				/* reply chunk absent */
	if ((uint64_t)hdrlen + reducedlen > SVC_RDMA_INLINE) {
		rc = EMSGSIZE;
		goto badsrc;
	}
	sendlen = hdrlen + reducedlen;

	/*
	 * Allocate the durable write state (outlives this call -- the writes and
	 * the SEND complete async).  M_NOWAIT (xp_reply runs under a leaf mutex);
	 * zeroed so every token starts false/NULL.
	 */
	ws = malloc(sizeof(*ws), M_NFSRDMA, M_NOWAIT | M_ZERO);
	if (ws == NULL) {
		rc = ENOMEM;
		goto badsrc;
	}
	ws->ws_conn = conn;

	/*
	 * Take ownership of the caller-supplied DMA source buffer and map it
	 * DMA_TO_DEVICE (the HCA READS it to push into the client).  src was
	 * contigmalloc'd AND filled with the read data by the caller BEFORE it took
	 * xr_lock -- the ~100 us per-READ copy that used to run here under the lock
	 * (serializing every concurrent read, the measured read ceiling) is now off
	 * the critical section; this routine only maps + posts.  contigmalloc'd for
	 * the same reason as reply_chunk's ws_src: a multi-page transfer must be
	 * physically contiguous for ib_dma_map_single.  ws owns src from here on
	 * (svc_rdma_write_free frees it).
	 */
	ws->ws_srclen = datalen;
	ws->ws_src = src;
	ws->ws_src_dma = ib_dma_map_single(dev, ws->ws_src, datalen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_src_dma)) {
		free(ws->ws_src, M_NFSRDMA);
		free(ws, M_NFSRDMA);
		return (EIO);
	}
	ws->ws_src_mapped = true;	/* mark live IMMEDIATELY (BLOCKER 1 rule) */

	/*
	 * Build the reduced RDMA_MSG SEND buffer: the transport header (echoing
	 * the write chunk with the bytes actually written) followed by the reduced
	 * inline body, mapped DMA_TO_DEVICE.
	 */
	ws->ws_hdrlen = sendlen;
	ws->ws_hdr = malloc(sendlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees ws */
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);				/* w0  rdma_xid */
	be32enc(h +  4, RPCRDMA_VERSION);		/* w1  rdma_vers */
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);	/* w2  rdma_credit (granted) */
	be32enc(h + 12, RDMA_MSG);			/* w3  rdma_proc */
	be32enc(h + 16, 0);				/* w4  read list (empty) */
	be32enc(h + 20, 1);				/* w5  write list: 1 chunk */
	be32enc(h + 24, n);				/* w6  nsegs */
	off = 28;
	remaining = datalen;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;

		be32enc(h + off + 0, write->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);		/* bytes written into this seg */
		be64enc(h + off + 8, write->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	be32enc(h + off, 0);				/* write list terminator */
	off += RPCRDMA_WORD;
	be32enc(h + off, 0);				/* reply chunk absent */
	off += RPCRDMA_WORD;
	if (reducedlen > 0)
		memcpy(h + off, reduced, reducedlen);	/* reduced inline body */
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, sendlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);	/* unmaps ws_src, frees both + ws */
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Build the RDMA Write WR chain into the write chunk's segments, exactly as
	 * reply_chunk does (one IB_WR_RDMA_WRITE per byte-carrying segment, single
	 * local SGE into ws_src, peer { rkey, remote_addr } verbatim, all
	 * unsignaled), then chain the reduced-RDMA_MSG SEND last and signal ONLY it.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	off = 0;			/* source offset within ws_src */
	remaining = datalen;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;
		int k = ws->ws_nwr;

		ws->ws_sge[k].addr = ws->ws_src_dma + off;
		ws->ws_sge[k].length = wlen;
		ws->ws_sge[k].lkey = conn->sc_pd->local_dma_lkey;

		memset(&ws->ws_wr[k], 0, sizeof(ws->ws_wr[k]));
		ws->ws_wr[k].wr.wr_cqe = &conn->sc_write_sink_cqe;	/* 3f-20 */
		ws->ws_wr[k].wr.sg_list = &ws->ws_sge[k];
		ws->ws_wr[k].wr.num_sge = 1;
		ws->ws_wr[k].wr.opcode = IB_WR_RDMA_WRITE;
		ws->ws_wr[k].wr.send_flags = 0;		/* unsignaled */
		ws->ws_wr[k].remote_addr = write->wc_segs[i].rs_offset;
		ws->ws_wr[k].rkey = write->wc_segs[i].rs_handle;
		ws->ws_nwr++;
		off += wlen;		/* bounded by datalen, no overflow */
		remaining -= wlen;
	}

	/* The tail reduced-RDMA_MSG SEND, signaled -- one completion per chain. */
	ws->ws_sndsge.addr = ws->ws_hdr_dma;
	ws->ws_sndsge.length = sendlen;
	ws->ws_sndsge.lkey = conn->sc_pd->local_dma_lkey;
	memset(&ws->ws_sndwr, 0, sizeof(ws->ws_sndwr));
	ws->ws_sndwr.wr_cqe = &ws->ws_cqe;
	ws->ws_sndwr.sg_list = &ws->ws_sndsge;
	ws->ws_sndwr.num_sge = 1;
	ws->ws_sndwr.opcode = IB_WR_SEND;
	ws->ws_sndwr.send_flags = IB_SEND_SIGNALED;
	ws->ws_sndwr.next = NULL;

	/* Link writes -> ... -> reduced-RDMA_MSG SEND. */
	for (i = 0; i + 1 < (uint32_t)ws->ws_nwr; i++)
		ws->ws_wr[i].wr.next = &ws->ws_wr[i + 1].wr;
	if (ws->ws_nwr > 0)
		ws->ws_wr[ws->ws_nwr - 1].wr.next = &ws->ws_sndwr;

	/*
	 * Arm the send-side teardown barrier and post, IDENTICALLY to
	 * svc_rdma_conn_reply_chunk: register on sc_writes, mark in flight, bump
	 * sc_sends under SC_UP; post with the lock dropped; decrement; partial-post
	 * discipline on failure.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (write-list READ) failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);

	/*
	 * Pre-ws-allocation failures (untrusted-peer validation, EMSGSIZE, ENOMEM):
	 * we own the caller's src buffer but never attached it to a ws, so free it
	 * here.  Once ws exists and ws_src = src, every later path frees src through
	 * svc_rdma_write_free (the completion, the SC_UP/post-fail teardown), so they
	 * must NOT reach this label.
	 */
badsrc:
	free(src, M_NFSRDMA);
	return (rc);
}

/*
 * Zero-copy twin of svc_rdma_conn_write_list (TASK_003f-19, Rick Macklem's
 * enable_mextpg direction).  Same contract, lifetime, completion, one-shot, sink
 * cqe (3f-20) and partial-post rules; the ONLY difference is the RDMA Write
 * SOURCE.  Instead of a contigmalloc'd copy the caller hands us the READ reply's
 * M_EXTPG data pages (mrep + pages[0..npages), summing to datalen) -- already in
 * page-aligned wired kernel pages -- which we map DMA_TO_DEVICE one page at a time
 * and gather into the write WRs (up to sc_max_send_sge pages per WR, never
 * crossing a write-list segment).  We TAKE OWNERSHIP of mrep on EVERY return
 * (0 or errno) -- a faithful twin of svc_rdma_conn_write_list's "engine owns src
 * on every return": a pre-ws validation failure m_freem()s it at the badm label,
 * a post-ws failure through svc_rdma_write_free, and success / committed partial
 * post at write completion or drain (the device read those pages, so they must
 * outlive the Write).  The caller must NOT touch mrep after this call.
 */
int
svc_rdma_conn_write_list_pages(struct svc_rdma_conn *conn, uint32_t xid,
    const struct svc_rdma_write_chunk *write, struct mbuf *mrep,
    const struct svc_rdma_page *pages, uint32_t npages,
    uint32_t datalen, const void *reduced, uint32_t reducedlen)
{
	struct svc_rdma_write_state *ws;
	struct ib_device *dev = conn->sc_id->device;
	const struct ib_send_wr *bad_wr;
	uint64_t capacity, pgsum;
	uint32_t i, n, off, remaining, hdrlen, sendlen, p, pgoff, nsge_total;
	char *h;
	int rc;

	/* Validate datalen + write-chunk shape, IDENTICAL to write_list. */
	if (datalen == 0 || datalen > SVC_RDMA_MAX_WRITE) {
		rc = EINVAL;
		goto badm;
	}
	n = write->wc_nsegs;
	if (n == 0 || n > SVC_RDMA_MAX_WRITE_SEGS) {
		rc = EINVAL;
		goto badm;
	}
	capacity = 0;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;

		if (slen == 0 || slen > SVC_RDMA_MAX_SEG_LEN) {
			rc = EINVAL;
			goto badm;
		}
		capacity += slen;
	}
	if ((uint64_t)datalen > capacity) {
		rc = EMSGSIZE;
		goto badm;
	}

	/*
	 * Validate the page vector (server-built, but bound it anyway): count fits
	 * the arrays, each page <= PAGE_SIZE, and the pages sum EXACTLY to datalen
	 * (the never-over-write invariant -- we write neither more nor less than the
	 * read data the header advertises).
	 */
	if (npages == 0 || npages > SVC_RDMA_MAX_WRITE_PAGES) {
		rc = EINVAL;
		goto badm;
	}
	pgsum = 0;
	for (p = 0; p < npages; p++) {
		if (pages[p].pg_len == 0 || pages[p].pg_len > PAGE_SIZE) {
			rc = EINVAL;
			goto badm;
		}
		pgsum += pages[p].pg_len;
	}
	if (pgsum != datalen) {
		rc = EINVAL;
		goto badm;
	}

	/* Reduced-RDMA_MSG header size check, IDENTICAL to write_list. */
	hdrlen = RPCRDMA_HDR_FIXED + RPCRDMA_WORD + 2 * RPCRDMA_WORD +
	    n * (RPCRDMA_SEG_WORDS * RPCRDMA_WORD) + RPCRDMA_WORD + RPCRDMA_WORD;
	if ((uint64_t)hdrlen + reducedlen > SVC_RDMA_INLINE) {
		rc = EMSGSIZE;
		goto badm;
	}
	sendlen = hdrlen + reducedlen;

	ws = malloc(sizeof(*ws), M_NFSRDMA, M_NOWAIT | M_ZERO);
	if (ws == NULL) {
		rc = ENOMEM;
		goto badm;
	}
	ws->ws_conn = conn;
	ws->ws_srclen = datalen;
	/*
	 * Ownership transfer point: ws owns mrep from here on, so EVERY post-alloc
	 * error path (all of which call svc_rdma_write_free) m_freem()s it exactly
	 * once.  Set it BEFORE the page map loop.
	 */
	ws->ws_keepm = mrep;

	/*
	 * Map each source page DMA_TO_DEVICE.  Bump ws_npgs and set ws_pages_mapped
	 * INCREMENTALLY, so on a mid-loop mapping error svc_rdma_write_free unmaps
	 * exactly the mapped prefix (no leak, no manual unwind).  The page is a wired
	 * kernel page reachable through the direct map (PHYS_TO_DMAP); no FRWR/MR
	 * registration is needed for a LOCAL source -- the PD's local_dma_lkey covers
	 * it, same as the contig path.
	 */
	for (p = 0; p < npages; p++) {
		u64 d = ib_dma_map_single(dev,
		    (void *)(PHYS_TO_DMAP(pages[p].pg_pa) + pages[p].pg_off),
		    pages[p].pg_len, DMA_TO_DEVICE);

		if (ib_dma_mapping_error(dev, d)) {
			svc_rdma_write_free(ws);	/* unmaps prefix, m_freem(mrep) */
			return (EIO);
		}
		ws->ws_pg_dma[p] = d;
		ws->ws_pg_len[p] = pages[p].pg_len;
		ws->ws_npgs = p + 1;
		ws->ws_pages_mapped = true;
	}

	/* Build the reduced-RDMA_MSG SEND buffer, IDENTICAL to write_list. */
	ws->ws_hdrlen = sendlen;
	ws->ws_hdr = malloc(sendlen, M_NFSRDMA, M_NOWAIT);
	if (ws->ws_hdr == NULL) {
		svc_rdma_write_free(ws);
		return (ENOMEM);
	}
	h = ws->ws_hdr;
	be32enc(h +  0, xid);
	be32enc(h +  4, RPCRDMA_VERSION);
	be32enc(h +  8, (uint32_t)conn->sc_nrecv);
	be32enc(h + 12, RDMA_MSG);
	be32enc(h + 16, 0);
	be32enc(h + 20, 1);
	be32enc(h + 24, n);
	off = 28;
	remaining = datalen;
	for (i = 0; i < n; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;

		be32enc(h + off + 0, write->wc_segs[i].rs_handle);
		be32enc(h + off + 4, wlen);
		be64enc(h + off + 8, write->wc_segs[i].rs_offset);
		off += RPCRDMA_SEG_WORDS * RPCRDMA_WORD;
		remaining -= wlen;
	}
	be32enc(h + off, 0);
	off += RPCRDMA_WORD;
	be32enc(h + off, 0);
	off += RPCRDMA_WORD;
	if (reducedlen > 0)
		memcpy(h + off, reduced, reducedlen);
	ws->ws_hdr_dma = ib_dma_map_single(dev, ws->ws_hdr, sendlen,
	    DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, ws->ws_hdr_dma)) {
		svc_rdma_write_free(ws);
		return (EIO);
	}
	ws->ws_hdr_mapped = true;

	/*
	 * Build the RDMA Write WR chain.  Walk write-list segments OUTER and source
	 * pages INNER in lockstep: cap each segment at min(remaining, rs_length)
	 * (never-over-write), gather consecutive pages into one WR's SGE list up to
	 * sc_max_send_sge, and start a new WR when the SGE list fills OR the segment
	 * ends (a WR carries exactly one segment's rkey/remote_addr).  Unsignaled,
	 * routed to the per-conn sink cqe (3f-20); only the tail SEND is signaled.
	 */
	ws->ws_cqe.done = svc_rdma_wc_rdma_write;
	remaining = datalen;
	p = 0;
	pgoff = 0;
	nsge_total = 0;
	ws->ws_nwr = 0;
	for (i = 0; i < n && remaining > 0; i++) {
		uint32_t slen = write->wc_segs[i].rs_length;
		uint32_t wlen = (remaining < slen) ? remaining : slen;
		uint64_t raddr = write->wc_segs[i].rs_offset;
		uint32_t seg_left = wlen;

		while (seg_left > 0) {
			int k = ws->ws_nwr;
			struct ib_sge *sg = &ws->ws_sge[nsge_total];
			int nsge = 0;
			uint32_t wbytes = 0;

			if (k >= SVC_RDMA_MAX_WRITE_WRS) {
				svc_rdma_write_free(ws);
				return (EMSGSIZE);
			}
			while (seg_left > 0 && nsge < (int)conn->sc_max_send_sge &&
			    p < npages && nsge_total < SVC_RDMA_MAX_WRITE_SGE) {
				uint32_t pavail = ws->ws_pg_len[p] - pgoff;
				uint32_t take = (seg_left < pavail) ? seg_left : pavail;

				sg[nsge].addr = ws->ws_pg_dma[p] + pgoff;
				sg[nsge].length = take;
				sg[nsge].lkey = conn->sc_pd->local_dma_lkey;
				nsge++;
				nsge_total++;
				wbytes += take;
				seg_left -= take;
				pgoff += take;
				if (pgoff == ws->ws_pg_len[p]) {
					p++;
					pgoff = 0;
				}
			}
			if (nsge == 0 || (seg_left > 0 && p >= npages)) {
				/* pages ran out mid-segment, or SGE array full: bug/overflow */
				svc_rdma_write_free(ws);
				return (EFAULT);
			}
			memset(&ws->ws_wr[k], 0, sizeof(ws->ws_wr[k]));
			ws->ws_wr[k].wr.wr_cqe = &conn->sc_write_sink_cqe;	/* 3f-20 */
			ws->ws_wr[k].wr.sg_list = sg;
			ws->ws_wr[k].wr.num_sge = nsge;
			ws->ws_wr[k].wr.opcode = IB_WR_RDMA_WRITE;
			ws->ws_wr[k].wr.send_flags = 0;		/* unsignaled */
			ws->ws_wr[k].remote_addr = raddr;
			ws->ws_wr[k].rkey = write->wc_segs[i].rs_handle;
			ws->ws_nwr++;
			raddr += wbytes;
		}
		remaining -= wlen;
	}

	/* The tail reduced-RDMA_MSG SEND, signaled -- one completion per chain. */
	ws->ws_sndsge.addr = ws->ws_hdr_dma;
	ws->ws_sndsge.length = sendlen;
	ws->ws_sndsge.lkey = conn->sc_pd->local_dma_lkey;
	memset(&ws->ws_sndwr, 0, sizeof(ws->ws_sndwr));
	ws->ws_sndwr.wr_cqe = &ws->ws_cqe;
	ws->ws_sndwr.sg_list = &ws->ws_sndsge;
	ws->ws_sndwr.num_sge = 1;
	ws->ws_sndwr.opcode = IB_WR_SEND;
	ws->ws_sndwr.send_flags = IB_SEND_SIGNALED;
	ws->ws_sndwr.next = NULL;

	for (i = 0; i + 1 < (uint32_t)ws->ws_nwr; i++)
		ws->ws_wr[i].wr.next = &ws->ws_wr[i + 1].wr;
	if (ws->ws_nwr > 0)
		ws->ws_wr[ws->ws_nwr - 1].wr.next = &ws->ws_sndwr;

	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		svc_rdma_write_free(ws);
		return (ENOTCONN);
	}
	TAILQ_INSERT_TAIL(&conn->sc_writes, ws, ws_link);
	ws->ws_active = true;
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	rc = ib_post_send(conn->sc_id->qp,
	    ws->ws_nwr > 0 ? &ws->ws_wr[0].wr : &ws->ws_sndwr, &bad_wr);

	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_post_send (write-list READ pages) failed: "
			    "%d (prefix may be committed; drain reclaims)\n", rc);
		svc_rdma_conn_close(conn);
		return (rc < 0 ? -rc : rc);
	}
	return (0);

	/*
	 * Pre-ws-allocation failures (validation, EMSGSIZE, ENOMEM before ws
	 * exists): we own mrep but never attached it to a ws, so m_freem() it here
	 * -- the "engine owns mrep on every return" contract, mirroring the contig
	 * twin's badsrc.  Every path AFTER ws_keepm = mrep frees mrep through
	 * svc_rdma_write_free (or, on a committed partial post, at drain) and must
	 * not reach this label.
	 */
badm:
	if (mrep != NULL)
		m_freem(mrep);
	return (rc);
}

/*
 * ===========================================================================
 * FRWR memory-registration substrate (TASK_003f-2).
 *
 * This is ONLY the registration plumbing the RDMA Read (3f-3) and RDMA Write
 * (3f-4) engines will sit on top of: a per-connection pool of fast-registration
 * MRs, a helper that fast-registers a SERVER buffer into one of them, a helper
 * that releases the MR's DMA mapping, and the completion handler for the REG_MR/
 * LOCAL_INV WRs.  NO RDMA Read/Write is posted here, and NO peer-supplied chunk
 * drives any of it -- the only buffer registered in 3f-2 is a server-allocated
 * one in the accept-time self-test below.
 *
 * The MR-vs-DMA lifetime rule (the #1 review hazard) is enforced as follows:
 *   - the MR is created at accept time and ib_dereg_mr()'d ONLY in the drained
 *     teardown, after ib_drain_qp(), so no REG_MR/LOCAL_INV completion can fire
 *     against a freed MR;
 *   - the scatterlist ib_map_mr_sg() consumes is ib_dma_map_sg()'d in the
 *     register helper and stays mapped until the MR is invalidated (the LOCAL_INV
 *     completion) or the connection is torn down -- it is NEVER unmapped while
 *     the MR could still be accessed; the teardown unmaps any slot still mapped
 *     at close;
 *   - the registration key is rotated (ib_update_fast_reg_key) on every
 *     (re)registration, so a stale rkey can never be reused.
 * ===========================================================================
 */

/*
 * Fast-register a SERVER buffer into one of this connection's pre-allocated MRs
 * and BUILD (but do NOT post) the IB_WR_REG_MR work request for it.  Posting is
 * the CALLER's job (the 3f-3/3f-4 data engine, or the self-test below), so that
 * the WR can be chained ahead of the RDMA Read/Write it gates on the same SQ.
 *
 * buf/len describe a contiguous, kernel-heap (never stack/pageable), SERVER-
 * allocated buffer -- in 3f-2 one of the connection's own send buffers.  len is
 * a fixed local size, NOT a peer-supplied length.  access is the MR access mask
 * the caller needs (IB_ACCESS_LOCAL_WRITE for a Read-target/Write-source, plus
 * IB_ACCESS_REMOTE_* if the rkey is to be handed to the peer -- the self-test
 * uses LOCAL_WRITE only, as a local MR is all the substrate needs to prove).
 *
 * Steps (the canonical FreeBSD FRWR sequence, verified against the in-tree KPI):
 *   1. describe buf as a one-entry scatterlist (sg_init_one);
 *   2. ib_dma_map_sg() it for the device -- this populates sg_dma_address/
 *      sg_dma_len that ib_map_mr_sg() reads.  The mapping MUST outlive the MR's
 *      registration; sm_sg_mapped records it so the unmap is paired exactly once
 *      (on invalidation or in teardown);
 *   3. ib_map_mr_sg() builds the MR's page vector from the mapped sg at
 *      PAGE_SIZE granularity; it returns the number of sg entries mapped.  We
 *      require it to map our single entry whole -- a short map means the buffer
 *      needed more pages than the MR holds (it cannot here: len <= the
 *      device-bounded page cap), which we treat as an error rather than
 *      registering a truncated region;
 *   4. rotate the registration key (ib_update_fast_reg_key) so the rkey/lkey are
 *      fresh -- no stale-rkey reuse;
 *   5. fill the prebuilt ib_reg_wr {opcode IB_WR_REG_MR, mr, key, access}.
 * On success *rkeyp is the fresh rkey (== lkey for a fast-reg MR) the caller will
 * cite in its RDMA Read/Write, and sm->sm_regwr is ready to post.  On any failure
 * the DMA mapping is undone here (so the caller need not) and a positive errno is
 * returned.
 *
 * Context: callable from the recv completion / a sleepable setup path; it does
 * not sleep (ib_dma_map_sg / ib_map_mr_sg do not) and takes no lock -- the caller
 * owns sm (claimed from the pool under sc_lock) for the duration.
 */
static int
svc_rdma_mr_reg(struct svc_rdma_conn *conn, struct svc_rdma_mr *sm,
    void *buf, uint32_t len, int access, uint32_t *rkeyp)
{
	struct ib_device *dev = conn->sc_id->device;
	int n;

	/*
	 * A server buffer must fit the MR's page vector.  sc_mr_pages was clamped
	 * to the device's fast-reg page-list cap at accept time, so this is a
	 * fixed local bound, not a peer length.  howmany() rounds up to whole
	 * pages (the first page may carry an offset; ib_map_mr_sg handles that).
	 */
	if (len == 0 || howmany(len, PAGE_SIZE) > conn->sc_mr_pages)
		return (EINVAL);

	/* (1) one-entry scatterlist over the contiguous server buffer. */
	sg_init_one(sm->sm_sg, buf, len);

	/*
	 * (2) DMA-map the sg for the device.  DMA_BIDIRECTIONAL is the safe choice
	 * for a substrate MR that a later increment may use as either an RDMA Read
	 * sink (device writes) or an RDMA Write source (device reads); the self-
	 * test here only registers and invalidates, touching no data.  Record the
	 * live mapping so it is unmapped exactly once.
	 */
	n = ib_dma_map_sg(dev, sm->sm_sg, 1, DMA_BIDIRECTIONAL);
	if (n != 1) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_dma_map_sg (FRWR) failed\n");
		return (EIO);
	}
	sm->sm_sg_mapped = true;

	/*
	 * (3) Build the MR page vector from the mapped sg.  Require the whole
	 * single entry to map; ib_map_mr_sg returns the count mapped (or a
	 * negative errno).  A partial/failed map leaves the MR unusable -- undo
	 * the DMA mapping and fail.
	 */
	n = ib_map_mr_sg(sm->sm_mr, sm->sm_sg, 1, NULL, PAGE_SIZE);
	if (n != 1) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: ib_map_mr_sg mapped %d of 1 sg\n", n);
		svc_rdma_mr_unmap(conn, sm);
		return (EIO);
	}

	/* (4) Rotate the registration key -- never reuse a stale rkey. */
	ib_update_fast_reg_key(sm->sm_mr, ++sm->sm_key);

	/* (5) Fill the prebuilt IB_WR_REG_MR; the caller posts it. */
	memset(&sm->sm_regwr, 0, sizeof(sm->sm_regwr));
	sm->sm_regwr.wr.opcode = IB_WR_REG_MR;
	sm->sm_regwr.wr.wr_cqe = &sm->sm_cqe;
	sm->sm_regwr.wr.num_sge = 0;
	sm->sm_regwr.wr.send_flags = 0;	/* signaling is the caller's choice */
	sm->sm_regwr.mr = sm->sm_mr;
	sm->sm_regwr.key = sm->sm_mr->rkey;
	sm->sm_regwr.access = access;

	if (rkeyp != NULL)
		*rkeyp = sm->sm_mr->rkey;
	return (0);
}

/*
 * Drop the DMA mapping an svc_rdma_mr_reg() established, exactly once.  Called
 * either when the MR's LOCAL_INV has completed (the device is done with the MR's
 * page vector) or from the drained teardown for a slot still mapped at close.
 * Idempotent via sm_sg_mapped, so a teardown after a normal release is a no-op.
 * Does NOT touch sm_mr (the MR itself is deregistered in the teardown).
 */
static void
svc_rdma_mr_unmap(struct svc_rdma_conn *conn, struct svc_rdma_mr *sm)
{
	struct ib_device *dev;

	if (!sm->sm_sg_mapped)
		return;
	dev = (conn->sc_id != NULL) ? conn->sc_id->device : NULL;
	if (dev != NULL)
		ib_dma_unmap_sg(dev, sm->sm_sg, 1, DMA_BIDIRECTIONAL);
	sm->sm_sg_mapped = false;
}

/*
 * Completion for a self-test REG_MR+LOCAL_INV chain (TASK_003f-2).  Dispatched by
 * the CQ core in the SAME IB_POLL_WORKQUEUE context as svc_rdma_wc_send(); keep
 * it short, take no sleepable lock, start no blocking teardown.  sm_cqe aliases
 * the wr_cqe of the (signaled) LOCAL_INV WR in the chain, so container_of()
 * recovers the MR descriptor and sm_conn the owning connection.
 *
 * The REG_MR in the chain is posted UNSIGNALED, so the only completion that fires
 * is for the LOCAL_INV; reaching here means the MR was fast-registered AND
 * invalidated successfully (or the chain flushed during teardown).  Either way
 * the device is done with the MR's page vector, so we drop the DMA mapping and
 * return the slot to the bounded pool.  This is the send-side mirror of
 * svc_rdma_wc_send(): it does NOT ib_dereg_mr() (the drained teardown does that
 * exactly once after ib_drain_qp()).
 *
 * IB_WC_WR_FLUSH_ERR is the expected status for a chain flushed when the QP
 * drains during teardown: swallow it silently -- the teardown task unmaps any
 * still-mapped slot and deregisters every MR, and it does so only AFTER
 * ib_drain_qp(), so this completion sees a still-live conn.  Any other error is a
 * real registration fault -> start a deferred teardown.
 *
 * The matching sc_sends decrement is done by the POSTING site (svc_rdma_mr_selftest)
 * right after ib_post_send returns, exactly as svc_rdma_conn_send() decrements its
 * own sc_sends after posting -- NOT here.  So this handler only reclaims the slot.
 *
 * ONE-SHOT (SHOULD-FIX, the same multi-completion guard as svc_rdma_wc_rdma_read).
 * A partially-committed chained post (REG_MR + LOCAL_INV) can flush BOTH WRs, so
 * this handler can be invoked >1x for one sm.  sm_inuse is the one-shot token: at
 * the top, under sc_lock, test-and-clear it; if it was already clear this is a
 * DUPLICATE completion and we return (the first invocation, or the drained
 * teardown, owns reclaim).  Teardown reclaim is driven by sm_sg_mapped / sm_mr
 * (NOT sm_inuse), so a flush/error path that returns the slot to the pool here
 * without unmapping still lets the teardown unmap+dereg exactly once.
 */
static void
svc_rdma_wc_reg(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svc_rdma_mr *sm;
	struct svc_rdma_conn *conn;
	bool first;

	/* Same single-workqueue-thread invariant as the recv/send handlers (N2). */
	MPASS(cq->poll_ctx == IB_POLL_WORKQUEUE);

	sm = container_of(wc->wr_cqe, struct svc_rdma_mr, sm_cqe);
	conn = sm->sm_conn;

	/*
	 * One-shot test-and-clear: only the FIRST completion for this MR proceeds;
	 * a duplicate (the chain's other WR flushing) finds sm_inuse already false
	 * and returns.  Clearing sm_inuse here also returns the slot to the pool for
	 * the success path (which previously cleared it at the end).
	 */
	mtx_lock(&conn->sc_lock);
	first = sm->sm_inuse;
	sm->sm_inuse = false;
	mtx_unlock(&conn->sc_lock);
	if (!first)
		return;

	if (wc->status != IB_WC_SUCCESS) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			if (ppsratecheck(&svc_rdma_log_last,
			    &svc_rdma_log_pps, 5))
				printf("nfsrdma: FRWR completion error %u\n",
				    wc->status);
			/*
			 * Leave sm_sg_mapped as-is: the teardown unmaps it (the
			 * device may still hold the registration on an error that
			 * did not invalidate).  The slot is already returned to the
			 * pool by the one-shot above, but the teardown owns the
			 * whole pool's unmap+dereg once it runs (gated by
			 * sm_sg_mapped/sm_mr, not sm_inuse), so this cannot leak.
			 */
			svc_rdma_conn_close(conn);
		}
		return;
	}

	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
		printf("nfsrdma: FRWR self-test register+invalidate ok "
		    "(rkey rotated)\n");

	/*
	 * Registered and invalidated cleanly: the device is done with the MR's
	 * page vector, so drop the DMA mapping (the slot was already returned to the
	 * pool by the one-shot above).  svc_rdma_mr_unmap is idempotent on
	 * sm_sg_mapped, so a racing drained-teardown unmap is a no-op.
	 */
	svc_rdma_mr_unmap(conn, sm);
}

/*
 * Accept-time FRWR self-test (TASK_003f-2): prove the registration/invalidation
 * completion path end-to-end by fast-registering one of the connection's own
 * send buffers into a pool MR and posting REG_MR + LOCAL_INV as a single chained
 * SEND WR, then letting svc_rdma_wc_reg() reap the (single, signaled) completion.
 *
 * This is the ONLY posting the substrate does in 3f-2; the real REG_MR posting
 * (chained ahead of an IB_WR_RDMA_READ/WRITE) is 3f-3/3f-4.  It registers a
 * SERVER buffer only -- no peer chunk, no peer length -- so nothing here is
 * attacker-influenced.
 *
 * Chaining: REG_MR is posted UNSIGNALED (the QP is IB_SIGNAL_REQ_WR, so an
 * unsignaled WR yields no CQE) followed by a SIGNALED LOCAL_INV.  The two WRs are
 * a single ib_post_send list, so they enter the SQ atomically and the device
 * registers-then-invalidates; exactly ONE completion (for the LOCAL_INV) fires,
 * which is exactly ONE sc_sends unit to account.  We register with LOCAL_WRITE
 * access only: a local MR is all the substrate proves, and we hand the rkey to no
 * peer here.
 *
 * sc_sends accounting (the load-bearing teardown-safety arm).  We arm the send
 * barrier IDENTICALLY to svc_rdma_conn_send(): in one sc_lock section verify the
 * conn is SC_UP, claim a free MR slot from the bounded pool (sm_inuse), and bump
 * sc_sends; then build + post with the lock dropped; then reacquire, decrement
 * sc_sends, and wake the teardown if we were the last in-flight send.  Because
 * svc_rdma_conn_close() publishes SC_CLOSING before enqueuing the teardown, once
 * teardown is pending this self-test cannot pass the SC_UP gate, and the barrier
 * waits only for an already-counted post to finish.  After sc_sends hits 0 the
 * chained WRs are on the SQ before ib_drain_qp(), so the SQ drain sentinel
 * catches them (their flush completion reaches svc_rdma_wc_reg with a live conn)
 * and nothing posts afterward -- the same argument the reply-send barrier makes.
 *
 * Best-effort: any failure (no free slot, registration error, post error) is
 * logged and dropped; the self-test never closes a healthy connection on its own
 * (a post failure does, via the shared close path, exactly like a reply send).
 */
static void
svc_rdma_mr_selftest(struct svc_rdma_conn *conn)
{
	struct svc_rdma_mr *sm;
	const struct ib_send_wr *bad_wr;
	uint32_t rkey;
	int i, rc;

	/* No MR pool (degenerate device) -> nothing to self-test. */
	if (conn->sc_mr == NULL || conn->sc_nmr == 0 ||
	    conn->sc_selftest_buf == NULL)
		return;

	/*
	 * Claim a free MR slot and arm the send barrier while SC_UP, in one
	 * sc_lock section -- the exact shape of svc_rdma_conn_send()'s claim.
	 */
	mtx_lock(&conn->sc_lock);
	if (conn->sc_state != SC_UP) {
		mtx_unlock(&conn->sc_lock);
		return;
	}
	sm = NULL;
	for (i = 0; i < conn->sc_nmr; i++) {
		if (!conn->sc_mr[i].sm_inuse) {
			sm = &conn->sc_mr[i];
			sm->sm_inuse = true;
			break;
		}
	}
	if (sm == NULL) {
		mtx_unlock(&conn->sc_lock);
		return;
	}
	conn->sc_sends++;
	mtx_unlock(&conn->sc_lock);

	/*
	 * Register our PRIVATE self-test buffer (sc_selftest_buf: a contiguous,
	 * server-owned SVC_RDMA_INLINE-byte heap allocation -- never stack/pageable,
	 * never a send-pool buffer) into the MR and build its REG_MR WR.  This buffer
	 * is owned solely by the self-test, so the FRWR register helper's bus_dma
	 * mapping is the ONLY mapping of this KVA: no aliasing with any concurrent
	 * reply SEND.  This is a no-data register/invalidate (the self-test transfers
	 * nothing); the mapping is torn down on the LOCAL_INV completion or by the
	 * drained teardown.  On failure release the slot and drop the send barrier.
	 */
	rc = svc_rdma_mr_reg(conn, sm, conn->sc_selftest_buf, SVC_RDMA_INLINE,
	    IB_ACCESS_LOCAL_WRITE, &rkey);
	if (rc != 0) {
		mtx_lock(&conn->sc_lock);
		sm->sm_inuse = false;
		if (--conn->sc_sends == 0)
			wakeup(&conn->sc_upcalls);
		mtx_unlock(&conn->sc_lock);
		return;
	}

	/*
	 * REG_MR (unsignaled) -> LOCAL_INV (signaled), chained.  The REG_MR WR
	 * was filled by svc_rdma_mr_reg(); chain the LOCAL_INV after it and make
	 * only the tail signaled, so a single completion reaches svc_rdma_wc_reg.
	 */
	sm->sm_regwr.wr.next = &sm->sm_invwr;

	memset(&sm->sm_invwr, 0, sizeof(sm->sm_invwr));
	sm->sm_invwr.next = NULL;
	sm->sm_invwr.opcode = IB_WR_LOCAL_INV;
	sm->sm_invwr.send_flags = IB_SEND_SIGNALED;
	sm->sm_invwr.ex.invalidate_rkey = sm->sm_mr->rkey;
	sm->sm_invwr.wr_cqe = &sm->sm_cqe;
	sm->sm_cqe.done = svc_rdma_wc_reg;

	if (bootverbose)
		printf("nfsrdma: FRWR self-test posting REG_MR+LOCAL_INV "
		    "rkey=0x%08x\n", rkey);

	rc = ib_post_send(conn->sc_id->qp, &sm->sm_regwr.wr, &bad_wr);

	/*
	 * SHOULD-FIX (same partial-post flaw as the RDMA Read chain): this is a
	 * 2-WR chain (REG_MR unsignaled + LOCAL_INV signaled).  mlx5 commits the
	 * already-built prefix to the HCA on a mid-chain failure (mlx5_ib_qp.c out:
	 * `if (likely(nreq))`), so on rc != 0 a committed REG_MR may be live and its
	 * flush/error completion will run svc_rdma_wc_reg via container_of on sm.  We
	 * must therefore NOT reclaim inline (no svc_rdma_mr_unmap, no sm_inuse=false):
	 * that would race the committed WR's completion and free a DMA mapping the
	 * device may still touch.  Leave sm_sg_mapped/sm_inuse set; the DRAINED
	 * teardown (svc_rdma_conn_free_verbs, after ib_drain_qp) is the single
	 * reclaimer (idempotent svc_rdma_mr_unmap + ib_dereg_mr).  We DO still
	 * decrement sc_sends (the posting op finished) so the teardown barrier can
	 * reach 0 and drain the committed prefix, then conn_close.  svc_rdma_wc_reg is
	 * one-shot-guarded against the resulting multiple completions (see there).
	 */
	mtx_lock(&conn->sc_lock);
	if (--conn->sc_sends == 0)
		wakeup(&conn->sc_upcalls);
	mtx_unlock(&conn->sc_lock);

	if (rc != 0) {
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: FRWR self-test ib_post_send failed: %d "
			    "(prefix may be committed; drain reclaims)\n", rc);
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
 * Report the granted flow-control credit -- the number of recv buffers we
 * actually posted for this connection (sc_nrecv), clamped at accept time to the
 * device's QP recv cap.  This is the value a consumer's reply should advertise
 * in the RPC-over-RDMA rdma_credit field (the same value svc_rdma_reply() uses
 * for the in-tree stub).  sc_nrecv is written once during accept and never
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
 * Surface the connection's PEER address (TASK_003f-6).  RDMA-CM resolved the
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
static void
svc_rdma_conn_peeraddr(struct svc_rdma_conn *conn, struct sockaddr_storage *ss)
{
	struct sockaddr *sa;

	memset(ss, 0, sizeof(*ss));
	if (conn->sc_id == NULL)
		return;
	sa = (struct sockaddr *)&conn->sc_id->route.addr.dst_addr;
	switch (sa->sa_family) {
	case AF_INET:
		memcpy(ss, sa, sizeof(struct sockaddr_in));
		ss->ss_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		memcpy(ss, sa, sizeof(struct sockaddr_in6));
		ss->ss_len = sizeof(struct sockaddr_in6);
		break;
	default:
		break;
	}
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
 * Marshal and post an RPC-over-RDMA version 1 RDMA_ERROR reply (RFC 8166 4.4/5,
 * TASK_028), echoing the call's KNOWN opaque xid.  This is the conformant
 * replacement for silently conn_close()ing a recoverable protocol error: it
 * tells the client WHY with a transport-level error reply.
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
 *                    identical to svc_rdma_reply(); never the peer's offered
 *                    credit.  Set once at accept time, never mutated, so reading
 *                    it here without sc_lock is safe.
 *   w3 rdma_proc   = RDMA_ERROR (4)
 *   w4 rdma_err    = errcode (ERR_VERS | ERR_CHUNK)
 *   ERR_VERS only:
 *     w5 vers_low  = RPCRDMA_VERSION (1)
 *     w6 vers_high = RPCRDMA_VERSION (1)
 * Total: 5 words (20 bytes) for ERR_CHUNK, 7 words (28 bytes) for ERR_VERS --
 * both well under SVC_RDMA_REPLY_LEN, so the fixed local buffer cannot overflow.
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
static int
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
 * Consumer-facing RDMA_ERROR entry point (the svo_conn_error op, TASK_028).  The
 * krpc consumer (sys/rpc/svc_rdma.c) reaches this through the registered
 * verbs-ops table when it cannot place a reply with the offered chunk lists and
 * wants to report ERR_CHUNK keyed by the request's xid instead of dropping
 * silently.  Thin wrapper over svc_rdma_send_error() so the consumer needs no
 * knowledge of the wire header; it does NOT close the connection (ERR_CHUNK is a
 * per-request error and the connection stays UP).  Declared extern in
 * <rdma/svc_rdma.h>; OPTIONAL (krpc NULL-checks it at the call site and
 * svc_rdma_register_verbs does not require it, so an older ibcore still loads and
 * over-inline drops keep their prior behavior).
 */
int
svc_rdma_conn_error(struct svc_rdma_conn *conn, uint32_t xid, uint32_t errcode)
{

	return (svc_rdma_send_error(conn, xid, errcode));
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

	/* Same single-workqueue-thread invariant as svc_rdma_wc_recv (N2): the
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
 * after this returns).  The caller (svc_rdma_conn_destroy) MUST have already
 * drained the QP via ib_drain_qp(); this routine then frees the CQs FIRST, and
 * ib_free_cq()'s flush_work() -- NOT ib_drain_qp() -- is the barrier that
 * guarantees the completion workqueue has dispatched every completion, so no
 * completion can fire against the writes/buffers/conn this frees afterward.
 *
 * Order: QP (clears sc_id->qp) -> recv CQ -> send CQ -> reclaim in-flight writes
 * -> unmap+free each recv buffer -> unmap+free each send buffer -> unmap+dereg
 * each FRWR MR -> PD.  The CQs are freed BEFORE any completion-referenced state
 * (writes/recv/send buffers) so the workqueue is quiesced first.  A CQ is never
 * freed under a live QP, and the PD (whose local_dma_lkey the recv/send
 * SGEs reference, and whose usecnt every MR holds) outlives every buffer and MR
 * that used it -- so the MR pool is deregistered BEFORE ib_dealloc_pd().
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
	 * Free the CQs BEFORE reclaiming any completion-referenced state
	 * (TASK_003f-20).  ib_free_cq() flush_work()s the completion workqueue, so
	 * once it returns NO completion can still run; that is the real quiescence
	 * barrier, NOT ib_drain_qp().  Under heavy close churn -- every ENOMEM /
	 * SQ-full post closes the conn -- a SUCCESSFUL tail-SEND completion can still
	 * be sitting undispatched in the send CQ when this teardown runs; ib_drain_qp()
	 * does not guarantee the workqueue has dispatched it.  The recv buffers, send
	 * pool, and MRs are freed AFTER the CQs for exactly this reason; the sc_writes
	 * reclaim below MUST be too.  (Empirically: reclaiming ws before the CQ free
	 * let a pending SEND completion dereference a freed ws_cqe -> GPF in
	 * ib_cq_poll_work, the 256-concurrent-read crash.)
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
	 * Reclaim any outbound RDMA Write (TASK_003f-4) whose completion NEVER ran:
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
			 * Reclaim any RDMA Read (TASK_003f-3) still in flight for
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

	if (conn->sc_mr != NULL) {
		/*
		 * FRWR MR pool (3f-2).  Mirror of the recv/send unwind, and it
		 * obeys the SAME drained-teardown precondition: the caller
		 * (svc_rdma_conn_destroy) has already run ib_drain_qp(), so no
		 * REG_MR/LOCAL_INV completion can be touching an MR or its DMA
		 * mapping when we release them here.  For each slot, in this order:
		 *   - drop any DMA mapping STILL live at close (a slot registered
		 *     but whose LOCAL_INV never completed -- e.g. closed mid-self-
		 *     test or a registration error); svc_rdma_mr_unmap is idempotent
		 *     via sm_sg_mapped, so a slot already released on its completion
		 *     is skipped.  The unmap MUST precede ib_dereg_mr (you cannot
		 *     unmap through a destroyed MR's device-less slot, and the device
		 *     must still be reading neither);
		 *   - ib_dereg_mr() the MR (NULL-guarded: a slot whose ib_alloc_mr
		 *     failed during a partial accept-time build has sm_mr == NULL).
		 * MRs are deregistered BEFORE ib_dealloc_pd() below: each MR holds a
		 * reference on the PD (ib_alloc_mr atomic_inc's pd->usecnt), so the PD
		 * must outlive every MR -- exactly the rule the recv/send SGEs'
		 * local_dma_lkey already imposes on the PD.
		 */
		for (i = 0; i < conn->sc_nmr; i++) {
			struct svc_rdma_mr *sm = &conn->sc_mr[i];

			svc_rdma_mr_unmap(conn, sm);
			if (sm->sm_mr != NULL) {
				ib_dereg_mr(sm->sm_mr);
				sm->sm_mr = NULL;
			}
		}
		free(conn->sc_mr, M_NFSRDMA);
		conn->sc_mr = NULL;
		conn->sc_nmr = 0;
	}

	/*
	 * Free the private self-test buffer AFTER the MR pool above: the FRWR
	 * self-test's sg mapping over this buffer (left live for the drained
	 * teardown in the partial-post case) is dropped by svc_rdma_mr_unmap() in
	 * the sc_mr block, so by here no MR mapping references it.
	 */
	if (conn->sc_selftest_buf != NULL) {
		free(conn->sc_selftest_buf, M_NFSRDMA);
		conn->sc_selftest_buf = NULL;
	}

	/*
	 * Read-buffer pool (TASK_003f-8).  Runs AFTER ib_drain_qp() (via caller
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
				free(rb->rb_buf, M_NFSRDMA);
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
 *      This flushes the QP and bounds the work, but it does NOT by itself
 *      guarantee the completion WORKQUEUE has dispatched every earlier CQE:
 *      empirically a SUCCESSFUL tail-SEND completion can still be sitting
 *      undispatched in the send CQ when this returns.  The hard quiescence
 *      barrier is ib_free_cq()'s flush_work() in step 4.
 *   4. svc_rdma_conn_free_verbs() -- destroy QP, then free the CQs (ib_free_cq()
 *      flush_work()s the completion workqueue: AFTER this no completion can run),
 *      THEN reclaim in-flight writes, unmap+free buffers, unmap+ib_dereg_mr the
 *      FRWR pool (3f-2), dealloc PD.  Freeing the CQs before any
 *      completion-referenced state is what makes the rest safe -- in particular
 *      no REG_MR/LOCAL_INV
 *      completion can be reading an MR or its DMA mapping, the MR-vs-DMA lifetime
 *      guarantee the reviewer cares about.
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
	TAILQ_INIT(&conn->sc_writes);	/* in-flight RDMA Write registry (3f-4) */
	conn->sc_write_sink_cqe.done = svc_rdma_wc_write_sink;	/* 3f-20 */
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
	 *
	 * max_wr is the RECV cap (and the reply-send pool depth).  max_send_wr is
	 * the SEND-queue cap: the reply depth PLUS FRWR head-room (3f-2) PLUS RDMA
	 * Read head-room (3f-3) PLUS RDMA Write head-room (3f-4).  The SQ carries reply
	 * SENDs, REG_MR + LOCAL_INV WRs, RDMA Read WR chains, AND RDMA Write WR chains
	 * (+ their header SEND), so it must hold them all without overflow.  We reserve:
	 *   - 2 WRs per MR slot (one REG_MR + one LOCAL_INV), 2 * SVC_RDMA_MR_DEPTH;
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
	max_send_wr = max_wr + 2 * SVC_RDMA_MR_DEPTH +
	    max_wr * SVC_RDMA_MAX_READ_SEGS +
	    max_wr * (SVC_RDMA_MAX_WRITE_WRS + 1);	/* 3f-19: page-gather chain */
	if (dev->attrs.max_qp_wr > 0 &&
	    (u32)dev->attrs.max_qp_wr < max_send_wr)
		max_send_wr = dev->attrs.max_qp_wr;
	max_sge = 1;
	if (dev->attrs.max_sge > 0 && (u32)dev->attrs.max_sge < max_sge)
		max_sge = dev->attrs.max_sge;
	/*
	 * Recv WRs use one SGE (an inline recv buffer); send WRs gather up to
	 * SVC_RDMA_MAX_SEND_SGE pages for the zero-copy outbound READ (3f-19),
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
	 * the 3f-2 FRWR head-room), the recv CQ to max_wr + 1.
	 * comp_vector (TASK_003f-9 fix #2): rotate per connection and put this
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
	qp_attr.cap.max_send_sge = max_send_sge;	/* 3f-19 page gather */
	qp_attr.cap.max_recv_sge = max_sge;
	qp_attr.cap.max_inline_data = 0;

	/*
	 * Create the QP.  The page-gather SQ (3f-19) requests a large send queue
	 * whose per-WQE size is inflated by max_send_sge; on some providers the
	 * ideal SQ exceeds what can be allocated and rdma_create_qp returns
	 * -ENOMEM (mlx5 rounds the WQE-buffer up to a power of two, so the exact
	 * ceiling is hard to predict statically).  Rather than guess, request the
	 * ideal size and, on ENOMEM, halve max_send_wr and retry down to a floor
	 * that still holds ONE full in-flight chain (one inbound read + one
	 * page-write reply + its SEND + MR head-room).  A smaller SQ only means
	 * ib_post_send can fill under heavy concurrency -- which every post path
	 * already handles by closing the connection -- never a silent overflow.
	 * rdma_create_qp() records id->qp on success; on failure id->qp stays
	 * NULL, which svc_rdma_conn_free_verbs() relies on to decide whether to
	 * rdma_destroy_qp().  The provider may write granted caps back into
	 * qp_attr.cap, so we keep using our own max_send_sge (<= requested) for
	 * conn->sc_max_send_sge, never the written-back value.
	 */
	{
		u32 min_send_wr = max_wr + 2 * SVC_RDMA_MR_DEPTH +
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
	conn->sc_max_send_sge = max_send_sge;	/* 3f-19: page-gather loop reads this */
	if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 1))
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
	 * Private FRWR self-test buffer (TASK_003f-2 hardening).  The establish-
	 * time MR self-test registers a server buffer; it must NOT alias a live
	 * send-pool buffer (a first reply could claim sc_send[0] and post a
	 * DMA_TO_DEVICE SEND concurrently with the self-test's independent map of
	 * the same KVA -- two oppositely-directioned mappings of one buffer).  This
	 * dedicated buffer is owned solely by the self-test, mapped only by it, and
	 * freed in svc_rdma_conn_free_verbs after the QP is drained.
	 */
	conn->sc_selftest_buf = malloc(SVC_RDMA_INLINE, M_NFSRDMA, M_WAITOK);

	/*
	 * Allocate the FRWR memory-registration pool (TASK_003f-2), the per-conn
	 * substrate the RDMA Read (3f-3) / RDMA Write (3f-4) engines register
	 * server buffers through.  Like the recv/send pools it is built at accept
	 * time and reclaimed only in the drained teardown (ib_dereg_mr after
	 * ib_drain_qp), so no completion can race the free.
	 *
	 * Per-MR page cap: bound SVC_RDMA_MR_PAGES (a fixed local constant) DOWN
	 * to the device's fast-reg page-list limit
	 * (dev->attrs.max_fast_reg_page_list_len) so we never ask ib_alloc_mr for
	 * more pages than the HCA supports; clamp to >= 1 so a degenerate
	 * device report cannot request a zero-page MR.  This is a device bound on
	 * a LOCAL constant -- never a peer-supplied size.  A device that reports 0
	 * fast-reg pages (no FRWR support) leaves sc_mr_pages 0 below, in which
	 * case we skip the pool entirely (sc_nmr stays 0) rather than fail the
	 * accept: 3f-2 only adds an optional substrate + self-test, and a non-FRWR
	 * device must still accept connections for the inline path.
	 */
	conn->sc_mr_pages = SVC_RDMA_MR_PAGES;
	if (dev->attrs.max_fast_reg_page_list_len > 0 &&
	    dev->attrs.max_fast_reg_page_list_len < conn->sc_mr_pages)
		conn->sc_mr_pages = dev->attrs.max_fast_reg_page_list_len;

	if (conn->sc_mr_pages == 0) {
		/* No FRWR support reported; run without an MR pool (inline only). */
		if (bootverbose)
			printf("nfsrdma: device reports no fast-reg pages; "
			    "FRWR pool disabled\n");
		conn->sc_nmr = 0;
		conn->sc_mr = NULL;
	} else {
		conn->sc_nmr = SVC_RDMA_MR_DEPTH;
		conn->sc_mr = malloc(conn->sc_nmr * sizeof(*conn->sc_mr),
		    M_NFSRDMA, M_WAITOK | M_ZERO);

		for (i = 0; i < conn->sc_nmr; i++) {
			struct svc_rdma_mr *sm = &conn->sc_mr[i];

			sm->sm_conn = conn;
			sm->sm_inuse = false;
			sm->sm_sg_mapped = false;
			sm->sm_cqe.done = svc_rdma_wc_reg;
			sm->sm_mr = ib_alloc_mr(conn->sc_pd, IB_MR_TYPE_MEM_REG,
			    conn->sc_mr_pages);
			if (IS_ERR(sm->sm_mr)) {
				rc = -PTR_ERR(sm->sm_mr);
				sm->sm_mr = NULL;
				printf("nfsrdma: ib_alloc_mr failed: %d\n", rc);
				goto fail;
			}
		}
	}

	/*
	 * Read-buffer pool (TASK_003f-8): pre-allocate + DMA-map contiguous read
	 * sinks so the NFS-WRITE RDMA-Read hot path does not contigmalloc per write.
	 * Best-effort: cap at the recv depth, and stop at the first allocation/map
	 * failure (a shorter pool just means more fallback, never an accept failure).
	 *
	 * M_NOWAIT for the contigmalloc (TASK_003f-10 review SHOULD-FIX): svc_rdma_accept
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

			rb->rb_buf = contigmalloc(SVC_RDMA_MAX_READ, M_NFSRDMA,
			    M_NOWAIT, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
			if (rb->rb_buf == NULL) {
				conn->sc_nrbpool = rbk;	/* short pool */
				break;
			}
			rb->rb_dma = ib_dma_map_single(dev, rb->rb_buf,
			    SVC_RDMA_MAX_READ, DMA_FROM_DEVICE);
			if (ib_dma_mapping_error(dev, rb->rb_dma)) {
				free(rb->rb_buf, M_NFSRDMA);
				rb->rb_buf = NULL;
				conn->sc_nrbpool = rbk;
				break;
			}
			rb->rb_mapped = true;
		}
	}

	/*
	 * Conservative accept parameters (mirroring rpcrdma_ep_create's
	 * remote_cma): advertise responder_resources from the device's RDMA
	 * read/atomic depth (capped to the u8 field) AND a matching initiator depth
	 * (the server ISSUES RDMA Reads to pull NFS WRITE data, TASK_003f-3, so
	 * the client must allow them via max_dest_rd_atomic), and
	 * RNR retry = 7 (infinite) (TASK_003f-9 fix #6): when the server's RQ
	 * momentarily drains under a concurrent WRITE burst, an inbound SEND from the
	 * client gets an RNR NAK; with rnr_retry_count 0 the QP errored on the first
	 * RNR -> connection kill -> 60 s NFS retransmit stall (the 8-stream collapse
	 * signature).  7 means retry-forever, so transient receive-side pressure
	 * PAUSES the peer instead of killing the connection.  This is a robustness
	 * floor; the real serialization fix is moving completion work off the single
	 * CQ thread (fix #1).  retry_count is ignored when accepting.  No private data
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
		uint32_t a = 0;

		svc_rdma_conn_peeraddr(conn, &pss);
		if (pss.ss_family == AF_INET)
			a = ((struct sockaddr_in *)&pss)->sin_addr.s_addr;
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: accept: recv_depth=%d send_depth=%d "
			    "peer_af=%d peer_be=0x%08x\n", conn->sc_nrecv,
			    conn->sc_nsend, pss.ss_family, a);
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
	.svo_conn_reply_chunk	= svc_rdma_conn_reply_chunk,
	.svo_conn_write_list	= svc_rdma_conn_write_list,
	.svo_conn_write_list_pages = svc_rdma_conn_write_list_pages,
	.svo_conn_set_ctx	= svc_rdma_conn_set_ctx,
	.svo_conn_get_ctx	= svc_rdma_conn_get_ctx,
	.svo_conn_credits	= svc_rdma_conn_credits,
	.svo_conn_peeraddr	= svc_rdma_conn_peeraddr,
	.svo_conn_error		= svc_rdma_conn_error,
	.svo_thread_setup	= svc_rdma_thread_setup,
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
