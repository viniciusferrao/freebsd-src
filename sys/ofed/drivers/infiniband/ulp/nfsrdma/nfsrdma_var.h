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

#ifndef _NFSRDMA_VAR_H_
#define	_NFSRDMA_VAR_H_

/*
 * svc_verbs.c -- server-side RDMA-CM listener for NFS-over-RDMA.
 *
 * This is the passive (server) side.  Note FreeBSD's rdma_cm API:
 * rdma_create_id() takes a leading struct vnet *, and the rdma_cm_event
 * carries no ->id member (the child cm_id of a CONNECT_REQUEST is
 * delivered as the handler's id argument).
 *
 * The server brings up a passive RDMA-CM listener that binds a port, accepts
 * inbound connections into real QPs, and posts receive buffers BEFORE accepting
 * (an RC peer transmits its first RPC-over-RDMA call immediately on ESTABLISHED;
 * an unposted recv would RNR-NAK and kill the connection).  An accepted call is
 * parsed (the RFC 8166 chunk-list decoder below), its inbound data pulled with
 * RDMA Read, dispatched to the registered consumer (the krpc/nfsd layer), and
 * the reply marshalled and sent inline or RDMA-Written into the client's reply
 * chunk.  The RDMA Read/Write data engines use the PD's local_dma_lkey for the
 * local sink/source and pass the peer's rkey VERBATIM to the HCA; there is no
 * fast registration (FRWR) in the data path.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>	/* SI_SUB_OFED_MODINIT */
#include <linux/netdevice.h>	/* init_net */
#include <linux/dma-mapping.h>	/* DMA_FROM_DEVICE */
#include <linux/sched.h>	/* linux_set_current for the krpc post threads (#59) */
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <rpc/svc_rdma.h>	/* consumer upcall interface */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>		/* be32dec: endian- and alignment-safe word decode */
#include <sys/kernel.h>		/* SYSUNINIT, bootverbose */
#include <sys/module.h>		/* DECLARE_MODULE, MODULE_DEPEND, MODULE_VERSION */
#include <sys/eventhandler.h>	/* vm_lowmem reclaim of the sink cache (#60) */
#include <sys/lock.h>
#include <sys/malloc.h>		/* malloc/free, MALLOC_DEFINE */
#include <sys/mbuf.h>		/* zero-copy read-sink mbuf assembly */
#include <sys/mutex.h>
#include <sys/queue.h>		/* TAILQ: per-listener connection registry */
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>	/* deferred (sleepable) connection teardown */
#include <sys/time.h>		/* ppsratecheck */

#include <netinet/in.h>

/*
 * Single module-global listener instance: one passive endpoint, bound to the
 * consumer (the krpc SVCXPRT) at start time.
 *
 * sl_lock serializes access to sl_id (and the sysctl-visible port) and makes
 * sl_id the single ownership token for destroying the listening cm_id.  sl_id
 * is the listening cm_id, or NULL when no listener is up.
 *
 * Two contexts mutate sl_id, both under sl_lock:
 *   - svc_rdma_listen_start_ops()/svc_rdma_listen_stop() (driven by the krpc
 *     consumer today): publish on start, capture-and-NULL on stop.
 *   - the CM event handler's RDMA_CM_EVENT_DEVICE_REMOVAL path: it acquires
 *     sl_lock to test/NULL sl_id and thereby decide whether IT or a racing
 *     listen_stop() owns the rdma_destroy_id() (see the long comment there).
 * The CONNECT_REQUEST path does NOT touch sl_id: that event is delivered on a
 * fresh child cm_id (the handler's id argument), which is declined and
 * destroyed by the CM core, independent of the listener.
 *
 * sl_ops/sl_ctx are the consumer upcall table and its opaque context, set once
 * by svc_rdma_listen_start_ops() before the listener is published and cleared on
 * stop.  The krpc/nfsd consumer binds its own ops here.  They are read under
 * sl_lock at accept time and COPIED onto each connection (sc_ops/sc_ctx), so
 * completions and the teardown task never chase the listener pointer (which may
 * be torn down out from under a live conn): a conn carries its own immutable
 * copy for its whole lifetime.  ops is a const function-pointer table the
 * consumer owns
 * and must outlive the listener; ctx must outlive svc_rdma_listen_stop().
 */
struct svc_rdma_listener {
	struct mtx		 sl_lock;
	struct rdma_cm_id	*sl_id;
	const struct svc_rdma_ops *sl_ops;
	void			*sl_ctx;
};

extern struct svc_rdma_listener svc_rdma_listener;

/* M_NFSRDMA is MALLOC_DEFINE'd in sys/rpc/svc_rdma.c (base kernel) so that
 * both svc_rdma.c and this module share the same malloc tag without a
 * KLD-to-base symbol dependency.  MALLOC_DECLARE in svc_rdma.h provides the
 * extern declaration consumed here. */

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
 * SVC_RDMA_SEND_DEPTH is the size of the per-connection reply-send buffer pool.
 * It matches SVC_RDMA_RECV_DEPTH so we can have a reply in flight for
 * every recv we can be processing concurrently.  Like the recv depth it is
 * clamped down to the device-reported QP send cap at accept time, so the pool
 * can never exceed what the SQ can hold (and thus never outruns the send CQ,
 * which is sized max_wr + 1 for the ib_drain_qp SQ sentinel).
 */
#define	SVC_RDMA_INLINE		4096
#define	SVC_RDMA_RECV_DEPTH	64
#define	SVC_RDMA_SEND_DEPTH	SVC_RDMA_RECV_DEPTH

/*
 * RDMA Read engine sizing.
 *
 * SVC_RDMA_MAX_READ is the hard cap on the total inbound length we will pull
 * from a peer's read-list chunks into a single server destination buffer.  It is
 * a FIXED LOCAL constant, NEVER a peer sum: a request whose summed read-list
 * length exceeds it is a clean close, not a larger allocation.  1 MiB covers the
 * common NFS WRITE rsize/wsize (up to 1 MiB) while bounding what one hostile call
 * can make us malloc.  The parser already overflow-checks each per-segment
 * length (<= SVC_RDMA_MAX_SEG_LEN) and the per-chunk total; this is an additional
 * whole-request cap re-asserted at post time.
 *
 * SVC_RDMA_MAX_READ_SEGS (defined in <rdma/svc_rdma.h>, == 64) is the cap on how
 * many RDMA Read WRs we will chain for one request.  It bounds the read list,
 * the rs_wr[]/rs_sge[] arrays, and the SQ read head-room reserved at accept.  It
 * is DECOUPLED from SVC_RDMA_MAX_CHUNKS (the write-list cap): an NFS WRITE's read
 * list is many single-segment entries of one position, and a real client splits
 * 1 MiB into ~16 of them, so the read list needs far more entries than the
 * 8-chunk write list.  Each WR consumes one SQ slot, so the value must fit the
 * SQ head-room reserved at accept time (see max_send_wr).
 */
#define	SVC_RDMA_MAX_READ	(1U << 20)	/* 1 MiB whole-request cap */
/* SVC_RDMA_MAX_READ_SEGS now lives in <rdma/svc_rdma.h> (sizes reads[] there). */

/*
 * RDMA Write engine sizing -- the OUTBOUND data path.
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
 * Zero-copy outbound-READ page-gather bounds.  The M_EXTPG read
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
 * Per-connection pool of pre-DMA-mapped CONTIGUOUS RDMA-Read sink buffers.
 * Each is SVC_RDMA_MAX_READ bytes (the per-request read cap) and
 * mapped DMA_FROM_DEVICE ONCE at accept, so the NFS-WRITE hot path grabs a ready
 * buffer instead of mapping per write.  Capped at the recv depth; a read that
 * finds the pool empty falls back to a per-read borrow+map.  16 * 1 MiB =
 * 16 MiB/conn (benchmark-tuned).
 *
 * The BACKING memory comes from the global recycle free-list (svc_rdma_sink_get/
 * put, #60), not contigmalloc per buffer: the zero-copy WRITE hand-off evacuates
 * a slot and the next read re-stocks it, so without recycling every write would
 * contigmalloc+free a 1 MiB buffer -- and the free() unmaps KVA and forces a
 * global TLB shootdown that caps WRITE throughput.  Recycling keeps that memory
 * out of kmem on the steady-state path.
 */
#define	SVC_RDMA_READBUF_POOL	16

/*
 * Pending CONNECT_REQUEST queue depth for the RDMA-CM listener.  Mirrors the
 * listen(2) backlog; Linux knfsd uses 128.
 */
#define	SVC_RDMA_CM_BACKLOG	128

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
 * struct svc_rdma_msg (the parsed inline RPC-over-RDMA call) and the opaque
 * struct svc_rdma_conn forward declaration now live in <rdma/svc_rdma.h>, the
 * shared consumer contract included above; that definition is authoritative.
 * rpc/rpc_len point into the recv buffer (no copy); they are only valid while
 * that buffer is owned by the completion that produced them (and, for a
 * consumer, only for the duration of the sro_recv upcall).  This layer only
 * locates the payload -- decoding the ONC RPC body is the krpc layer's job.
 *
 * Budget guard.  We keep a DURABLE per-recv copy of this struct
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
 * per-connection read-buffer pool.
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
 * Durable inbound-read state, embedded in each recv descriptor.
 *
 * THE LIFETIME FIX.  The parser fills a struct svc_rdma_msg whose rpc/segment
 * pointers reference rr_buf, and the recv path reposts rr_buf the instant the
 * recv handler returns.  An RDMA Read completes LATER (async on the SQ), so both
 * the chunk metadata AND the inline head bytes the read splices into must outlive
 * the recv handler.  This struct provides that durable storage: when a request bears
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
 * Global recycling free-list for RDMA-Read sink buffers (#60).
 *
 * Every inbound NFS WRITE pulls its payload into a SVC_RDMA_MAX_READ-sized,
 * physically-contiguous sink buffer.  Those were contigmalloc'd and free'd PER
 * RPC: free()ing 1 MiB of KVA-mapped contiguous memory returns it to kmem,
 * which UNMAPS the kernel VA and forces a TLB shootdown (an IPI to every CPU)
 * plus pmap-lock contention.  At small-write rates that one free() dominated
 * the server (~88% of nfsd on-CPU time, ~455 us/op) and pinned 4 KiB writes at
 * ~7.8k IOPS regardless of payload size.  The per-conn pool did not help the
 * WRITE path: the zero-copy hand-off EVACUATES the slot and frees the buffer,
 * then the next read contigmalloc's a fresh one.
 *
 * Keep a global
 * LIFO of fixed-size sink buffers and recycle them across RPCs and connections,
 * so the steady-state write path never returns memory to kmem and never shoots
 * down the TLB.  Buffers on the list are PLAIN, UNMAPPED, SVC_RDMA_MAX_READ-
 * sized contiguous memory -- the DMA mapping is always torn down before a buffer
 * is put back, and every buffer is full-size so any borrow fits any read.  The
 * free-list link is stored in the buffer's first word: its contents are dead
 * while free, and contigmalloc is PAGE_SIZE-aligned so the store is aligned.
 *
 * Bounded at SVC_RDMA_SINK_CACHE_MAX buffers (derived from the recv depth, ~4
 * connections' worth of in-flight reads, NOT a magic constant); a put over the
 * cap actually free()s (the one remaining path that can unmap/shoot down -- so a
 * server busier than the cap pays the shootdown only on the overflow margin, a
 * graceful degradation rather than a cliff).  The cache is ELASTIC: it grows on
 * demand and is handed back to the system under memory pressure by a vm_lowmem
 * handler (svc_rdma_sink_reclaim) -- this is contigmalloc memory, the scarcest
 * allocator, so it must not pin a high-water-mark forever.  Fully drained at
 * module unload (svc_rdma_uninit), after every connection has torn down.
 */

#define	SVC_RDMA_SINK_CACHE_MAX	(4 * SVC_RDMA_RECV_DEPTH)  /* ~256 MiB high-water; vm_lowmem reclaims it */
extern struct mtx svc_rdma_sink_lock;
extern void	*svc_rdma_sink_head;	/* LIFO; next ptr lives in buf[0] */
extern int	 svc_rdma_sink_count;
extern volatile int svc_rdma_sink_draining;	/* set once at unload; never cleared */
extern eventhandler_tag svc_rdma_sink_lowmem_tag; /* vm_lowmem registration (#60) */

/*
 * Durable outbound-write state -- the OUTBOUND data path's analogue of
 * svc_rdma_read_state.
 *
 * THE LIFETIME FIX (mirroring the read state).  A reply-chunk RDMA Write
 * originates from the consumer's xp_reply (a krpc pool thread), not from a recv
 * buffer, so this state has no natural durable home like rr_rs.  It is malloc'd
 * on demand by svc_rdma_conn_reply_chunk() and THREADED on the per-conn
 * sc_writes list so the drained teardown can reclaim a write still in flight at
 * close.  The RDMA Write
 * chain + the header SEND complete LATER (async on the SQ), so the source bytes
 * (the marshalled reply) and the header bytes must outlive the xp_reply call:
 * both are COPIED into ws_src / ws_hdr here, never aliasing the caller's buffer.
 *
 *   ws_link  - sc_writes registry linkage (sc_lock); inserted at post, removed on
 *              the first completion (or by the drained teardown).
 *   ws_cqe   - completion callback for the chain.  ONLY the signaled tail SEND
 *              aliases &ws_cqe; the unsignaled RDMA Write WRs route to the per-conn
 *              sink cqe, so svc_rdma_wc_rdma_write runs EXACTLY ONCE per ws
 *              (recovered via container_of), with no duplicate flush CQE.
 *   ws_src   - the source buffer the RDMA Writes read FROM (the marshalled ONC RPC
 *              reply), malloc'd ws_srclen bytes, DMA-mapped DMA_TO_DEVICE.
 *   ws_srclen- the reply length (server-known, bounded <= SVC_RDMA_MAX_WRITE).
 *   ws_src_dma / ws_src_mapped - ws_src DMA map + its idempotency token (sc_lock).
 *   ws_src_pooled - when true, write_free calls svc_rdma_sink_put (recycle #B1)
 *     instead of free() on ws_src.
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
	bool			 ws_src_pooled;	/* true = sink_put, not free (#B1) */
	void			*ws_hdr;	/* RDMA_NOMSG header SEND buffer */
	uint32_t		 ws_hdrlen;
	u64			 ws_hdr_dma;
	bool			 ws_hdr_mapped;
	bool			 ws_active;	/* completion one-shot guard (sc_lock) */
	int			 ws_nwr;
	/*
	 * Zero-copy M_EXTPG page source, used ONLY by
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
 * rr_rs is this recv's durable inbound-read state.  At most ONE
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
	uint32_t		 rr_early_len;	/* byte_len of a DEFERRED early recv (sc_lock) */
	STAILQ_ENTRY(svc_rdma_recv) rr_early;	/* sc_early hold-list link (sc_lock) */
};

/*
 * One reply-send buffer.  The exact send-side mirror of svc_rdma_recv:
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
 * sc_sends is the send-side mirror of sc_reposts: it counts reply sends
 * currently in flight in svc_rdma_conn_send() (incremented while still SC_UP
 * under sc_lock, decremented after ib_post_send returns).  The teardown task
 * waits for sc_sends == 0 in the SAME barrier that waits for sc_reposts == 0,
 * BEFORE ib_drain_qp(), so no late SEND WR can be posted behind the SQ drain
 * sentinel -- the identical post-after-drain UAF barrier applied to the SQ.
 *
 * sc_upcalls extends that quiescence pattern to the CONSUMER upcalls: it
 * counts in-flight sro_newconn + sro_recv calls (incremented under
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
 *
 * The lockless decrements of sc_reposts/sc_sends/sc_upcalls are safe because
 * IB_POLL_WORKQUEUE delivers completions on a single per-CQ workqueue thread
 * (see the ib_alloc_cq call below), so decrement and wakeup are serialized
 * per-CQ -- no concurrent decrements race the teardown's re-evaluation.
 */
struct svc_rdma_conn {
	struct rdma_cm_id	*sc_id;		/* child cm_id; QP is sc_id->qp */
	struct ib_pd		*sc_pd;
	struct ib_cq		*sc_scq;	/* send CQ */
	struct ib_cq		*sc_rcq;	/* recv CQ */
	struct svc_rdma_recv	*sc_recv;	/* sc_nrecv-element array */
	int			 sc_nrecv;
	struct svc_rdma_send	*sc_send;	/* sc_nsend-element reply-send pool */
	int			 sc_nsend;
	struct svc_rdma_readbuf	*sc_rbpool;	/* sc_nrbpool-element read-buffer pool */
	int			 sc_nrbpool;
	struct mtx		 sc_lock;
	enum {
		SC_CONNECTING = 0,
		SC_UP,
		SC_CLOSING
	}			 sc_state;
	int			 sc_reposts;	/* in-flight reposts (sc_lock) */
	int			 sc_sends;	/* in-flight reply sends (sc_lock) */
	/*
	 * Early-recv hold list.  A peer's first inline call can
	 * complete in the recv CQ BEFORE the ESTABLISHED handler has run sro_newconn
	 * and published (SC_UP && sc_newconn_done).  Such a recv is NOT dropped -- an
	 * RC client never retransmits a delivered call, so a dropped first RPC hangs
	 * the mount forever -- it is held here, un-reposted, and DRAINED by the
	 * ESTABLISHED handler once the gate is open.  Bounded by sc_nearly < sc_nrecv/2
	 * so the RQ cannot deplete; a peer that floods past the cap before ESTABLISHED
	 * is closed (it reconnects, and the deterministic window resolves).
	 */
	STAILQ_HEAD(, svc_rdma_recv) sc_early;	/* deferred early recvs (sc_lock) */
	int			 sc_nearly;	/* count of held early recvs (sc_lock) */
	/*
	 * Outbound RDMA Write state registry.  A reply-chunk write is
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
	 * Sink completion for the UNSIGNALED RDMA Write WRs of a chain.
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
	uint32_t		 sc_max_send_sge;	/* granted send-SGE cap (page gather) */
	struct task		 sc_teardown;	/* deferred (sleepable) unwind */
	TAILQ_ENTRY(svc_rdma_conn) sc_link;	/* registry (svc_rdma_conns_lock) */

	/*
	 * Consumer upcall binding.  sc_ops/sc_ctx are the
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
 * its queued sc_teardown task pointing into nfsrdma text that is about to be
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
TAILQ_HEAD(svc_rdma_conn_list, svc_rdma_conn);
extern struct svc_rdma_conn_list svc_rdma_conns;
extern struct mtx svc_rdma_conns_lock;

/*
 * Rate limiter for the per-CONNECT_REQUEST log line.  A remote peer controls
 * the arrival rate of connection requests, so logging one line per request
 * unconditionally is a remotely-triggerable console-flood.  ppsratecheck()
 * caps us at a few lines per second and counts the suppressed remainder.
 */
extern struct timeval svc_rdma_log_last;
extern int svc_rdma_log_pps;

/*
 * Rotating completion-vector assignment.  comp_vector
 * selects which device completion vector (MSI-X / per-core ib-comp workqueue)
 * a CQ's completions steer to.  Pinning every CQ to vector 0 funnels all RDMA
 * completion processing onto one core (the ~99%-idle/concurrency-1 symptom in
 * the WRITE benchmark); rotating per-connection, and putting a connection's send
 * and recv CQ on adjacent vectors, fans completion work across cores.  This is
 * ONLY a vector (steering) change -- each CQ still uses IB_POLL_WORKQUEUE with
 * one work item per CQ, so the per-CQ completion serialization the lockless
 * counters / teardown barrier rely on is unchanged.
 */
extern volatile u_int svc_rdma_cqv;

/*
 * Last requested listen port; 0 means stopped.  This is the value the sysctl
 * read-back reports.  It is kept in sync with svc_rdma_listener.sl_id and is
 * read/written ONLY under sl_lock so the read-back can never be stale or
 * mismatched against the actual listener state (including when the CM core
 * destroys the id from under us on DEVICE_REMOVAL).
 */
extern int svc_rdma_listen_port;

void	*svc_rdma_sink_get(void);
void	svc_rdma_sink_put(void *buf);
void	svc_rdma_sink_reclaim(void *arg __unused, int how __unused);
void	svc_rdma_sink_drain(void);
int	svc_rdma_parse_header(const void *buf, uint32_t len,
	    struct svc_rdma_msg *out);
void	svc_rdma_wc_recv(struct ib_cq *cq, struct ib_wc *wc);
void	svc_rdma_dispatch_recv(struct svc_rdma_conn *conn,
	    struct svc_rdma_recv *rr, uint32_t len);
void	svc_rdma_read_free(struct svc_rdma_conn *conn,
	    struct svc_rdma_recv *rr);
void	svc_rdma_wc_write_sink(struct ib_cq *cq, struct ib_wc *wc);
void	svc_rdma_write_free(struct svc_rdma_write_state *ws);
void	svc_rdma_conn_close(struct svc_rdma_conn *conn);
int	svc_rdma_send_error(struct svc_rdma_conn *conn, uint32_t xid,
	    uint32_t errcode);
void	svc_rdma_conn_peeraddr(struct svc_rdma_conn *conn,
	    struct sockaddr_storage *ss);
void	svc_rdma_listen_stop(void);

#endif /* _NFSRDMA_VAR_H_ */
