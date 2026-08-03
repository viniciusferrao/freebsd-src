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
 * Server side of NFS-over-RDMA.  FreeBSD's rdma_cm differs from Linux here:
 * rdma_create_id() takes a leading struct vnet *, and rdma_cm_event has no
 * ->id member, so a CONNECT_REQUEST's child id arrives as the handler's id
 * argument.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <rpc/svc_rdma.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/eventhandler.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/time.h>

#include <netinet/in.h>

/*
 * sl_lock covers sl_id and sl_id6, and a non-NULL id under it is the token
 * for destroying it, which is how listen_stop and DEVICE_REMOVAL agree on
 * which of them calls rdma_destroy_id().  sl_ops and sl_ctx are copied onto
 * each connection at accept, so a completion never follows this pointer.
 */
struct svc_rdma_listener {
	struct mtx		 sl_lock;
	struct rdma_cm_id	*sl_id;		/* AF_INET listener */
	struct rdma_cm_id	*sl_id6;	/* AF_INET6 listener */
	const struct svc_rdma_ops *sl_ops;
	void			*sl_ctx;
};

extern struct svc_rdma_listener svc_rdma_listener;

/*
 * M_NFSRDMA is defined in sys/rpc/svc_rdma.c so both it and this module
 * share one malloc tag.
 */

/*
 * RFC 8166 defaults the inline threshold to 1024 bytes; a page leaves head
 * room and keeps one buffer to a single mapping.  The send depth matches the
 * recv depth so every call in flight can have a reply.  Both are clamped to
 * the device QP caps at accept.
 */
#define	SVC_RDMA_INLINE		4096
#define	SVC_RDMA_RECV_DEPTH	64
#define	SVC_RDMA_SEND_DEPTH	SVC_RDMA_RECV_DEPTH

/*
 * Caps the inbound length pulled from one read list.  A local constant, not
 * a peer-supplied sum: a request asking for more is closed.  The companion
 * SVC_RDMA_MAX_READ_SEGS caps the chained WRs, each of which takes an SQ slot
 * and must fit the head room reserved at accept.
 */
#define	SVC_RDMA_MAX_READ	(1U << 20)	/* 1 MiB whole-request cap */
/* SVC_RDMA_MAX_READ_SEGS lives in <rdma/svc_rdma.h>, which sizes reads[]. */

/*
 * Caps the length written into a client's chunks for one reply.  The source
 * is the server's own marshalled reply, so the length is known locally and
 * never taken from a peer field.
 */
#define	SVC_RDMA_MAX_WRITE	(1U << 20)	/* 1 MiB whole-reply cap */
#define	SVC_RDMA_MAX_WRITE_SEGS	SVC_RDMA_MAX_SEGS
/*
 * An M_EXTPG read source is at most SVC_RDMA_MAX_WRITE bytes of page SGEs.
 * A WR gathers up to MAX_SEND_SGE pages and never crosses a write-list
 * segment, since each segment carries its own rkey, so the WR count is
 * bounded by pages per SGE plus one partial WR per segment.
 */
#define	SVC_RDMA_MAX_SEND_SGE	MBUF_PEXT_MAX_PGS
#define	SVC_RDMA_MAX_WRITE_PAGES (SVC_RDMA_MAX_WRITE / PAGE_SIZE)
#define	SVC_RDMA_MAX_WRITE_WRS	(SVC_RDMA_MAX_WRITE_PAGES / SVC_RDMA_MAX_SEND_SGE + \
				 SVC_RDMA_MAX_WRITE_SEGS)
/* One SGE per page, plus one per segment boundary that splits a page. */
#define	SVC_RDMA_MAX_WRITE_SGE	\
	(SVC_RDMA_MAX_WRITE_PAGES + SVC_RDMA_MAX_WRITE_SEGS)

/*
 * Per-connection pool of read sink buffers, mapped once at accept; a read
 * finding it empty maps per read instead.  The memory comes from the global
 * recycle list, since freeing contiguous memory unmaps KVA and forces a TLB
 * shootdown, which is what caps WRITE throughput.
 */
#define	SVC_RDMA_READBUF_POOL	16

/* Pending CONNECT_REQUEST depth, the listen(2) backlog analogue. */
#define	SVC_RDMA_CM_BACKLOG	128

/*
 * RFC 8166 transport header: four fixed words, then the read list, write list
 * and reply chunk, each variable length and zero-terminated (RFC 8166 4.3).
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
 * The rdma_err discriminator (RFC 8166 4.4).  ERR_VERS appends the range we
 * support and the recv path then closes, since a version cannot change on a
 * live connection; ERR_CHUNK leaves the connection up.  Both need a known
 * xid, so an unparseable header gets neither.
 */
enum {
	ERR_VERS	= 1,	/* unsupported rdma_vers; vers range follows */
	ERR_CHUNK	= 2	/* chunk lists unusable for this reply */
};

/*
 * rpc and rpc_len point into the recv buffer rather than a copy, so they are
 * valid only while the completion that produced them owns it.  Each recv
 * keeps a durable copy of the struct, so the CTASSERT below bounds its size:
 * growing the fixed-capacity arrays would otherwise inflate per-connection
 * memory silently.
 */
CTASSERT(sizeof(struct svc_rdma_msg) <= 4096);

/*
 * One contiguous read sink from the per-connection pool.  Its mapping is
 * established once at accept and torn down once in the teardown.  rb_inuse,
 * under sc_lock, is the free-list token: a read borrows the buffer and
 * svc_rdma_read_free() returns it rather than unmapping.  rb_mapped is set
 * only after a successful map, so a partial build skips the unmap.
 */
struct svc_rdma_readbuf {
	void	*rb_buf;	/* contigmalloc'd SVC_RDMA_MAX_READ bytes (contiguous) */
	u64	 rb_dma;	/* ib_dma_map_single DMA_FROM_DEVICE, mapped once */
	bool	 rb_mapped;	/* rb_dma is a live mapping */
	bool	 rb_inuse;	/* lent to an in-flight read (sc_lock) */
};

/*
 * Durable inbound-read state, embedded in each recv descriptor.  The parsed
 * message points into rr_buf, which the recv path reposts as soon as the
 * handler returns, but the read completes later on the SQ, so a request
 * bearing a read list copies the message and inline head here and rr_buf
 * waits for the read.
 *
 * rs_mapped and rs_active are covered by sc_lock.  rs_active is a one-shot,
 * since a chained post can flush several unsignaled WRs; it does not gate
 * reclaim, and the teardown still reclaims a read that never completed.
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
 * Global LIFO of read sink buffers, recycled across RPCs and connections.
 * Freeing contiguous memory returns KVA to kmem, unmapping it and forcing a
 * TLB shootdown, so the steady-state write path must not free these; the
 * per-connection pool alone is not enough, since the zero-copy hand-off
 * evacuates a slot.
 *
 * Buffers on the list are unmapped and full size, so any borrow fits any
 * read.  The link lives in the buffer's first word, dead while free and
 * aligned because contigmalloc returns page-aligned memory.  A vm_lowmem
 * handler hands the cache back under pressure, since contigmalloc memory
 * must not be pinned at a high-water mark.
 */

#define	SVC_RDMA_SINK_CACHE_MAX	(4 * SVC_RDMA_RECV_DEPTH)  /* ~256 MiB high-water; vm_lowmem reclaims it */
extern struct mtx svc_rdma_sink_lock;
extern void	*svc_rdma_sink_head;	/* LIFO; next ptr lives in buf[0] */
extern int	 svc_rdma_sink_count;
extern volatile int svc_rdma_sink_draining;	/* set once at unload; never cleared */
extern eventhandler_tag svc_rdma_sink_lowmem_tag;

/*
 * Durable outbound-write state, the write-side analogue of
 * svc_rdma_read_state.
 *
 * A reply-chunk write originates from the consumer's xp_reply rather than
 * from a recv buffer, so it has no natural durable home.  It is allocated by
 * svc_rdma_conn_reply_chunk() and threaded on the per-connection sc_writes
 * list, so the drained teardown can reclaim a write still in flight at close.
 * The chain completes later on the SQ, so the reply bytes and the header are
 * copied into ws_src and ws_hdr rather than aliasing the caller's buffers.
 *
 * Only the signaled tail SEND aliases &ws_cqe; the RDMA Write WRs are
 * unsignaled and route to the per-connection sink cqe, so
 * svc_rdma_wc_rdma_write() runs once per state.  ws_active, ws_src_mapped and
 * ws_hdr_mapped are covered by sc_lock, and ws_active is a one-shot that does
 * not gate reclaim.
 */
struct svc_rdma_write_state {
	TAILQ_ENTRY(svc_rdma_write_state) ws_link;
	struct ib_cqe		 ws_cqe;
	struct svc_rdma_conn	*ws_conn;
	void			*ws_src;	/* RDMA Write source (reply bytes) */
	uint32_t		 ws_srclen;
	u64			 ws_src_dma;
	bool			 ws_src_mapped;
	bool			 ws_src_pooled;	/* true = sink_put, not free */
	void			*ws_hdr;	/* RDMA_NOMSG header SEND buffer */
	uint32_t		 ws_hdrlen;
	u64			 ws_hdr_dma;
	bool			 ws_hdr_mapped;
	bool			 ws_active;	/* completion one-shot guard (sc_lock) */
	int			 ws_nwr;
	/*
	 * Zero-copy M_EXTPG page source, used only by
	 * svc_rdma_conn_write_list_pages and zeroed on every other path.  The
	 * unmap iterates ws_npgs rather than ws_nwr, since one WR may gather
	 * several pages.  The engine owns ws_keepm and frees it in
	 * svc_rdma_write_free: the pages must outlive the Write.
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
 * One posted receive buffer.  rr_wr.wr_cqe aliases &rr_cqe, so a completion
 * reaches svc_rdma_wc_recv() with this rr_* via container_of.
 *
 * At most one RDMA Read is in flight per recv buffer: the buffer is not
 * reposted while its read is outstanding, so the read engine never reuses
 * rr_rs under a live read.
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
 * One reply-send buffer, the send-side mirror of svc_rdma_recv.  ss_buf is
 * mapped once at accept and unmapped in the drained teardown.  ss_inuse,
 * under sc_lock, makes the pool a bounded free list: a reply takes a buffer
 * and the send completion returns it.
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
 * Per-accepted-connection state.  id->context points here for the child
 * cm_id, while the listener's own id keeps context == &svc_rdma_listener,
 * which is how the shared CM handler tells the two apart.
 *
 * sc_state, under sc_lock, is the single ownership token for tearing the
 * connection down, as sl_id is for the listener.  The transition to
 * SC_CLOSING happens at most once, and only the thread that wins it
 * enqueues sc_teardown, which is the one place that frees the verbs
 * resources and calls rdma_destroy_id().
 *
 * sc_reposts, sc_sends and sc_upcalls count in-flight reposts, reply sends
 * and consumer upcalls.  The teardown drains all three in one barrier before
 * ib_drain_qp(), so nothing can be posted behind the drain sentinel, and
 * before delivering sro_disconnect, so the consumer may free its per-
 * connection state from inside disconnect.
 *
 * They share the &sc_upcalls wakeup channel: any decrement wakes the sleeper,
 * which re-evaluates all three.  The decrements need no lock because
 * IB_POLL_WORKQUEUE delivers completions on one workqueue thread per CQ.
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
	 * A peer's first inline call can complete before the ESTABLISHED
	 * handler has run sro_newconn.  An RC client never retransmits a
	 * delivered call, so such a recv must not be dropped: it is held here
	 * un-reposted and drained once the gate is open.  Bounded by
	 * sc_nrecv / 2 so the RQ cannot deplete.
	 */
	STAILQ_HEAD(, svc_rdma_recv) sc_early;	/* deferred early recvs (sc_lock) */
	int			 sc_nearly;	/* count of held early recvs (sc_lock) */
	/*
	 * In-flight reply-chunk writes, threaded here under sc_lock so the
	 * drained teardown can reclaim one still outstanding at close.  This
	 * list owns the single free of a write's buffers, maps and state:
	 * by its completion if one runs, otherwise by the teardown.
	 *
	 * sc_sends counts only the post call, not the async WR, so the barrier
	 * that drains write WRs is ib_drain_qp().
	 */
	TAILQ_HEAD(, svc_rdma_write_state) sc_writes;	/* in-flight writes (sc_lock) */
	/*
	 * Flush sink for the unsignaled RDMA Write WRs of a chain.  On QP error
	 * every WR flushes, signaled or not, so writes aliasing &ws_cqe would
	 * deliver duplicate completions for one state; a trailing duplicate
	 * could then match a recycled state and free it mid-post.  Routing them
	 * here leaves the signaled SEND as the only completion per state.
	 *
	 * The counters are touched only by the send-CQ workqueue.
	 */
	struct ib_cqe		 sc_write_sink_cqe;	/* unsignaled-write flush sink */
	uint64_t		 sc_write_sink_flushes;	/* write WRs flushed to sink */
	uint64_t		 sc_write_sink_errs;	/* non-flush write WR errors */
	uint32_t		 sc_max_send_sge;	/* granted send-SGE cap (page gather) */
	struct task		 sc_teardown;	/* deferred (sleepable) unwind */
	TAILQ_ENTRY(svc_rdma_conn) sc_link;	/* registry (svc_rdma_conns_lock) */

	/*
	 * sc_ops and sc_ctx are the copy of the listener's binding taken at
	 * accept, so a completion or the teardown reaches the consumer without
	 * touching a listener that may already have stopped.  Set once before
	 * the connection goes live and never mutated, so read without sc_lock.
	 *
	 * sc_cctx is the consumer's own per-connection state.  The verbs layer
	 * never dereferences it and holds sc_lock across set and get only to
	 * order them against the upcalls.
	 *
	 * The two latches are not redundant.  sc_newconn_fired is set before
	 * sro_newconn is called and pairs it with sro_disconnect, so a
	 * teardown landing between the two still delivers disconnect.
	 * sc_newconn_done is set after sro_newconn returns and gates
	 * sro_recv, so no recv upcall runs while sro_newconn is in progress.
	 */
	const struct svc_rdma_ops *sc_ops;	/* consumer upcalls (immutable) */
	void			*sc_ctx;	/* consumer listener ctx (immut.) */
	void			*sc_cctx;	/* consumer per-conn state (sc_lock) */
	bool			 sc_newconn_fired; /* sro_newconn entered (sc_lock) */
	bool			 sc_newconn_done; /* sro_newconn returned (sc_lock) */
	int			 sc_upcalls;	/* in-flight consumer upcalls (sc_lock) */
};

/*
 * Every live accepted connection, so listener stop and module unload can
 * sweep and drain them.  Without it an established connection would keep its
 * QP, CQs and posted buffers, and its completion callbacks would point into
 * module text that is about to be freed.
 *
 * A connection is inserted once in svc_rdma_accept() and removed once at the
 * end of svc_rdma_conn_destroy().
 *
 * Lock order: svc_rdma_conns_lock before sc_lock.  The sweep holds the
 * registry lock across svc_rdma_conn_close(), and the teardown's remove takes
 * the registry lock alone.
 */
TAILQ_HEAD(svc_rdma_conn_list, svc_rdma_conn);
extern struct svc_rdma_conn_list svc_rdma_conns;
extern struct mtx svc_rdma_conns_lock;
extern struct sx svc_rdma_listen_cfg_lock;

/*
 * Rate limiter for the per-CONNECT_REQUEST log line: a peer controls how
 * fast connection requests arrive, so the line has to be capped.
 */
extern struct timeval svc_rdma_log_last;
extern int svc_rdma_log_pps;

/*
 * Rotating completion-vector assignment.  comp_vector steers a CQ's
 * completions to a device vector, so pinning every CQ to vector 0 would run
 * all completion processing on one core.  Connections rotate, and a
 * connection's send and recv CQ sit on adjacent vectors.
 *
 * This changes steering only.  Each CQ still has one IB_POLL_WORKQUEUE work
 * item, so the per-CQ serialization the counters rely on is unchanged.
 */
extern volatile u_int svc_rdma_cqv;

/*
 * The port the sysctl reads back; 0 means stopped.  It is read and written
 * only under sl_lock, so it cannot disagree with the listener state, device
 * removal included.
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
