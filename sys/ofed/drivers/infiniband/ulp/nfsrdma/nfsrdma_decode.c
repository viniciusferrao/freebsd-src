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

#include "nfsrdma_var.h"

/*
 * ===========================================================================
 * RFC 8166 chunk-list decoder.  UNTRUSTED-PEER PARSER.
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
 * SINGLE rdma_position constraint.  RFC 8166 4.3 permits a read list whose
 * segments carry DIFFERING rdma_position values (data spliced into the XDR
 * stream at several offsets).  The RDMA Read engine assembles the read data as
 * ONE contiguous run spliced at a SINGLE position
 * (reads[0].rc_position), so a multi-position read list would be mis-assembled.
 * We therefore REJECT (EOPNOTSUPP -- well-formed but not served) any read list
 * whose entries do not all share reads[0].rc_position, rather than silently
 * assuming a single position; a Linux NFS/RDMA client always sends a single
 * position for an NFS WRITE, so this rejects only genuinely multi-position lists
 * we do not handle.
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
int
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
