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
 * RFC 8166 chunk-list decoder.  Everything here reads peer bytes: the cursor
 * advances only after a bounds check, and counts are bounded by the fixed
 * caps rather than by the peer's own count.
 */

static __inline bool
svc_rdma_need(uint32_t off, uint32_t need, uint32_t len)
{

	return ((uint64_t)off + (uint64_t)need <= (uint64_t)len);
}

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

	if (seg->rs_length == 0 || seg->rs_length > SVC_RDMA_MAX_SEG_LEN)
		return (EBADMSG);

	*offp = off;
	return (0);
}

/*
 * Decode the read list, flattening the 1/0-terminated chain into out->reads[].
 *
 * RFC 8166 4.3 permits entries with differing rdma_position, but the engine
 * splices the data at one position, so a list that does not share
 * reads[0].rc_position is refused rather than mis-assembled.
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
		if (!svc_rdma_need(off, RPCRDMA_WORD, len))
			return (EBADMSG);
		more = be32dec((const char *)buf + off);
		off += RPCRDMA_WORD;

		if (more == 0)
			break;
		if (more != 1)
			return (EBADMSG);

		if (out->rd_nchunks >= SVC_RDMA_MAX_READ_SEGS)
			return (EOPNOTSUPP);

		if (!svc_rdma_need(off, RPCRDMA_WORD, len))
			return (EBADMSG);
		position = be32dec((const char *)buf + off);
		off += RPCRDMA_WORD;

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

/* nsegs is capped, never used to size anything. */
static int
svc_rdma_decode_write_chunk(const void *buf, uint32_t len, uint32_t *offp,
    struct svc_rdma_write_chunk *wc)
{
	uint32_t off = *offp;
	uint32_t nsegs, i;
	int rc;

	if (!svc_rdma_need(off, RPCRDMA_WORD, len))
		return (EBADMSG);
	nsegs = be32dec((const char *)buf + off);
	off += RPCRDMA_WORD;

	if (nsegs == 0 || nsegs > SVC_RDMA_MAX_SEGS)
		return (EOPNOTSUPP);

	wc->wc_nsegs = 0;
	wc->wc_total = 0;
	for (i = 0; i < nsegs; i++) {
		rc = svc_rdma_decode_segment(buf, len, &off, &wc->wc_segs[i]);
		if (rc != 0)
			return (rc);

		/*
		 * Each length is already within SVC_RDMA_MAX_SEG_LEN, so
		 * rejecting a sum past UINT32_MAX keeps wc_total exact.
		 */
		if (wc->wc_segs[i].rs_length > UINT32_MAX - wc->wc_total)
			return (EBADMSG);
		wc->wc_total += wc->wc_segs[i].rs_length;
		wc->wc_nsegs++;
	}

	*offp = off;
	return (0);
}

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

		if (more == 0)
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

	if (present == 0) {
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
 * Parse the RPC-over-RDMA version 1 header, decode the chunk lists and locate
 * the inline payload.  len is wc->byte_len, already clamped to
 * SVC_RDMA_INLINE.  buf is never cast to uint32_t *: be32dec and be64dec read
 * byte by byte and are endian- and alignment-safe.
 *
 * EBADMSG for a malformed header, EOPNOTSUPP for a well-formed one past a
 * cap.  On a nonzero return *out is undefined and no pointer into buf
 * escapes.
 */
int
svc_rdma_parse_header(const void *buf, uint32_t len, struct svc_rdma_msg *out)
{
	uint32_t vers, proc, off;
	int rc;

	/*
	 * One gate for the fixed prefix: this check authorizes the four
	 * be32dec()s at offsets 0 through 12.  Past word3 the cursor gates
	 * every read.
	 */
	if (len < RPCRDMA_HDR_FIXED)
		return (EBADMSG);

	/*
	 * A version mismatch returns EPROTONOSUPPORT rather than EBADMSG, so
	 * the recv path can answer RDMA_ERROR with ERR_VERS.  That reply needs
	 * the real xid, and the prefix gate above proved word0 readable, so it
	 * is stamped here.  No other out field is defined on this path.
	 */
	vers = be32dec((const char *)buf + 4);
	if (vers != RPCRDMA_VERSION) {
		out->xid = be32dec((const char *)buf + 0);
		return (EPROTONOSUPPORT);
	}

	/*
	 * Only RDMA_MSG and RDMA_NOMSG carry chunk lists.  Any other proc is
	 * well-formed but not a valid client-to-server v1 call, so it returns
	 * EOPNOTSUPP and the connection closes.
	 */
	proc = be32dec((const char *)buf + 12);
	if (proc != RDMA_MSG && proc != RDMA_NOMSG)
		return (EOPNOTSUPP);

	out->xid     = be32dec((const char *)buf + 0);
	out->credit  = be32dec((const char *)buf + 8);
	out->rdma_proc = proc;
	out->rd_nchunks = 0;
	out->wr_nchunks = 0;
	out->reply_present = false;
	out->rpc = NULL;
	out->rpc_len = 0;

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
	 * Whatever follows the chunk lists is the inline body, which may be
	 * empty; RDMA_NOMSG has none, so rpc_len stays 0.  The cursor keeps off
	 * within len, so len - off cannot underflow.
	 */
	if (proc == RDMA_MSG) {
		out->rpc = (const char *)buf + off;
		out->rpc_len = len - off;
	}
	return (0);
}
