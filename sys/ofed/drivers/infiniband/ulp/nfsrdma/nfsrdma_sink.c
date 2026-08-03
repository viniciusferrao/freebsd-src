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

struct mtx svc_rdma_sink_lock;
void	*svc_rdma_sink_head;	/* LIFO; next ptr lives in buf[0] */
int	 svc_rdma_sink_count;
volatile int svc_rdma_sink_draining;	/* set once at unload; never cleared */
eventhandler_tag svc_rdma_sink_lowmem_tag;

/*
 * Borrow a sink buffer from the recycle list, or allocate one.  Always
 * SVC_RDMA_MAX_READ bytes, so any buffer fits any read.  M_NOWAIT because the
 * callers run in the CQ workqueue and under the CM handler mutex.  The
 * returned memory is unmapped; the caller maps it.
 */
void *
svc_rdma_sink_get(void)
{
	void *buf;

	mtx_lock(&svc_rdma_sink_lock);
	buf = svc_rdma_sink_head;
	if (buf != NULL) {
		svc_rdma_sink_head = *(void **)buf;
		svc_rdma_sink_count--;
	}
	mtx_unlock(&svc_rdma_sink_lock);
	if (buf == NULL)
		buf = contigmalloc(SVC_RDMA_MAX_READ, M_NFSRDMA, M_NOWAIT, 0,
		    ~(vm_paddr_t)0, PAGE_SIZE, 0);
	return (buf);
}

/*
 * Return a sink buffer, which must be unmapped and full size.  Recycle it
 * unless the cache is full or we are draining at unload, in which case free
 * it.  NULL-safe.
 *
 * The draining flag is checked twice.  The unlocked check comes first because
 * MOD_UNLOAD destroys svc_rdma_sink_lock once svc_rdma_sink_drain() has run,
 * and a sink mbuf owned by nfsd can outlive the connection and be freed after
 * that point; it must free directly rather than touch the destroyed mutex.
 * The check under the lock stops a put that raced drain from re-stocking a
 * list nothing will drain again.
 */
void
svc_rdma_sink_put(void *buf)
{
	if (buf == NULL)
		return;
	if (atomic_load_acq_int(&svc_rdma_sink_draining)) {
		free(buf, M_NFSRDMA);	/* the lock may already be destroyed */
		return;
	}
	mtx_lock(&svc_rdma_sink_lock);
	if (!svc_rdma_sink_draining &&
	    svc_rdma_sink_count < SVC_RDMA_SINK_CACHE_MAX) {
		*(void **)buf = svc_rdma_sink_head;
		svc_rdma_sink_head = buf;
		svc_rdma_sink_count++;
		buf = NULL;
	}
	mtx_unlock(&svc_rdma_sink_lock);
	if (buf != NULL)
		free(buf, M_NFSRDMA);
}

/*
 * Free every buffer on the recycle list.  The lock is dropped around each
 * free so a contiguous free never nests under svc_rdma_sink_lock.
 */
static void
svc_rdma_sink_flush(void)
{
	void *buf;

	mtx_lock(&svc_rdma_sink_lock);
	while ((buf = svc_rdma_sink_head) != NULL) {
		svc_rdma_sink_head = *(void **)buf;
		svc_rdma_sink_count--;
		mtx_unlock(&svc_rdma_sink_lock);
		free(buf, M_NFSRDMA);
		mtx_lock(&svc_rdma_sink_lock);
	}
	mtx_unlock(&svc_rdma_sink_lock);
}

/*
 * vm_lowmem handler: hand the idle cache back under memory pressure.
 * In-flight sinks are not on the list.  This is a transient trim and does not
 * set svc_rdma_sink_draining, so the cache refills once pressure passes.
 */
void
svc_rdma_sink_reclaim(void *arg __unused, int how __unused)
{
	svc_rdma_sink_flush();
}

/*
 * Drain the cache at unload.  The flag is set first, so a concurrent or later
 * put frees instead of caching and the list cannot be repopulated.
 */
void
svc_rdma_sink_drain(void)
{
	mtx_lock(&svc_rdma_sink_lock);
	atomic_store_rel_int(&svc_rdma_sink_draining, 1);
	mtx_unlock(&svc_rdma_sink_lock);
	svc_rdma_sink_flush();
}
