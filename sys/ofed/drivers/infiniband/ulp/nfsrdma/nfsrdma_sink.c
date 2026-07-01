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
eventhandler_tag svc_rdma_sink_lowmem_tag; /* vm_lowmem registration (#60) */
MTX_SYSINIT(svc_rdma_sink_lock, &svc_rdma_sink_lock, "nfsrdma_sink", MTX_DEF);

/*
 * Borrow a sink buffer: pop the recycle list, else contigmalloc a fresh one.
 * Always SVC_RDMA_MAX_READ bytes so any buffer fits any read.  M_NOWAIT -- the
 * callers (CQ workqueue, accept under the CM handler_mutex) are non-sleepable
 * and already handle NULL.  Returned memory is UNMAPPED; the caller maps it.
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
 * Return a sink buffer.  It MUST be plain, unmapped, SVC_RDMA_MAX_READ-sized
 * contiguous memory (the invariant every caller upholds).  Recycle it unless the
 * cache is full OR we are draining at unload, in which case free() it (bounded,
 * rare).  NULL-safe.
 *
 * The svc_rdma_sink_draining gate makes a LATE put -- a sink mbuf that is nfsd-
 * owned and outlives the conn (see svc_rdma_read_extfree) and is freed after
 * svc_rdma_sink_drain() has run at module unload -- free() the buffer back to the
 * system instead of re-stocking a list that will never be drained again.
 *
 * The flag is checked TWICE.  The first check is an unlocked atomic load BEFORE
 * svc_rdma_sink_lock is taken: at module unload the MTX_SYSINIT teardown of
 * svc_rdma_sink_lock (SI_SUB_LOCK = 0x1B00000) runs BEFORE malloc_uninit of
 * M_NFSRDMA (SI_SUB_KMEM = 0x1800000), so a late ext_free in that window must NOT
 * touch the already-destroyed mutex -- it free()s directly, exactly as the
 * pre-recycle code did (which took no such lock).  The second check, under the
 * lock, closes the post-drain re-stock leak (a put that passed the unlocked check
 * just as drain set the flag still must not cache).  Once M_NFSRDMA itself is
 * gone the residual exposure (free() / the stored ext_free function pointer) is
 * inherent to any KLD ext_free and is unchanged from the pre-recycle code.
 */
void
svc_rdma_sink_put(void *buf)
{
	if (buf == NULL)
		return;
	if (atomic_load_acq_int(&svc_rdma_sink_draining)) {
		free(buf, M_NFSRDMA);	/* unload: never touch the (torn-down) lock */
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

/* Pop-and-free every buffer currently on the recycle list (drops the lock for
 * each free() so the contig free never nests under svc_rdma_sink_lock). */
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
 * vm_lowmem handler (#60): under memory pressure, hand the IDLE recycle cache
 * back to the system.  In-flight sinks are not on the list and are untouched;
 * the cache refills on demand (sink_get's contigmalloc fallback) once pressure
 * passes.  This does NOT set svc_rdma_sink_draining -- it is a transient trim,
 * the analogue of UMA's per-zone lowmem drain, not the permanent unload drain.
 */
void
svc_rdma_sink_reclaim(void *arg __unused, int how __unused)
{
	svc_rdma_sink_flush();
}

/*
 * Free every recycled sink buffer; called from svc_rdma_uninit at unload.  Set
 * the draining flag FIRST (under the lock) so any concurrent or later put stops
 * caching and free()s instead -- the list then cannot be re-populated and any
 * mbuf that outlives this drain returns its buffer to the system, not the list.
 */
void
svc_rdma_sink_drain(void)
{
	mtx_lock(&svc_rdma_sink_lock);
	atomic_store_rel_int(&svc_rdma_sink_draining, 1);
	mtx_unlock(&svc_rdma_sink_lock);
	svc_rdma_sink_flush();
}
