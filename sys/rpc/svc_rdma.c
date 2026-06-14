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
 * svc_rdma.c -- krpc-side (built into the kernel) glue to the NFS-over-RDMA
 * verbs layer that lives in the ibcore module (svc_verbs.c).
 *
 * TASK_003e-2a scope (this increment): the CROSS-MODULE LAYERING GLUE ONLY.
 * It proves the krpc<->ibcore path end to end -- a built-in krpc consumer that
 * ibcore can drive -- and nothing more.  It does NOT build an SVCXPRT, does NOT
 * register a transport with the nfsd SVCPOOL, and does NOT dispatch RPCs: a
 * minimal consumer whose three upcalls just LOG (rate-limited) is the
 * deliverable.  The real SVCXPRT/xp_ops + nfsd-pool wiring is TASK_003e-2b/2c.
 *
 * Module layering (docs/16-svcxprt-rdma-integration.md "Module layering").
 * The verbs entry points (svc_rdma_listen_start_ops, svc_rdma_conn_send,
 * svc_rdma_conn_set_ctx, svc_rdma_conn_get_ctx, plus the private
 * svc_rdma_listen_stop) are DEFINED in the ibcore MODULE.  This file is built
 * INTO the kernel (it is part of krpc: rpc/svc*.c are compiled in whenever
 * NFSD/NFSCL/NFSLOCKD are, which they are on GENERIC-OFED).  A kernel built-in
 * cannot hard-link a loadable module's symbols, so we never call those verbs
 * entry points directly.  Instead:
 *
 *   - This file EXPORTS two built-in kernel symbols, svc_rdma_register_verbs()
 *     and svc_rdma_unregister_verbs().  A built-in kernel symbol is always
 *     resolvable from a later-loaded module, so ibcore can link to these with
 *     no MODULE_DEPEND on krpc (krpc is NOT a separate krpc.ko here -- it is in
 *     the kernel image, so there is no module to depend on).
 *   - ibcore, at module load, calls svc_rdma_register_verbs(&ibcore_verbs_ops)
 *     to hand us a function-pointer table of the verbs entry points; at module
 *     unload it calls svc_rdma_unregister_verbs().
 *   - We store that table under svc_rdma_verbs_lock and reach the verbs only
 *     through it.  With nothing registered (ibcore not loaded), the bring-up
 *     sysctl below returns ENXIO rather than dereferencing a NULL table.
 *
 * Bring-up sysctl (TEMPORARY, mirrors svc_verbs.c's vfs.nfsrdma.listen).
 * vfs.nfsrdma_krpc.listen is an int: a nonzero port drives the registered
 * verbs' svo_listen_start() with OUR logging ops (so an accepted connection's
 * newconn/recv/disconnect events are delivered up here into the krpc layer,
 * proving the cross-module callback path); 0 drives svo_listen_stop().  With no
 * verbs registered it returns ENXIO.  This is the krpc-side counterpart to the
 * ibcore-side vfs.nfsrdma.listen; the real nfsd-pool hook is TASK_003e-2c and
 * replaces this knob.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/time.h>		/* ppsratecheck: rate-limit the proof-of-life logs */

#include <rdma/svc_rdma.h>	/* the shared cross-module contract */

/*
 * The registered ibcore verbs-ops table, or NULL when ibcore is not loaded.
 *
 * svc_rdma_verbs_lock serializes register/unregister against the sysctl reader
 * so the sysctl never samples a half-published table and a verbs call is never
 * issued against a table that unregister is concurrently clearing.  It is a
 * leaf mutex held only briefly (publish/clear, snapshot-the-pointer, or
 * arm/drop the in-flight refcount); the actual blocking verbs calls in the
 * sysctl are made AFTER dropping it (see the sysctl).
 *
 * svc_rdma_verbs is read/written ONLY under this lock.
 *
 * svc_rdma_verbs_inflight counts sysctl threads that have snapshotted a non-NULL
 * svc_rdma_verbs and are about to call (or are calling) through it with the lock
 * DROPPED.  It is the modular-build use-after-free guard: svc_rdma_unregister_verbs()
 * waits for it to reach 0 -- after it has cleared the pointer so no NEW in-flight
 * caller can arm -- BEFORE it calls svo_listen_stop() and returns.  That way, when
 * a truly modular ibcore.ko is unloaded and its text freed, no sysctl thread is
 * still executing inside the ops it is about to revoke.  Incremented/decremented
 * only under svc_rdma_verbs_lock; the decrementer wakes &svc_rdma_verbs_inflight.
 */
static struct mtx		 svc_rdma_verbs_lock;
static const struct svc_rdma_verbs_ops *svc_rdma_verbs;
static int			 svc_rdma_verbs_inflight;

MTX_SYSINIT(svc_rdma_verbs_lock, &svc_rdma_verbs_lock, "svcrdma_verbs", MTX_DEF);

/*
 * Rate limiter for the proof-of-life upcall logs.  The arrival rate of
 * connections/recvs is peer-controlled, so logging one line per event
 * unconditionally would be a remotely-triggerable console flood.  Capped to a
 * few lines/sec, counting the suppressed remainder -- the same discipline
 * svc_verbs.c uses on its side.
 */
static struct timeval		 svc_rdma_krpc_log_last;
static int			 svc_rdma_krpc_log_pps;

/*
 * Last requested bring-up listen port; 0 means stopped.  This is the value the
 * sysctl read-back reports.  Written only by the sysctl handler under
 * svc_rdma_verbs_lock (alongside the verbs calls), so the read-back cannot tear
 * against a concurrent register/unregister.
 */
static int			 svc_rdma_krpc_listen_port;

/*
 * ---------------------------------------------------------------------------
 * Minimal logging consumer (the TASK_003e-2a deliverable).
 *
 * This is the krpc-side struct svc_rdma_ops that ibcore drives through the
 * registered verbs table.  Its only job in this increment is to PROVE the
 * cross-module callback path: ibcore's CM/recv/teardown contexts call up into
 * the kernel-resident krpc layer here.  Each upcall just logs (rate-limited).
 *
 * It honors the svc_rdma_ops context contract (see <rdma/svc_rdma.h>) even
 * though it does nothing real yet:
 *   - sro_newconn runs in the sleepable CM context; we attach no per-conn state
 *     (svc_rdma_conn_set_ctx is left for 2b's SVCXPRT) and only log.
 *   - sro_recv runs in the recv-completion (workqueue) context and MUST NOT
 *     sleep; we only log and return 0 (continue) -- we do NOT copy msg->rpc
 *     (which is valid only for the call) because we dispatch nothing, and we do
 *     NOT post a reply here (the verbs default-ops self-test path is the one
 *     that exercises svc_rdma_conn_send; this consumer just observes events).
 *   - sro_disconnect runs in the sleepable teardown context, paired with
 *     newconn; we only log.  No per-conn state to free.
 * Returning 0 from sro_recv asks the verbs layer to repost and await the next
 * call (we never ask it to drop the connection).
 * ---------------------------------------------------------------------------
 */
static void
svc_rdma_krpc_newconn(void *ctx __unused, struct svc_rdma_conn *conn __unused)
{

	if (ppsratecheck(&svc_rdma_krpc_log_last, &svc_rdma_krpc_log_pps, 5))
		printf("svc_rdma(krpc): newconn upcall (cross-module path up)\n");
}

static int
svc_rdma_krpc_recv(void *ctx __unused, struct svc_rdma_conn *conn __unused,
    const struct svc_rdma_msg *msg)
{

	if (ppsratecheck(&svc_rdma_krpc_log_last, &svc_rdma_krpc_log_pps, 5))
		printf("svc_rdma(krpc): recv upcall xid=0x%08x credit=%u "
		    "inline rpc=%u bytes (logged only; no dispatch yet)\n",
		    msg->xid, msg->credit, msg->rpc_len);
	/*
	 * 0 == continue: let the verbs layer repost and await the next call.
	 * 2b replaces this with enqueue + xprt_active() into the nfsd pool.
	 */
	return (0);
}

static void
svc_rdma_krpc_disconnect(void *ctx __unused, struct svc_rdma_conn *conn __unused)
{

	if (ppsratecheck(&svc_rdma_krpc_log_last, &svc_rdma_krpc_log_pps, 5))
		printf("svc_rdma(krpc): disconnect upcall\n");
}

static const struct svc_rdma_ops svc_rdma_krpc_logging_ops = {
	.sro_newconn	= svc_rdma_krpc_newconn,
	.sro_recv	= svc_rdma_krpc_recv,
	.sro_disconnect	= svc_rdma_krpc_disconnect,
};

/*
 * ---------------------------------------------------------------------------
 * Cross-module verbs-ops registration (called from ibcore).
 *
 * These are the built-in kernel symbols ibcore resolves and calls at module
 * load/unload.  Single-provider: a second register while one is live is EBUSY;
 * unregister is OWNER-KEYED (see below) and idempotent.
 *
 * Owner-keying (BLOCKER fix).  In the shipping GENERIC-OFED config options OFED
 * compiles the provider IN-KERNEL -- the in-kernel svc_rdma_verbs_register()
 * SYSINIT registers its &ibcore_verbs_ops at boot -- AND also builds ibcore.ko
 * carrying a DUPLICATE register/unregister pair over the MODULE's OWN, distinct
 * &ibcore_verbs_ops object.  A root `kldload ibcore' then finds a provider
 * already registered and gets EBUSY (the module's table never becomes the
 * owner).  Without owner-keying, a later `kldunload ibcore' would call
 * svc_rdma_unregister_verbs() unconditionally and tear down the IN-KERNEL
 * provider's live listener (NULLing the global and draining every active
 * NFS-over-RDMA connection) -- root-triggerable in the shipping config.  So
 * svc_rdma_register_verbs() records EXACTLY the ops pointer it was handed, and
 * svc_rdma_unregister_verbs(ops) proceeds ONLY if that pointer is the current
 * owner; the EBUSY'd module passes its own &ibcore_verbs_ops, which never
 * matches, so its unload is a NO-OP that cannot touch the real provider.
 *
 * Lifecycle note (the unload-with-active-listener question).  ibcore's OWNER
 * calls svc_rdma_unregister_verbs() on the unload path before its listener
 * teardown (svc_verbs.c's SI_ORDER_SIXTH unregister runs before the
 * SI_ORDER_FIFTH svc_rdma_uninit -> svc_rdma_listen_stop).  As a defense in
 * depth, unregister itself stops any bring-up listener still up THROUGH the
 * outgoing table's svo_listen_stop (held valid for the call) and, before doing
 * so, waits out every in-flight sysctl caller (svc_rdma_verbs_inflight) so no
 * thread is executing inside the ops when the provider goes away -- the
 * modular-build UAF guard (SHOULD-FIX).
 * ---------------------------------------------------------------------------
 */
int
svc_rdma_register_verbs(const struct svc_rdma_verbs_ops *ops)
{

	/*
	 * A partial table would let the sysctl call through a NULL function
	 * pointer; require every entry the consumer can invoke.
	 */
	if (ops == NULL || ops->svo_listen_start == NULL ||
	    ops->svo_listen_stop == NULL || ops->svo_conn_send == NULL ||
	    ops->svo_conn_set_ctx == NULL || ops->svo_conn_get_ctx == NULL)
		return (EINVAL);

	mtx_lock(&svc_rdma_verbs_lock);
	if (svc_rdma_verbs != NULL) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return (EBUSY);
	}
	/*
	 * Record EXACTLY the caller's ops pointer; the matching unregister keys
	 * on this same pointer (owner-keying above).
	 */
	svc_rdma_verbs = ops;
	mtx_unlock(&svc_rdma_verbs_lock);

	printf("svc_rdma(krpc): ibcore verbs registered\n");
	return (0);
}

void
svc_rdma_unregister_verbs(const struct svc_rdma_verbs_ops *ops)
{

	mtx_lock(&svc_rdma_verbs_lock);

	/*
	 * OWNER-KEYED.  Only the registration that actually owns the global may
	 * revoke it.  A non-owner (e.g. the EBUSY'd duplicate ibcore.ko unloading)
	 * passes a different &ibcore_verbs_ops and is a strict no-op here -- it
	 * does NOT clear the pointer, does NOT touch svc_rdma_krpc_listen_port, and
	 * does NOT call svo_listen_stop, so it cannot tear down the in-kernel
	 * provider's live listener.
	 */
	if (ops == NULL || svc_rdma_verbs != ops) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return;
	}

	/*
	 * Detach the table FIRST, under the lock, so no NEW sysctl caller can arm
	 * an in-flight reference against it (the sysctl arms svc_rdma_verbs_inflight
	 * only while observing svc_rdma_verbs != NULL under this same lock).  Then
	 * wait for every ALREADY-armed in-flight caller to finish its lock-dropped
	 * svo_* call and decrement -- this is the modular-build UAF guard: when this
	 * returns no thread is still executing inside ops, so the caller (ibcore)
	 * may let the module text holding ops go away.  msleep is legal here:
	 * svc_rdma_unregister_verbs runs in ibcore's SYSUNINIT/unload context, which
	 * is sleepable.  No LOR: msleep atomically drops svc_rdma_verbs_lock while
	 * blocked, and the only thing it waits on (in-flight sysctl threads) takes
	 * that same lock only briefly to decrement and never blocks on us.
	 */
	svc_rdma_verbs = NULL;
	svc_rdma_krpc_listen_port = 0;
	while (svc_rdma_verbs_inflight != 0)
		msleep(&svc_rdma_verbs_inflight, &svc_rdma_verbs_lock, 0,
		    "svcrdvu", 0);
	mtx_unlock(&svc_rdma_verbs_lock);

	/*
	 * Now stop any bring-up listener still up, THROUGH the outgoing table.
	 * The lock is dropped (svo_listen_stop blocks draining teardown tasks and
	 * must not run under a leaf mutex); the pointer is already cleared so the
	 * sysctl returns ENXIO, and the in-flight drain above guarantees no sysctl
	 * thread is concurrently using ops.
	 */
	ops->svo_listen_stop();
	printf("svc_rdma(krpc): ibcore verbs unregistered\n");
}

/*
 * ---------------------------------------------------------------------------
 * TEMPORARY bring-up sysctl (TASK_003e-2a).  vfs.nfsrdma_krpc.listen:
 *   - read back the port the krpc-driven listener is up on (0 when down);
 *   - write a nonzero port -> if ibcore is registered, drive svo_listen_start()
 *     with our logging ops (NULL consumer ctx -- 2b passes the SVCPOOL here);
 *   - write 0 -> drive svo_listen_stop();
 *   - if ibcore is NOT registered, return ENXIO (no NULL deref).
 * Replaced by the nfsd-pool listen hook in TASK_003e-2c.
 *
 * Dual-knob note (NIT).  There are now TWO sysctls driving the ONE module-global
 * verbs listener: the legacy vfs.nfsrdma.listen (in svc_verbs.c, binding the
 * verbs' in-tree DEFAULT self-test ops) and this vfs.nfsrdma_krpc.listen
 * (binding the krpc LOGGING ops).  They are ALTERNATIVES, not additive: only one
 * listener exists, so whichever starts first wins and the other's start returns
 * EBUSY until the first is stopped.  This krpc knob is the forward direction
 * (events flow up into the krpc layer); the legacy knob remains for the
 * verbs-only self-test.  The real nfsd-pool listen hook in TASK_003e-2c
 * supersedes both -- they are NOT unified here on purpose.
 * ---------------------------------------------------------------------------
 */
SYSCTL_NODE(_vfs, OID_AUTO, nfsrdma_krpc, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "NFS over RDMA server (krpc layer)");

static int
sysctl_nfsrdma_krpc_listen(SYSCTL_HANDLER_ARGS)
{
	const struct svc_rdma_verbs_ops *ops;
	int error, newport;

	/* Snapshot the current port under the lock for a non-torn read-back. */
	mtx_lock(&svc_rdma_verbs_lock);
	newport = svc_rdma_krpc_listen_port;
	mtx_unlock(&svc_rdma_verbs_lock);

	error = sysctl_handle_int(oidp, &newport, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (newport < 0 || newport > 65535)
		return (EINVAL);

	/*
	 * Snapshot the registered verbs table under the lock, record the
	 * requested port, and ARM the in-flight refcount -- all in one critical
	 * section while observing svc_rdma_verbs != NULL -- then issue the
	 * (blocking) verbs call with the lock DROPPED.
	 *
	 * The arm/drain pairing is what makes the lock-dropped snapshot safe in a
	 * truly modular ibcore.ko build (TOCTOU / use-after-free fix): a concurrent
	 * svc_rdma_unregister_verbs() clears svc_rdma_verbs under the lock and then
	 * WAITS for svc_rdma_verbs_inflight to reach 0 before it calls
	 * svo_listen_stop() and returns -- and ibcore only frees the module text
	 * holding ops after that returns.  Because we incremented inflight under the
	 * same lock while ops was still the live owner, unregister cannot complete
	 * (and the text cannot be freed) until we decrement below; so the snapshot
	 * we call through here is guaranteed live for the whole svo_* call.
	 *
	 * If no provider is registered, return ENXIO: ibcore (the verbs) is not
	 * loaded, so there is nothing to listen with.  This is the explicit
	 * "RDMA refused unless registered" rule from the design doc.
	 */
	mtx_lock(&svc_rdma_verbs_lock);
	ops = svc_rdma_verbs;
	if (ops == NULL) {
		mtx_unlock(&svc_rdma_verbs_lock);
		return (ENXIO);
	}
	svc_rdma_krpc_listen_port = newport;
	svc_rdma_verbs_inflight++;
	mtx_unlock(&svc_rdma_verbs_lock);

	/*
	 * Drive the verbs listener with our logging ops and a NULL consumer ctx
	 * (2b passes the nfsd SVCPOOL here).  newport == 0 stops; nonzero starts.
	 */
	if (newport == 0) {
		ops->svo_listen_stop();
		error = 0;
	} else {
		error = ops->svo_listen_start((uint16_t)newport,
		    &svc_rdma_krpc_logging_ops, NULL);
	}

	/*
	 * Drop the in-flight refcount (waking a waiting unregister if we were the
	 * last) and, on a failed start, roll the recorded port back to 0 -- both in
	 * one critical section.  Only clear the port if it still reflects our failed
	 * attempt; a racing unregister may already have zeroed it.
	 */
	mtx_lock(&svc_rdma_verbs_lock);
	if (error != 0 && newport != 0 && svc_rdma_krpc_listen_port == newport)
		svc_rdma_krpc_listen_port = 0;
	if (--svc_rdma_verbs_inflight == 0)
		wakeup(&svc_rdma_verbs_inflight);
	mtx_unlock(&svc_rdma_verbs_lock);

	return (error);
}
SYSCTL_PROC(_vfs_nfsrdma_krpc, OID_AUTO, listen,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW, NULL, 0,
    sysctl_nfsrdma_krpc_listen, "I",
    "TEMP (3e-2a): nonzero port starts the krpc-driven RDMA listener "
    "(logging consumer), 0 stops it; ENXIO if ibcore is not loaded");
