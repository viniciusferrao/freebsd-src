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
 * Stop the listener at module unload, before the CM core can go away, so no
 * dangling cm_id is left
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
	/*
	 * Every connection has now torn down and returned its sink buffers to
	 * the recycle list (#60); free them.  Runs at SI_ORDER_FIFTH, before the
	 * MTX_SYSINIT teardown of svc_rdma_sink_lock (SI_SUB_LOCK), so the lock
	 * is still live.
	 */
	svc_rdma_sink_drain();
}
SYSUNINIT(svc_rdma_uninit, SI_SUB_OFED_MODINIT, SI_ORDER_FIFTH,
    svc_rdma_uninit, NULL);

/*
 * ===========================================================================
 * Cross-module verbs-ops registration with the krpc layer.
 *
 * Module layering.  The SVCXPRT/krpc consumer lives in sys/rpc/svc_rdma.c, built
 * into the kernel with nfsd; the verbs live here in nfsrdma.ko.  The krpc layer
 * exports svc_rdma_register_verbs()/svc_rdma_unregister_verbs() (declared in
 * <rpc/svc_rdma.h>); this module declares MODULE_DEPEND on krpc, so those
 * symbols are resolved at load.  We hand krpc a table of our verbs entry points
 * at module load and revoke it at module unload; krpc reaches the verbs ONLY
 * through this table and refuses RDMA (ENXIO) when it is absent.
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
	.svo_sink_get		= svc_rdma_sink_get,
	.svo_sink_put		= svc_rdma_sink_put,
};

/*
 * Register the verbs-ops with krpc at module load.
 *
 * NOTE: this is now the standalone nfsrdma.ko (an IB ULP), with a hard
 * MODULE_DEPEND on ibcore, so the ibcore/CM core is fully up BEFORE this
 * module loads -- the load order, not the SI_ORDER below, is what guarantees
 * "register after cma_init".  The SI_ORDER FIFTH/SIXTH levels below now only
 * sequence THIS module's own register vs its listener teardown.
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
	/* Make the sink recycle cache elastic: give it back under memory
	 * pressure (#60).  svc_rdma_sink_lock is live by now (MTX_SYSINIT runs
	 * at the earlier SI_SUB_LOCK). */
	svc_rdma_sink_lowmem_tag = EVENTHANDLER_REGISTER(vm_lowmem,
	    svc_rdma_sink_reclaim, NULL, EVENTHANDLER_PRI_ANY);
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
 * into freed nfsrdma text.  That svc_rdma_listen_stop() runs here at SIXTH(5),
 * still strictly before cma_cleanup's FOURTH(3), so it drains against a live CM
 * core -- the same constraint svc_rdma_uninit relies on.  The subsequent
 * svc_rdma_uninit's own svc_rdma_listen_stop() is then an idempotent no-op (sl_id
 * already NULL, registry already empty).
 *
 * OWNER-KEYED.  We pass &ibcore_verbs_ops -- the EXACT pointer this module's
 * svc_rdma_verbs_register() recorded -- so unregister revokes the global ONLY if
 * this table is the one currently registered.  Registration is single-owner (a
 * second register gets EBUSY), so this just makes unregister a safe no-op if we
 * were not the owner.
 *
 * THIS MUST STAY > svc_rdma_uninit's SI_ORDER_FIFTH (so it runs before it) and,
 * transitively, > cma_cleanup's SI_ORDER_FOURTH; lowering it would let the
 * listener teardown (or the CM core) go away before the krpc consumer is cut
 * off, reintroducing exactly the dangling-callback hazard this ordering closes.
 */
static void
svc_rdma_verbs_unregister(void *arg __unused)
{

	/* Drop the vm_lowmem handler FIRST (SIXTH, before any teardown):
	 * EVENTHANDLER_DEREGISTER waits for an in-flight reclaim to finish, so
	 * svc_rdma_sink_reclaim cannot race the later svc_rdma_uninit drain. */
	if (svc_rdma_sink_lowmem_tag != NULL) {
		EVENTHANDLER_DEREGISTER(vm_lowmem, svc_rdma_sink_lowmem_tag);
		svc_rdma_sink_lowmem_tag = NULL;
	}
	svc_rdma_unregister_verbs(&ibcore_verbs_ops);
}
SYSUNINIT(svc_rdma_verbs_unregister, SI_SUB_OFED_MODINIT, SI_ORDER_SIXTH,
    svc_rdma_verbs_unregister, NULL);

/*
 * Module identity and dependencies.  This file is the NFS-over-RDMA server verbs
 * layer, shipped as the loadable nfsrdma.ko (sys/modules/nfsrdma) -- an InfiniBand
 * upper-layer protocol, like ipoib.  The actual load/unload work is the
 * SYSINIT/SYSUNINIT pair above (register/unregister of the verbs-ops table); the
 * evhand is a no-op that just carries the module name (the ipoib pattern).
 * Dependencies:
 *   ibcore   -- the IB verbs / RDMA-CM core this code drives (imported symbols);
 *   krpc     -- the base svc_rdma.c SVCXPRT layer we register with
 *               (svc_rdma_register_verbs, M_NFSRDMA), built in whenever nfsd is;
 *   linuxkpi -- the compat layer this OFED code is written against.
 */
static int
nfsrdma_evhand(module_t mod __unused, int event __unused, void *arg __unused)
{
	return (0);
}

static moduledata_t nfsrdma_mod = {
	.name = "nfsrdma",
	.evhand = nfsrdma_evhand,
};

DECLARE_MODULE(nfsrdma, nfsrdma_mod, SI_SUB_OFED_MODINIT, SI_ORDER_ANY);
MODULE_VERSION(nfsrdma, 1);
MODULE_DEPEND(nfsrdma, ibcore, 1, 1, 1);
MODULE_DEPEND(nfsrdma, krpc, 1, 1, 1);
MODULE_DEPEND(nfsrdma, linuxkpi, 1, 1, 1);
