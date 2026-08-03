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
 * text can go away (MOD_UNLOAD below), so krpc never holds a dangling table.
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
 * Module lifecycle.  This file is the NFS-over-RDMA server verbs layer, shipped
 * as the loadable nfsrdma.ko (sys/modules/nfsrdma) -- an InfiniBand upper-layer
 * protocol, like ipoib.  It is module-only: svc_verbs.c is not in
 * sys/conf/files, so there is no built-in variant to sequence against and all
 * load/unload work belongs in the module event handler.
 *
 * Dependencies (MODULE_DEPEND below):
 *   ibcore   -- the IB verbs/RDMA-CM core this code drives (imported syms);
 *   krpc     -- the base svc_rdma.c SVCXPRT layer we register with
 *               (svc_rdma_register_verbs, M_NFSRDMA), built in with nfsd;
 *   linuxkpi -- the compat layer this OFED code is written against.
 *
 * The ibcore dependency is what makes the teardown below safe.  Every verbs and
 * CM call on the unload path -- rdma_destroy_id() on the listening ids, and the
 * per-connection rdma_disconnect/ib_drain_qp/rdma_destroy_id that the teardown
 * tasks run -- needs the CM core and the provider still alive.  MODULE_DEPEND
 * holds a reference on ibcore for as long as this module is loaded, so ibcore
 * cannot unload before we do and the core is live for the whole of MOD_UNLOAD.
 *
 * Unload order is load-bearing:
 *   1. drop the vm_lowmem handler -- EVENTHANDLER_DEREGISTER waits for an
 *      in-flight svc_rdma_sink_reclaim, so it cannot race the drain in step 4;
 *   2. revoke the verbs table -- krpc's pointer goes NULL and its bring-up
 *      returns ENXIO, so no NEW listen can start against text about to be
 *      freed.  svc_rdma_unregister_verbs() drains in-flight callers and
 *      itself calls svo_listen_stop() on the outgoing table, tearing a live
 *      listener down THROUGH the still-valid verbs path rather than
 *      orphaning callbacks into freed text;
 *   3. svc_rdma_listen_stop() again -- idempotent (sl_id/sl_id6 already NULL,
 *      registry already empty), and the belt-and-braces path if this module was
 *      never the registered owner;
 *   4. drain the sink recycle cache, now that every connection has torn
 *      down and returned its buffers;
 *   5. destroy the locks last, once nothing can take them.
 *
 * A failed MOD_LOAD deliberately does NOT unwind inline.
 * module_register_init() (kern_module.c) calls MOD_EVENT(MOD_LOAD) and, on any
 * nonzero return, immediately calls MOD_EVENT(MOD_UNLOAD) on the same handler
 * before releasing the module.  MOD_UNLOAD is therefore the single teardown
 * path, and it is already correct after a failed registration:
 * svc_rdma_unregister_verbs() is owner-keyed and no-ops when we never became
 * the owner, svc_rdma_listen_stop() finds NULL cm_ids and an empty registry,
 * svc_rdma_sink_drain() an empty cache, and every lock is destroyed exactly
 * once.  Unwinding here would destroy the locks that the follow-up MOD_UNLOAD
 * then locks and destroys again.
 * module_release() drops the module from its linker file afterwards, so a later
 * kldunload cannot deliver a second MOD_UNLOAD.
 *
 * The error is not visible to kldload(8) -- module_register_init() is a void
 * SYSINIT callback -- so a failed registration leaves this module resident but
 * inert: krpc's verbs table stays NULL and its bring-up returns ENXIO.
 */
static int
nfsrdma_evhand(module_t mod __unused, int event, void *arg __unused)
{
	int error;

	switch (event) {
	case MOD_LOAD:
		sx_init(&svc_rdma_listen_cfg_lock, "nfsrdma_listencfg");
		mtx_init(&svc_rdma_listener.sl_lock, "nfsrdma_listener", NULL,
		    MTX_DEF);
		mtx_init(&svc_rdma_conns_lock, "nfsrdma_conns", NULL, MTX_DEF);
		mtx_init(&svc_rdma_sink_lock, "nfsrdma_sink", NULL, MTX_DEF);
		error = svc_rdma_register_verbs(&ibcore_verbs_ops);
		if (error != 0) {
			printf("nfsrdma: svc_rdma_register_verbs failed: %d\n",
			    error);
			break;
		}
		/*
		 * Make the sink recycle cache elastic: give it back under
		 * memory pressure.
		 */
		svc_rdma_sink_lowmem_tag = EVENTHANDLER_REGISTER(vm_lowmem,
		    svc_rdma_sink_reclaim, NULL, EVENTHANDLER_PRI_ANY);
		break;
	case MOD_UNLOAD:
		if (svc_rdma_sink_lowmem_tag != NULL) {
			EVENTHANDLER_DEREGISTER(vm_lowmem,
			    svc_rdma_sink_lowmem_tag);
			svc_rdma_sink_lowmem_tag = NULL;
		}
		svc_rdma_unregister_verbs(&ibcore_verbs_ops);
		svc_rdma_listen_stop();
		svc_rdma_sink_drain();
		mtx_destroy(&svc_rdma_sink_lock);
		mtx_destroy(&svc_rdma_conns_lock);
		mtx_destroy(&svc_rdma_listener.sl_lock);
		sx_destroy(&svc_rdma_listen_cfg_lock);
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
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
