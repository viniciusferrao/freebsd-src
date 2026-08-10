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
 * Verbs entry points krpc calls into.  The table must outlive its
 * registration, so it is static for the life of the module text.
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
 * Unload order: deregister the vm_lowmem handler before draining the sink
 * cache, revoke the verbs table before stopping the listener, destroy the
 * locks last.
 *
 * MOD_LOAD must not unwind on failure.  module_register_init() calls
 * MOD_UNLOAD itself when MOD_LOAD returns nonzero, so unwinding here would
 * destroy the locks twice.
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
		svc_rdma_publish_listen(true);
		svc_rdma_sink_lowmem_tag = EVENTHANDLER_REGISTER(vm_lowmem,
		    svc_rdma_sink_reclaim, NULL, EVENTHANDLER_PRI_ANY);
		break;
	case MOD_UNLOAD:
		/*
		 * Refuse while nfsd is running: its pool holds SVCXPRTs whose
		 * ops live in this module's text.
		 */
		if (svc_rdma_nfsd_running()) {
			error = EBUSY;
			break;
		}
		svc_rdma_publish_listen(false);
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
MODULE_DEPEND(nfsrdma, nfsd, 1, 1, 1);
MODULE_DEPEND(nfsrdma, linuxkpi, 1, 1, 1);
