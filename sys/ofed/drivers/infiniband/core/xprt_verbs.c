// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2014-2017 Oracle.  All rights reserved.
 * Copyright (c) 2003-2007 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file is loosely based on net/sunrpc/xprtrdma/verbs.c.
 * in Linux.
 * It is significantly different, due to FreeBSD's rdma_XXX()
 * functions having different arguments, among other things.
 */
/*
 * verbs.c
 *
 * Encapsulates the major functions managing:
 *  o adapters
 *  o endpoints
 *  o connections
 *  o buffer memory
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <rdma/rdma_cm.h>
#include <rdma/xprt_rdma.h>

static void rpcrdma_ep_destroy(struct kref *kref)
{
	struct rpcrdma_ep *ep = container_of(kref, struct rpcrdma_ep, re_kref);

	if (ep->re_id->qp) {
		rdma_destroy_qp(ep->re_id);
		ep->re_id->qp = NULL;
	}

	if (ep->re_attr.recv_cq)
		ib_free_cq(ep->re_attr.recv_cq);
	ep->re_attr.recv_cq = NULL;
	if (ep->re_attr.send_cq)
		ib_free_cq(ep->re_attr.send_cq);
	ep->re_attr.send_cq = NULL;

	if (ep->re_pd)
		ib_dealloc_pd(ep->re_pd);
	ep->re_pd = NULL;

#ifdef notyet
	rpcrdma_rn_unregister(ep->re_id->device, &ep->re_rn);
#endif

	kfree(ep);
}

static noinline int rpcrdma_ep_put(struct rpcrdma_ep *ep)
{
	return kref_put(&ep->re_kref, rpcrdma_ep_destroy);
}

static int
rpcrdma_cm_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct rpcrdma_ep *ep = id->context;

	might_sleep();

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		ep->re_async_rc = 0;
		complete(&ep->re_done);
		return 0;
	case RDMA_CM_EVENT_ADDR_ERROR:
		ep->re_async_rc = -EPROTO;
		complete(&ep->re_done);
		return 0;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		ep->re_async_rc = -ENETUNREACH;
		complete(&ep->re_done);
		return 0;
#ifdef notyet
	case RDMA_CM_EVENT_ADDR_CHANGE:
		ep->re_connect_status = -ENODEV;
		goto disconnected;
	case RDMA_CM_EVENT_ESTABLISHED:
		rpcrdma_ep_get(ep);
		ep->re_connect_status = 1;
		rpcrdma_update_cm_private(ep, &event->param.conn);
		trace_xprtrdma_inline_thresh(ep);
		wake_up_all(&ep->re_connect_wait);
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
		ep->re_connect_status = -ENOTCONN;
		goto wake_connect_worker;
	case RDMA_CM_EVENT_UNREACHABLE:
		ep->re_connect_status = -ENETUNREACH;
		goto wake_connect_worker;
	case RDMA_CM_EVENT_REJECTED:
		ep->re_connect_status = -ECONNREFUSED;
		if (event->status == IB_CM_REJ_STALE_CONN)
			ep->re_connect_status = -ENOTCONN;
wake_connect_worker:
		wake_up_all(&ep->re_connect_wait);
		return 0;
	case RDMA_CM_EVENT_DISCONNECTED:
		ep->re_connect_status = -ECONNABORTED;
disconnected:
		rpcrdma_force_disconnect(ep);
		return rpcrdma_ep_put(ep);
#endif
	default:
		break;
	}

	return 0;
}

static struct rdma_cm_id *
rpcrdma_create_id(struct vnet *net, struct sockaddr *saddr,
    struct rpcrdma_ep *ep)
{
	unsigned long wtimeout = msecs_to_jiffies(RDMA_RESOLVE_TIMEOUT) + 1;
	struct rdma_cm_id *id;
	int rc;

	init_completion(&ep->re_done);

	id = rdma_create_id(net, rpcrdma_cm_event_handler, ep,
	    RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id))
		return id;

	ep->re_async_rc = -ETIMEDOUT;
	rc = rdma_resolve_addr(id, NULL, saddr, RDMA_RESOLVE_TIMEOUT);
	if (rc)
		goto out;
	rc = wait_for_completion_interruptible_timeout(&ep->re_done, wtimeout);
	if (rc < 0)
		goto out;

	rc = ep->re_async_rc;
	if (rc)
		goto out;

	ep->re_async_rc = -ETIMEDOUT;
	rc = rdma_resolve_route(id, RDMA_RESOLVE_TIMEOUT);
	if (rc)
		goto out;
	rc = wait_for_completion_interruptible_timeout(&ep->re_done, wtimeout);
	if (rc < 0)
		goto out;
	rc = ep->re_async_rc;
	if (rc)
		goto out;

#ifdef notnow
	rc = rpcrdma_rn_register(id->device, &ep->re_rn, rpcrdma_ep_removal_done);
	if (rc)
		goto out;
#endif

	return id;

out:
	rdma_destroy_id(id);
	return ERR_PTR(rc);
}

static int
rpcrdma_ep_create(struct vnet *net, struct sockaddr *saddr, int max_reqs,
    struct rpcrdma_xprt *r_xprt)
{
	struct ib_device *device;
	struct rdma_cm_id *id;
	struct rpcrdma_ep *ep;
	int rc;

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep)
		return -ENOTCONN;
	kref_init(&ep->re_kref);

	id = rpcrdma_create_id(net, saddr, ep);
	if (IS_ERR(id)) {
		kfree(ep);
		return PTR_ERR(id);
	}
	device = id->device;
	ep->re_id = id;
	reinit_completion(&ep->re_done);

	ep->re_max_requests = max_reqs;
#ifdef notyet
	rc = frwr_query_device(ep, device);
	if (rc)
		goto out_destroy;
#endif

	ep->re_attr.srq = NULL;
	ep->re_attr.cap.max_inline_data = 0;
	ep->re_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ep->re_attr.qp_type = IB_QPT_RC;
	ep->re_attr.port_num = ~0;

	init_waitqueue_head(&ep->re_connect_wait);

#ifdef notyet
	ep->re_attr.send_cq = ib_alloc_cq_any(device, r_xprt,
	      ep->re_attr.cap.max_send_wr, IB_POLL_WORKQUEUE);
	if (IS_ERR(ep->re_attr.send_cq)) {
		rc = PTR_ERR(ep->re_attr.send_cq);
		ep->re_attr.send_cq = NULL;
		goto out_destroy;
	}

	ep->re_attr.recv_cq = ib_alloc_cq_any(device, r_xprt,
	      ep->re_attr.cap.max_recv_wr, IB_POLL_WORKQUEUE);
	if (IS_ERR(ep->re_attr.recv_cq)) {
		rc = PTR_ERR(ep->re_attr.recv_cq);
		ep->re_attr.recv_cq = NULL;
		goto out_destroy;
	}
#endif
	ep->re_receive_count = 0;

	/* Initialize cma parameters */
	memset(&ep->re_remote_cma, 0, sizeof(ep->re_remote_cma));

	/* Client offers RDMA Read but does not initiate */
	ep->re_remote_cma.initiator_depth = 0;
	ep->re_remote_cma.responder_resources =
	    min_t(int, U8_MAX, device->attrs.max_qp_rd_atom);

	/* Limit transport retries so client can detect server
	 * GID changes quickly. RPC layer handles re-establishing
	 * transport connection and retransmission.
	 */
	ep->re_remote_cma.retry_count = 6;

	/* RPC-over-RDMA handles its own flow control. In addition,
	 * make all RNR NAKs visible so we know that RPC-over-RDMA
	 * flow control is working correctly (no NAKs should be seen).
	 */
	ep->re_remote_cma.flow_control = 0;
	ep->re_remote_cma.rnr_retry_count = 0;

	ep->re_pd = ib_alloc_pd(device, 0);
	if (IS_ERR(ep->re_pd)) {
		rc = PTR_ERR(ep->re_pd);
		ep->re_pd = NULL;
		goto out_destroy;
	}

	rc = rdma_create_qp(id, ep->re_pd, &ep->re_attr);
	if (rc)
		goto out_destroy;

	r_xprt->rx_ep = ep;
	return 0;

out_destroy:
	rpcrdma_ep_put(ep);
	rdma_destroy_id(id);
	return rc;
}

int
xprt_rdma_send(struct rpcrdma_ep *ep, struct mbuf *mreq)
{

	return (0);
}
