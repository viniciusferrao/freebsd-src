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

/**
 * xprt_cm_event_handler - Handle RDMA CM events
 * @id: rdma_cm_id on which an event has occurred
 * @event: details of the event
 *
 * Called with @id's mutex held. Returns 1 if caller should
 * destroy @id, otherwise 0.
 */
static int
xprt_cm_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct xprt_rdma_ep *ep = id->context;

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
_xprt_create_id(struct vnet *net, struct sockaddr *saddr,
    struct xprt_rdma_ep *ep, rdma_cm_event_handler event_handler, void *context,
    enum rdma_port_space ps, enum ib_qp_type qptype)
{
	unsigned long wtimeout = msecs_to_jiffies(RDMA_RESOLVE_TIMEOUT) + 1;
	struct rdma_cm_id *id;
	int rc;

	init_completion(&ep->re_done);

	id = rdma_create_id(net, event_handler, context, ps, qptype);
	if (IS_ERR(id))
		return (id);

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

	return (id);

out:
	rdma_destroy_id(id);
	return (ERR_PTR(rc));
}

int
xprt_create_id(struct vnet *net, struct sockaddr *saddr,
    struct xprt_rdma_ep *ep)
{
	struct rdma_cm_id *id;

	id = _xprt_create_id(net, saddr, ep, xprt_cm_event_handler, ep,
	    RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id))
		return (PTR_ERR(id));
	ep->re_id = id;
	return (0);
}

