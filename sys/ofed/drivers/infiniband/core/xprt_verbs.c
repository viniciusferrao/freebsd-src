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

/*
 * Release all verbs resources attached to an endpoint, in reverse order of
 * allocation.  This is the single unwind path shared by rpcrdma_ep_create()'s
 * mid-construction error handling and by xprt_rdma_connect()'s post-create
 * failure handling, so it must tolerate ANY subset of the resources being
 * absent (NULL):
 *   - QP: created by rdma_create_qp(), which records it in re_id->qp; absent
 *     unless that call succeeded.  rdma_destroy_qp() is the cm_id-paired
 *     destructor (ib_cma.c:869): it takes id_priv->qp_mutex, calls
 *     ib_destroy_qp(), and clears id->qp -- so we must NOT touch re_id->qp by
 *     hand, and must guard it (only call when a QP actually exists).
 *   - recv_cq / send_cq / re_pd: each NULL until its alloc succeeds; the
 *     create-time failure paths NULL the failing pointer before unwinding.
 *   - re_id: always present once rpcrdma_create_id() returned; rdma_destroy_id
 *     MUST run even when re_id->qp is NULL, so it sits outside the qp guard.
 * Order: QP -> recv_cq -> send_cq -> PD -> cm_id.  A CQ is never freed while a
 * live QP references it, and the PD outlives both.  Every pointer is nulled
 * after release so a second call (or a create-then-connect failure sequence)
 * cannot double-free.
 */
static void
rpcrdma_ep_destroy(struct rpcrdma_ep *ep)
{
	if (ep->re_id != NULL && ep->re_id->qp != NULL)
		rdma_destroy_qp(ep->re_id);
	if (ep->re_attr.recv_cq != NULL) {
		ib_free_cq(ep->re_attr.recv_cq);
		ep->re_attr.recv_cq = NULL;
	}
	if (ep->re_attr.send_cq != NULL) {
		ib_free_cq(ep->re_attr.send_cq);
		ep->re_attr.send_cq = NULL;
	}
	if (ep->re_pd != NULL) {
		ib_dealloc_pd(ep->re_pd);
		ep->re_pd = NULL;
	}
	if (ep->re_id != NULL) {
		rdma_destroy_id(ep->re_id);
		ep->re_id = NULL;
	}
}

static int
rpcrdma_ep_create(struct vnet *net, struct sockaddr *saddr, int max_reqs,
    struct rpcrdma_ep *ep)
{
	struct ib_device *device;
	struct rdma_cm_id *id;
	int rc;

	/*
	 * max_reqs is signed and is stored into the unsigned re_max_requests
	 * and the u32 QP caps below.  A value <= 0 would size the QP and CQs to
	 * zero entries, which is degenerate (mlx4 rejects a 0-entry CQ) -- and
	 * a negative value would wrap to a huge unsigned cap.  Reject it before
	 * allocating anything.  After this guard the min_t() caps are >= 1.
	 */
	if (max_reqs <= 0)
		return -EINVAL;

	id = rpcrdma_create_id(net, saddr, ep);
	if (IS_ERR(id))
		return PTR_ERR(id);
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

	/*
	 * Size the QP conservatively from the negotiated request depth,
	 * clamped to what the device can support.  re_max_requests is the
	 * number of RPCs we expect to have in flight; each consumes roughly
	 * one send and one receive WR, so a 1:1 mapping bounded by
	 * device->attrs.max_qp_wr is a safe, correct starting point.  This is
	 * the correctness task, not the performance task: no extra head-room
	 * for FRWR register/invalidate or RDMA Read/Write WRs is reserved yet
	 * (those arrive with the WR-posting work in a later task).
	 *
	 * device->attrs.max_sge is the driver-reported per-QP scatter/gather
	 * limit (see mlx5: props->max_sge = min(max_rq_sg, max_sq_sg)).  Note
	 * that the ib_device_attr.max_send_sge / max_recv_sge members on this
	 * FreeBSD OFED alias max_srq_sge in a union and do NOT describe the QP
	 * limit, so max_sge is the field to bound against here.  Until real
	 * scatter/gather buffers are provisioned we request a single SGE per
	 * WR, which is sufficient for an inline (single-segment) message.
	 */
	ep->re_attr.cap.max_send_wr = min_t(unsigned int, ep->re_max_requests,
	    (unsigned int)device->attrs.max_qp_wr);
	ep->re_attr.cap.max_recv_wr = min_t(unsigned int, ep->re_max_requests,
	    (unsigned int)device->attrs.max_qp_wr);
	ep->re_attr.cap.max_send_sge = min_t(unsigned int, 1U,
	    (unsigned int)device->attrs.max_sge);
	ep->re_attr.cap.max_recv_sge = min_t(unsigned int, 1U,
	    (unsigned int)device->attrs.max_sge);

	init_waitqueue_head(&ep->re_connect_wait);

	/*
	 * comp_vector 0 is a deliberate minimal choice.  Linux uses
	 * ib_alloc_cq_any(), which round-robins completion vectors across
	 * device->num_comp_vectors to spread interrupt load; doing that here
	 * is a later optimization.  Pass ep (not the xprt) as the CQ context;
	 * the xprt is not in scope at this layer.  nr_cqe matches the
	 * corresponding QP cap so the CQ cannot overflow.
	 */
	ep->re_attr.send_cq = ib_alloc_cq(device, ep,
	    ep->re_attr.cap.max_send_wr, 0, IB_POLL_WORKQUEUE);
	if (IS_ERR(ep->re_attr.send_cq)) {
		rc = PTR_ERR(ep->re_attr.send_cq);
		ep->re_attr.send_cq = NULL;
		goto out_destroy;
	}

	ep->re_attr.recv_cq = ib_alloc_cq(device, ep,
	    ep->re_attr.cap.max_recv_wr, 0, IB_POLL_WORKQUEUE);
	if (IS_ERR(ep->re_attr.recv_cq)) {
		rc = PTR_ERR(ep->re_attr.recv_cq);
		ep->re_attr.recv_cq = NULL;
		goto out_destroy;
	}
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

	return 0;

	/*
	 * Reachable partial-construction states (the failing pointer is NULLed
	 * before the goto in each case): send_cq fail (no CQs/PD/QP); recv_cq
	 * fail (send_cq only); ib_alloc_pd fail (both CQs, no PD/QP);
	 * rdma_create_qp fail (both CQs + PD, re_id->qp still NULL).
	 * rpcrdma_ep_destroy() tolerates every one of these.
	 */
out_destroy:
	rpcrdma_ep_destroy(ep);
	return rc;
}

/*
 * WARNING: the connection-establishment path is INCOMPLETE.
 * rpcrdma_cm_event_handler() still has RDMA_CM_EVENT_ESTABLISHED (and
 * DISCONNECTED) behind #ifdef notyet, so re_done is never completed on a
 * successful connect: the post-connect wait below always times out and this
 * function always reports failure, tearing the endpoint back down.  That is
 * intended and safe for now (no resource is left dangling), but it means NO
 * caller (clnt_rdma.c) may be wired to this transport until TASK_003 enables
 * the ESTABLISHED/DISCONNECTED handling and the establishment handshake.
 */
int
xprt_rdma_connect(struct vnet *net, struct sockaddr *saddr,
    struct rpcrdma_xprt *rdmaxprt, int max_reqs,
    struct rdma_conn_param *conn_param)
{
	unsigned long wtimeout = msecs_to_jiffies(RDMA_RESOLVE_TIMEOUT) + 1;
	struct rpcrdma_ep *ep;
	int rc;

	ep = &rdmaxprt->rx_ep;
	memset(ep, 0, sizeof(*ep));
	rc = rpcrdma_ep_create(net, saddr, max_reqs, ep);
	if (rc)
		return (ECONNREFUSED);	/* ep already torn down internally */

	rc = rdma_connect(ep->re_id, conn_param);
	if (rc) {
		rc = ECONNREFUSED;
		goto out_destroy;
	}

	/*
	 * wait_for_completion_interruptible_timeout() returns >0 when the
	 * completion fired, 0 on timeout, and <0 when interrupted
	 * (linux_compat.c).  Only a strictly positive return is success; map
	 * timeout to ETIMEDOUT and anything else (interrupt / negative) to
	 * ECONNREFUSED.  On any failure the endpoint we just built must be
	 * released here -- rpcrdma_ep_create() only frees on its own failure.
	 */
	rc = wait_for_completion_interruptible_timeout(&ep->re_done, wtimeout);
	if (rc > 0)
		return (0);
	rc = (rc == 0) ? ETIMEDOUT : ECONNREFUSED;

out_destroy:
	rpcrdma_ep_destroy(ep);
	return (rc);
}

int
xprt_rdma_send(struct rpcrdma_ep *ep, struct mbuf *mreq)
{

	return (0);
}
