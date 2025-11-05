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

struct rdma_cm_id *
xprt_create_id(struct vnet *net, struct sockaddr *saddr,
    rdma_cm_event_handler event_handler, void *context, enum rdma_port_space ps,
    enum ib_qp_type qptype)
{
	struct rdma_cm_id *id;
	int rc;

	id = rdma_create_id(net, event_handler, context, ps, qptype);
	if (IS_ERR(id))
		return (id);

	rc = rdma_resolve_addr(id, NULL, saddr, RDMA_RESOLVE_TIMEOUT);
	if (rc)
		goto out;

	rc = rdma_resolve_route(id, RDMA_RESOLVE_TIMEOUT);
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

