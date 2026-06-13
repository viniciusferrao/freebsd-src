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
 * svc_verbs.c -- server-side RDMA-CM listener for NFS-over-RDMA.
 *
 * This is the passive (server) counterpart to the active-connect substrate in
 * This is the passive (server) side.  Note FreeBSD's rdma_cm API:
 * rdma_create_id() takes a leading struct vnet *, and the rdma_cm_event
 * carries no ->id member (the child cm_id of a CONNECT_REQUEST is
 * delivered as the handler's id argument).
 *
 * TASK_003 (3a) scope: bring up a passive RDMA-CM listener that binds a port
 * and logs incoming connection-management events.  There is NO data path here:
 * a CONNECT_REQUEST is logged and then *declined* cleanly (rdma_reject + a
 * non-zero handler return, which makes the CM core destroy the child cm_id for
 * us -- see the contract note below).  Accepting the connection into a working
 * QP, posting receive buffers, RFC 8166 parsing, and nfsd dispatch all arrive
 * in later increments (3b..3d).
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>	/* SI_SUB_OFED_MODINIT */
#include <linux/netdevice.h>	/* init_net */
#include <rdma/rdma_cm.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>		/* SYSUNINIT, bootverbose */
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>		/* ppsratecheck */

#include <netinet/in.h>

/*
 * Single module-global listener instance.  3a only needs one passive endpoint;
 * the real SVCXPRT-per-netconfig wiring (rdma/rdma6) is TASK_003e.
 *
 * sl_lock serializes access to sl_id (and the sysctl-visible port) and makes
 * sl_id the single ownership token for destroying the listening cm_id.  sl_id
 * is the listening cm_id, or NULL when no listener is up.
 *
 * Two contexts mutate sl_id, both under sl_lock:
 *   - svc_rdma_listen_start()/stop() (driven by the sysctl today): publish on
 *     start, capture-and-NULL on stop.
 *   - the CM event handler's RDMA_CM_EVENT_DEVICE_REMOVAL path: it acquires
 *     sl_lock to test/NULL sl_id and thereby decide whether IT or a racing
 *     listen_stop() owns the rdma_destroy_id() (see the long comment there).
 * The CONNECT_REQUEST path does NOT touch sl_id: that event is delivered on a
 * fresh child cm_id (the handler's id argument), which is declined and
 * destroyed by the CM core, independent of the listener.
 */
struct svc_rdma_listener {
	struct mtx		 sl_lock;
	struct rdma_cm_id	*sl_id;
};

static struct svc_rdma_listener svc_rdma_listener = {
	.sl_id = NULL,
};

/*
 * Initialize/destroy sl_lock at module load/unload via MTX_SYSINIT.  This file
 * is linked into the ibcore KLD, so it has no module event of its own; SYSINIT
 * machinery is how an ibcore-internal source unit gets init/teardown hooks.
 */
MTX_SYSINIT(svc_rdma_listener_lock, &svc_rdma_listener.sl_lock,
    "nfsrdma_listener", MTX_DEF);

SYSCTL_NODE(_vfs, OID_AUTO, nfsrdma, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "NFS over RDMA server");

/*
 * Rate limiter for the per-CONNECT_REQUEST log line.  A remote peer controls
 * the arrival rate of connection requests, so logging one line per request
 * unconditionally is a remotely-triggerable console-flood.  ppsratecheck()
 * caps us at a few lines per second and counts the suppressed remainder.
 */
static struct timeval svc_rdma_log_last;
static int svc_rdma_log_pps;

/*
 * Last requested listen port; 0 means stopped.  This is the value the sysctl
 * read-back reports.  It is kept in sync with svc_rdma_listener.sl_id and is
 * read/written ONLY under sl_lock so the read-back can never be stale or
 * mismatched against the actual listener state (including when the CM core
 * destroys the id from under us on DEVICE_REMOVAL).
 */
static int svc_rdma_listen_port;

static int svc_rdma_listen_start(uint16_t port);
static void svc_rdma_listen_stop(void);

/*
 * CM event handler for the *listener* cm_id and for the child cm_ids it
 * spawns.  Runs in the rdma_cm work context.
 *
 * Untrusted peer: every field reachable through "event" that originates from
 * the wire (private data, param.conn.*) is attacker-controlled and is NOT
 * touched here.  We read exactly one peer-derived datum,
 * id->route.addr.dst_addr, only to log it.  Be precise about why that is safe:
 * for an IP-based CM request the dst_addr is NOT "purely local" -- it is
 * derived from the CM REQ header the peer sent (cma_save_ip4_info() copies
 * hdr->src_addr/hdr->port into dst_addr, ib_cma.c), but the CM core has
 * validated/resolved it into a well-formed sockaddr_storage before this
 * handler runs.  So reading a fixed-size sockaddr and logging it is safe, yet
 * the value is still peer-originated.  This file is the template the rest of
 * the server will copy: future code MUST keep treating peer-supplied lengths,
 * offsets, chunk counts, and private data as hostile and bounds-check them --
 * the validity of this one resolved sockaddr does not extend to anything else
 * in the event.
 *
 * CONNECT_REQUEST contract (FreeBSD ib_cma.c cma_req_handler()):
 *   - "id" here IS the freshly-created child cm_id (Linux's event->id); the
 *     FreeBSD rdma_cm_event has no ->id member.
 *   - Per rdma_cm.h: "Users may not call rdma_destroy_id from this callback to
 *     destroy the passed in id ... Returning a non-zero value from the callback
 *     will destroy the passed in id."  So to decline we call rdma_reject() and
 *     return non-zero; the CM core then destroys the child for us.  We must NOT
 *     call rdma_destroy_id(id) ourselves -- that would be the forbidden
 *     reentrant destroy of the passed-in id and would double-free.
 */
static int
svc_rdma_cm_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	const struct sockaddr *sa;
	const struct sockaddr_in *sin;
	bool owned;
	int rc;

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		/*
		 * A real inbound connection request landed on the listener.
		 * Log the peer (rate-limited) and decline it -- 3a has no QP
		 * to accept into yet.
		 */
		sa = (const struct sockaddr *)&id->route.addr.dst_addr;
		if (ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5)) {
			if (sa->sa_family == AF_INET) {
				uint32_t a;

				sin = (const struct sockaddr_in *)sa;
				/*
				 * Format the dotted quad by hand: native
				 * printf(9)/kvprintf() does NOT implement the
				 * LinuxKPI-only %pI4 extension.  s_addr is in
				 * network byte order; ntohl() gives host order
				 * so the high octet prints first.
				 */
				a = ntohl(sin->sin_addr.s_addr);
				printf("nfsrdma: CONNECT_REQUEST from "
				    "%u.%u.%u.%u:%u declined "
				    "(3a: no accept yet)\n",
				    (a >> 24) & 0xff, (a >> 16) & 0xff,
				    (a >> 8) & 0xff, a & 0xff,
				    ntohs(sin->sin_port));
			} else {
				printf("nfsrdma: CONNECT_REQUEST (af %u) "
				    "declined (3a: no accept yet)\n",
				    sa->sa_family);
			}
		}

		/*
		 * Decline cleanly.  rdma_reject() may fail (e.g. the peer
		 * already went away); regardless, we return non-zero so the CM
		 * core destroys this child cm_id -- there is no path here that
		 * leaks it.  No private data is sent back.  A peer that can
		 * force reject failures controls how often this fires, so the
		 * failure log is rate-limited too (shares the CONNECT_REQUEST
		 * limiter) to stay flood-proof.
		 */
		rc = rdma_reject(id, NULL, 0);
		if (rc != 0 &&
		    ppsratecheck(&svc_rdma_log_last, &svc_rdma_log_pps, 5))
			printf("nfsrdma: rdma_reject failed: %d\n", rc);
		return (ECONNREFUSED);

	case RDMA_CM_EVENT_DISCONNECTED:
		printf("nfsrdma: DISCONNECTED\n");
		return (0);

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/*
		 * The underlying device is going away.  Exactly ONE party must
		 * rdma_destroy_id() this id: either us-via-the-CM-core (by
		 * returning nonzero here -- cma_process_remove() ->
		 * cma_remove_id_dev() in ib_cma.c calls rdma_destroy_id() iff
		 * the handler returns nonzero) or svc_rdma_listen_stop().
		 * rdma_destroy_id() is NOT idempotent (it cma_exch()es to
		 * DESTROYING and unconditionally kfree()s id_priv), so a double
		 * call is a use-after-free.
		 *
		 * sl_id is the single ownership token, mutated only under
		 * sl_lock.  Whoever NULLs it owns the destroy:
		 *   - If id == sl_id here, WE take ownership (NULL it) and
		 *     return nonzero so the core destroys it now, while cma_dev
		 *     is still alive.  A later listen_stop() sees sl_id == NULL
		 *     and does nothing.
		 *   - If id != sl_id, listen_stop() already claimed this id and
		 *     will rdma_destroy_id() it; we return 0 so the core does
		 *     NOT also destroy it.  This is leak/hang-free: the id holds
		 *     a cma_device reference until that destroy calls
		 *     cma_release_dev(), and cma_remove_one() blocks on
		 *     wait_for_completion(&cma_dev->comp) until that reference
		 *     drops -- so cma_dev is never freed under the pending
		 *     destroy, and the device-removal completes once
		 *     listen_stop() finishes.
		 * The two sl_lock critical sections (here and in listen_stop())
		 * are serialized, so ownership is unambiguous.  We never call
		 * rdma_destroy_id() ourselves from the callback (forbidden
		 * reentrant destroy of the passed-in id).
		 */
		mtx_lock(&svc_rdma_listener.sl_lock);
		owned = (id == svc_rdma_listener.sl_id);
		if (owned) {
			svc_rdma_listener.sl_id = NULL;
			svc_rdma_listen_port = 0;
		}
		mtx_unlock(&svc_rdma_listener.sl_lock);
		if (owned) {
			printf("nfsrdma: DEVICE_REMOVAL, destroying listener\n");
			return (ECONNABORTED);
		}
		return (0);

	default:
		/* Logged at debug only; do not flood for benign events. */
		if (bootverbose)
			printf("nfsrdma: CM event %u\n", event->event);
		return (0);
	}
}

/*
 * Bring up the passive listener on the wildcard AF_INET address and the given
 * (host-order) port.  Leak-free unwind: any failure destroys the cm_id we
 * created and leaves sl_id NULL.  Idempotent-safe against double start: a
 * second start while one is up is rejected (EBUSY) rather than leaking the
 * first cm_id.
 *
 * Returns a POSITIVE errno on failure.  The FreeBSD rdma_*() helpers return
 * NEGATIVE Linux errnos (rdma_bind_addr/rdma_listen, ib_cma.c), and
 * rdma_create_id reports via ERR_PTR; this function normalizes all of them to
 * positive so callers (the sysctl below, and the future SVCXPRT wiring) get a
 * conventional FreeBSD errno.
 */
int
svc_rdma_listen_start(uint16_t port)
{
	struct sockaddr_in sin;
	struct rdma_cm_id *id;
	int rc;

	if (port == 0)
		return (EINVAL);

	mtx_lock(&svc_rdma_listener.sl_lock);
	if (svc_rdma_listener.sl_id != NULL) {
		mtx_unlock(&svc_rdma_listener.sl_lock);
		return (EBUSY);
	}
	mtx_unlock(&svc_rdma_listener.sl_lock);

	/*
	 * &init_net is the default vnet (vnet0); the in-tree server-side users
	 * (e.g. sdp_main.c) pass it to rdma_create_id().  RDMA_PS_TCP / IB_QPT_RC
	 * match the iWARP/RoCE/IB RC transport NFS-over-RDMA uses.
	 */
	id = rdma_create_id(&init_net, svc_rdma_cm_event_handler,
	    &svc_rdma_listener, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id)) {
		rc = -PTR_ERR(id);
		printf("nfsrdma: rdma_create_id failed: %d\n", rc);
		return (rc != 0 ? rc : EINVAL);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);

	rc = rdma_bind_addr(id, (struct sockaddr *)&sin);
	if (rc != 0) {
		printf("nfsrdma: rdma_bind_addr(port %u) failed: %d\n",
		    port, rc);
		goto out_destroy;
	}

	/*
	 * Modest backlog; this is just to observe inbound requests in 3a.  The
	 * value is tuned with the real accept path in a later increment.
	 */
	rc = rdma_listen(id, 8);
	if (rc != 0) {
		printf("nfsrdma: rdma_listen(port %u) failed: %d\n", port, rc);
		goto out_destroy;
	}

	mtx_lock(&svc_rdma_listener.sl_lock);
	if (svc_rdma_listener.sl_id != NULL) {
		/* Lost a start race; drop ours rather than overwrite/leak. */
		mtx_unlock(&svc_rdma_listener.sl_lock);
		rc = EBUSY;
		goto out_destroy;
	}
	svc_rdma_listener.sl_id = id;
	/* Publish the port under the same lock that guards sl_id (NIT). */
	svc_rdma_listen_port = port;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	printf("nfsrdma: listening on port %u\n", port);
	return (0);

out_destroy:
	/*
	 * No cm_id is stored yet on this path, so this cannot double-free.
	 * Normalize the (possibly negative LinuxKPI) errno to positive; never
	 * return 0 from a failure path.
	 */
	rdma_destroy_id(id);
	rc = (rc < 0) ? -rc : rc;
	return (rc != 0 ? rc : EINVAL);
}

/*
 * Tear the listener down.  Safe vs an in-flight CONNECT_REQUEST: we detach the
 * stored pointer under the lock first, then rdma_destroy_id() the listener
 * outside the lock.  rdma_destroy_id() cancels in-flight asynchronous CM
 * operations associated with the id and does not return until the handler is
 * no longer running (verified in TASK_002), so no CONNECT_REQUEST can be in or
 * enter the handler for this listener after it returns.  Idempotent: a second
 * call (or unload after an explicit stop) finds sl_id NULL and does nothing.
 *
 * We must drop sl_lock before rdma_destroy_id(): the CM teardown can block, and
 * holding a non-sleepable mtx across it would be wrong; nothing else needs the
 * lock once we have unpublished the pointer.
 */
void
svc_rdma_listen_stop(void)
{
	struct rdma_cm_id *id;

	mtx_lock(&svc_rdma_listener.sl_lock);
	id = svc_rdma_listener.sl_id;
	svc_rdma_listener.sl_id = NULL;
	svc_rdma_listen_port = 0;	/* keep read-back in sync (NIT) */
	mtx_unlock(&svc_rdma_listener.sl_lock);

	if (id != NULL) {
		rdma_destroy_id(id);
		printf("nfsrdma: listener stopped\n");
	}
}

/*
 * ===========================================================================
 * TEMPORARY test scaffolding for TASK_003 (3a).
 *
 * vfs.nfsrdma.listen is an int knob: writing a nonzero value starts the
 * listener on that port; writing 0 stops it.  Reading reflects the port the
 * listener is up on (0 when down).  This exists ONLY to drive/observe the
 * listener by hand on the interop VM; it is to be REPLACED by the krpc
 * SVCXPRT + netconfig (rdma/rdma6) integration in TASK_003e and removed.
 * ===========================================================================
 */
static int
sysctl_nfsrdma_listen(SYSCTL_HANDLER_ARGS)
{
	int error, newport;

	/*
	 * Snapshot the current port under sl_lock so the read-back cannot be
	 * torn against a concurrent start/stop (NIT).  svc_rdma_listen_start()
	 * and svc_rdma_listen_stop() are the only writers and they keep the
	 * port in sync with sl_id under the same lock, so we do not write it
	 * here.
	 */
	mtx_lock(&svc_rdma_listener.sl_lock);
	newport = svc_rdma_listen_port;
	mtx_unlock(&svc_rdma_listener.sl_lock);

	error = sysctl_handle_int(oidp, &newport, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	/* Reject out-of-range port values from userspace. */
	if (newport < 0 || newport > 65535)
		return (EINVAL);

	if (newport == 0) {
		svc_rdma_listen_stop();
		return (0);
	}

	return (svc_rdma_listen_start((uint16_t)newport));
}
SYSCTL_PROC(_vfs_nfsrdma, OID_AUTO, listen,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW, NULL, 0,
    sysctl_nfsrdma_listen, "I",
    "TEMP (3a): nonzero port starts the RDMA listener, 0 stops it");

/*
 * Stop the listener at module unload (and at kernel shutdown for a built-in
 * GENERIC-OFED), before the CM core can go away, so no dangling cm_id is left
 * for a later teardown to destroy through freed CM state.  Safe even if the
 * listener was never started (sl_id NULL -> no-op).
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
 */
static void
svc_rdma_uninit(void *arg __unused)
{

	svc_rdma_listen_stop();
}
SYSUNINIT(svc_rdma_uninit, SI_SUB_OFED_MODINIT, SI_ORDER_FIFTH,
    svc_rdma_uninit, NULL);
