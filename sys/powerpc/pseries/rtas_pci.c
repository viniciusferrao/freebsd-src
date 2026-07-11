/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 Nathan Whitehorn
 * All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/rman.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_pci.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofwpci.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <machine/bus.h>
#include <machine/intr_machdep.h>
#include <machine/md_var.h>
#include <machine/pio.h>
#include <machine/resource.h>
#include <machine/rtas.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <powerpc/pseries/plpar_iommu.h>

#include "pcib_if.h"
#include "iommu_if.h"

/*
 * Device interface.
 */
static int		rtaspci_probe(device_t);
static int		rtaspci_attach(device_t);

/*
 * pcib interface.
 */
static u_int32_t	rtaspci_read_config(device_t, u_int, u_int, u_int,
			    u_int, int);
static void		rtaspci_write_config(device_t, u_int, u_int, u_int,
			    u_int, u_int32_t, int);
static int		rtaspci_alloc_msi(device_t, device_t, int, int, int *);
static int		rtaspci_release_msi(device_t, device_t, int, int *);
static int		rtaspci_alloc_msix(device_t, device_t, int *);
static int		rtaspci_release_msix(device_t, device_t, int);
static int		rtaspci_map_msi(device_t, device_t, int, uint64_t *,
			    uint32_t *);

/*
 * PAPR RTAS ibm,change-msi function numbers (PAPR 7.3.10.5.1, Linux
 * arch/powerpc/platforms/pseries/msi.c and QEMU hw/ppc/spapr_pci.c).
 * Function 0 queries the current allocation; releasing is a change call
 * that requests zero interrupts.  1 is the legacy request (plain MSI
 * only, the sole function on platforms without the /rtas
 * "ibm,change-msix-capable" property); 3 requests MSI, 4 requests MSI-X
 * and 5 requests 32-bit MSI, for devices whose MSI capability cannot
 * hold a 64-bit message address.  Function 5 is the only sound source
 * of a 32-bit-addressable message on msix-capable platforms; where such
 * a platform lacks it (QEMU), 32-bit-only devices get no MSI and fall
 * back to INTx (see rtaspci_msi_setup()).
 */
#define	RTASPCI_CHANGE_FN	1
#define	RTASPCI_CHANGE_MSI_FN	3
#define	RTASPCI_CHANGE_MSIX_FN	4
#define	RTASPCI_CHANGE_32MSI_FN	5

/*
 * MSI message window of QEMU's sPAPR PHB.  The hypervisor catches device
 * writes to this address and converts them into the XICS source number
 * carried in the message data.  See QEMU include/hw/pci-host/spapr.h
 * (SPAPR_PCI_MSI_WINDOW) and hw/ppc/spapr_pci.c (spapr_msi_setmsg()).
 * This is a QEMU implementation constant, not PAPR-architected; PowerVM
 * is untested (see rtaspci_map_msi).
 */
#define	RTASPCI_MSI_WINDOW	0x40000000000ULL

/*
 * Architectural upper bound on a single device's MSI-X vectors: the PCI MSI-X
 * table-size field is 11 bits (1..2048).  Used only as a sanity clamp on the
 * count we request from RTAS; the actual per-child state is sized from the
 * device's own MSI-X table and allocated dynamically (see rtaspci_msi).
 */
#define	RTASPCI_MAX_MSI_VECS	2048

/*
 * Number of times an RTAS call is retried while it reports busy, with a
 * 1 ms wait per retry (~100 ms total).  Extended-delay statuses suggesting
 * waits beyond that budget are treated as failure: these paths hold a
 * mutex and cannot sleep, and QEMU resolves busy well within the budget.
 */
#define	RTASPCI_RTAS_RETRIES	100

/*
 * Per-child MSI/MSI-X allocation state.  PAPR allocates all of a device's
 * MSI(-X) vectors in a single ibm,change-msi RTAS call, whereas the FreeBSD
 * pcib interface hands MSI-X messages out one at a time.  We perform the RTAS
 * allocation on the first request for a given child, query each vector's XICS
 * source, and hand the resulting FreeBSD IRQs out individually.  Entries are
 * allocated on demand and linked on the softc; the irqs[] and live[] arrays
 * are carved from the tail of the same allocation, sized to the actual RTAS
 * allocation.  live[i] tracks whether irqs[i] is currently handed out, so
 * release can be matched to a specific IRQ and the RTAS allocation freed only
 * once every vector has been released.
 */
struct rtaspci_msi {
	SLIST_ENTRY(rtaspci_msi) link;
	device_t	child;
	bool		is_msix;
	int		fn;		/* ibm,change-msi function used */
	int		count;		/* vectors allocated from RTAS */
	int		nlive;		/* vectors currently handed out */
	int		*irqs;		/* [count] FreeBSD IRQs (tail of *m) */
	bool		*live;		/* [count] handed-out (tail of *m) */
};

MALLOC_DEFINE(M_RTASPCI_MSI, "rtaspci_msi", "PAPR RTAS PCI MSI state");

/*
 * Driver methods.
 */
static device_method_t	rtaspci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		rtaspci_probe),
	DEVMETHOD(device_attach,	rtaspci_attach),

	/* pcib interface */
	DEVMETHOD(pcib_read_config,	rtaspci_read_config),
	DEVMETHOD(pcib_write_config,	rtaspci_write_config),
	DEVMETHOD(pcib_alloc_msi,	rtaspci_alloc_msi),
	DEVMETHOD(pcib_release_msi,	rtaspci_release_msi),
	DEVMETHOD(pcib_alloc_msix,	rtaspci_alloc_msix),
	DEVMETHOD(pcib_release_msix,	rtaspci_release_msix),
	DEVMETHOD(pcib_map_msi,		rtaspci_map_msi),

	DEVMETHOD_END
};

struct rtaspci_softc {
	struct ofw_pci_softc	pci_sc;

	struct ofw_pci_register	sc_pcir;

	cell_t			read_pci_config, write_pci_config;
	cell_t			ex_read_pci_config, ex_write_pci_config;
	int			sc_extended_config;

	/* MSI/MSI-X support via RTAS ibm,change-msi. */
	cell_t			sc_change_msi;
	cell_t			sc_query_msi;
	bool			sc_msix_capable;
	uint32_t		sc_msi_xref;	/* XICS PIC node xref */
	struct mtx		sc_msi_mtx;
	SLIST_HEAD(, rtaspci_msi) sc_msi_list;
};

DEFINE_CLASS_1(pcib, rtaspci_driver, rtaspci_methods,
    sizeof(struct rtaspci_softc), ofw_pcib_driver);
DRIVER_MODULE(rtaspci, ofwbus, rtaspci_driver, 0, 0);

static int
rtaspci_probe(device_t dev)
{
	const char	*type;

	if (!rtas_exists())
		return (ENXIO);

	type = ofw_bus_get_type(dev);

	if (OF_getproplen(ofw_bus_get_node(dev), "used-by-rtas") < 0)
		return (ENXIO);
	if (type == NULL || strcmp(type, "pci") != 0)
		return (ENXIO);

	device_set_desc(dev, "RTAS Host-PCI bridge");
	return (BUS_PROBE_GENERIC);
}

static int
rtaspci_attach(device_t dev)
{
	struct		rtaspci_softc *sc;
	phandle_t	rtas_node;
	int		error;

	sc = device_get_softc(dev);

	if (OF_getencprop(ofw_bus_get_node(dev), "reg", (pcell_t *)&sc->sc_pcir,
	    sizeof(sc->sc_pcir)) == -1)
		return (ENXIO);

	sc->read_pci_config = rtas_token_lookup("read-pci-config");
	sc->write_pci_config = rtas_token_lookup("write-pci-config");
	sc->ex_read_pci_config = rtas_token_lookup("ibm,read-pci-config");
	sc->ex_write_pci_config = rtas_token_lookup("ibm,write-pci-config");

	sc->sc_extended_config = 0;
	OF_getencprop(ofw_bus_get_node(dev), "ibm,pci-config-space-type",
	    &sc->sc_extended_config, sizeof(sc->sc_extended_config));

	/*
	 * Look up the RTAS methods used for PAPR MSI/MSI-X allocation.  These
	 * are optional: if absent (-1) the alloc methods below fail gracefully
	 * and the device falls back to no MSI support.
	 */
	sc->sc_change_msi = rtas_token_lookup("ibm,change-msi");
	sc->sc_query_msi =
	    rtas_token_lookup("ibm,query-interrupt-source-number");
	/*
	 * Without this property only the legacy ibm,change-msi function 1
	 * (plain MSI) is valid; the explicit functions 3/4/5 need it.
	 */
	rtas_node = OF_finddevice("/rtas");
	sc->sc_msix_capable = (rtas_node != -1 &&
	    OF_hasprop(rtas_node, "ibm,change-msix-capable"));
	sc->sc_msi_xref = 0;
	mtx_init(&sc->sc_msi_mtx, "rtaspci_msi", NULL, MTX_DEF);
	SLIST_INIT(&sc->sc_msi_list);

	error = ofw_pcib_attach(dev);
	if (error != 0)
		mtx_destroy(&sc->sc_msi_mtx);
	return (error);
}

/*
 * Resolve the xref of the XICS interrupt controller (the system root PIC).
 * The hardware interrupt numbers returned by ibm,change-msi are XICS source
 * numbers, which are mapped to FreeBSD IRQs through this PIC.  root_pic is
 * not set up until BUS_PASS_INTERRUPT, hence the lazy resolution here.
 */
static uint32_t
rtaspci_msi_xref(struct rtaspci_softc *sc)
{
	if (sc->sc_msi_xref == 0 && root_pic != NULL)
		sc->sc_msi_xref =
		    OF_xref_from_node(ofw_bus_get_node(root_pic));

	return (sc->sc_msi_xref);
}

/*
 * Issue an ibm,change-msi RTAS call, requesting num_irqs of the given type
 * (RTASPCI_CHANGE_MSI_FN or RTASPCI_CHANGE_MSIX_FN) for the device at
 * config_addr.  Returns the number of interrupts the platform actually
 * allocated, or a negative value on failure.  num_irqs == 0 releases all of
 * the device's MSIs.
 *
 * RTAS leaves its status in the first return cell; rtas_call_method() returns
 * a negative value only on a call-mechanism (machine-check) failure.  Busy /
 * extended-delay status is retried with a short backoff.
 */
static int
rtaspci_change_msi(struct rtaspci_softc *sc, uint32_t config_addr, int fn,
    int num_irqs)
{
	cell_t status, retirqs, seq;
	int i, result;

	seq = 1;
	for (i = 0; i < RTASPCI_RTAS_RETRIES; i++) {
		status = 0;
		retirqs = 0;
		result = rtas_call_method(sc->sc_change_msi, 6, 3, config_addr,
		    sc->sc_pcir.phys_hi, sc->sc_pcir.phys_mid, fn, num_irqs,
		    seq, &status, &retirqs, &seq);
		if (result < 0)
			return (-1);
		if (rtas_status_busy(status)) {
			DELAY(1000);
			continue;
		}
		if (status != RTAS_OK)
			return (-1);
		return (retirqs);
	}

	return (-1);
}

/*
 * Query the XICS hardware interrupt (source) number for the given MSI vector
 * index (ioa_intr_number) of the device at config_addr.  Busy / extended-delay
 * status is retried with the same backoff as ibm,change-msi.
 */
static int
rtaspci_query_msi_irq(struct rtaspci_softc *sc, uint32_t config_addr,
    int index)
{
	cell_t status, hwirq, trig;
	int i, result;

	for (i = 0; i < RTASPCI_RTAS_RETRIES; i++) {
		status = 0;
		hwirq = 0;
		trig = 0;
		result = rtas_call_method(sc->sc_query_msi, 4, 3, config_addr,
		    sc->sc_pcir.phys_hi, sc->sc_pcir.phys_mid, index,
		    &status, &hwirq, &trig);
		if (result < 0)
			return (-1);
		if (rtas_status_busy(status)) {
			DELAY(1000);
			continue;
		}
		if (status != RTAS_OK)
			return (-1);
		return (hwirq);
	}

	return (-1);
}

/*
 * Compute the PAPR config address of a child PCI device: the OFW phys.hi
 * word (bus/dev/func), matching the addressing used by ibm,read-pci-config
 * above.
 */
static uint32_t
rtaspci_child_config_addr(device_t child)
{
	return ((pci_get_bus(child) << OFW_PCI_PHYS_HI_BUSSHIFT) |
	    (pci_get_slot(child) << OFW_PCI_PHYS_HI_DEVICESHIFT) |
	    (pci_get_function(child) << OFW_PCI_PHYS_HI_FUNCTIONSHIFT));
}

/*
 * Find the MSI allocation state for a child, or NULL.  Caller holds
 * sc_msi_mtx.
 */
static struct rtaspci_msi *
rtaspci_msi_find(struct rtaspci_softc *sc, device_t child)
{
	struct rtaspci_msi *m;

	mtx_assert(&sc->sc_msi_mtx, MA_OWNED);

	SLIST_FOREACH(m, &sc->sc_msi_list, link)
		if (m->child == child)
			return (m);

	return (NULL);
}

/*
 * Release a child's entire RTAS MSI allocation (a change call requesting
 * zero interrupts), reporting a failure instead of silently diverging
 * from the platform.
 */
static void
rtaspci_msi_rollback(struct rtaspci_softc *sc, device_t child,
    uint32_t config_addr, int fn)
{
	if (rtaspci_change_msi(sc, config_addr, fn, 0) < 0)
		device_printf(child, "ibm,change-msi release failed; "
		    "interrupt sources may remain allocated\n");
}

/*
 * Release a child's RTAS MSI allocation, unlink it, and free its state.
 * Caller holds sc_msi_mtx.  The entry and its irqs[]/live[] arrays are one
 * allocation (see rtaspci_msi_setup), so a single free() suffices.
 */
static void
rtaspci_msi_free(struct rtaspci_softc *sc, struct rtaspci_msi *m)
{
	mtx_assert(&sc->sc_msi_mtx, MA_OWNED);

	rtaspci_msi_rollback(sc, m->child,
	    rtaspci_child_config_addr(m->child), m->fn);
	SLIST_REMOVE(&sc->sc_msi_list, m, rtaspci_msi, link);
	free(m, M_RTASPCI_MSI);
}

/*
 * Perform the RTAS allocation for a child's MSI/MSI-X vectors (if not already
 * done) and map them to FreeBSD IRQs.  Per-vector state is sized to the actual
 * allocation and linked on the softc.  Caller holds sc_msi_mtx.
 */
static int
rtaspci_msi_setup(struct rtaspci_softc *sc, device_t child, bool is_msix,
    int want)
{
	struct rtaspci_msi *m;
	uint32_t config_addr, xref;
	uint16_t ctrl;
	int alloc, cap, fn, hwirq, i, req;

	mtx_assert(&sc->sc_msi_mtx, MA_OWNED);

	xref = rtaspci_msi_xref(sc);
	if (xref == 0)
		return (ENXIO);

	/* Already set up for this child? */
	m = rtaspci_msi_find(sc, child);
	if (m != NULL)
		return (m->is_msix == is_msix ? 0 : ENXIO);

	if (want < 1 || want > RTASPCI_MAX_MSI_VECS)
		return (EINVAL);

	config_addr = rtaspci_child_config_addr(child);
	if (is_msix) {
		if (!sc->sc_msix_capable)
			return (ENODEV);
		fn = RTASPCI_CHANGE_MSIX_FN;
	} else if (!sc->sc_msix_capable) {
		/*
		 * A backlevel platform without "ibm,change-msix-capable"
		 * implements only the legacy function, which requests plain
		 * MSI and programs a message compatible with the device's
		 * capability; rtaspci_map_msi() reads that message back.
		 */
		fn = RTASPCI_CHANGE_FN;
	} else {
		/*
		 * A device whose MSI capability cannot hold a 64-bit message
		 * address needs the 32-bit variant of ibm,change-msi so the
		 * platform assigns an address the device can generate.
		 */
		if (pci_find_cap(child, PCIY_MSI, &cap) != 0)
			return (ENODEV);
		ctrl = pci_read_config(child, cap + PCIR_MSI_CTRL, 2);
		fn = (ctrl & PCIM_MSICTRL_64BIT) ? RTASPCI_CHANGE_MSI_FN :
		    RTASPCI_CHANGE_32MSI_FN;
	}

	req = want;
	alloc = rtaspci_change_msi(sc, config_addr, fn, req);
	if (alloc < 0 && fn == RTASPCI_CHANGE_32MSI_FN) {
		/*
		 * The platform does not implement the 32-bit variant (QEMU
		 * does not).  A plain function-3 allocation is no substitute:
		 * it assigns a message address above 4 GiB (QEMU's MSI window
		 * is 0x40000000000) that a 32-bit-only capability can neither
		 * hold -- the address truncates to zero in the capability --
		 * nor generate.  Refuse, so the device falls back to INTx.
		 */
		return (ENXIO);
	}
	/*
	 * Re-request a smaller-than-requested successful return until the
	 * call is satisfied verbatim; the count strictly decreases, so
	 * this terminates.  QEMU returns the corrected count without
	 * assigning and expects the guest to ask again (Linux retries the
	 * same way), but PAPR defines a short successful return as the
	 * number of interrupts actually assigned -- so if a retry then
	 * fails, release whatever the prior call may have assigned rather
	 * than leak it.
	 */
	while (alloc > 0 && alloc < req) {
		req = alloc;
		alloc = rtaspci_change_msi(sc, config_addr, fn, req);
	}
	if (alloc <= 0) {
		if (req != want)
			rtaspci_msi_rollback(sc, child, config_addr, fn);
		return (ENXIO);
	}
	alloc = MIN(alloc, req);
	/*
	 * MSI needs exactly 'want' vectors; a short allocation cannot
	 * satisfy it, so roll the RTAS allocation back rather than leave a
	 * partial one live.  (MSI-X messages are handed out one at a time,
	 * so a short allocation there is acceptable -- fewer messages
	 * available.)  PAPR does not promise contiguous interrupt source
	 * numbers, so each vector's source is queried individually below;
	 * multi-message MSI hardware ORs the vector index into the message
	 * data, which constrains what a platform granting count > 1 can
	 * hand out (see rtaspci_map_msi()).
	 */
	if (!is_msix && alloc < want) {
		rtaspci_msi_rollback(sc, child, config_addr, fn);
		return (ENXIO);
	}

	/*
	 * One allocation holds the entry and both per-vector arrays
	 * (irqs[] then live[] in the tail), so teardown is a single free()
	 * and there is no partial-allocation state to unwind.
	 */
	m = malloc(sizeof(*m) + alloc * sizeof(*m->irqs) +
	    alloc * sizeof(*m->live), M_RTASPCI_MSI, M_NOWAIT | M_ZERO);
	if (m == NULL) {
		rtaspci_msi_rollback(sc, child, config_addr, fn);
		return (ENOMEM);
	}
	m->irqs = (int *)(m + 1);
	m->live = (bool *)(m->irqs + alloc);

	for (i = 0; i < alloc; i++) {
		hwirq = rtaspci_query_msi_irq(sc, config_addr, i);
		if (hwirq < 0) {
			rtaspci_msi_rollback(sc, child, config_addr, fn);
			free(m, M_RTASPCI_MSI);
			return (ENXIO);
		}
		m->irqs[i] = MAP_IRQ(xref, hwirq);
	}

	/*
	 * PAPR permits noncontiguous interrupt source numbers, but
	 * FreeBSD's MSI consumers -- LinuxKPI in particular fabricates a
	 * device's vectors as irq_start + i and claims that whole interval
	 * -- assume the contiguous blocks every other platform allocator
	 * hands out.  Refuse a sparse allocation rather than let
	 * interleaved intervals misroute another device's interrupts; the
	 * device falls back to INTx.  (QEMU always allocates contiguous
	 * blocks, so this triggers only on platforms that exercise the
	 * PAPR allowance.)
	 */
	for (i = 1; i < alloc; i++) {
		if (m->irqs[i] != m->irqs[0] + i) {
			device_printf(child, "noncontiguous MSI sources "
			    "from the platform; refusing allocation\n");
			rtaspci_msi_rollback(sc, child, config_addr, fn);
			free(m, M_RTASPCI_MSI);
			return (ENXIO);
		}
	}

	m->child = child;
	m->is_msix = is_msix;
	m->fn = fn;
	m->count = alloc;
	SLIST_INSERT_HEAD(&sc->sc_msi_list, m, link);

	return (0);
}

static uint32_t
rtaspci_read_config(device_t dev, u_int bus, u_int slot, u_int func, u_int reg,
    int width)
{
	struct rtaspci_softc *sc;
	uint32_t retval = 0xffffffff;
	uint32_t config_addr;
	int error, pcierror;

	sc = device_get_softc(dev);

	config_addr = ((bus & 0xff) << 16) | ((slot & 0x1f) << 11) |
	    ((func & 0x7) << 8) | (reg & 0xff);
	if (sc->sc_extended_config)
		config_addr |= (reg & 0xf00) << 16;

	if (sc->ex_read_pci_config != -1)
		error = rtas_call_method(sc->ex_read_pci_config, 4, 2,
		    config_addr, sc->sc_pcir.phys_hi,
		    sc->sc_pcir.phys_mid, width, &pcierror, &retval);
	else
		error = rtas_call_method(sc->read_pci_config, 2, 2,
		    config_addr, width, &pcierror, &retval);

	/* Sign-extend output */
	switch (width) {
	case 1:
		retval = (int32_t)(int8_t)(retval);
		break;
	case 2:
		retval = (int32_t)(int16_t)(retval);
		break;
	}

	if (error < 0 || pcierror != 0)
		retval = 0xffffffff;

	return (retval);
}

static void
rtaspci_write_config(device_t dev, u_int bus, u_int slot, u_int func,
    u_int reg, uint32_t val, int width)
{
	struct rtaspci_softc *sc;
	uint32_t config_addr;
	int pcierror;

	sc = device_get_softc(dev);

	config_addr = ((bus & 0xff) << 16) | ((slot & 0x1f) << 11) |
	    ((func & 0x7) << 8) | (reg & 0xff);
	if (sc->sc_extended_config)
		config_addr |= (reg & 0xf00) << 16;

	if (sc->ex_write_pci_config != -1)
		rtas_call_method(sc->ex_write_pci_config, 5, 1, config_addr,
		    sc->sc_pcir.phys_hi, sc->sc_pcir.phys_mid,
		    width, val, &pcierror);
	else
		rtas_call_method(sc->write_pci_config, 3, 1, config_addr,
		    width, val, &pcierror);
}

/*
 * MSI/MSI-X allocation via the PAPR RTAS ibm,change-msi mechanism.
 *
 * The FreeBSD pcib interface allocates MSI-X messages one at a time, while
 * PAPR allocates all of a device's vectors in a single RTAS call (and a
 * subsequent ibm,change-msi for the same device replaces the prior
 * allocation).  We bridge this by performing the RTAS allocation on the
 * first message request for a given child (sized to the device's MSI-X
 * table, which is the most messages the PCI layer can ask for) and handing
 * the resulting interrupts out one at a time on subsequent calls.
 */

static int
rtaspci_alloc_msix(device_t dev, device_t child, int *irq)
{
	struct rtaspci_softc *sc = device_get_softc(dev);
	struct rtaspci_msi *m;
	int error, msgnum, i;

	if (sc->sc_change_msi == -1 || sc->sc_query_msi == -1)
		return (ENODEV);

	/*
	 * Size the request to the device's MSI-X table.  The pcib interface
	 * hands vectors out one at a time with no up-front total, and a
	 * later ibm,change-msi call REPLACES the device's existing
	 * allocation (renumbering live vectors), so the whole table is
	 * reserved on first use -- the same bridge arm64's gicv3_its uses
	 * for the identical interface mismatch.
	 */
	msgnum = pci_msix_count(child);
	if (msgnum == 0)
		return (ENODEV);

	mtx_lock(&sc->sc_msi_mtx);
	error = rtaspci_msi_setup(sc, child, true, msgnum);
	if (error != 0) {
		mtx_unlock(&sc->sc_msi_mtx);
		return (error);
	}

	/* Hand out the lowest-numbered vector that is not currently in use. */
	m = rtaspci_msi_find(sc, child);
	if (m != NULL) {
		for (i = 0; i < m->count; i++) {
			if (!m->live[i]) {
				m->live[i] = true;
				m->nlive++;
				*irq = m->irqs[i];
				mtx_unlock(&sc->sc_msi_mtx);
				return (0);
			}
		}
	}
	mtx_unlock(&sc->sc_msi_mtx);

	return (ENOSPC);
}

static int
rtaspci_release_msix(device_t dev, device_t child, int irq)
{
	struct rtaspci_softc *sc = device_get_softc(dev);
	struct rtaspci_msi *m;
	int i;

	mtx_lock(&sc->sc_msi_mtx);
	m = rtaspci_msi_find(sc, child);
	if (m == NULL) {
		mtx_unlock(&sc->sc_msi_mtx);
		return (ENXIO);
	}

	/* Match the specific IRQ being released against the handed-out set. */
	for (i = 0; i < m->count; i++)
		if (m->irqs[i] == irq && m->live[i])
			break;
	if (i == m->count) {
		mtx_unlock(&sc->sc_msi_mtx);
		return (EINVAL);
	}
	m->live[i] = false;
	m->nlive--;

	/* Once every vector is released, free the RTAS allocation. */
	if (m->nlive == 0)
		rtaspci_msi_free(sc, m);
	mtx_unlock(&sc->sc_msi_mtx);

	return (0);
}

static int
rtaspci_alloc_msi(device_t dev, device_t child, int count, int maxcount,
    int *irqs)
{
	struct rtaspci_softc *sc = device_get_softc(dev);
	struct rtaspci_msi *m;
	int error, i;

	if (sc->sc_change_msi == -1 || sc->sc_query_msi == -1)
		return (ENODEV);

	mtx_lock(&sc->sc_msi_mtx);
	error = rtaspci_msi_setup(sc, child, false, count);
	if (error != 0) {
		mtx_unlock(&sc->sc_msi_mtx);
		return (error);
	}

	m = rtaspci_msi_find(sc, child);
	if (m == NULL || m->count < count) {
		mtx_unlock(&sc->sc_msi_mtx);
		return (ENOSPC);
	}

	/* MSI hands out the whole contiguous block at once. */
	for (i = 0; i < count; i++) {
		irqs[i] = m->irqs[i];
		m->live[i] = true;
	}
	m->nlive = count;
	mtx_unlock(&sc->sc_msi_mtx);

	return (0);
}

static int
rtaspci_release_msi(device_t dev, device_t child, int count, int *irqs)
{
	struct rtaspci_softc *sc = device_get_softc(dev);
	struct rtaspci_msi *m;

	mtx_lock(&sc->sc_msi_mtx);
	m = rtaspci_msi_find(sc, child);
	if (m != NULL)
		rtaspci_msi_free(sc, m);
	mtx_unlock(&sc->sc_msi_mtx);

	return (0);
}

/*
 * Return the MSI message address/data the child must program into its
 * MSI/MSI-X capability.
 *
 * MSI-X: the platform owns the message and the table write is suppressed
 * (see plpar_pcibus_enable_msix()); return the sPAPR MSI window address
 * and the XICS source number so the PCI layer's bookkeeping matches what
 * the hypervisor decodes.
 *
 * Plain MSI: the platform programmed the device's MSI capability while
 * servicing ibm,change-msi, and config space is RTAS-mediated, so read
 * the message back and return it.  The PCI layer's writeback then
 * preserves the platform's message verbatim -- correct for 32-bit and
 * 64-bit capabilities alike, and independent of any QEMU-specific window
 * constant.  Vector i of a multi-vector MSI block uses the base data
 * plus i, matching how multi-message MSI hardware derives per-vector
 * data; PAPR does not promise contiguous source numbers, so the
 * per-vector IRQs themselves come from individual queries.
 */
static int
rtaspci_map_msi(device_t dev, device_t child, int irq, uint64_t *addr,
    uint32_t *data)
{
	struct rtaspci_softc *sc = device_get_softc(dev);
	struct rtaspci_msi *m;
	uint32_t xref;
	uint16_t ctrl;
	bool is_msix;
	int cap, count, i;

	xref = rtaspci_msi_xref(sc);
	if (xref == 0)
		return (ENXIO);

	mtx_lock(&sc->sc_msi_mtx);
	m = rtaspci_msi_find(sc, child);
	if (m == NULL) {
		mtx_unlock(&sc->sc_msi_mtx);
		return (ENXIO);
	}
	is_msix = m->is_msix;
	count = m->count;
	for (i = 0; i < count; i++)
		if (m->irqs[i] == irq)
			break;
	mtx_unlock(&sc->sc_msi_mtx);

	if (is_msix) {
		*addr = RTASPCI_MSI_WINDOW;
		*data = irq - MAP_IRQ(xref, 0);
		return (0);
	}

	if (i == count)
		return (EINVAL);
	if (pci_find_cap(child, PCIY_MSI, &cap) != 0)
		return (ENXIO);
	ctrl = pci_read_config(child, cap + PCIR_MSI_CTRL, 2);
	*addr = pci_read_config(child, cap + PCIR_MSI_ADDR, 4);
	if (ctrl & PCIM_MSICTRL_64BIT) {
		*addr |= (uint64_t)pci_read_config(child,
		    cap + PCIR_MSI_ADDR_HIGH, 4) << 32;
		*data = pci_read_config(child, cap + PCIR_MSI_DATA_64BIT, 2);
	} else
		*data = pci_read_config(child, cap + PCIR_MSI_DATA, 2);
	*data += i;

	return (0);
}
