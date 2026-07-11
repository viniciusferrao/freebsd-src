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
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/module.h>
#include <sys/pciio.h>

#include <dev/ofw/openfirm.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pci_private.h>

#include <machine/bus.h>
#include <machine/rtas.h>

#include <powerpc/ofw/ofw_pcibus.h>
#include <powerpc/pseries/plpar_iommu.h>

#include "pci_if.h"
#include "iommu_if.h"

static int		plpar_pcibus_probe(device_t);
static bus_dma_tag_t	plpar_pcibus_get_dma_tag(device_t dev, device_t child);
static void		plpar_pcibus_enable_msix(device_t dev, device_t child,
			    u_int index, uint64_t address, uint32_t data);

/*
 * Driver methods.
 */
static device_method_t	plpar_pcibus_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		plpar_pcibus_probe),

	/* PCI interface */
	DEVMETHOD(pci_enable_msix,	plpar_pcibus_enable_msix),

	/* IOMMU functions */
	DEVMETHOD(bus_get_dma_tag,	plpar_pcibus_get_dma_tag),
	DEVMETHOD(iommu_map,		phyp_iommu_map),
	DEVMETHOD(iommu_unmap,		phyp_iommu_unmap),

	DEVMETHOD_END
};

DEFINE_CLASS_1(pci, plpar_pcibus_driver, plpar_pcibus_methods,
    sizeof(struct pci_softc), ofw_pcibus_driver);
DRIVER_MODULE(plpar_pcibus, pcib, plpar_pcibus_driver, 0, 0);

static int
plpar_pcibus_probe(device_t dev)
{
	phandle_t rtas;

	if (ofw_bus_get_node(dev) == -1 || !rtas_exists())
		return (ENXIO);

	rtas = OF_finddevice("/rtas");
	if (!OF_hasprop(rtas, "ibm,hypertas-functions"))
		return (ENXIO);

	device_set_desc(dev, "POWER Hypervisor PCI bus");

	return (BUS_PROBE_SPECIFIC);
}

static bus_dma_tag_t
plpar_pcibus_get_dma_tag(device_t dev, device_t child)
{
	struct ofw_pcibus_devinfo *dinfo;

	while (device_get_parent(child) != dev)
		child = device_get_parent(child);

	dinfo = device_get_ivars(child);

	if (dinfo->opd_dma_tag != NULL)
		return (dinfo->opd_dma_tag);

	bus_dma_tag_create(bus_get_dma_tag(dev),
	    1, 0, BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
	    NULL, NULL, BUS_SPACE_MAXSIZE, BUS_SPACE_UNRESTRICTED,
	    BUS_SPACE_MAXSIZE, 0, NULL, NULL, &dinfo->opd_dma_tag);
	phyp_iommu_set_dma_tag(dev, child, dinfo->opd_dma_tag);

	return (dinfo->opd_dma_tag);
}

/*
 * Program a child's MSI-X message into the device.
 *
 * Under PAPR the hypervisor owns the device's MSI/MSI-X message: it programs
 * the (address, data) pair as part of ibm,change-msi (rtaspci_alloc_msix).
 * The generic PCI code, however, also writes the FreeBSD-side message --
 * the per-PHB sPAPR MSI window address plus the XICS source number -- into
 * the device's MSI-X table BAR via MMIO.  For an emulated device QEMU traps
 * that table and the write is harmless, but for a VFIO PCI passthrough
 * device (e.g. mlx5) the write reaches the real adapter's MSI-X table and
 * overwrites the host-programmed interrupt address with the guest window
 * address.  When the adapter firmware then raises an interrupt it DMA-writes
 * the MSI message to an address that is no longer the host-programmed one,
 * the adapter firmware wedges, and its MMIO reads return all-0xff.
 * (Observed on mlx5: the host PE itself does not freeze and there is no
 * host EEH event -- the fault is on the adapter side.)  Linux's pseries MSI
 * code likewise never writes the device MSI-X table.  Suppress the write
 * here; the generic code still unmasks the vector (pci_unmask_msix)
 * separately, so interrupt delivery set up by the hypervisor is unaffected.
 *
 * Consequence: because the device table is never written by the guest, the
 * hypervisor's index->source mapping fixed at ibm,change-msi is authoritative,
 * and pci_remap_msix() (which would reprogram table entries to rebalance
 * vectors) is NOT honored on this path.  No in-tree driver on this platform
 * remaps; a general implementation would need a pseries-specific remap policy
 * (or to reject a non-identity remap).
 */
static void
plpar_pcibus_enable_msix(device_t dev __unused, device_t child __unused,
    u_int index __unused, uint64_t address __unused, uint32_t data __unused)
{
}
