/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013, Nathan Whitehorn <nwhitehorn@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/vmem.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_pci.h>
#include <dev/ofw/openfirm.h>

#include <dev/pci/pcivar.h>

#include <machine/bus.h>
#include <machine/platform.h>
#include <machine/rtas.h>

#include <powerpc/pseries/phyp-hvcall.h>
#include <powerpc/pseries/plpar_iommu.h>

MALLOC_DEFINE(M_PHYPIOMMU, "iommu", "IOMMU data for PAPR LPARs");

struct papr_iommu_map {
	uint32_t iobn;
	vmem_t *vmem;
	struct papr_iommu_map *next;
};

static SLIST_HEAD(iommu_maps, iommu_map) iommu_map_head =
    SLIST_HEAD_INITIALIZER(iommu_map_head);
static int papr_supports_stuff_tce = -1;

struct iommu_map {
	uint32_t iobn;
	vmem_t *vmem;

	SLIST_ENTRY(iommu_map) entries;
};

struct dma_window {
	struct iommu_map *map;
	bus_addr_t start;
	bus_addr_t end;

	/*
	 * Direct-mapped Dynamic DMA Window (DDW): when set, the whole guest
	 * RAM is identity-mapped into a 64-bit window at dma_offset, so a DMA
	 * bus address is simply the physical address plus dma_offset and no
	 * per-transfer H_PUT_TCE is needed.  Required for VFIO PCI passthrough
	 * (e.g. mlx5), whose device DMA the default 32-bit window cannot reach.
	 * The legacy translated window below remains set up alongside it;
	 * phyp_iommu_map() uses the direct window only for mappings whose
	 * child tag constraints the high window address can satisfy.
	 */
	bool		direct;
	bus_addr_t	dma_offset;	/* 64-bit DDW window base */
	uint32_t	liobn;		/* DDW logical I/O bus number */
};

/*
 * Token indices in the PHB's "ibm,ddw-applicable" property (PAPR DDW option):
 * ibm,query-pe-dma-windows, ibm,create-pe-dma-window, ibm,remove-pe-dma-window.
 */
#define	DDW_QUERY_PE_DMA_WIN	0
#define	DDW_CREATE_PE_DMA_WIN	1
#define	DDW_REMOVE_PE_DMA_WIN	2

#define	DDW_TCE_RW		0x3	/* TCE_PCI_READ | TCE_PCI_WRITE */

/*
 * RTAS busy retries, 1 ms apart (~100 ms budget): these paths cannot
 * sleep, so longer extended delays are treated as failure.
 */
#define	PHYP_RTAS_RETRIES	100

/*
 * Largest I/O page shift we will request for a direct DDW.
 *
 * For a VFIO PCI passthrough device the hypervisor (QEMU) backs the guest's
 * DDW with the HOST IOMMU, whose TCE page size is the host's MMU page size
 * (64 KiB on a POWER9/POWER10 ppc64le host).  We populate the window with one
 * H_PUT_TCE per page-size stride (see phyp_iommu_setup_ddw), so the requested
 * page size must not exceed the host IOMMU page: the host maps in host-page
 * units, so a coarser guest page would leave the window only partially mapped
 * (host-page-sized chunks mapped, the rest of each stride a hole the device
 * cannot reach).  Cap at 64 KiB to match the host IOMMU exactly; an equal or
 * finer guest page is safe, a coarser one is not.
 */
#define	PHYP_DDW_MAX_SHIFT	16	/* 64 KiB: POWER VFIO host IOMMU page */

/*
 * Decode a PAPR/QEMU DDW page-size bitmask (as returned by
 * ibm,query-pe-dma-windows) into the largest supported I/O page shift that is
 * still no larger than the host IOMMU page (see PHYP_DDW_MAX_SHIFT).  The
 * table deliberately encodes the full architected mask, including sizes
 * above the cap, so a future cap change needs no table edit.
 */
static int
phyp_ddw_page_shift(uint32_t mask)
{
	static const struct {
		uint32_t bit;
		int	 shift;
	} sizes[] = {
		{ 0x80,  34 },	/* 16 GB */
		{ 0x40,  28 },	/* 256 MB */
		{ 0x20,  27 },	/* 128 MB */
		{ 0x10,  26 },	/* 64 MB */
		{ 0x08,  25 },	/* 32 MB */
		{ 0x04,  24 },	/* 16 MB */
		{ 0x100, 21 },	/* 2 MB */
		{ 0x02,  16 },	/* 64 KB */
		{ 0x01,  12 },	/* 4 KB */
	};
	u_int i;

	for (i = 0; i < nitems(sizes); i++)
		if ((mask & sizes[i].bit) &&
		    sizes[i].shift <= PHYP_DDW_MAX_SHIFT)
			return (sizes[i].shift);
	return (0);
}

/*
 * PAPR config address (BUS/DEV/FUNC) of a child PCI device, as the DDW
 * RTAS calls expect it.
 */
static uint32_t
phyp_pci_config_addr(device_t dev)
{
	return ((pci_get_bus(dev) << OFW_PCI_PHYS_HI_BUSSHIFT) |
	    (pci_get_slot(dev) << OFW_PCI_PHYS_HI_DEVICESHIFT) |
	    (pci_get_function(dev) << OFW_PCI_PHYS_HI_FUNCTIONSHIFT));
}

/*
 * Shared per-node DDW state.  A dynamic DMA window belongs to the PE/PHB
 * node it was created for and the platform limits how many windows a node
 * may have (QEMU permits a single DDW per PHB), so creation must happen
 * once per node and be reused by every device mapping through it -- Linux
 * keys its reuse list the same way.  The outcome of the attempt is cached
 * either way, so siblings do not repeat failing RTAS calls.  Like
 * iommu_map_head above, the list is only touched at device-attach time.
 */
struct phyp_ddw {
	SLIST_ENTRY(phyp_ddw) entries;
	phandle_t	node;
	bool		avail;
	uint32_t	liobn;
	uint64_t	base;
};

static SLIST_HEAD(, phyp_ddw) phyp_ddw_head =
    SLIST_HEAD_INITIALIZER(phyp_ddw_head);

/* PAPR caps a single H_STUFF_TCE call at 512 TCEs. */
#define	PHYP_STUFF_TCE_MAX	512

/*
 * Clear 'len' bytes worth of TCEs starting at I/O bus address 'ioba', in
 * checked H_STUFF_TCE batches of at most PHYP_STUFF_TCE_MAX entries (the
 * PAPR per-call cap), falling back to checked per-entry H_PUT_TCE.
 * Returns false if any entry could not be cleared.
 */
static bool
phyp_tce_clear(uint32_t liobn, uint64_t ioba, uint64_t len,
    int page_shift)
{
	uint64_t done, entries, n, off;

	entries = len >> page_shift;
	if (papr_supports_stuff_tce) {
		for (done = 0; done < entries; done += n) {
			n = MIN(entries - done,
			    (uint64_t)PHYP_STUFF_TCE_MAX);
			if (phyp_hcall(H_STUFF_TCE, (uint64_t)liobn,
			    ioba + (done << page_shift), 0, n) !=
			    H_SUCCESS)
				break;
		}
		if (done >= entries)
			return (true);
	}
	for (off = 0; off < len; off += (1ULL << page_shift))
		if (phyp_hcall(H_PUT_TCE, (uint64_t)liobn, ioba + off,
		    0) != H_SUCCESS)
			return (false);
	return (true);
}

/*
 * Tear down a (possibly partially populated) DDW.  PAPR requires that a
 * window contain no valid mappings before ibm,remove-pe-dma-window, so
 * clear the TCEs installed so far -- and leave the window in place with
 * a warning if that fails -- then remove with busy retry, reporting a
 * failed removal rather than silently stranding the window.
 */
static void
phyp_ddw_destroy(cell_t remove_tok, uint32_t liobn, uint64_t win_addr,
    uint64_t populated, int page_shift)
{
	cell_t st;
	int i;

	if (populated > 0 &&
	    !phyp_tce_clear(liobn, win_addr, populated, page_shift)) {
		printf("phyp_iommu: cannot clear DDW %#x; leaving the "
		    "window in place\n", liobn);
		return;
	}
	st = RTAS_HW_ERROR;
	for (i = 0; i < PHYP_RTAS_RETRIES; i++) {
		if (rtas_call_method(remove_tok, 1, 1, liobn, &st) < 0) {
			st = RTAS_HW_ERROR;
			break;
		}
		if (!rtas_status_busy(st))
			break;
		DELAY(1000);
	}
	if (st != RTAS_OK)
		printf("phyp_iommu: ibm,remove-pe-dma-window(%#x) failed: "
		    "%d\n", liobn, (int)st);
}

/*
 * Create a direct-mapped 64-bit DDW for the PE/PHB at 'node' and
 * identity-map it over all of RAM, mirroring what Linux/PowerVM do for
 * high-DMA / passthrough devices.  Returns true with the window's LIOBN
 * and base on success; false on any failure, with nothing left allocated.
 */
static bool
phyp_ddw_create(device_t dev, phandle_t node, uint64_t legacy_end,
    uint32_t *liobnp, uint64_t *basep)
{
	cell_t ddw_avail[3];
	cell_t ext[3];
	cell_t reg[2];
	cell_t st, wn, lb_hi, lb_lo, psmask, mig, liobn, addr_hi, addr_lo;
	struct mem_region *phys, *avail;
	uint64_t largest_block, win_addr, ramsize, pa;
	uint32_t cfg_addr, buid_hi, buid_lo;
	int page_shift, qout, rc, window_shift, i, r, nphys, navail;

	/* DDW tokens live in the PHB node, not the global RTAS list. */
	if (OF_getencprop(node, "ibm,ddw-applicable", ddw_avail,
	    sizeof(ddw_avail)) != (ssize_t)sizeof(ddw_avail))
		return (false);

	/* BUID hi/lo are the first two cells of the PHB "reg" property. */
	if (OF_getencprop(node, "reg", reg, sizeof(reg)) < (ssize_t)sizeof(reg))
		return (false);
	buid_hi = reg[0];
	buid_lo = reg[1];

	cfg_addr = phyp_pci_config_addr(dev);

	/*
	 * From LoPAR 2.8, "ibm,ddw-extensions" PAPR list index 3 -- that
	 * is ext[2] here, after the leading extension count and the reset
	 * entry -- rules how many outputs ibm,query-pe-dma-windows has: 5
	 * by default, or 6 (64-bit largest block) when the extension value
	 * is 1.  Requesting 6 outputs from firmware that implements
	 * only 5 is a parameter error, so parse either format, as Linux
	 * does.
	 */
	qout = 5;
	if (OF_getencprop(node, "ibm,ddw-extensions", ext, sizeof(ext)) >=
	    3 * (ssize_t)sizeof(cell_t) && ext[0] >= 2 && ext[2] == 1)
		qout = 6;

	st = wn = lb_hi = lb_lo = psmask = mig = 0;
	for (i = 0; i < PHYP_RTAS_RETRIES; i++) {
		if (qout == 6)
			rc = rtas_call_method(ddw_avail[DDW_QUERY_PE_DMA_WIN],
			    3, 6, cfg_addr, buid_hi, buid_lo, &st, &wn,
			    &lb_hi, &lb_lo, &psmask, &mig);
		else
			rc = rtas_call_method(ddw_avail[DDW_QUERY_PE_DMA_WIN],
			    3, 5, cfg_addr, buid_hi, buid_lo, &st, &wn,
			    &lb_lo, &psmask, &mig);
		if (rc < 0)
			return (false);
		if (!rtas_status_busy(st))
			break;
		DELAY(1000);
	}
	if (st != RTAS_OK || wn < 1)
		return (false);
	largest_block = (qout == 6) ?
	    (((uint64_t)lb_hi << 32) | lb_lo) : lb_lo;

	page_shift = phyp_ddw_page_shift(psmask);
	if (page_shift == 0)
		return (false);

	/*
	 * Size the window to span up to the highest assigned RAM address,
	 * taken from the same mem_regions() list the population loop below
	 * walks.  Do NOT size from Maxmem: it is derived from phys_avail,
	 * which excludes reserved RAM and so can fall below the top of the
	 * phys region list -- a window sized that way would be too small and
	 * the top TCE would overflow it (H_PARAMETER).  The window still
	 * spans the top assigned address even when lower ranges are holes;
	 * only the population is restricted to assigned RAM.
	 */
	mem_regions(&phys, &nphys, &avail, &navail);
	ramsize = 0;
	for (r = 0; r < nphys; r++) {
		uint64_t rend;

		rend = roundup2(phys[r].mr_start + phys[r].mr_size,
		    1ULL << page_shift);
		ramsize = MAX(ramsize, rend);
	}
	if (ramsize == 0)
		return (false);
	window_shift = flsll(ramsize - 1);
	window_shift = MAX(window_shift, page_shift);
	/* Direct mapping is only possible if the PE can map all of RAM. */
	if (largest_block < (1ULL << (window_shift - page_shift)))
		return (false);

	/* ibm,create-pe-dma-window: 5 in, 4 out. */
	st = liobn = addr_hi = addr_lo = 0;
	for (i = 0; i < PHYP_RTAS_RETRIES; i++) {
		if (rtas_call_method(ddw_avail[DDW_CREATE_PE_DMA_WIN], 5, 4,
		    cfg_addr, buid_hi, buid_lo, page_shift, window_shift,
		    &st, &liobn, &addr_hi, &addr_lo) < 0)
			return (false);
		if (!rtas_status_busy(st))
			break;
		DELAY(1000);
	}
	if (st != RTAS_OK)
		return (false);
	win_addr = ((uint64_t)addr_hi << 32) | addr_lo;

	/*
	 * phyp_iommu_unmap() classifies segments by address range, which
	 * requires the direct window to be disjoint from (above) the legacy
	 * one.  All real PAPR/QEMU firmware places DDWs far above it; refuse
	 * anything else rather than assume.
	 */
	if (win_addr <= legacy_end) {
		phyp_ddw_destroy(ddw_avail[DDW_REMOVE_PE_DMA_WIN], liobn,
		    win_addr, 0, page_shift);
		return (false);
	}

	/*
	 * Identity-map the assigned RAM into the window: bus address ==
	 * physical address + win_addr, so a mapping is just an offset add
	 * with no per-DMA hypercalls.  Populate only the platform's actual
	 * physical memory regions, NOT the whole 0..top span: a pseries
	 * partition may have holes below the top of RAM (independently assigned
	 * dynamic-reconfiguration LMBs), and H_PUT_TCE for an address
	 * outside the partition's assigned range returns H_PARAMETER.
	 * Leave the holes' TCEs invalid.  On failure roll back every TCE
	 * installed so far -- clearing the contiguous span up to the last
	 * address touched, which harmlessly rewrites the hole TCEs (already
	 * invalid) to invalid.
	 */
	for (r = 0; r < nphys; r++) {
		uint64_t rstart, rend;

		/*
		 * Round each region to the I/O page.  Real PAPR/QEMU LMB
		 * (hole) granularity (16 MiB and up) far exceeds any DDW
		 * page size, so rounding never crosses a true hole
		 * boundary; adjacent non-hole regions may round into mild
		 * overlap, which is harmless (H_PUT_TCE is idempotent).
		 */
		rstart = rounddown2(phys[r].mr_start, 1ULL << page_shift);
		rend = roundup2(phys[r].mr_start + phys[r].mr_size,
		    1ULL << page_shift);
		if (bootverbose)
			device_printf(dev, "DDW: mapping RAM region "
			    "[%#jx, %#jx)\n", (uintmax_t)rstart,
			    (uintmax_t)rend);
		for (pa = rstart; pa < rend; pa += (1ULL << page_shift)) {
			rc = phyp_hcall(H_PUT_TCE, (uint64_t)liobn,
			    win_addr + pa, pa | DDW_TCE_RW);
			if (rc != H_SUCCESS) {
				/*
				 * Every TCE installed so far lies below pa
				 * (earlier regions and this region up to pa);
				 * clearing the contiguous [0, pa) span covers
				 * them all and harmlessly re-invalidates the
				 * holes in between, so the window is empty
				 * before ibm,remove-pe-dma-window.
				 */
				phyp_ddw_destroy(
				    ddw_avail[DDW_REMOVE_PE_DMA_WIN], liobn,
				    win_addr, pa, page_shift);
				return (false);
			}
		}
	}

	if (bootverbose)
		device_printf(dev, "DDW: direct 64-bit DMA window liobn %#x "
		    "base %#jx page 2^%d (%ju TCEs)\n", liobn,
		    (uintmax_t)win_addr, page_shift,
		    (uintmax_t)(ramsize >> page_shift));

	*liobnp = liobn;
	*basep = win_addr;
	return (true);
}

/*
 * Give a child device the direct DDW of its PE/PHB node, creating and
 * identity-mapping it on the node's first request.  Returns true and
 * marks *window direct on success; false when the node has no usable
 * DDW, so the caller keeps the legacy default-window path.
 */
static bool
phyp_iommu_setup_ddw(device_t dev, phandle_t node, struct dma_window *window)
{
	struct phyp_ddw *ddw;

	SLIST_FOREACH(ddw, &phyp_ddw_head, entries)
		if (ddw->node == node)
			break;
	if (ddw == NULL) {
		ddw = malloc(sizeof(struct phyp_ddw), M_PHYPIOMMU,
		    M_WAITOK | M_ZERO);
		ddw->node = node;
		ddw->avail = phyp_ddw_create(dev, node, window->end,
		    &ddw->liobn, &ddw->base);
		SLIST_INSERT_HEAD(&phyp_ddw_head, ddw, entries);
	} else if (ddw->avail && bootverbose)
		device_printf(dev, "DDW: using direct window liobn %#x "
		    "base %#jx\n", ddw->liobn, (uintmax_t)ddw->base);
	if (!ddw->avail)
		return (false);

	window->direct = true;
	window->dma_offset = ddw->base;
	window->liobn = ddw->liobn;
	return (true);
}

int
phyp_iommu_set_dma_tag(device_t bus, device_t dev, bus_dma_tag_t tag)
{
	device_t p;
	phandle_t node;
	cell_t dma_acells, dma_scells, dmawindow[6];
	struct iommu_map *i;
	struct dma_window *window;
	int cell;

	for (p = dev; device_get_parent(p) != NULL; p = device_get_parent(p)) {
		if (ofw_bus_has_prop(p, "ibm,my-dma-window"))
			break;
		if (ofw_bus_has_prop(p, "ibm,dma-window"))
			break;
	}

	if (p == NULL)
		return (ENXIO);

	node = ofw_bus_get_node(p);

	window = malloc(sizeof(struct dma_window), M_PHYPIOMMU,
	    M_WAITOK | M_ZERO);

	if (OF_getencprop(node, "ibm,#dma-size-cells", &dma_scells,
	    sizeof(cell_t)) <= 0)
		OF_searchencprop(node, "#size-cells", &dma_scells,
		    sizeof(cell_t));
	if (OF_getencprop(node, "ibm,#dma-address-cells", &dma_acells,
	    sizeof(cell_t)) <= 0)
		OF_searchencprop(node, "#address-cells", &dma_acells,
		    sizeof(cell_t));

	if (ofw_bus_has_prop(p, "ibm,my-dma-window"))
		OF_getencprop(node, "ibm,my-dma-window", dmawindow,
		    sizeof(cell_t)*(dma_scells + dma_acells + 1));
	else
		OF_getencprop(node, "ibm,dma-window", dmawindow,
		    sizeof(cell_t)*(dma_scells + dma_acells + 1));

	window->start = 0;
	for (cell = 1; cell < 1 + dma_acells; cell++) {
		window->start <<= 32;
		window->start |= dmawindow[cell];
	}
	window->end = 0;
	for (; cell < 1 + dma_acells + dma_scells; cell++) {
		window->end <<= 32;
		window->end |= dmawindow[cell];
	}
	window->end += window->start;

	if (bootverbose)
		device_printf(dev, "Mapping IOMMU domain %#x\n", dmawindow[0]);
	window->map = NULL;
	SLIST_FOREACH(i, &iommu_map_head, entries) {
		if (i->iobn == dmawindow[0]) {
			window->map = i;
			break;
		}
	}

	if (window->map == NULL) {
		window->map = malloc(sizeof(struct iommu_map), M_PHYPIOMMU,
		    M_WAITOK);
		window->map->iobn = dmawindow[0];
		/*
		 * Allocate IOMMU range beginning at PAGE_SIZE. Some drivers
		 * (em(4), for example) do not like getting mappings at 0.
		 */
		window->map->vmem = vmem_create("IOMMU mappings", PAGE_SIZE,
		    trunc_page(VMEM_ADDR_MAX) - PAGE_SIZE, PAGE_SIZE, 0,
		    M_BESTFIT | M_NOWAIT);
		SLIST_INSERT_HEAD(&iommu_map_head, window->map, entries);
	}

	/*
	 * Check experimentally whether we can use H_STUFF_TCE. It is required
	 * by the spec but some firmware (e.g. QEMU) does not actually support
	 * it
	 */
	if (papr_supports_stuff_tce == -1)
		papr_supports_stuff_tce = !(phyp_hcall(H_STUFF_TCE,
		    window->map->iobn, 0, 0, 0) == H_FUNCTION);

	/*
	 * Additionally try to set up a direct-mapped DDW.  Required for VFIO
	 * PCI passthrough devices (e.g. mlx5), whose DMA the default 32-bit
	 * window cannot reach.  The legacy window above stays available:
	 * phyp_iommu_map() falls back to it per mapping when the child tag's
	 * addressing constraints rule the high direct window out, and
	 * entirely when DDW setup fails.
	 */
	(void)phyp_iommu_setup_ddw(dev, node, window);

	bus_dma_tag_set_iommu(tag, bus, window);

	return (0);
}

int
phyp_iommu_map(device_t dev, bus_dma_segment_t *segs, int *nsegs,
    bus_addr_t min, bus_addr_t max, bus_size_t alignment, bus_addr_t boundary,
    void *cookie)
{
	struct dma_window *window = cookie;
	bus_addr_t minaddr, maxaddr;
	bus_addr_t alloced;
	bus_size_t allocsize;
	int error, i, j;
	uint64_t tce;

	/*
	 * Direct-mapped DDW: the whole of RAM is identity-mapped, so the DMA
	 * bus address is just the physical address plus the window base --
	 * no vmem allocation and no per-transfer H_PUT_TCE.  The window sits
	 * high (well above 4 GiB), so honor the child tag's contract: take
	 * this path only if every resulting bus address stays at or below
	 * the tag's exclusion floor (min) and the window base preserves the
	 * requested alignment and boundary.  Otherwise fall through to the
	 * legacy translated window, which allocates constraint-satisfying
	 * bus addresses explicitly.
	 */
	if (window->direct &&
	    (alignment <= 1 || (window->dma_offset & (alignment - 1)) == 0) &&
	    (boundary == 0 || (window->dma_offset & (boundary - 1)) == 0)) {
		for (i = 0; i < *nsegs; i++)
			if (window->dma_offset + segs[i].ds_addr +
			    segs[i].ds_len - 1 > min)
				break;
		if (i == *nsegs) {
			for (i = 0; i < *nsegs; i++)
				segs[i].ds_addr += window->dma_offset;
			return (0);
		}
	}

	minaddr = window->start;
	maxaddr = window->end;

	/* XXX: handle exclusion range in a more useful way */
	if (min < maxaddr)
		maxaddr = min;

	/* XXX: consolidate segs? */
	for (i = 0; i < *nsegs; i++) {
		allocsize = round_page(segs[i].ds_len +
		    (segs[i].ds_addr & PAGE_MASK));
		error = vmem_xalloc(window->map->vmem, allocsize,
		    (alignment < PAGE_SIZE) ? PAGE_SIZE : alignment, 0,
		    boundary, minaddr, maxaddr, M_BESTFIT | M_NOWAIT, &alloced);
		if (error != 0) {
			panic("VMEM failure: %d\n", error);
			return (error);
		}
		KASSERT(alloced % PAGE_SIZE == 0, ("Alloc not page aligned"));
		KASSERT((alloced + (segs[i].ds_addr & PAGE_MASK)) %
		    alignment == 0,
		    ("Allocated segment does not match alignment constraint"));

		tce = trunc_page(segs[i].ds_addr);
		tce |= 0x3; /* read/write */
		for (j = 0; j < allocsize; j += PAGE_SIZE) {
			error = phyp_hcall(H_PUT_TCE, window->map->iobn,
			    alloced + j, tce + j);
			if (error < 0) {
				panic("IOMMU mapping error: %d\n", error);
				return (ENOMEM);
			}
		}

		segs[i].ds_addr = alloced + (segs[i].ds_addr & PAGE_MASK);
		KASSERT(segs[i].ds_addr > 0, ("Address needs to be positive"));
		KASSERT(segs[i].ds_addr + segs[i].ds_len < maxaddr,
		    ("Address not in range"));
		if (error < 0) {
			panic("IOMMU mapping error: %d\n", error);
			return (ENOMEM);
		}
	}

	return (0);
}

int
phyp_iommu_unmap(device_t dev, bus_dma_segment_t *segs, int nsegs, void *cookie)
{
	struct dma_window *window = cookie;
	bus_addr_t pageround;
	bus_size_t roundedsize;
	int i;
	bus_addr_t j;

	for (i = 0; i < nsegs; i++) {
		/*
		 * Segments in the direct DDW (at or above the window base)
		 * are part of the permanent identity map; only legacy-window
		 * segments have translations and vmem to release.
		 */
		if (window->direct && segs[i].ds_addr >= window->dma_offset)
			continue;

		pageround = trunc_page(segs[i].ds_addr);
		roundedsize = round_page(segs[i].ds_len +
		    (segs[i].ds_addr & PAGE_MASK));

		if (papr_supports_stuff_tce) {
			phyp_hcall(H_STUFF_TCE, window->map->iobn, pageround, 0,
			    roundedsize/PAGE_SIZE);
		} else {
			for (j = 0; j < roundedsize; j += PAGE_SIZE)
				phyp_hcall(H_PUT_TCE, window->map->iobn,
				    pageround + j, 0);
		}

		vmem_xfree(window->map->vmem, pageround, roundedsize);
	}

	return (0);
}
