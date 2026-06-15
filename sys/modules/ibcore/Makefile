.PATH:  ${SRCTOP}/sys/ofed/drivers/infiniband/core

KMOD=	ibcore
SRCS= \
	ib_addr.c \
	ib_agent.c \
	ib_cache.c \
	ib_cm.c \
	ib_cma.c \
	ib_core_uverbs.c \
	ib_cq.c \
	ib_device.c \
	ib_fmr_pool.c \
	ib_iwcm.c \
	ib_iwpm_msg.c \
	ib_iwpm_util.c \
	ib_mad.c \
	ib_mad_rmpp.c \
	ib_multicast.c \
	ib_packer.c \
	ib_rdma_core.c \
	ib_roce_gid_mgmt.c \
	ib_sa_query.c \
	ib_smi.c \
	ib_sysfs.c \
	ib_ucm.c \
	ib_ucma.c \
	ib_ud_header.c \
	ib_umem.c \
	ib_user_mad.c \
	ib_uverbs_cmd.c \
	ib_uverbs_ioctl.c \
	ib_uverbs_main.c \
	ib_uverbs_marshall.c \
	ib_uverbs_std_types.c \
	ib_uverbs_std_types_async_fd.c \
	ib_uverbs_std_types_counters.c \
	ib_uverbs_std_types_cq.c \
	ib_uverbs_std_types_device.c \
	ib_uverbs_std_types_dm.c \
	ib_uverbs_std_types_flow_action.c \
	ib_uverbs_std_types_mr.c \
	ib_uverbs_uapi.c \
	ib_verbs.c \
	xprt_verbs.c
# svc_verbs.c (the NFS-over-RDMA server) is intentionally NOT built into this
# loadable module: it calls svc_rdma_register_verbs()/svc_rdma_unregister_verbs(),
# defined in sys/rpc/svc_rdma.c (native krpc, "optional ofed"), which is not
# packaged in any .ko, so kldload'ing ibcore here would fail with unresolved
# symbols.  The NFS-over-RDMA server is provided only by a kernel built with
# "options OFED" (e.g. GENERIC-OFED), where svc_verbs.c and svc_rdma.c are both
# compiled in.  A standalone loadable nfsrdma.ko (depending on ibcore + krpc) is
# left as follow-up packaging work.

SRCS+=	${LINUXKPI_GENSRCS}
SRCS+=	opt_inet.h opt_inet6.h

CFLAGS+= -I${SRCTOP}/sys/ofed/include
CFLAGS+= -I${SRCTOP}/sys/ofed/include/uapi
CFLAGS+= ${LINUXKPI_INCLUDES}
CFLAGS+= -DINET6 -DINET -DCONFIG_INFINIBAND_USER_MEM

EXPORT_SYMS=	YES

.include <bsd.kmod.mk>

CWARNFLAGS+= -Wno-cast-qual -Wno-pointer-arith
CWARNFLAGS+=	${NO_WUNUSED_BUT_SET_VARIABLE}
