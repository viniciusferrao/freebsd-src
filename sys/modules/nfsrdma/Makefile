.PATH:	${SRCTOP}/sys/ofed/drivers/infiniband/ulp/nfsrdma

KMOD=	nfsrdma
SRCS=	svc_verbs.c nfsrdma_sink.c nfsrdma_decode.c nfsrdma_data.c nfsrdma_conn.c
SRCS+=	${LINUXKPI_GENSRCS}
SRCS+=	opt_inet.h opt_inet6.h opt_ofed.h

CFLAGS+= -I${SRCTOP}/sys/ofed/drivers/infiniband/ulp/nfsrdma
CFLAGS+= -I${SRCTOP}/sys/ofed/include
CFLAGS+= -I${SRCTOP}/sys/ofed/include/uapi
CFLAGS+= ${LINUXKPI_INCLUDES}

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith
