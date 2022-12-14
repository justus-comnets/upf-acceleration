# BSD LICENSE
#
# Copyright (c) 2015-2017 Atomic Rules LLC
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
# * Neither the name of copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_ark.a

CFLAGS += -O3 -I./
CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_pmd_ark_version.map

LIBABIVER := 1

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_ddm.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_ethdev_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_ethdev_tx.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_mpu.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_pktchkr.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_pktdir.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_pktgen.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_rqp.c
SRCS-$(CONFIG_RTE_LIBRTE_ARK_PMD) += ark_udm.c

# this lib depends upon:
LDLIBS += -lpthread
ifdef CONFIG_RTE_EXEC_ENV_LINUXAPP
LDLIBS += -ldl
endif

include $(RTE_SDK)/mk/rte.lib.mk
