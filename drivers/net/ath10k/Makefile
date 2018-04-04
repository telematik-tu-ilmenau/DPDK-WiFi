include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_ath10k.a

# CFLAGS += -O3 -g
CFLAGS += -O0 -g
CFLAGS += $(WERROR_FLAGS)

# REENABLE THE FOLLOWING FLAGS LATER
CFLAGS += -Wno-error
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-unused-value
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-strict-aliasing
CFLAGS += -Wno-format
CFLAGS += -Wno-missing-field-initializers
CFLAGS += -Wno-pointer-to-int-cast
CFLAGS += -Wno-format-nonliteral
CFLAGS += -Wno-format-security
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-cast-qual
CFLAGS += -Wno-discarded-qualifiers
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-pointer-arith
CFLAGS += -Wno-comment
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-cast-qual
CFLAGS += -Wno-discarded-qualifiers
CFLAGS += -Wno-int-conversion
CFLAGS += -Wno-incompatible-pointer-types

# AddressSanitizer
#   WARNING: If you enable AddressSanitizer, you MUST also enable it in app/test-ath10k/Makefile
#   using the same CFLAGS, else build will fail
CFLAGS += -fsanitize=address

# includes
CFLAGS += -I$(RTE_SDK)/lib/librte_80211

EXPORT_MAP := rte_pmd_ath10k_version.map

LIBABIVER := 1

#
# Add extra flags for base driver files (also known as shared code)
# to disable warnings
#
CFLAGS_BASE_DRIVER  = -Wno-sign-compare
CFLAGS_BASE_DRIVER += -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing
CFLAGS_BASE_DRIVER += -Wno-format
CFLAGS_BASE_DRIVER += -Wno-missing-field-initializers
CFLAGS_BASE_DRIVER += -Wno-pointer-to-int-cast
CFLAGS_BASE_DRIVER += -Wno-format-nonliteral
CFLAGS_BASE_DRIVER += -Wno-format-security
CFLAGS_BASE_DRIVER += -Wno-unused-variable
CFLAGS_BASE_DRIVER += -Wno-cast-qual
CFLAGS_BASE_DRIVER += -Wno-discarded-qualifiers
CFLAGS_BASE_DRIVER += -Wno-unused-function
CFLAGS_BASE_DRIVER += -Wno-pointer-arith
CFLAGS_BASE_DRIVER += -Wno-comment
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-cast-qual
CFLAGS_BASE_DRIVER += -Wno-discarded-qualifiers
CFLAGS_BASE_DRIVER += -Wno-int-conversion
CFLAGS_BASE_DRIVER += -Wno-unused-label
CFLAGS_BASE_DRIVER += -Wno-uninitialized
ifeq ($(shell test $(GCC_VERSION) -ge 44 && echo 1), 1)
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
endif

OBJS_BASE_DRIVER=$(patsubst %.c,%.o,$(notdir $(wildcard $(SRCDIR)/base/*.c)))
$(foreach obj, $(OBJS_BASE_DRIVER), $(eval CFLAGS_$(obj)+=$(CFLAGS_BASE_DRIVER)))

VPATH += $(SRCDIR)/base

#
# all source are stored in SRCS-y
#

SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += ath10k_ethdev.c

# base dir
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += ath10k_osdep.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += bmi.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += ce.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += core.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += dma.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += debug.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += firmware.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += htc.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += htt.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += htt_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += htt_tx.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += hw.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += linux_completion.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += linux_idr.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += mac.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += pci.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += sleepqueue.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += swap.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += taskqueue.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += txrx.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += wifi.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += wmi.c
SRCS-$(CONFIG_RTE_LIBRTE_LLWA_PMD) += wmi-tlv.c

include $(RTE_SDK)/mk/rte.lib.mk
