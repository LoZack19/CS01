# Firmware Makefile
#
# Goal: keep firmware/include/tpm2_spec_protocol.h in sync with the QEMU copy,
# while forcing it to use the firmware-local fifo8 header.
#
# - Source:   ../qemu/include/hw/misc/tpm2_spec_protocol.h
# - Dest:     include/tpm2_spec_protocol.h
# - Rewrite:  #include "include/qemu/fifo8.h"  ->  #include "fifo8.h"

QEMU_DIR ?= ../qemu

# Fake/stub headers for NXP SDK and FreeRTOS (used when building outside the
# real SDK).  Place this directory *after* include/ so that project-local
# headers take precedence.
CFLAGS += -Iinclude -Ifakeinclude

QEMU_TPM2_HDR := $(QEMU_DIR)/include/hw/misc/tpm2_spec_protocol.h
FIRMWARE_TPM2_HDR := include/tpm2_spec_protocol.h

.PHONY: setup clean

setup: $(FIRMWARE_TPM2_HDR)

clean:
	rm -f $(FIRMWARE_TPM2_HDR)

$(FIRMWARE_TPM2_HDR): $(QEMU_TPM2_HDR)
	cp -f $< $@
	@# Ensure we actually replaced the QEMU fifo8 include with the firmware one.
	@grep -q '"include/qemu/fifo8.h"' $@ || { \
		echo "Error: expected QEMU fifo8 include not found in $@" >&2; \
		exit 1; \
	}
	@sed -i 's|#include "include/qemu/fifo8.h"|#include "fifo8.h"|' $@
	@chmod a-w $@
