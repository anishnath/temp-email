# QEMU Raspberry Pi 3B emulation service.
#
# Contains qemu-system-aarch64 + kernel8.img + device tree + Raspberry Pi OS Lite.
# Each instance gets a disposable qcow2 overlay (copy-on-write, ~8GB virtual, <100MB actual).
#
# Build from repo root:
#   docker build -t qemu-pi3:local -f docker/qemu-pi3/Dockerfile .
#
# Run standalone test (boots to shell):
#   docker run --rm -p 5555:5555 qemu-pi3:local \
#     /boot.sh 5555
#
# Environment:
#   PI_QEMU_DOCKER_IMAGE=qemu-pi3:local
#
# Size: ~800MB (QEMU ~50MB + Pi OS Lite ~500MB + kernel/dtb + tools)

FROM debian:trixie-slim AS base

# Use Debian trixie (testing) which has QEMU 9.x with proper raspi3b serial support.
# Bookworm's QEMU 7.2 lacks earlycon for PL011, producing no serial output.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils unzip kpartx fdisk \
    qemu-system-arm qemu-utils mtools dosfstools \
    && rm -rf /var/lib/apt/lists/*

# Verify QEMU
RUN qemu-system-aarch64 --version | head -1 && \
    qemu-system-aarch64 -machine help | grep raspi3b && \
    qemu-img --version | head -1

WORKDIR /opt/pi

# ── Download Raspberry Pi OS Lite (64-bit, headless) ──
# Using the official archive. ~500MB compressed, ~2GB extracted.
ARG PIOS_DATE=2024-11-19
ARG PIOS_NAME=2024-11-19-raspios-bookworm-arm64-lite
ARG PIOS_URL=https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-${PIOS_DATE}/${PIOS_NAME}.img.xz

RUN echo "Downloading Raspberry Pi OS Lite..." && \
    curl -fSL -o /tmp/pios.img.xz "${PIOS_URL}" && \
    xz -d /tmp/pios.img.xz && \
    mv /tmp/pios.img /opt/pi/sdcard.img && \
    ls -lh /opt/pi/sdcard.img

# ── Extract kernel and dtb from boot partition ──
# The .img has two partitions: boot (FAT32, offset 512*8192) and root (ext4).
# We extract kernel8.img and the dtb from the boot partition.
RUN OFFSET=$(fdisk -l /opt/pi/sdcard.img | grep "\.img1" | awk '{print $2 * 512}') && \
    echo "Boot partition offset: $OFFSET" && \
    mkdir -p /tmp/boot && \
    # Mount-free extraction using dd + mcopy (or fallback to loop mount)
    # mtools already installed in base layer
    true && \
    # Create a temp file with just the boot partition
    SECTORS=$(fdisk -l /opt/pi/sdcard.img | grep "\.img1" | awk '{print ($4 - $2) * 512}') && \
    dd if=/opt/pi/sdcard.img of=/tmp/boot.fat bs=1 skip=$OFFSET count=$SECTORS 2>/dev/null && \
    mcopy -i /tmp/boot.fat ::kernel8.img /opt/pi/kernel8.img && \
    mcopy -i /tmp/boot.fat ::bcm2710-rpi-3-b.dtb /opt/pi/bcm2710-rpi-3-b.dtb && \
    rm -f /tmp/boot.fat && \
    true && \
    rm -rf /var/lib/apt/lists/* && \
    ls -lh /opt/pi/kernel8.img /opt/pi/bcm2710-rpi-3-b.dtb

# ── Boot script ──
# Creates a qcow2 overlay, starts QEMU with two serial ports (terminal + GPIO shim).
# Usage: /boot.sh <serial_port> [gpio_port]
COPY docker/qemu-pi3/boot.sh /opt/pi/boot.sh
RUN chmod +x /opt/pi/boot.sh

# Working dir for overlays
RUN mkdir -p /tmp/pi-overlays

EXPOSE 5555 5556

CMD ["/opt/pi/boot.sh", "5555", "5556"]
