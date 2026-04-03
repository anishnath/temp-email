# QEMU ESP32 emulation service — runs ESP32/ESP32-C3 firmware via Espressif's QEMU fork.
#
# Provides qemu-system-riscv32 (ESP32-C3) and qemu-system-xtensa (ESP32/ESP32-S3).
# Used by the Go API's WebSocket endpoint for interactive simulation.
#
# Build from repo root:
#   docker build -t qemu-esp32:local -f docker/qemu-esp32/Dockerfile .
#
# Run standalone test:
#   docker run --rm -v /path/to/sketch.ino.merged.bin:/fw.bin qemu-esp32:local \
#     qemu-system-riscv32 -machine esp32c3 -nographic \
#     -drive file=/fw.bin,if=mtd,format=raw -serial mon:stdio -no-reboot
#
# Machines:
#   esp32c3  → qemu-system-riscv32  (RISC-V RV32IMC @ 160 MHz)
#   esp32    → qemu-system-xtensa   (Xtensa LX6 @ 240 MHz)
#   esp32s3  → qemu-system-xtensa   (Xtensa LX7 @ 240 MHz)

FROM debian:bookworm-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils \
    libglib2.0-0 libpixman-1-0 libgcrypt20 \
    libsdl2-2.0-0 libslirp0 \
    && rm -rf /var/lib/apt/lists/*

# ── Download Espressif pre-built QEMU binaries ──
# Source: https://github.com/espressif/qemu/releases
ARG QEMU_VERSION=esp-develop-9.2.2-20250817

# RISC-V (ESP32-C3)
# Use tr for hyphen→underscore (POSIX sh; bash ${var//-/_} breaks under dash: "Bad substitution").
RUN ARCH=$(dpkg --print-architecture) && \
    QEMU_VER_US=$(echo "$QEMU_VERSION" | tr '-' '_') && \
    case "$ARCH" in \
      amd64) QARCH=x86_64 ;; \
      arm64) QARCH=aarch64 ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/qemu-riscv32.tar.xz \
      "https://github.com/espressif/qemu/releases/download/${QEMU_VERSION}/qemu-riscv32-softmmu-${QEMU_VER_US}-${QARCH}-linux-gnu.tar.xz" && \
    tar xf /tmp/qemu-riscv32.tar.xz -C /usr/local && \
    rm /tmp/qemu-riscv32.tar.xz

# Xtensa (ESP32 / ESP32-S3)
RUN ARCH=$(dpkg --print-architecture) && \
    QEMU_VER_US=$(echo "$QEMU_VERSION" | tr '-' '_') && \
    case "$ARCH" in \
      amd64) QARCH=x86_64 ;; \
      arm64) QARCH=aarch64 ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/qemu-xtensa.tar.xz \
      "https://github.com/espressif/qemu/releases/download/${QEMU_VERSION}/qemu-xtensa-softmmu-${QEMU_VER_US}-${QARCH}-linux-gnu.tar.xz" && \
    tar xf /tmp/qemu-xtensa.tar.xz -C /usr/local && \
    rm /tmp/qemu-xtensa.tar.xz

# Symlink binaries to PATH
RUN ln -sf /usr/local/qemu/bin/qemu-system-riscv32 /usr/local/bin/qemu-system-riscv32 && \
    ln -sf /usr/local/qemu/bin/qemu-system-xtensa /usr/local/bin/qemu-system-xtensa 2>/dev/null || true

# Verify all machines
RUN qemu-system-riscv32 --version && \
    qemu-system-riscv32 -machine help | grep esp32c3 && \
    qemu-system-xtensa --version && \
    qemu-system-xtensa -machine help | grep -E "esp32 |esp32s3"

# Temp dir for firmware files (QEMU needs write access for flash emulation)
RUN mkdir -p /tmp/qemu-fw

WORKDIR /tmp/qemu-fw

# Default: print versions
CMD ["sh", "-c", "qemu-system-riscv32 --version && qemu-system-xtensa --version"]
