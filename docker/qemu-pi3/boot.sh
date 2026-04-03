#!/bin/sh
# Boot Raspberry Pi 3B in QEMU with serial over TCP.
#
# Usage: /boot.sh <serial_port> [gpio_port]
#   serial_port — TCP port for ttyAMA0 (user terminal)
#   gpio_port   — TCP port for ttyAMA1 (GPIO shim, optional)
#
# Creates a disposable qcow2 overlay so the base SD image is never modified.

set -e

SERIAL_PORT="${1:-5555}"
GPIO_PORT="${2:-5556}"

BASE_IMG="/opt/pi/sdcard.img"
KERNEL="/opt/pi/kernel8.img"
DTB="/opt/pi/bcm2710-rpi-3-b.dtb"
OVERLAY="/tmp/pi-overlays/overlay-$$.qcow2"

# Verify boot files
for f in "$BASE_IMG" "$KERNEL" "$DTB"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: Missing $f" >&2
    exit 1
  fi
done

# Create qcow2 overlay (copy-on-write)
qemu-img create -f qcow2 -b "$BASE_IMG" -F raw "$OVERLAY" >/dev/null
qemu-img resize "$OVERLAY" 8G >/dev/null 2>&1 || true

# Cleanup overlay on exit
trap "rm -f '$OVERLAY'" EXIT

echo "Booting Raspberry Pi 3B..."
echo "  Serial (ttyAMA0): tcp:0.0.0.0:${SERIAL_PORT}"
echo "  GPIO   (ttyAMA1): tcp:0.0.0.0:${GPIO_PORT}"

exec qemu-system-aarch64 \
  -M raspi3b \
  -kernel "$KERNEL" \
  -dtb "$DTB" \
  -drive "file=${OVERLAY},if=sd,format=qcow2" \
  -m 1G \
  -smp 4 \
  -display none \
  -chardev socket,id=serial0,host=0.0.0.0,port=${SERIAL_PORT},server=on,wait=off \
  -serial chardev:serial0 \
  -chardev socket,id=serial1,host=0.0.0.0,port=${GPIO_PORT},server=on,wait=off \
  -serial chardev:serial1 \
  -monitor none \
  -append "console=ttyAMA0 earlycon=pl011,0x3f201000 root=/dev/mmcblk0p2 rootwait rw dwc_otg.lpm_enable=0"
