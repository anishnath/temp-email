package arduino

// qemuBridgeSource is a C++ source file injected into ESP32 sketches when
// compiling for QEMU simulation. It creates a FreeRTOS task that:
//   - Polls GPIO_OUT_REG every ~10ms
//   - Reports pin state changes as structured messages on UART0
//   - Listens for ADC set commands on UART0 (##ADC:ch:val##)
//
// Protocol (QEMU → host):
//   \x01G<pin>:<0|1>\n    — GPIO output pin changed (e.g. \x01G8:1\n)
//   \x01P<pin>:<duty>\n   — PWM duty changed (0-255)
//
// Protocol (host → QEMU):
//   ##ADC:<channel>:<raw12bit>##  — set ADC channel value (0-4095)
//   ##PIN:<pin>:<0|1>##           — set input pin state
//
// The \x01 prefix lets the browser distinguish bridge messages from user Serial output.

const qemuBridgeFilename = "_qemu_bridge.h"

// qemuBridgeSource is a header placed in the sketch directory. The compile
// handler prepends #include "_qemu_bridge.h" to the user's sketch.ino so the
// macro definitions apply to all user code.
//
// It redefines digitalWrite/analogWrite as inline functions that:
//  1. Call the ESP-IDF gpio_set_level() directly (avoids macro recursion)
//  2. Print a structured serial message for the browser (SOH + "G<pin>:<val>")
//
// Protocol: SOH (0x01) + "G<pin>:<0|1>\n" for GPIO, "P<pin>:<duty>\n" for PWM.
const qemuBridgeSource = `#pragma once
#include "driver/gpio.h"

// Lazy-init Serial on first bridge call. Safe to call begin() multiple times.
// Can't use a global constructor on ESP32-C3 (UART not ready that early).
static bool __qb_serial_ready = false;
static inline void __qb_ensure_serial() {
    if (!__qb_serial_ready) {
        Serial.begin(115200);
        __qb_serial_ready = true;
    }
}

static inline void __qb_gw(uint8_t pin, uint8_t val) {
    gpio_set_level((gpio_num_t)pin, val);
    __qb_ensure_serial();
    char buf[20];
    buf[0] = 1;  // SOH marker
    buf[1] = 'G';
    sprintf(buf + 2, "%d:%d\n", (int)pin, (int)val);
    Serial.print(buf);
}

#define digitalWrite(p, v) __qb_gw((p), (v))
`

// qemuBridgeBuildFlag is no longer needed — the bridge is included via
// #include prepended to the sketch source.
const qemuBridgeBuildFlag = ""

// qemuBridgeSketchPrefix is prepended to the user's sketch.ino content
// when compiling for ESP32 boards to activate the GPIO bridge.
const qemuBridgeSketchPrefix = "#include \"_qemu_bridge.h\"\n"
