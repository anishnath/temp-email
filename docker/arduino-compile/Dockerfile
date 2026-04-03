# arduino-cli + arduino:avr + rp2040 (Pico) + esp32 (Espressif) + curated libraries for isolated compiles
# (no network at compile time).
#
# Build from repo root:
#   docker build -t arduino-compile:local -f docker/arduino-compile/Dockerfile .
#
# Run API with:
#   ARDUINO_DOCKER_IMAGE=arduino-compile:local
#
# FQBN examples: rp2040:rp2040:rpipico, rp2040:rp2040:rpipicow; esp32:esp32:esp32, esp32:esp32:esp32c3, esp32:esp32:esp32s3, etc.
#
# Wire, SPI, EEPROM: bundled with board cores (arduino:avr, rp2040, etc.; do not lib install).
# Names below must match Library Manager (arduino-cli lib search <name>).
# BundledDockerLibraryNames + dockerBundledLibs in internal/arduino/libcatalog.go / docker.go must match.

FROM debian:bookworm-slim

# python3: required by Earle Philhower rp2040 platform build (post_link scripts, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | BINDIR=/usr/local/bin sh

ENV PATH="/usr/local/bin:${PATH}"
ENV ARDUINO_DIRECTORIES_DATA=/opt/arduino15

# Earle Philhower RP2040 core (Pico / Pico W)
ENV RP2040_BOARD_INDEX="https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json"
# Espressif Arduino-ESP32 core (ESP32, ESP32-C3, ESP32-S2, ESP32-S3, …)
ENV ESP32_BOARD_INDEX="https://espressif.github.io/arduino-esp32/package_esp32_index.json"

RUN mkdir -p /opt/arduino15 && \
    arduino-cli version && \
    arduino-cli config init && \
    arduino-cli config add board_manager.additional_urls "${RP2040_BOARD_INDEX}" && \
    arduino-cli config add board_manager.additional_urls "${ESP32_BOARD_INDEX}" && \
    arduino-cli core update-index && \
    arduino-cli core install arduino:avr && \
    arduino-cli core install rp2040:rp2040 && \
    arduino-cli lib install \
        Servo \
        LiquidCrystal \
        Stepper \
        "Adafruit NeoPixel" \
        "DHT sensor library" \
        Ethernet \
        SD \
        PubSubClient \
        ArduinoJson \
        MFRC522 \
        RTClib \
        OneWire \
        DallasTemperature \
        AccelStepper \
        FastLED \
        IRremote \
        Bounce2 \
        "Adafruit GFX Library" \
        "Adafruit SSD1306" \
        U8g2

RUN arduino-cli core install esp32:esp32

WORKDIR /work

RUN arduino-cli core list && arduino-cli lib list

CMD ["arduino-cli", "version"]
