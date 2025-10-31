#!/bin/bash
#
# A simple wrapper for common project commands.
# Usage: ./run.sh <command>

COMMAND=$1

if [ "$COMMAND" == "build-cellular-hello" ]; then
    echo "Building app-cellular-hello..."
	rm -rf apps/build-cellular-hello
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-cellular-hello apps/app-cellular-hello/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-cellular-hello-menuconfig" ]; then
	echo "Building menuconfig for app-cellular-hello..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-cellular-hello -t menuconfig apps/app-cellular-hello

elif [ "$COMMAND" == "build-hello-world" ]; then
    echo "Building app-hello-world..."
	rm -rf apps/build-hello-world
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-hello-world apps/app-hello-world/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-hello-world-menuconfig" ]; then
	echo "Building menuconfig for app-hello-world..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-hello-world -t menuconfig apps/app-hello-world
	
elif [ "$COMMAND" == "build-adaptive-wifi" ]; then
    echo "Building app-adaptive-wifi..."
	rm -rf apps/build-adaptive-wifi
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-adaptive-wifi apps/app-adaptive-wifi/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-adaptive-wifi-menuconfig" ]; then
	echo "Building menuconfig for app-adaptive-wifi..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-adaptive-wifi -t menuconfig apps/app-adaptive-wifi

elif [ "$COMMAND" == "build-adaptive-modem" ]; then
    echo "Building app-adaptive-modem..."
	rm -rf apps/build-adaptive-modem
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-adaptive-modem apps/app-adaptive-modem/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-adaptive-modem-menuconfig" ]; then
	echo "Building menuconfig for app-adaptive-modem..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-adaptive-modem -t menuconfig apps/app-adaptive-modem

elif [ "$COMMAND" == "build-wifi-update" ]; then
    echo "Building app-wifi-update..."
	rm -rf apps/build-wifi-update
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-wifi-update apps/app-wifi-update/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-wifi-update-menuconfig" ]; then
	echo "Building menuconfig for app-wifi-update..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-wifi-update -t menuconfig apps/app-wifi-update

elif [ "$COMMAND" == "build-adaptive-update" ]; then
    echo "Building app-adaptive-update..."
	rm -rf apps/build-adaptive-update
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-adaptive-update apps/app-adaptive-update/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-adaptive-update-menuconfig" ]; then
	echo "Building menuconfig for app-adaptive-update..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-adaptive-update -t menuconfig apps/app-adaptive-update

elif [ "$COMMAND" == "build-mcuboot" ]; then
	echo "Building MCUboot..."
	west build -b esp32_devkitc/esp32/procpu --pristine -d build-mcuboot bootloader/mcuboot/boot/zephyr

elif [ "$COMMAND" == "connect-to-update-server" ]; then
	echo "Connecting to update server..."
	ssh -i "zephyr-fota-key.pem" ubuntu@3.85.57.185

elif [ "$COMMAND" == "sign-first-image" ]; then
	echo "Signing the first image..."
	west sign -t imgtool -d apps/build-adaptive-update -- --version 1.0.0 --pad --key bootloader/mcuboot/root-rsa-2048.pem

elif [ "$COMMAND" == "flash-first-signed-image" ]; then
	echo "Flashing the first signed image..."
	west flash -d apps/build-adaptive-update --bin-file apps/build-adaptive-update/zephyr/zephyr.signed.bin

elif [ "$COMMAND" == "build-second-image" ]; then
	rm -rf apps/build-hello-world .uhu
	west build -b esp32_devkitc/esp32/procpu -d apps/build-hello-world apps/app-hello-world/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"
	west sign --no-hex --bin -B apps/build-hello-world/zephyr-2.0.0.bin -t imgtool -d apps/build-hello-world -- --version 2.0.0 --key bootloader/mcuboot/root-rsa-2048.pem
	uhu product use "e4d37cfe6ec48a2d069cc0bbb8b078677e9a0d8df3a027c4d8ea131130c4265f"
	uhu package add apps/build-hello-world/zephyr-2.0.0.bin -m zephyr
	uhu package version 2.0.0
	uhu package archive --output apps/build-hello-world/zephyr-2.0.0.pkg

elif [ "$COMMAND" == "sign-second-image" ]; then
	west sign --no-hex --bin -B apps/build-hello-world/zephyr-2.0.0.bin -t imgtool -d apps/build-hello-world -- --version 2.0.0 --key bootloader/mcuboot/root-rsa-2048.pem

elif [ "$COMMAND" == "prep-image-2" ]; then
	rm -rf .uhu
	rm -rf apps/build-hello-world
	west build -b esp32_devkitc/esp32/procpu -d apps/build-hello-world apps/app-hello-world/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"
	west sign --no-hex --bin -B apps/build-hello-world/zephyr-2.0.0.bin -t imgtool -d apps/build-hello-world -- --version 2.0.0 --key bootloader/mcuboot/root-rsa-2048.pem
	uhu product use "e4d37cfe6ec48a2d069cc0bbb8b078677e9a0d8df3a027c4d8ea131130c4265f"
	uhu package add apps/build-adaptive-update-2/zephyr-2.0.0.bin -m zephyr
	uhu package version 2.0.0
	uhu package archive --output apps/build-adaptive-update-2/zephyr-2.0.0.pkg

elif [ "$COMMAND" == "prep-image-1" ]; then
	west build -b esp32_devkitc/esp32/procpu -d apps/build-adaptive-update apps/app-adaptive-update/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"
	west sign -t imgtool -d apps/build-adaptive-update -- --version 1.0.0 --pad --key bootloader/mcuboot/root-rsa-2048.pem
	west flash -d apps/build-adaptive-update --bin-file apps/build-adaptive-update/zephyr/zephyr.signed.bin


else
    echo "Error: Unknown command '$COMMAND'"
    echo ""
    echo "Usage: ./run.sh {command}"
    echo ""
    echo "Available commands:"
    echo "  setup-environment      Activates the python venv and sources the Zephyr environment."
    echo "  build-cellular-update  Builds the 'cellular-update' application."
    exit 1
fi

