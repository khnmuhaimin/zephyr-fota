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

elif [ "$COMMAND" == "build-mcuboot" ]; then
	echo "Building MCUboot..."
	west build -b esp32_devkitc/esp32/procpu --pristine -d build-mcuboot bootloader/mcuboot/boot/zephyr

elif [ "$COMMAND" == "connect-to-update-server" ]; then
	echo "Connecting to update server..."
	ssh -i "zephyr-fota-key.pem" ubuntu@3.85.57.185

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

