#!/bin/bash
#
# A simple wrapper for common project commands.
# Usage: ./run.sh <command>

COMMAND=$1

if [ "$COMMAND" == "build-cellular-update" ]; then
    echo "Building app-cellular-update..."
	rm -rf apps/build-cellular-update
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-cellular-update apps/app-cellular-update/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-cellular-update-menuconfig" ]; then
	echo "Building menuconfig for app-cellular-update..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-cellular-update -t menuconfig apps/app-cellular-update

elif [ "$COMMAND" == "build-hello-world" ]; then
    echo "Building app-hello-world..."
	rm -rf apps/build-hello-world
    west build -b esp32_devkitc/esp32/procpu --pristine -d apps/build-hello-world apps/app-hello-world/ -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-hello-world-menuconfig" ]; then
	echo "Building menuconfig for app-hello-world..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-hello-world -t menuconfig apps/app-hello-world

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

