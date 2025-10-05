#!/bin/bash
#
# A simple wrapper for common project commands.
# Usage: ./run.sh <command>

COMMAND=$1

if [ "$COMMAND" == "build-cellular-update" ]; then
    echo "Building app-cellular-update..."
    west build -b "esp32_devkitc/esp32/procpu" --pristine -d "apps/build-cellular-update" "apps/app-cellular-update/" -- -DDTC_OVERLAY_FILE="boards/esp32-overlay.dts"

elif [ "$COMMAND" == "build-cellular-update-menuconfig" ]; then
	echo "Building menuconfig for app-cellular-update..."
	west build -b esp32_devkitc/esp32/procpu -d apps/build-cellular-update -t menuconfig apps/app-cellular-update

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

