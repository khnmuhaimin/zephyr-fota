# Copyright (c) 2021 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0
# message(STATUS ">>> Processing: ${CMAKE_CURRENT_LIST_FILE} <<<")

# Out-of-tree drivers for custom classes
add_subdirectory_ifdef(CONFIG_BLINK blink)

# Out-of-tree drivers for existing driver classes
add_subdirectory_ifdef(CONFIG_SENSOR sensor)

# Stuff I added
add_subdirectory_ifdef(CONFIG_MODEM modem)
# end stuff I added
