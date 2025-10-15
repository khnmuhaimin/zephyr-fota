# Copyright (c) 2021 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

# message(STATUS ">>> Processing: ${CMAKE_CURRENT_LIST_FILE} <<<")


# add_subdirectory_ifdef(CONFIG_EXAMPLE_SENSOR example_sensor)

# Stuff I added
add_subdirectory_ifdef(CONFIG_MODEM_A76XX simcom-a76xx)
# end stuff I added
