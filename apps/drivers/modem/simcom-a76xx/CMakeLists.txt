# Copyright (c) 2021 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0
# message(STATUS ">>> Processing: ${CMAKE_CURRENT_LIST_FILE} <<<")

zephyr_library()

# activate CONFIG_MODEM to get all of the zephyr modem driver files
# they dont need to be repeated here

if (CONFIG_MODEM_A76XX)
	zephyr_library_sources(simcom-a76xx.c)
    zephyr_library_include_directories(../../../include)  # add my include dir for the .h file
    zephyr_library_include_directories(${ZEPHYR_BASE}/drivers/modem)  # add include for zephyr's modem files
    zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)  # more include dirs needed
    zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/lib/sockets)  # more include dirs needed
endif()

