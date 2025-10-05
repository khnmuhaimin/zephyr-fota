# Copyright (c) 2021 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

zephyr_library()

# activate CONFIG_MODEM to get all of the zephyr modem driver files
# they dont need to be repeated here

if (CONFIG_MODEM_A76XX)
	zephyr_library_sources(simcom-a76xx.c)
    zephyr_library_include_directories(../../../include)  # add the include dir for 
endif()

