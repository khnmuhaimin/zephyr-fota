# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cellular_update)
zephyr_library_include_directories(${ZEPHYR_BASE}/drivers/modem)
zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)  # more include dirs needed
zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/lib/sockets)  # more include dirs needed
target_sources(app PRIVATE src/main.c)