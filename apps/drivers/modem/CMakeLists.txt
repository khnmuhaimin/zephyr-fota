# Copyright (c) 2021 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

# add_subdirectory_ifdef(CONFIG_EXAMPLE_SENSOR example_sensor)

# Stuff I added
add_subdirectory_ifdef(CONFIG_EEE4022S_A76XX eee4022s_a76xx)
# end stuff I added
