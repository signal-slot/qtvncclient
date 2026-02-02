# Copyright (C) 2025 Signal Slot Inc.
# SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

qt_examples_build_begin(EXTERNAL_BUILD)

add_subdirectory(vncclient)

find_package(Qt6 QUIET COMPONENTS McpServer)
if(Qt6McpServer_FOUND)
    add_subdirectory(mcp-vnc)
endif()

qt_examples_build_end()
