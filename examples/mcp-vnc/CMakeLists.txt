# Copyright (C) 2025 Signal Slot Inc.
# SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(mcp-vnc LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(NOT DEFINED INSTALL_EXAMPLESDIR)
    set(INSTALL_EXAMPLESDIR "examples")
endif()

set(INSTALL_EXAMPLEDIR "${INSTALL_EXAMPLESDIR}/qtvncclient/mcp-vnc")

find_package(Qt6 REQUIRED COMPONENTS Core Network Widgets VncClient McpServer)

qt_standard_project_setup()

qt_add_executable(mcp-vnc
    main.cpp
    tools.h tools.cpp
    vncwidget.h vncwidget.cpp
)

set_target_properties(mcp-vnc PROPERTIES
    WIN32_EXECUTABLE FALSE
    MACOSX_BUNDLE FALSE
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(mcp-vnc PRIVATE
    Qt::Core
    Qt::Network
    Qt::Widgets
    Qt::VncClient
    Qt::McpServer
)

install(TARGETS mcp-vnc
    RUNTIME DESTINATION "${INSTALL_EXAMPLEDIR}"
    BUNDLE DESTINATION "${INSTALL_EXAMPLEDIR}"
    LIBRARY DESTINATION "${INSTALL_EXAMPLEDIR}"
)
