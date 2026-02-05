# Copyright (C) 2025 Signal Slot Inc.
# SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(vnc-watcher LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(NOT DEFINED INSTALL_EXAMPLESDIR)
    set(INSTALL_EXAMPLESDIR "examples")
endif()

set(INSTALL_EXAMPLEDIR "${INSTALL_EXAMPLESDIR}/qtvncclient/vnc-watcher")

find_package(Qt6 REQUIRED COMPONENTS Widgets VncClient)

qt_standard_project_setup()

qt_add_executable(vnc-watcher
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    spinbox.cpp
    spinbox.h
    vncwidget.cpp
    vncwidget.h
)

set_target_properties(vnc-watcher PROPERTIES
    WIN32_EXECUTABLE FALSE
    MACOSX_BUNDLE TRUE
)

target_link_libraries(vnc-watcher PRIVATE
    Qt::VncClient
    Qt::Widgets
)

install(TARGETS vnc-watcher
    RUNTIME DESTINATION "${INSTALL_EXAMPLEDIR}"
    BUNDLE DESTINATION "${INSTALL_EXAMPLEDIR}"
    LIBRARY DESTINATION "${INSTALL_EXAMPLEDIR}"
)

