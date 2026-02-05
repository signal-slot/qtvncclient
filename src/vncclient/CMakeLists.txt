# Copyright (C) 2025 Signal Slot Inc.
# SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

# Option to enable ZLIB support (for Tight and ZRLE encoding)
option(VNCCLIENT_USE_ZLIB "Enable ZLIB compression support" ON)

# Find dependencies for Tight encoding
if(VNCCLIENT_USE_ZLIB)
    find_package(ZLIB)
    if(ZLIB_FOUND)
        add_definitions(-DUSE_ZLIB)
    endif()
endif()
 
qt_internal_add_module(VncClient
    SOURCES
        qtvncclientglobal.h
        qvncclient.cpp
        qtvncclientlogging.cpp
        qvncclient.h
        qvncdes_p.h
    INCLUDE_DIRECTORIES
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC_LIBRARIES
        Qt::Core
        Qt::Network
        Qt::Gui
)

# Add ZLIB library if found
if(VNCCLIENT_USE_ZLIB AND ZLIB_FOUND)
    target_link_libraries(VncClient PRIVATE ZLIB::ZLIB)
endif()

