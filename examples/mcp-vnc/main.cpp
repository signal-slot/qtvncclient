// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include <QtWidgets/QApplication>
#include <QtMcpServer/QMcpServer>
#include "tools.h"
#include "vncwidget.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("MCP VNC Server");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("Signal Slot Inc.");
    app.setOrganizationDomain("signal-slot.co.jp");
    app.setQuitOnLastWindowClosed(false);

    QMcpServer server("stdio"_L1);
    auto *tools = new Tools(&server);
    server.registerToolSet(tools, {
        { "connect", "Connect to a VNC server" },
        { "connect/host", "Hostname or IP address of the VNC server" },
        { "connect/port", "Port number of the VNC server (default: 5900)" },
        { "connect/password", "Password for VNC authentication (optional)" },
        { "disconnect", "Disconnect from the VNC server" },
        { "screenshot", "Take a screenshot of the current VNC screen" },
        { "screenshot/x", "X coordinate of the region (default: 0)" },
        { "screenshot/y", "Y coordinate of the region (default: 0)" },
        { "screenshot/width", "Width of the region (default: -1 for full width)" },
        { "screenshot/height", "Height of the region (default: -1 for full height)" },
        { "save", "Save the current screenshot to a file" },
        { "save/filePath", "File path to save the screenshot (e.g., /tmp/screenshot.png)" },
        { "save/x", "X coordinate of the region (default: 0)" },
        { "save/y", "Y coordinate of the region (default: 0)" },
        { "save/width", "Width of the region (default: -1 for full width)" },
        { "save/height", "Height of the region (default: -1 for full height)" },
        { "status", "Get the current connection status" },
        { "mouseMove", "Move the mouse cursor to a position" },
        { "mouseMove/x", "X coordinate" },
        { "mouseMove/y", "Y coordinate" },
        { "mouseClick", "Click the mouse at a position" },
        { "mouseClick/x", "X coordinate" },
        { "mouseClick/y", "Y coordinate" },
        { "mouseClick/button", "Mouse button (1=left, 2=middle, 3=right, default: 1)" },
        { "dragAndDrop", "Drag from the current mouse position and drop at the given position. Call mouseMove first to set the start position." },
        { "dragAndDrop/x", "X coordinate of the drop position" },
        { "dragAndDrop/y", "Y coordinate of the drop position" },
        { "dragAndDrop/button", "Mouse button (1=left, 2=middle, 3=right, default: 1)" },
        { "sendKey", "Send a key event" },
        { "sendKey/keysym", "X11 keysym value" },
        { "sendKey/down", "true for key press, false for key release" },
        { "sendText", "Type text as if it were typed on the keyboard" },
        { "sendText/text", "Text to type" },
        { "setPreview", "Show or hide the live VNC preview window" },
        { "setPreview/visible", "true to show, false to hide" },
        { "setInteractive", "Enable or disable interactive mode on the preview window. When enabled, mouse and keyboard events on the preview window are forwarded to the VNC server. Default is off (view-only)." },
        { "setInteractive/enabled", "true to enable interactive mode, false to disable" },
    });
    server.start();

    VncWidget vncWidget;
    vncWidget.setClient(tools->client());
    vncWidget.setWindowTitle(app.applicationName());
    tools->setPreviewWidget(&vncWidget);

    return app.exec();
}
