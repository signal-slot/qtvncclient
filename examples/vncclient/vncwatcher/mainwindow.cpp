// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtVncClient/QVncClient>
#include "vncwidget.h"

#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtWidgets/QPushButton>
#include <QtNetwork/QTcpSocket>

class MainWindow::Private : public Ui::MainWindow
{
public:
    Private(::MainWindow *parent);
    ~Private();

private:
    ::MainWindow *q;
    QSettings settings;
    QTcpSocket socket;
    QTimer timer;
    QVncClient vncClient;
};

MainWindow::Private::Private(::MainWindow *parent)
    : q(parent)
    , vncClient(parent)
{
    setupUi(q);
    
    // Connect input components
    connect(server, &QLineEdit::returnPressed, q, [this]() {
        watch->animateClick();
    });
    connect(port, &SpinBox::returnPressed, q, [this]() {
        watch->animateClick();
    });
    connect(password, &QLineEdit::returnPressed, q, [this]() {
        watch->animateClick();
    });
    
    // Set up the VNC client
    stackedWidget->setCurrentIndex(0);
    vncClient.setSocket(&socket);
    
    // Important: Replace QVncClient from UI with QVncWidget
    // Cast vnc widget reference from UI to our VncWidget type
    VncWidget *vncWidget = static_cast<VncWidget*>(vnc);
    vncWidget->setClient(&vncClient);
    
    // Load saved settings
    settings.beginGroup("Window");
    q->restoreGeometry(settings.value("small_geometry").toByteArray());
    server->setText(settings.value("server", server->text()).toString());
    port->setValue(settings.value("port", port->value()).toInt());
    settings.setValue("port", port->value());
    settings.endGroup();
    
    // Set up reconnection logic
    connect(&socket, &QTcpSocket::connected, &timer, &QTimer::stop);
    connect(&socket, &QTcpSocket::disconnected, &timer, QOverload<>::of(&QTimer::start));
    timer.setInterval(5000);
    connect(&timer, &QTimer::timeout, q, [this]() {
        socket.connectToHost(server->text(), port->value());
    });
    if (socket.state() == QTcpSocket::UnconnectedState)
        timer.start();
    
    // Handle server requesting password when none was set
    connect(&vncClient, &QVncClient::passwordRequested, q, [this]() {
        stackedWidget->setCurrentIndex(0);
        password->setFocus();
    });

    // Connect watch button
    connect(watch, &QPushButton::clicked, q, [this]() {
        settings.beginGroup("Window");
        settings.setValue("small_geometry", q->saveGeometry());
        settings.setValue("server", server->text());
        settings.setValue("port", port->value());
        vncClient.setPassword(password->text());
        socket.connectToHost(server->text(), port->value());
        stackedWidget->setCurrentIndex(1);
        vnc->setFocus();
        q->restoreGeometry(settings.value("large_geometry").toByteArray());
        q->setWindowTitle(QString("%1:%2").arg(server->text()).arg(port->value()));
        settings.endGroup();
    });
}

MainWindow::Private::~Private()
{
    settings.beginGroup("Window");
    switch (stackedWidget->currentIndex()) {
    case 0:
        settings.setValue("small_geometry", q->saveGeometry());
        break;
    case 1:
        settings.setValue("large_geometry", q->saveGeometry());
        break;
    }
    settings.endGroup();
}

MainWindow::MainWindow(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{}

MainWindow::~MainWindow() = default;
