// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include "tools.h"
#include "vncwidget.h"
#include <QtVncClient/QVncClient>
#include <QtNetwork/QTcpSocket>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>

class Tools::Private
{
public:
    QTcpSocket socket;
    QVncClient vncClient;
    VncWidget *previewWidget = nullptr;
    bool previewEnabled = false;
    QPointF pos;
};

Tools::Tools(QObject *parent)
    : QObject(parent)
    , d(new Private)
{
    d->vncClient.setSocket(&d->socket);
    QObject::connect(&d->vncClient, &QVncClient::connectionStateChanged, this, [this](bool connected) {
        if (!d->previewWidget)
            return;
        if (connected && d->previewEnabled)
            d->previewWidget->show();
        else if (!connected)
            d->previewWidget->hide();
    });
}

Tools::~Tools() = default;

QVncClient *Tools::client() const
{
    return &d->vncClient;
}

void Tools::setPreviewWidget(VncWidget *widget)
{
    d->previewWidget = widget;
}

void Tools::connect(const QString &host, int port, const QString &password)
{
    if (!password.isEmpty())
        d->vncClient.setPassword(password);
    d->socket.connectToHost(host, port);
}

void Tools::disconnect()
{
    d->socket.disconnectFromHost();
}

QImage Tools::screenshot(int x, int y, int width, int height) const
{
    const QImage &image = d->vncClient.image();
    if (width < 0)
        width = image.width() - x;
    if (height < 0)
        height = image.height() - y;
    if (x == 0 && y == 0 && width == image.width() && height == image.height())
        return image;
    return image.copy(x, y, width, height);
}

bool Tools::save(const QString &filePath, int x, int y, int width, int height) const
{
    return screenshot(x, y, width, height).save(filePath);
}

QString Tools::status() const
{
    if (d->socket.state() == QTcpSocket::ConnectedState) {
        return QStringLiteral("connected to %1:%2 (%3x%4)")
            .arg(d->socket.peerName())
            .arg(d->socket.peerPort())
            .arg(d->vncClient.framebufferWidth())
            .arg(d->vncClient.framebufferHeight());
    }
    return QStringLiteral("disconnected");
}

void Tools::mouseMove(int x, int y)
{
    d->pos = QPointF(x, y);
    QMouseEvent event(QEvent::MouseMove, d->pos, d->pos, Qt::NoButton, Qt::NoButton, Qt::NoModifier);
    d->vncClient.handlePointerEvent(&event);
}

void Tools::mouseClick(int x, int y, int button)
{
    Qt::MouseButton qtButton = Qt::LeftButton;
    if (button == 2)
        qtButton = Qt::MiddleButton;
    else if (button == 3)
        qtButton = Qt::RightButton;

    d->pos = QPointF(x, y);

    // Press
    QMouseEvent pressEvent(QEvent::MouseButtonPress, d->pos, d->pos, qtButton, qtButton, Qt::NoModifier);
    d->vncClient.handlePointerEvent(&pressEvent);

    // Release
    QMouseEvent releaseEvent(QEvent::MouseButtonRelease, d->pos, d->pos, Qt::NoButton, Qt::NoButton, Qt::NoModifier);
    d->vncClient.handlePointerEvent(&releaseEvent);
}

void Tools::dragAndDrop(int x, int y, int button)
{
    Qt::MouseButton qtButton = Qt::LeftButton;
    if (button == 2)
        qtButton = Qt::MiddleButton;
    else if (button == 3)
        qtButton = Qt::RightButton;

    const QPointF endPos(x, y);

    // Press at current position
    QMouseEvent pressEvent(QEvent::MouseButtonPress, d->pos, d->pos, qtButton, qtButton, Qt::NoModifier);
    d->vncClient.handlePointerEvent(&pressEvent);

    // Move to end position with button held
    QMouseEvent moveEvent(QEvent::MouseMove, endPos, endPos, Qt::NoButton, qtButton, Qt::NoModifier);
    d->vncClient.handlePointerEvent(&moveEvent);

    // Release at end position
    QMouseEvent releaseEvent(QEvent::MouseButtonRelease, endPos, endPos, qtButton, Qt::NoButton, Qt::NoModifier);
    d->vncClient.handlePointerEvent(&releaseEvent);

    d->pos = endPos;
}

void Tools::sendKey(int keysym, bool down)
{
    QKeyEvent event(down ? QEvent::KeyPress : QEvent::KeyRelease, keysym, Qt::NoModifier);
    d->vncClient.handleKeyEvent(&event);
}

void Tools::sendText(const QString &text)
{
    for (const QChar &ch : text) {
        int keysym = ch.unicode();
        QKeyEvent pressEvent(QEvent::KeyPress, 0, Qt::NoModifier, QString(ch));
        d->vncClient.handleKeyEvent(&pressEvent);
        QKeyEvent releaseEvent(QEvent::KeyRelease, 0, Qt::NoModifier, QString(ch));
        d->vncClient.handleKeyEvent(&releaseEvent);
    }
}

void Tools::setPreview(bool visible)
{
    d->previewEnabled = visible;
    if (!d->previewWidget)
        return;
    if (visible && d->socket.state() == QTcpSocket::ConnectedState)
        d->previewWidget->show();
    else
        d->previewWidget->hide();
}

void Tools::setInteractive(bool enabled)
{
    if (d->previewWidget)
        d->previewWidget->setInteractive(enabled);
}
