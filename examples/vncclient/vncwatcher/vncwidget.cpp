// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include "vncwidget.h"

#include <QtGui/QPainter>
#include <QtGui/QPaintEvent>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>

class VncWidget::Private
{
public:
    Private(VncWidget *parent);
    
    void paint(const QRect &rect);
    
private:
    VncWidget *q;
    
public:
    QVncClient *client = nullptr;
};

VncWidget::Private::Private(VncWidget *parent)
    : q(parent)
{
    q->setMouseTracking(true);
}

void VncWidget::Private::paint(const QRect &rect)
{
    QPainter p(q);
    if (!client || !client->socket() || client->socket()->state() != QTcpSocket::ConnectedState) {
        p.setOpacity(0.5);
        p.fillRect(rect, Qt::lightGray);
        return;
    }
    
    p.drawImage(rect, client->image(), rect);
}

VncWidget::VncWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

VncWidget::~VncWidget() = default;

QVncClient *VncWidget::client() const
{
    return d->client;
}

void VncWidget::setClient(QVncClient *client)
{
    if (d->client == client)
        return;
        
    if (d->client) {
        disconnect(d->client, nullptr, this, nullptr);
    }
    
    d->client = client;
    
    if (client) {
        connect(client, &QVncClient::framebufferSizeChanged, this, [this](int width, int height) {
            setFixedSize(width, height);
            update();
        });
        
        connect(client, &QVncClient::imageChanged, this, [this](const QRect &rect) {
            update(rect);
        });
        
        connect(client, &QVncClient::connectionStateChanged, this, [this](bool connected) {
            repaint();
            if (connected)
                window()->raise();
        });
    }
    
    emit clientChanged(client);
}

void VncWidget::keyPressEvent(QKeyEvent *e)
{
    if (d->client) {
        d->client->handleKeyEvent(e);
    }
}

void VncWidget::keyReleaseEvent(QKeyEvent *e)
{
    if (d->client) {
        d->client->handleKeyEvent(e);
    }
}

void VncWidget::mousePressEvent(QMouseEvent *e)
{
    if (d->client) {
        d->client->handlePointerEvent(e);
    }
}

void VncWidget::mouseMoveEvent(QMouseEvent *e)
{
    if (d->client) {
        d->client->handlePointerEvent(e);
    }
}

void VncWidget::mouseReleaseEvent(QMouseEvent *e)
{
    if (d->client) {
        d->client->handlePointerEvent(e);
    }
}

void VncWidget::paintEvent(QPaintEvent *e)
{
    d->paint(e->rect());
}
