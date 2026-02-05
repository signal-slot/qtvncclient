// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#ifndef VNCWIDGET_H
#define VNCWIDGET_H

#include <QtWidgets/QWidget>
#include <QtVncClient/QVncClient>

class QKeyEvent;
class QMouseEvent;
class QPaintEvent;

class VncWidget : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(QVncClient *client READ client WRITE setClient NOTIFY clientChanged)

public:
    explicit VncWidget(QWidget *parent = nullptr);
    ~VncWidget() override;

    QVncClient *client() const;
    void setClient(QVncClient *client);

signals:
    void clientChanged(QVncClient *client);

protected:
    void keyPressEvent(QKeyEvent *e) override;
    void keyReleaseEvent(QKeyEvent *e) override;
    void mousePressEvent(QMouseEvent *e) override;
    void mouseMoveEvent(QMouseEvent *e) override;
    void mouseReleaseEvent(QMouseEvent *e) override;
    void paintEvent(QPaintEvent *e) override;

private:
    class Private;
    QScopedPointer<Private> d;
};

#endif // VNCWIDGET_H
