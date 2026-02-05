// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#ifndef TOOLS_H
#define TOOLS_H

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>
#include <QtGui/QImage>

class QVncClient;
class QWidget;
class VncWidget;

class Tools : public QObject
{
    Q_OBJECT
public:
    explicit Tools(QObject *parent = nullptr);
    ~Tools() override;

    QVncClient *client() const;
    void setPreviewWidget(VncWidget *widget);

    Q_INVOKABLE void connect(const QString &host, int port, const QString &password = QString());
    Q_INVOKABLE void disconnect();
    Q_INVOKABLE QImage screenshot(int x = 0, int y = 0, int width = -1, int height = -1) const;
    Q_INVOKABLE bool save(const QString &filePath, int x = 0, int y = 0, int width = -1, int height = -1) const;
    Q_INVOKABLE QString status() const;
    Q_INVOKABLE void mouseMove(int x, int y);
    Q_INVOKABLE void mouseClick(int x, int y, int button = 1);
    Q_INVOKABLE void dragAndDrop(int x, int y, int button = 1);
    Q_INVOKABLE void sendKey(int keysym, bool down);
    Q_INVOKABLE void sendText(const QString &text);
    Q_INVOKABLE void setPreview(bool visible);
    Q_INVOKABLE void setInteractive(bool enabled);

private:
    class Private;
    QScopedPointer<Private> d;
};

#endif // TOOLS_H
