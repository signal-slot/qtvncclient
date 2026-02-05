// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
#ifndef QVNCCLIENT_H
#define QVNCCLIENT_H

#include <QtVncClient/qtvncclientglobal.h>
#include <QtNetwork/QTcpSocket>
#include <QtGui/QImage>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtCore/QScopedPointer>

QT_BEGIN_NAMESPACE

class Q_VNCCLIENT_EXPORT QVncClient : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QTcpSocket *socket READ socket WRITE setSocket NOTIFY socketChanged)
    Q_PROPERTY(ProtocolVersion protocolVersion READ protocolVersion NOTIFY protocolVersionChanged)
    Q_PROPERTY(SecurityType securityType READ securityType NOTIFY securityTypeChanged)
    Q_PROPERTY(QString password READ password WRITE setPassword NOTIFY passwordChanged)
public:
    enum ProtocolVersion {
        ProtocolVersionUnknown,
        ProtocolVersion33 = 0x0303,
        ProtocolVersion37 = 0x0307,
        ProtocolVersion38 = 0x0308,
    };
    Q_ENUM(ProtocolVersion)
    
    enum SecurityType : qint8 {
        SecurityTypeUnknwon = -1,
        SecurityTypeInvalid = 0,
        SecurityTypeNone = 1,
        SecurityTypeVncAuthentication = 2,
        SecurityTypeRA2 = 5,
        SecurityTypeRA2ne = 6,
        SecurityTypeTight = 16,
        SecurityTypeUltra = 17,
        SecurityTypeTLS = 18,
        SecurityTypeVeNCrypt = 19,
        SecurityTypeGtkVncSasl = 20,
        SecurityTypeMd5HashAuthentication = 21,
        SecurityTypeColinDeanXvp = 22,
    };
    Q_ENUM(SecurityType)

    explicit QVncClient(QObject *parent = nullptr);
    ~QVncClient() override;

    QTcpSocket *socket() const;
    ProtocolVersion protocolVersion() const;
    SecurityType securityType() const;
    
    // Get framebuffer size
    int framebufferWidth() const;
    int framebufferHeight() const;
    
    // Get current image
    QImage image() const;
    QString password() const;

    // Process input events
    void handleKeyEvent(QKeyEvent *e);
    void handlePointerEvent(QMouseEvent *e);

public slots:
    void setSocket(QTcpSocket *socket);
    void setPassword(const QString &password);

private:
    void setProtocolVersion(ProtocolVersion protocolVersion);
    void setSecurityType(SecurityType securityType);

signals:
    void socketChanged(QTcpSocket *socket);
    void protocolVersionChanged(ProtocolVersion protocolVersion);
    void securityTypeChanged(SecurityType securityType);
    void framebufferSizeChanged(int width, int height);
    void imageChanged(const QRect &rect);
    void connectionStateChanged(bool connected);
    void passwordChanged(const QString &password);
    void passwordRequested();

private:
    class Private;
    QScopedPointer<Private> d;
};

QT_END_NAMESPACE

#endif // QVNCCLIENT_H
