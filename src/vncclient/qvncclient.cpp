// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

//
// QVncClient API Documentation
// ===========================
//
// This file implements the QVncClient class, which provides a VNC client implementation.
// 
// Class Overview:
// - QVncClient connects to VNC servers using a provided QTcpSocket
// - Handles protocol handshaking, authentication, and framebuffer updates
// - Provides an interface for sending input events to the VNC server
// - Emits signals when framebuffer is updated or connection state changes
//
// Protocol Support:
// - VNC Protocol version 3.3 (legacy)
// - Basic security types (None authentication)
// - Raw, Hextile, and ZRLE encoding methods
// - Keyboard and pointer (mouse) event handling
//
// Main Classes and Functions:
// - QVncClient: Main public API for client applications
//   - setSocket(): Sets the socket for VNC communication
//   - image(): Gets the current framebuffer image
//   - handleKeyEvent(): Forwards keyboard events to the server
//   - handlePointerEvent(): Forwards mouse events to the server
//
// See the detailed API documentation in:
// - src/vncclient/api_documentation.md (Markdown documentation)
// - src/vncclient/qvncclient.qdoc (QDoc format for Qt Help)
//
// For Qt Help integration, build with: qdoc src/vncclient/vncclient.qdocconf
//
#include "qvncclient.h"
#include "qvncdes_p.h"

#include <QtCore/QDebug>
#include <QtCore/QtEndian>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtGui/QPainter>

// Include for Tight encoding
#ifdef USE_ZLIB
#include <zlib.h>
#endif

/*!
    \internal
    \class QVncClient::Private
    \brief The Private class implements the VNC protocol details for QVncClient.
    
    This class handles the protocol-level communication including handshaking,
    security negotiation, encoding/decoding framebuffer updates, and sending
    input events to the VNC server.
*/
class QVncClient::Private
{
public:
    /*!
        \internal
        \enum QVncClient::Private::HandshakingState
        \brief States for the VNC protocol handshaking process.
        
        These states represent the different stages in establishing a VNC connection,
        from initial protocol version negotiation to the normal operation mode.
    */
    enum HandshakingState {
        ProtocolVersionState = 0x611, ///< Negotiating the protocol version
        SecurityState = 0x612,        ///< Negotiating security type
        SecurityResultState = 0x613,  ///< Processing security handshake result
        VncAuthenticationState = 0x614, ///< VNC authentication challenge-response
        ClientInitState = 0x631,      ///< Client initialization
        ServerInitState = 0x632,      ///< Server initialization
        WaitingState = 0x640,         ///< Normal operation state, waiting for server messages
    };

    /*!
        \internal
        \enum QVncClient::Private::ClientMessageType
        \brief Message types that a VNC client can send to the server.
        
        These constants represent the standard message types defined by the VNC protocol
        for client-to-server communication.
    */
    enum ClientMessageType : quint8 {
        SetPixelFormat = 0x00,           ///< Set the pixel format for framebuffer data
        SetEncodings = 0x02,             ///< Set the encoding types the client supports
        FramebufferUpdateRequest = 0x03, ///< Request an update of the framebuffer
    };

    /*!
        \internal
        \enum QVncClient::Private::ServerMessageType
        \brief Message types that a VNC server sends to the client.
        
        These constants represent the standard message types defined by the VNC protocol
        for server-to-client communication.
    */
    enum ServerMessageType {
        FramebufferUpdate = 0x00, ///< Server sends framebuffer update data
    };

    /*!
        \internal
        \enum QVncClient::Private::EncodingType
        \brief Encoding types supported for framebuffer updates.
        
        VNC supports multiple encoding types for framebuffer data. These values
        represent the standard encoding types as defined in the RFB protocol.
    */
    enum EncodingType {
        RawEncoding = 0, ///< Raw pixel data (no compression)
        CopyRect = 1,    ///< Copy rectangle from another area of the framebuffer
        RRE = 2,         ///< Rise-and-Run-length Encoding
        Hextile = 5,     ///< Hextile encoding (divides rect into 16x16 tiles)
        ZRLE = 16,       ///< ZRLE (Zlib Run-Length Encoding)
#ifdef USE_ZLIB
        Tight = 7,       ///< Tight encoding (with zlib compression and JPEG)
#endif
    };
    
    /*!
        \internal
        \enum QVncClient::Private::HextileSubencoding
        \brief Subencoding flags for the Hextile encoding method.
        
        Hextile encoding uses these bit flags to indicate how each tile is encoded.
        Multiple flags may be combined.
    */
    enum HextileSubencoding { 
        RawSubencoding = 1,      ///< Tile is encoded as raw pixel data
        BackgroundSpecified = 2, ///< Tile has background color specified 
        ForegroundSpecified = 4, ///< Tile has foreground color specified
        AnySubrects = 8,         ///< Tile contains subrectangles
        SubrectsColoured = 16    ///< Each subrect has its own color (otherwise foreground color)
    };

    /*!
        \internal
        \brief Constructs a private implementation object for QVncClient.
        \param parent The QVncClient instance that owns this Private implementation.
        
        Sets up key mappings for keyboard events and connects signals for handling
        socket events and protocol state changes.
    */
    Private(QVncClient *parent);

#ifdef USE_ZLIB
    /*!
        \internal
        \struct QVncClient::Private::TightData
        \brief Holds data for Tight encoding processing.
        
        This structure contains zlib streams and related configuration
        data for handling Tight encoding. ZLIB support is optional.
    */
    struct TightData {
        z_stream zlibStream[4];      ///< Zlib streams for compression channels
        bool zlibStreamActive[4];    ///< Whether each zlib stream is active
        int jpegQuality;             ///< JPEG quality level (0-100)
        int compressionLevel;        ///< Compression level (1-9)

        TightData() : jpegQuality(75), compressionLevel(6) {
            for (int i = 0; i < 4; i++) {
                zlibStreamActive[i] = false;
            }
        }
        
        ~TightData() {
            resetZlibStreams();
        }
        
        void resetZlibStreams() {
            for (int i = 0; i < 4; i++) {
                if (zlibStreamActive[i]) {
                    inflateEnd(&zlibStream[i]);
                    zlibStreamActive[i] = false;
                }
            }
        }
    };
#endif

    /*!
        \internal
        \struct QVncClient::Private::PixelFormat
        \brief Describes the pixel data format used in VNC communication.
        
        This structure follows the RFB protocol specification for pixel format
        descriptors. It specifies how pixel data is encoded, including bit depth,
        color channel information, and endianness.
    */
    struct PixelFormat {
        quint8 bitsPerPixel = 0;     ///< Bits per pixel (typically 8, 16, or 32)
        quint8 depth = 0;            ///< Color depth
        quint8 bigEndianFlag = 0;    ///< 1 if big-endian, 0 if little-endian
        quint8 trueColourFlag = 0;   ///< 1 if true color, 0 if color map
        quint16_be redMax;           ///< Maximum value for red channel
        quint16_be greenMax;         ///< Maximum value for green channel
        quint16_be blueMax;          ///< Maximum value for blue channel
        quint8 redShift = 0;         ///< Bit shift for red channel
        quint8 greenShift = 0;       ///< Bit shift for green channel
        quint8 blueShift = 0;        ///< Bit shift for blue channel
        quint8 padding1 = 0;         ///< Padding (unused)
        quint8 padding2 = 0;         ///< Padding (unused)
        quint8 padding3 = 0;         ///< Padding (unused)
    };

    /*!
        \internal
        \struct QVncClient::Private::Rectangle
        \brief Defines a rectangle in VNC protocol messages.
        
        Used for specifying regions of the framebuffer in update requests
        and framebuffer update messages.
    */
    struct Rectangle {
        quint16_be x;  ///< X-coordinate of the top-left corner
        quint16_be y;  ///< Y-coordinate of the top-left corner
        quint16_be w;  ///< Width of the rectangle
        quint16_be h;  ///< Height of the rectangle
    };

    /*!
        \internal
        \brief Handles a keyboard event and sends it to the VNC server.
        \param e The keyboard event to be processed and sent.
        
        Translates Qt key events to VNC protocol key events and sends them to the server.
    */
    void keyEvent(QKeyEvent *e);
    
    /*!
        \internal
        \brief Handles a mouse event and sends it to the VNC server.
        \param e The mouse event to be processed and sent.
        
        Translates Qt mouse events to VNC protocol pointer events and sends them to the server.
    */
    void pointerEvent(QMouseEvent *e);

private:
    void reset();

    /*!
        \internal
        \brief Checks if the connection to the server is valid.
        \return true if the socket is connected, false otherwise.
    */
    bool isValid() const {
        return socket && socket->state() == QTcpSocket::ConnectedState;
    }
    
    /*!
        \internal
        \brief Reads and processes data from the socket based on the current state.
        
        This is the main state machine dispatcher that directs incoming data to the
        appropriate parsing function based on the current protocol state.
    */
    void read();
    
    /*!
        \internal
        \brief Reads a binary structure from the socket.
        \param out Pointer to the structure to be filled with data.
        \tparam T The type of structure to read.
        
        Reads binary data from the socket directly into the provided structure.
    */
    template<class T>
    void read(T *out) {
        if (isValid())
            socket->read(reinterpret_cast<char *>(out), sizeof(T));
    }
    
    /*!
        \internal
        \brief Writes a string to the socket.
        \param out The null-terminated string to write.
        
        Sends string data to the VNC server.
    */
    void write(const char *out) {
        if (isValid())
            socket->write(out, strlen(out));
    }
    
    /*!
        \internal
        \brief Writes binary data to the socket.
        \param out The binary data to write.
        \param len The length of the data in bytes.
        
        Sends raw binary data to the VNC server.
    */
    void write(const unsigned char *out, int len) {
        if (isValid())
            socket->write(reinterpret_cast<const char *>(out), len);
    }
    
    /*!
        \internal
        \brief Writes a binary structure to the socket.
        \param out The structure to write.
        \tparam T The type of structure to write.
        
        Sends binary structure data to the VNC server.
    */
    template<class T>
    void write(const T &out) {
        if (isValid())
            socket->write(reinterpret_cast<const char *>(&out), sizeof(T));
    }

    /// Handshaking Messages
    
    /*!
        \internal
        \brief Parses the protocol version from the server.
        
        Reads the RFB protocol version string from the server and sets the
        appropriate version enum value.
    */
    void parseProtocolVersion();
    
    /*!
        \internal
        \brief Handles protocol version changes.
        \param protocolVersion The new protocol version.
        
        Called when the protocol version is set or changes. Responds to the
        server with the appropriate version response and updates internal state.
    */
    void protocolVersionChanged(ProtocolVersion protocolVersion);
    
    /*!
        \internal
        \brief Dispatches to the appropriate security parsing function.
        
        Selects the security parsing method based on the negotiated protocol version.
    */
    void parseSecurity();
    
    /*!
        \internal
        \brief Parses security data for protocol version 3.3.
        
        Handles the security type message format specific to VNC protocol version 3.3.
    */
    void parseSecurity33();
    
    /*!
        \internal
        \brief Parses security data for protocol version 3.7 and later.
        
        Handles the security type message format for VNC protocol versions 3.7 and 3.8.
    */
    void parseSecurity37();
    
    /*!
        \internal
        \brief Handles security type changes.
        \param securityType The new security type.
        
        Called when the security type is set or changes. Responds to the server
        with the appropriate security handshake and updates internal state.
    */
    void securityTypeChanged(SecurityType securityType);
    
    /*!
        \internal
        \brief Parses the reason for a security failure.
        
        Reads and logs the reason string provided by the server when security negotiation fails.
    */
    void parseSecurityReason();
    void parseVncAuthentication();
    void sendVncAuthResponse();

    /*!
        \internal
        \brief Parses the security result message.

        The server sends a 4-byte result after authentication.
        0 = success, non-zero = failure (3.8 includes a reason string).
    */
    void parseSecurityResult();

    // Initialisation Messages
    
    /*!
        \internal
        \brief Sends the client initialization message.
        
        Sends the client initialization message to the server, indicating whether
        the connection will be shared.
    */
    void clientInit();
    
    /*!
        \internal
        \brief Parses the server initialization message.
        
        Processes the server initialization data, including framebuffer dimensions,
        pixel format, and server name.
    */
    void parserServerInit();

    // Client to server messages
    
    /*!
        \internal
        \brief Sends a SetPixelFormat message to the server.
        
        Configures the pixel format that the server should use when sending
        framebuffer updates.
    */
    void setPixelFormat();
    
    /*!
        \internal
        \brief Sends a SetEncodings message to the server.
        \param encodings List of encoding types the client supports.
        
        Tells the server which encoding types the client prefers for framebuffer updates.
    */
    void setEncodings(const QList<qint32> &encodings);
    
    /*!
        \internal
        \brief Sends a FramebufferUpdateRequest message to the server.
        \param incremental If true, only changed parts of the framebuffer are requested.
        \param rect The rectangle to update, or empty for the entire framebuffer.
        
        Requests the server to send framebuffer updates for the specified region.
    */
    void framebufferUpdateRequest(bool incremental = true, const QRect &rect = QRect());

    // Server to client messages
    
    /*!
        \internal
        \brief Parses and dispatches incoming server messages.
        
        Reads the message type from the socket and calls the appropriate handler.
    */
    void parseServerMessages();
    
    /*!
        \internal
        \brief Processes a framebuffer update message.
        
        Reads the number of rectangles and processes each one based on its encoding type.
    */
    void framebufferUpdate();
    void processFramebufferRects();
    
    /*!
        \internal
        \brief Handles raw-encoded rectangle data.
        \param rect The rectangle dimensions.
        
        Processes uncompressed pixel data for the specified rectangle.
    */
    bool handleRawEncoding(const Rectangle &rect);
    bool handleHextileEncoding(const Rectangle &rect);
#ifdef USE_ZLIB
    bool handleTightEncoding(const Rectangle &rect);
#endif
    
    /*!
        \internal
        \brief Processes a JPEG-compressed rectangle in Tight encoding.
        \param rect The rectangle dimensions.
        \param dataLength The length of the JPEG data in bytes.
        \return true if successful, false if there was an error.
        
        Reads and decompresses JPEG image data for a rectangle in Tight encoding.
    */
    bool handleTightJpeg(const Rectangle &rect, int dataLength);
    
#ifdef USE_ZLIB
    /*!
        \internal
        \brief Decompresses zlib data for Tight encoding.
        \param rect The rectangle dimensions.
        \param stream The zlib stream to use.
        \param data The compressed data.
        \param dataLength The length of the compressed data.
        \param expectedBytes The expected size of the decompressed data.
        \return The decompressed data, or an empty array on error.
        
        Decompresses zlib-compressed data for a Tight-encoded rectangle.
    */
    QByteArray decompressTightData(int streamId, const QByteArray &data, int expectedBytes);
#endif

    /*!
        \internal
        \brief Handles ZRLE-encoded rectangle data.
        \param rect The rectangle dimensions.
        
        Processes ZRLE (Zlib Run-Length Encoding) data for the specified rectangle.
    */
    bool handleZRLEEncoding(const Rectangle &rect);

private:
    QVncClient *q;                              ///< Pointer to the public class
    QTcpSocket *prev = nullptr;                 ///< Previous socket for cleanup
    HandshakingState state = ProtocolVersionState; ///< Current protocol state
    bool reading = false;                           ///< Reentrancy guard for read()

    // Framebuffer update state for non-blocking processing
    struct {
        int totalRects = 0;
        int currentRect = 0;
        Rectangle rect;
        int encoding = -1;
        bool active = false;       ///< Currently processing a framebuffer update
        bool rectHeaderRead = false; ///< Current rect header has been read
        // Hextile resume state
        int hextileTY = 0;
        int hextileTX = 0;
        quint32 hextileBG = 0;
        quint32 hextileFG = 0;
    } fbu;
    PixelFormat pixelFormat;                    ///< Current pixel format
    QMap<int, quint32> keyMap;                  ///< Map from Qt keys to VNC key codes
public:
    QTcpSocket *socket = nullptr;               ///< Socket for VNC communication
#ifdef USE_ZLIB
    QScopedPointer<TightData> tightData;        ///< Data for Tight encoding
    z_stream zrleStream;
    bool zrleStreamActive = false;
#endif
    ProtocolVersion protocolVersion = ProtocolVersionUnknown; ///< Current protocol version
    SecurityType securityType = SecurityTypeUnknwon;         ///< Current security type
    QString password;                             ///< Stored password for VNC authentication
    QByteArray vncChallenge;                     ///< Stored challenge for deferred VNC auth
    QImage image;                               ///< Image containing the framebuffer
    int frameBufferWidth = 0;                   ///< Framebuffer width
    int frameBufferHeight = 0;                  ///< Framebuffer height
};

/*!
    \internal
    Constructs the private implementation with keyboard mapping and signal connections.
    
    \param parent The QVncClient instance that owns this implementation.
*/
QVncClient::Private::Private(QVncClient *parent)
    : q(parent)
#ifdef USE_ZLIB
    , tightData(new TightData())
#endif
{
    const QList<quint32> keyList {
        // Key mappings
        Qt::Key_Backspace, 0xff08,
        Qt::Key_Tab, 0xff09,
        Qt::Key_Return, 0xff0d,
        Qt::Key_Enter, 0xff0d,
        Qt::Key_Insert, 0xff63,
        Qt::Key_Delete, 0xffff,
        Qt::Key_Home, 0xff50,
        Qt::Key_End, 0xff57,
        Qt::Key_PageUp, 0xff55,
        Qt::Key_PageDown, 0xff56,
        Qt::Key_Left, 0xff51,
        Qt::Key_Up, 0xff52,
        Qt::Key_Right, 0xff53,
        Qt::Key_Down, 0xff54,
        Qt::Key_F1, 0xffbe,
        Qt::Key_F2, 0xffbf,
        Qt::Key_F3, 0xffc0,
        Qt::Key_F4, 0xffc1,
        Qt::Key_F5, 0xffc2,
        Qt::Key_F6, 0xffc3,
        Qt::Key_F7, 0xffc4,
        Qt::Key_F8, 0xffc5,
        Qt::Key_F9, 0xffc6,
        Qt::Key_F10, 0xffc7,
        Qt::Key_F11, 0xffc8,
        Qt::Key_F12, 0xffc9,
        Qt::Key_Shift, 0xffe1,
        Qt::Key_Control, 0xffe3,
        Qt::Key_Meta, 0xffe7,
        Qt::Key_Alt, 0xffe9
    };
    for (int i = 0; i < keyList.length(); i+=2) {
        keyMap.insert(static_cast<int>(keyList.at(i)), keyList.at(i+1));
    }

    connect(q, &QVncClient::socketChanged, q, [this](QTcpSocket *socket) {
        if (prev) {
            disconnect(prev, nullptr, q, nullptr);
        }
        reset ();

        if (socket) {
            connect(socket, &QTcpSocket::connected, q, [this]() {
                emit q->connectionStateChanged(true);
                qCInfo(lcVncClient) << "Connected to VNC server";
                state = ProtocolVersionState;
                q->setProtocolVersion(ProtocolVersionUnknown);
                q->setSecurityType(SecurityTypeUnknwon);
                read();
            });
            connect(socket, &QTcpSocket::disconnected, q, [this, socket]() {
                qCInfo(lcVncClient) << "Disconnected from VNC server";
                emit q->connectionStateChanged(false);
                
                reset();
            });
            connect(socket, &QTcpSocket::readyRead, q, [this]() {
                read();
            });
        }
        prev = socket;
    });

    connect(q, &QVncClient::protocolVersionChanged, q, [this](ProtocolVersion protocolVersion) {
        protocolVersionChanged(protocolVersion);
    });
    connect(q, &QVncClient::securityTypeChanged, q, [this](SecurityType securityType) {
        securityTypeChanged(securityType);
    });
    connect(q, &QVncClient::passwordChanged, q, [this](const QString &) {
        if (state == VncAuthenticationState && !vncChallenge.isEmpty() && !password.isEmpty())
            sendVncAuthResponse();
    });
}

void QVncClient::Private::reset()
{
    state = ProtocolVersionState;
    q->setProtocolVersion(ProtocolVersionUnknown);
    q->setSecurityType(SecurityTypeUnknwon);
    vncChallenge.clear();
    fbu.active = false;
    frameBufferWidth = 0;
    frameBufferHeight = 0;
    image = QImage();
#ifdef USE_ZLIB
    if (zrleStreamActive) { inflateEnd(&zrleStream); zrleStreamActive = false; }
#endif
    emit q->framebufferSizeChanged(0, 0);
}

/*!
    \internal
    Main state machine dispatcher for handling incoming socket data based on the current protocol state.
*/
void QVncClient::Private::read()
{
    if (reading)
        return;
    reading = true;
    switch (state) {
    case ProtocolVersionState:
        parseProtocolVersion();
        break;
    case SecurityState:
        parseSecurity();
        break;
    case VncAuthenticationState:
        parseVncAuthentication();
        break;
    case SecurityResultState:
        parseSecurityResult();
        break;
    case ServerInitState:
        parserServerInit();
        break;
    case WaitingState:
        parseServerMessages();
        break;
    default:
        qDebug() << socket->readAll();
        break;
    }
    reading = false;
    // Re-enter if there is buffered data we can still make progress on.
    // Skip when waiting for more data mid-FBU to avoid a spin loop.
    if (socket && socket->bytesAvailable() > 0 && !fbu.active)
        QMetaObject::invokeMethod(q, [this]() { read(); }, Qt::QueuedConnection);
}

#ifdef USE_ZLIB
/*!
    \internal
    Handles Tight-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    Tight encoding is a complex encoding that can use zlib compression, JPEG compression,
    or various subencodings for efficient representation of framebuffer data.
*/
bool QVncClient::Private::handleTightEncoding(const Rectangle &rect)
{
    if (socket->bytesAvailable() < 1) return false;

    // Calculate TPIXEL size: 3 bytes when bpp=32, trueColor, all maxes == 255
    const int tpixelSize = (pixelFormat.bitsPerPixel == 32 && pixelFormat.trueColourFlag
        && pixelFormat.redMax == 255 && pixelFormat.greenMax == 255
        && pixelFormat.blueMax == 255) ? 3 : (pixelFormat.bitsPerPixel / 8);

    // Helper to read a TPIXEL from a byte buffer
    auto readTPixel = [&](const char *data, int &off) -> quint32 {
        quint32 color = 0;
        if (tpixelSize == 3) {
            if (pixelFormat.bigEndianFlag) {
                color = (static_cast<quint8>(data[off]) << 16)
                      | (static_cast<quint8>(data[off + 1]) << 8)
                      | static_cast<quint8>(data[off + 2]);
            } else {
                color = static_cast<quint8>(data[off])
                      | (static_cast<quint8>(data[off + 1]) << 8)
                      | (static_cast<quint8>(data[off + 2]) << 16);
            }
        } else if (tpixelSize == 4) {
            memcpy(&color, data + off, 4);
        } else if (tpixelSize == 2) {
            quint16 c16; memcpy(&c16, data + off, 2); color = c16;
        } else {
            color = static_cast<quint8>(data[off]);
        }
        off += tpixelSize;
        return color;
    };

    auto toRgb = [&](quint32 color) -> QRgb {
        const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
        const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
        const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
        return qRgb(r, g, b);
    };

    // Parse VNC compact length from a byte buffer at given offset.
    // Returns bytes consumed, or 0 if not enough data.
    auto parseCompactLength = [](const QByteArray &buf, int off, int *length) -> int {
        if (buf.size() <= off) return 0;
        quint8 b1 = static_cast<quint8>(buf.at(off));
        if (!(b1 & 0x80)) { *length = b1; return 1; }
        if (buf.size() <= off + 1) return 0;
        quint8 b2 = static_cast<quint8>(buf.at(off + 1));
        if (!(b2 & 0x80)) { *length = (b1 & 0x7F) | (b2 << 7); return 2; }
        if (buf.size() <= off + 2) return 0;
        quint8 b3 = static_cast<quint8>(buf.at(off + 2));
        *length = (b1 & 0x7F) | ((b2 & 0x7F) << 7) | (b3 << 14);
        return 3;
    };

    // Peek enough to parse any Tight header (ctrl + filter + palette + compact len)
    const qint64 peekSize = qMin(socket->bytesAvailable(), qint64(1 + 1 + 1 + 256 * tpixelSize + 3));
    const QByteArray peek = socket->peek(peekSize);
    if (peek.isEmpty()) return false;

    const quint8 compControl = static_cast<quint8>(peek.at(0));

    // Process stream reset flags (bits 0-3)
    for (int i = 0; i < 4; i++) {
        if ((compControl & (1 << i)) && tightData->zlibStreamActive[i]) {
            inflateEnd(&tightData->zlibStream[i]);
            tightData->zlibStreamActive[i] = false;
        }
    }

    // Extract compression type from bits 4-7
    const int compType = compControl >> 4;

    if (compType == 0x08) {
        // --- Fill compression: 1 TPIXEL, no compact length, no zlib ---
        const qint64 totalNeeded = 1 + tpixelSize;
        if (socket->bytesAvailable() < totalNeeded) return false;

        socket->read(1); // control byte
        QByteArray pixelData = socket->read(tpixelSize);
        int off = 0;
        QRgb rgb = toRgb(readTPixel(pixelData.constData(), off));
        for (int y = 0; y < rect.h; y++)
            for (int x = 0; x < rect.w; x++)
                image.setPixel(rect.x + x, rect.y + y, rgb);
        return true;

    } else if (compType == 0x09) {
        // --- JPEG compression: compact length + JPEG data ---
        int dataLength = 0;
        int lenBytes = parseCompactLength(peek, 1, &dataLength);
        if (lenBytes == 0) return false;

        const qint64 totalNeeded = 1 + lenBytes + dataLength;
        if (socket->bytesAvailable() < totalNeeded) return false;

        socket->read(1);        // control byte
        socket->read(lenBytes); // compact length bytes
        handleTightJpeg(rect, dataLength);
        return true;

    } else {
        // --- Basic compression (compType 0-7) ---
        const int streamId = compType & 0x03;
        const bool hasFilter = (compType & 0x04) != 0;

        int off = 1; // past control byte
        int filterId = 0; // default: Copy
        int numColors = 0;
        int paletteDataBytes = 0;

        if (hasFilter) {
            if (peek.size() <= off) return false;
            filterId = static_cast<quint8>(peek.at(off));
            off++;
        }

        if (filterId == 1) { // Palette filter
            if (peek.size() <= off) return false;
            numColors = static_cast<quint8>(peek.at(off)) + 1;
            off++;
            paletteDataBytes = numColors * tpixelSize;
            if (peek.size() < off + paletteDataBytes) return false;
            off += paletteDataBytes;
        }

        // Calculate uncompressed data size
        int dataSize = 0;
        if (filterId == 1) {
            dataSize = (numColors <= 2) ? (((rect.w + 7) / 8) * rect.h)
                                        : (rect.w * rect.h);
        } else {
            // Copy (0) or Gradient (2)
            dataSize = rect.w * rect.h * tpixelSize;
        }

        qint64 totalNeeded;
        int compressedLength = 0;
        int lenBytes = 0;

        if (dataSize < 12) {
            // Small data: sent raw, no compact length, no zlib
            totalNeeded = off + dataSize;
        } else {
            // Larger data: compact length + zlib compressed
            lenBytes = parseCompactLength(peek, off, &compressedLength);
            if (lenBytes == 0) return false;
            totalNeeded = off + lenBytes + compressedLength;
        }

        if (socket->bytesAvailable() < totalNeeded) return false;

        // --- All data available: consume ---
        socket->read(1); // control byte
        if (hasFilter) socket->read(1); // filter ID

        // Read palette
        QVector<QRgb> palette;
        if (filterId == 1) {
            socket->read(1); // numColors - 1
            QByteArray paletteRaw = socket->read(paletteDataBytes);
            palette.resize(numColors);
            int pOff = 0;
            for (int i = 0; i < numColors; i++)
                palette[i] = toRgb(readTPixel(paletteRaw.constData(), pOff));
        }

        // Read pixel data (raw or zlib-compressed)
        QByteArray pixelData;
        if (dataSize < 12) {
            pixelData = socket->read(dataSize);
        } else {
            socket->read(lenBytes); // compact length bytes
            QByteArray compressedData = socket->read(compressedLength);

            // Ensure zlib stream is initialized
            if (!tightData->zlibStreamActive[streamId]) {
                memset(&tightData->zlibStream[streamId], 0, sizeof(z_stream));
                tightData->zlibStream[streamId].zalloc = Z_NULL;
                tightData->zlibStream[streamId].zfree = Z_NULL;
                tightData->zlibStream[streamId].opaque = Z_NULL;
                inflateInit(&tightData->zlibStream[streamId]);
                tightData->zlibStreamActive[streamId] = true;
            }

            pixelData = decompressTightData(streamId, compressedData, dataSize);
            if (pixelData.isEmpty()) {
                qCWarning(lcVncClient) << "Failed to decompress Tight Basic data";
                return true;
            }
        }

        // --- Decode pixels based on filter ---
        if (filterId == 1) {
            // Palette filter
            if (numColors <= 2) {
                // 1 bit per pixel, rows padded to byte boundary
                int byteIdx = 0;
                for (int y = 0; y < rect.h; y++) {
                    int bitOff = 0;
                    for (int x = 0; x < rect.w; x++) {
                        if (byteIdx >= pixelData.size()) break;
                        int index = (static_cast<quint8>(pixelData.at(byteIdx)) >> (7 - bitOff)) & 1;
                        if (index < numColors)
                            image.setPixel(rect.x + x, rect.y + y, palette[index]);
                        if (++bitOff == 8) { bitOff = 0; byteIdx++; }
                    }
                    if (bitOff > 0) { byteIdx++; } // pad to byte boundary
                }
            } else {
                // 8 bits per pixel
                for (int y = 0; y < rect.h; y++) {
                    for (int x = 0; x < rect.w; x++) {
                        int idx = y * rect.w + x;
                        if (idx >= pixelData.size()) break;
                        int ci = static_cast<quint8>(pixelData.at(idx));
                        if (ci < numColors)
                            image.setPixel(rect.x + x, rect.y + y, palette[ci]);
                    }
                }
            }
        } else if (filterId == 2) {
            // Gradient filter: predict pixel from neighbors, data is error term
            QVector<QRgb> prevRow(rect.w, qRgb(0, 0, 0));
            QVector<QRgb> row(rect.w);
            int dOff = 0;
            for (int y = 0; y < rect.h; y++) {
                for (int x = 0; x < rect.w; x++) {
                    quint32 est = readTPixel(pixelData.constData(), dOff);
                    int eR = (est >> pixelFormat.redShift) & 0xFF;
                    int eG = (est >> pixelFormat.greenShift) & 0xFF;
                    int eB = (est >> pixelFormat.blueShift) & 0xFF;

                    int lR = 0, lG = 0, lB = 0;
                    int aR = 0, aG = 0, aB = 0;
                    int alR = 0, alG = 0, alB = 0;
                    if (x > 0) { lR = qRed(row[x-1]); lG = qGreen(row[x-1]); lB = qBlue(row[x-1]); }
                    if (y > 0) { aR = qRed(prevRow[x]); aG = qGreen(prevRow[x]); aB = qBlue(prevRow[x]); }
                    if (x > 0 && y > 0) { alR = qRed(prevRow[x-1]); alG = qGreen(prevRow[x-1]); alB = qBlue(prevRow[x-1]); }

                    QRgb rgb = qRgb((qBound(0, lR + aR - alR, 255) + eR) & 0xFF,
                                    (qBound(0, lG + aG - alG, 255) + eG) & 0xFF,
                                    (qBound(0, lB + aB - alB, 255) + eB) & 0xFF);
                    row[x] = rgb;
                    image.setPixel(rect.x + x, rect.y + y, rgb);
                }
                prevRow = row;
            }
        } else {
            // Copy filter (filter 0 or default)
            int dOff = 0;
            for (int y = 0; y < rect.h; y++)
                for (int x = 0; x < rect.w; x++)
                    image.setPixel(rect.x + x, rect.y + y, toRgb(readTPixel(pixelData.constData(), dOff)));
        }

        return true;
    }
}
#endif

/*!
    \internal
    Processes a JPEG-compressed rectangle in Tight encoding.
    
    \param rect The rectangle dimensions.
    \param dataLength The length of the JPEG data in bytes.
    \return true if successful, false if there was an error.
*/
bool QVncClient::Private::handleTightJpeg(const Rectangle &rect, int dataLength)
{
    // Read JPEG data (caller already ensured data is available)
    QByteArray jpegData = socket->read(dataLength);
    if (jpegData.size() < dataLength) {
        qCWarning(lcVncClient) << "Failed to read JPEG data for Tight encoding";
        return false;
    }
    
    // Decode JPEG image using Qt
    QImage jpegImage;
    if (!jpegImage.loadFromData(jpegData, "JPEG")) {
        qCWarning(lcVncClient) << "Failed to decode JPEG data for Tight encoding";
        return false;
    }
    
    // Copy the JPEG image to the framebuffer
    QPainter painter(&image);
    painter.drawImage(rect.x, rect.y, jpegImage);
    
    return true;
}

#ifdef USE_ZLIB
/*!
    \internal
    Decompresses zlib data for Tight encoding.
    
    \param streamId The zlib stream ID (0-3).
    \param data The compressed data.
    \param expectedBytes The expected size of the decompressed data.
    \return The decompressed data, or an empty array on error.
*/
QByteArray QVncClient::Private::decompressTightData(int streamId, const QByteArray &data, int expectedBytes)
{
    QByteArray uncompressedData;
    uncompressedData.resize(expectedBytes);
    
    tightData->zlibStream[streamId].next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    tightData->zlibStream[streamId].avail_in = data.size();
    tightData->zlibStream[streamId].next_out = reinterpret_cast<Bytef*>(uncompressedData.data());
    tightData->zlibStream[streamId].avail_out = uncompressedData.size();
    
    // Perform decompression
    int result = inflate(&tightData->zlibStream[streamId], Z_SYNC_FLUSH);
    if (result != Z_OK && result != Z_STREAM_END) {
        qCWarning(lcVncClient) << "Zlib inflation failed with error code:" << result;
        return QByteArray();
    }
    
    int uncompressedSize = uncompressedData.size() - tightData->zlibStream[streamId].avail_out;
    uncompressedData.resize(uncompressedSize);
    
    return uncompressedData;
}
#endif

/*!
    \internal
    Parses the RFB protocol version string sent by the server.
    
    The server sends a string like "RFB 003.008\n" indicating its supported protocol version.
    This method reads this string and sets the appropriate protocol version enum value.
*/
void QVncClient::Private::parseProtocolVersion()
{
    if (socket->bytesAvailable() < 12) {
        qCDebug(lcVncClient) << "Waiting for more protocol version data:" << socket->peek(12);
        return;
    }
    const auto value = socket->read(12);
    if (value == "RFB 003.003\n")
        q->setProtocolVersion(ProtocolVersion33);
    else if (value == "RFB 003.007\n")
        q->setProtocolVersion(ProtocolVersion37);
    else if (value == "RFB 003.008\n")
        q->setProtocolVersion(ProtocolVersion38);
    else
        qCWarning(lcVncClient) << "Unsupported protocol version:" << value;
}

/*!
    \internal
    Handles protocol version changes by sending the appropriate response to the server.
    
    \param protocolVersion The new protocol version.
*/
void QVncClient::Private::protocolVersionChanged(ProtocolVersion protocolVersion)
{
    qCDebug(lcVncClient) << "Protocol version changed to:" << protocolVersion;
    switch (protocolVersion) {
    case ProtocolVersion33:
        socket->write("RFB 003.003\n");
        state = SecurityState;
        break;
    case ProtocolVersion37:
        socket->write("RFB 003.007\n");
        state = SecurityState;
        break;
    case ProtocolVersion38:
        socket->write("RFB 003.008\n");
        state = SecurityState;
        break;
    default:
        break;
    }
}

/*!
    \internal
    Dispatches to the appropriate security parsing method based on the protocol version.
*/
void QVncClient::Private::parseSecurity()
{
    switch (protocolVersion) {
    case ProtocolVersion33:
        parseSecurity33();
        break;
    case ProtocolVersion37:
    case ProtocolVersion38:
        parseSecurity37();
        break;
    default:
        break;
    }
}

/*!
    \internal
    Parses security data for protocol version 3.3.
    
    In RFB 3.3, the server directly sends a 32-bit security type value.
*/
void QVncClient::Private::parseSecurity33()
{
    if (socket->bytesAvailable() < 4) {
        qCDebug(lcVncClient) << "Waiting for more security data:" << socket->peek(4);
        return;
    }
    quint32_be data;
    read(&data);
    q->setSecurityType(static_cast<SecurityType>(static_cast<unsigned int>(data)));
}

/*!
    \internal
    Parses security data for protocol version 3.7 and later.
    
    In RFB 3.7+, the server sends a list of supported security types, and the client
    chooses one.
*/
void QVncClient::Private::parseSecurity37()
{
    if (socket->bytesAvailable() < 1) {
        qCDebug(lcVncClient) << "Waiting for security type count:" << socket->peek(1);
        return;
    }
    quint8 numberOfSecurityTypes = 0;
    read(&numberOfSecurityTypes);
    if (numberOfSecurityTypes == 0) {
        parseSecurityReason();
        return;
    }
    if (socket->bytesAvailable() < numberOfSecurityTypes) {
        qCDebug(lcVncClient) << "Waiting for security types:" << socket->peek(numberOfSecurityTypes);
        return;
    }
    QList<quint8> securityTypes;
    for (unsigned char i = 0; i < numberOfSecurityTypes; i++) {
        quint8 securityType = 0;
        read(&securityType);
        securityTypes.append(securityType);
    }
    if (securityTypes.contains(SecurityTypeVncAuthentication))
        q->setSecurityType(SecurityTypeVncAuthentication);
    else if (securityTypes.contains(SecurityTypeNone))
        q->setSecurityType(SecurityTypeNone);
    else
        q->setSecurityType(SecurityTypeInvalid);
}

/*!
    \internal
    Handles security type changes by sending the appropriate response to the server.
    
    \param securityType The new security type.
*/
void QVncClient::Private::securityTypeChanged(SecurityType securityType)
{
    qCDebug(lcVncClient) << "Security type changed to:" << securityType;
    switch (securityType) {
    case SecurityTypeUnknwon:
        break;
    case SecurityTypeInvalid:
        parseSecurityReason();
        break;
    case SecurityTypeNone:
        switch (protocolVersion) {
        case ProtocolVersion33:
            state = ClientInitState;
            clientInit();
            break;
        case ProtocolVersion37:
            state = ClientInitState;
            write(securityType);
            clientInit();
            break;
        case ProtocolVersion38:
            write(securityType);
            state = SecurityResultState;
            break;
        default:
            break;
        }
        break;
    case SecurityTypeVncAuthentication:
        switch (protocolVersion) {
        case ProtocolVersion33:
            state = VncAuthenticationState;
            parseVncAuthentication();  // challenge may already be buffered
            break;
        case ProtocolVersion37:
        case ProtocolVersion38:
            write(securityType);  // send 1-byte type selection
            state = VncAuthenticationState;
            break;
        default:
            break;
        }
        break;
    default:
        qCWarning(lcVncClient) << "Security type" << securityType << "not supported";
        break;
    }
}

/*!
    \internal
    Parses and logs the reason for a security failure sent by the server.
*/
void QVncClient::Private::parseSecurityReason()
{
    if (socket->bytesAvailable() < 4) {
        qCDebug(lcVncClient) << "Waiting for reason length:" << socket->peek(4);
        return;
    }
    quint32_be reasonLength;
    read(&reasonLength);
    if (socket->bytesAvailable() < reasonLength) {
        qCDebug(lcVncClient) << "Waiting for reason data:" << socket->peek(reasonLength);
        return;
    }
    qCWarning(lcVncClient) << "Security failure reason:" << socket->read(reasonLength);
}

/*!
    \internal
    Parses the 16-byte VNC authentication challenge from the server.

    If no password is set, stores the challenge and emits passwordRequested()
    to allow the application to supply a password later via setPassword().
*/
void QVncClient::Private::parseVncAuthentication()
{
    if (socket->bytesAvailable() < 16)
        return;
    vncChallenge = socket->read(16);
    if (password.isEmpty()) {
        emit q->passwordRequested();
        return;
    }
    sendVncAuthResponse();
}

/*!
    \internal
    Encrypts the stored VNC challenge with the password and sends the response.

    After sending, transitions to the appropriate next state based on protocol version:
    - 3.3: directly to ClientInit (no SecurityResult in 3.3)
    - 3.7/3.8: to SecurityResultState
*/
void QVncClient::Private::sendVncAuthResponse()
{
    const QByteArray response = vncEncryptChallenge(password, vncChallenge);
    if (isValid())
        socket->write(response);
    vncChallenge.clear();

    switch (protocolVersion) {
    case ProtocolVersion33:
        state = ClientInitState;
        clientInit();
        break;
    case ProtocolVersion37:
    case ProtocolVersion38:
        state = SecurityResultState;
        break;
    default:
        break;
    }
}

/*!
    \internal
    Parses the SecurityResult message (u32) sent after authentication.

    Result 0 means success (proceed to ClientInit).
    Non-zero means failure; protocol 3.8 includes a reason string.
*/
void QVncClient::Private::parseSecurityResult()
{
    if (socket->bytesAvailable() < 4)
        return;
    quint32_be result;
    read(&result);
    if (result == 0) {
        state = ClientInitState;
        clientInit();
    } else {
        qCWarning(lcVncClient) << "VNC authentication failed";
        if (protocolVersion == ProtocolVersion38)
            parseSecurityReason();
        // Server will close the connection
    }
}

/*!
    \internal
    Sends the client initialization message to the server.
    
    This message indicates whether the connection will be shared with other clients.
*/
void QVncClient::Private::clientInit()
{
    quint8 sharedFlag = 1;
    write(sharedFlag);
    state = ServerInitState;
}

/*!
    \internal
    Parses the server initialization message containing framebuffer dimensions,
    pixel format, and the server name.
*/
void QVncClient::Private::parserServerInit()
{
    if (socket->bytesAvailable() < 2 + 2 + 16 + 4) {
        qCDebug(lcVncClient) << "Waiting for server init data:" << socket->peek(2 + 2 + 16 + 4);
        return;
    }

    quint16_be framebufferWidth;
    read(&framebufferWidth);
    quint16_be framebufferHeight;
    read(&framebufferHeight);
    qCDebug(lcVncClient) << "Framebuffer size:" << framebufferWidth << "x" << framebufferHeight;
    
    frameBufferWidth = framebufferWidth;
    frameBufferHeight = framebufferHeight;
    emit q->framebufferSizeChanged(frameBufferWidth, frameBufferHeight);
    
    image = QImage(framebufferWidth, framebufferHeight, QImage::Format_ARGB32);
    image.fill(Qt::white);

    read(&pixelFormat);
    qCDebug(lcVncClient) << "Pixel format:";
    qCDebug(lcVncClient) << "  Bits per pixel:" << pixelFormat.bitsPerPixel;
    qCDebug(lcVncClient) << "  Depth:" << pixelFormat.depth;
    qCDebug(lcVncClient) << "  Big endian:" << pixelFormat.bigEndianFlag;
    qCDebug(lcVncClient) << "  True color:" << pixelFormat.trueColourFlag;
    qCDebug(lcVncClient) << "  Red:" << pixelFormat.redMax << pixelFormat.redShift;
    qCDebug(lcVncClient) << "  Green:" << pixelFormat.greenMax << pixelFormat.greenShift;
    qCDebug(lcVncClient) << "  Blue:" << pixelFormat.blueMax << pixelFormat.blueShift;

    quint32_be nameLength;
    read(&nameLength);
    qCDebug(lcVncClient) << "Name length:" << nameLength;
    if (socket->bytesAvailable() < nameLength) {
        qCDebug(lcVncClient) << "Waiting for name data:" << socket->peek(nameLength);
        return;
    }
    const auto nameString = socket->read(nameLength);
    qCDebug(lcVncClient) << "Server name:" << nameString;
    state = WaitingState;

    setPixelFormat();
    
    // Set supported encodings based on available libraries
    const QList<qint32> encodings {
#ifdef USE_ZLIB
        Tight,
#endif
        ZRLE,
        Hextile,
        RawEncoding,
    };
    setEncodings(encodings);
    framebufferUpdateRequest(false);
}

/*!
    \internal
    Sends a SetPixelFormat message to the server.
    
    This message configures the pixel format that the server should use when
    sending framebuffer updates.
*/
void QVncClient::Private::setPixelFormat()
{
    write(SetPixelFormat);
    write("   "); // padding
    write(pixelFormat);
}

/*!
    \internal
    Sends a SetEncodings message to the server.
    
    \param encodings List of encoding types the client supports, in order of preference.
*/
void QVncClient::Private::setEncodings(const QList<qint32> &encodings)
{
    write(SetEncodings);
    write(" "); // padding
    write(quint16_be(encodings.length()));
    for (const auto encoding : encodings)
        write(qint32_be(encoding));
}

/*!
    \internal
    Sends a FramebufferUpdateRequest message to the server.
    
    \param incremental If true, only changed parts of the framebuffer are requested.
    \param rect The rectangle to update, or empty for the entire framebuffer.
*/
void QVncClient::Private::framebufferUpdateRequest(bool incremental, const QRect &rect)
{
    write(FramebufferUpdateRequest);
    write(quint8(incremental ? 1 : 0));
    Rectangle rectangle;
    if (rect.isEmpty()) {
        rectangle.x = 0;
        rectangle.y = 0;
        rectangle.w = frameBufferWidth;
        rectangle.h = frameBufferHeight;
    } else {
        rectangle.x = rect.x();
        rectangle.y = rect.y();
        rectangle.w = rect.width();
        rectangle.h = rect.height();
    }
    write(rectangle);
}

/*!
    \internal
    Parses and dispatches incoming server messages.
    
    Reads the message type from the socket and calls the appropriate handler.
*/
void QVncClient::Private::parseServerMessages()
{
    if (fbu.active) {
        processFramebufferRects();
        return;
    }
    if (socket->bytesAvailable() < 1) return;
    quint8 messageType = 0;
    read(&messageType);
    switch (messageType) {
    case FramebufferUpdate:
        framebufferUpdate();
        break;
    default:
        qCWarning(lcVncClient) << "Unknown message type:" << messageType;
    }
}

/*!
    \internal
    Processes a framebuffer update message.
    
    Reads the number of rectangles and processes each one based on its encoding type.
*/
void QVncClient::Private::framebufferUpdate()
{
    if (socket->bytesAvailable() < 3) return;
    socket->read(1); // padding
    quint16_be numberOfRectangles;
    read(&numberOfRectangles);
    fbu.totalRects = numberOfRectangles;
    fbu.currentRect = 0;
    fbu.active = true;
    fbu.rectHeaderRead = false;
    qCDebug(lcVncClient) << "FramebufferUpdate: rectangles:" << fbu.totalRects;
    processFramebufferRects();
}

void QVncClient::Private::processFramebufferRects()
{
    while (fbu.currentRect < fbu.totalRects) {
        if (!fbu.rectHeaderRead) {
            if (socket->bytesAvailable() < 12) return;
            read(&fbu.rect);
            qint32_be encodingType;
            read(&encodingType);
            fbu.encoding = encodingType;
            fbu.rectHeaderRead = true;
            fbu.hextileTX = 0;
            fbu.hextileTY = 0;
        }

        bool ok = false;
        switch (fbu.encoding) {
        case ZRLE:
            ok = handleZRLEEncoding(fbu.rect);
            break;
#ifdef USE_ZLIB
        case Tight:
            ok = handleTightEncoding(fbu.rect);
            break;
#endif
        case Hextile:
            ok = handleHextileEncoding(fbu.rect);
            break;
        case RawEncoding:
            ok = handleRawEncoding(fbu.rect);
            break;
        default:
            qCWarning(lcVncClient) << "Unsupported encoding:" << fbu.encoding;
            ok = true; // skip
            break;
        }

        if (!ok) return; // not enough data, will resume on next readyRead

        emit q->imageChanged(QRect(fbu.rect.x, fbu.rect.y, fbu.rect.w, fbu.rect.h));
        fbu.rectHeaderRead = false;
        fbu.currentRect++;
    }
    fbu.active = false;
    framebufferUpdateRequest();
}

/*!
    \internal
    Handles raw-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    Raw encoding sends uncompressed pixel data for each pixel in the rectangle.
*/
bool QVncClient::Private::handleRawEncoding(const Rectangle &rect)
{
    const qint64 needed = static_cast<qint64>(rect.w) * rect.h * pixelFormat.bitsPerPixel / 8;
    if (socket->bytesAvailable() < needed)
        return false;

    for (int y = 0; y < rect.h; y++) {
        for (int x = 0; x < rect.w; x++) {
            switch (pixelFormat.bitsPerPixel) {
            case 32: {
                quint32_le color;
                read(&color);
                const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
                const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
                const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
                image.setPixel(rect.x + x, rect.y + y, qRgb(r, g, b));
                break; }
            default:
                qCWarning(lcVncClient) << pixelFormat.bitsPerPixel << "bits per pixel not supported";
                return true; // skip
            }
        }
    }
    return true;
}

/*!
    \internal
    Handles hextile-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    Hextile encoding divides the rectangle into 16x16 tiles, each with its own
    subencoding that can include background colors, foreground colors, and subrectangles.
*/
bool QVncClient::Private::handleHextileEncoding(const Rectangle &rect)
{
    const int tileWidth = 16;
    const int tileHeight = 16;
    const int bpp = pixelFormat.bitsPerPixel / 8;

    quint32 &backgroundColor = fbu.hextileBG;
    quint32 &foregroundColor = fbu.hextileFG;

    for (int &ty = fbu.hextileTY; ty < rect.h; ty += tileHeight) {
        const int th = qMin(tileHeight, rect.h - ty);

        for (int &tx = fbu.hextileTX; tx < rect.w; tx += tileWidth) {
            const int tw = qMin(tileWidth, rect.w - tx);

            // Peek at subencoding to calculate tile data size before consuming
            if (socket->bytesAvailable() < 1) return false;
            const QByteArray peek = socket->peek(qMin(socket->bytesAvailable(), qint64(2048)));
            const quint8 subencoding = static_cast<quint8>(peek.at(0));

            qint64 tileBytes = 1; // subencoding byte
            if (subencoding & RawSubencoding) {
                tileBytes += tw * th * bpp;
            } else {
                if (subencoding & BackgroundSpecified) tileBytes += bpp;
                if (subencoding & AnySubrects) {
                    if (subencoding & ForegroundSpecified) tileBytes += bpp;
                    tileBytes += 1; // numSubrects byte
                    if (peek.size() < tileBytes) return false;
                    const quint8 numSubrects = static_cast<quint8>(peek.at(tileBytes - 1));
                    const int subrectSize = (subencoding & SubrectsColoured) ? bpp + 2 : 2;
                    tileBytes += numSubrects * subrectSize;
                }
            }

            if (socket->bytesAvailable() < tileBytes) return false;

            // All tile data available — consume and process
            quint8 sub;
            read(&sub);

            if (sub & RawSubencoding) {
                for (int y = 0; y < th; y++) {
                    for (int x = 0; x < tw; x++) {
                        if (bpp == 4) {
                            quint32_le color;
                            read(&color);
                            const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
                            const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
                            const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
                            image.setPixel(rect.x + tx + x, rect.y + ty + y, qRgb(r, g, b));
                        }
                    }
                }
                continue;
            }

            if (sub & BackgroundSpecified) {
                if (bpp == 4) {
                    quint32_le bg;
                    read(&bg);
                    backgroundColor = bg;
                }
            }

            for (int y = 0; y < th; y++) {
                for (int x = 0; x < tw; x++) {
                    const auto r = (backgroundColor >> pixelFormat.redShift) & pixelFormat.redMax;
                    const auto g = (backgroundColor >> pixelFormat.greenShift) & pixelFormat.greenMax;
                    const auto b = (backgroundColor >> pixelFormat.blueShift) & pixelFormat.blueMax;
                    image.setPixel(rect.x + tx + x, rect.y + ty + y, qRgb(r, g, b));
                }
            }

            if (sub & AnySubrects) {
                if (sub & ForegroundSpecified) {
                    if (bpp == 4) {
                        quint32_le fg;
                        read(&fg);
                        foregroundColor = fg;
                    }
                }

                quint8 numSubrects;
                read(&numSubrects);

                for (int i = 0; i < numSubrects; i++) {
                    quint32 color = foregroundColor;
                    if (sub & SubrectsColoured) {
                        if (bpp == 4) {
                            quint32_le c;
                            read(&c);
                            color = c;
                        }
                    }
                    quint8 xy, wh;
                    read(&xy);
                    read(&wh);

                    const int sx = (xy >> 4) & 0xf;
                    const int sy = xy & 0xf;
                    const int sw = ((wh >> 4) & 0xf) + 1;
                    const int sh = (wh & 0xf) + 1;

                    for (int y = 0; y < sh && sy + y < th; y++) {
                        for (int x = 0; x < sw && sx + x < tw; x++) {
                            const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
                            const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
                            const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
                            image.setPixel(rect.x + tx + sx + x, rect.y + ty + sy + y, qRgb(r, g, b));
                        }
                    }
                }
            }
        }
        fbu.hextileTX = 0;
    }
    fbu.hextileTY = 0;
    return true;
}

/*!
    \internal
    Handles ZRLE-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    ZRLE (Zlib Run-Length Encoding) compresses the pixel data using zlib and
    uses various subencodings for efficient representation.
*/
bool QVncClient::Private::handleZRLEEncoding(const Rectangle &rect)
{
    // Peek at the 4-byte length prefix to check total availability
    if (socket->bytesAvailable() < 4) return false;
    const QByteArray lenPeek = socket->peek(4);
    quint32_be zlibDataLength;
    memcpy(&zlibDataLength, lenPeek.constData(), 4);

    if (zlibDataLength == 0) {
        socket->read(4); // consume the length
        return true;
    }

    if (socket->bytesAvailable() < 4 + static_cast<qint64>(zlibDataLength))
        return false;

    // All data available — consume
    read(&zlibDataLength);
    QByteArray compressedData = socket->read(zlibDataLength);

    // Decompress using persistent zlib stream (dictionary reuse across rects)
#ifdef USE_ZLIB
    if (!zrleStreamActive) {
        memset(&zrleStream, 0, sizeof(zrleStream));
        zrleStream.zalloc = Z_NULL;
        zrleStream.zfree = Z_NULL;
        zrleStream.opaque = Z_NULL;
        zrleStream.avail_in = 0;
        zrleStream.next_in = Z_NULL;
        if (inflateInit(&zrleStream) != Z_OK) {
            qCWarning(lcVncClient) << "Failed to initialize ZRLE zlib stream";
            return true;
        }
        zrleStreamActive = true;
    }

    zrleStream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressedData.data()));
    zrleStream.avail_in = compressedData.size();

    QByteArray uncompressedData;
    do {
        int prevSize = uncompressedData.size();
        uncompressedData.resize(prevSize + 65536);
        zrleStream.next_out = reinterpret_cast<Bytef*>(uncompressedData.data() + prevSize);
        zrleStream.avail_out = 65536;

        int ret = inflate(&zrleStream, Z_SYNC_FLUSH);
        uncompressedData.resize(prevSize + 65536 - zrleStream.avail_out);

        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            qCWarning(lcVncClient) << "ZRLE zlib inflate failed:" << ret;
            return true;
        }
        if (ret == Z_STREAM_END || zrleStream.avail_in == 0)
            break;
    } while (zrleStream.avail_out == 0);
#else
    qCWarning(lcVncClient) << "ZRLE encoding requires zlib support";
    return true;
#endif

    if (uncompressedData.isEmpty()) {
        qCWarning(lcVncClient) << "Failed to decompress ZRLE data";
        return true;
    }

    // CPIXEL size: 3 bytes when bpp=32, trueColor, all maxes <= 255
    const int cpixelSize = (pixelFormat.bitsPerPixel == 32 && pixelFormat.trueColourFlag
        && pixelFormat.redMax <= 255 && pixelFormat.greenMax <= 255
        && pixelFormat.blueMax <= 255) ? 3 : (pixelFormat.bitsPerPixel / 8);

    const char *buf = uncompressedData.constData();
    const int bufSize = uncompressedData.size();
    int dataOffset = 0;

    // Helper to read a CPIXEL from the decompressed buffer
    auto readCPixel = [&]() -> quint32 {
        quint32 color = 0;
        if (dataOffset + cpixelSize > bufSize) return 0;
        if (cpixelSize == 3) {
            if (pixelFormat.bigEndianFlag) {
                color = (static_cast<quint8>(buf[dataOffset]) << 16)
                      | (static_cast<quint8>(buf[dataOffset + 1]) << 8)
                      | static_cast<quint8>(buf[dataOffset + 2]);
            } else {
                color = static_cast<quint8>(buf[dataOffset])
                      | (static_cast<quint8>(buf[dataOffset + 1]) << 8)
                      | (static_cast<quint8>(buf[dataOffset + 2]) << 16);
            }
        } else if (cpixelSize == 4) {
            memcpy(&color, buf + dataOffset, 4);
        } else if (cpixelSize == 2) {
            memcpy(&color, buf + dataOffset, 2);
        } else {
            color = static_cast<quint8>(buf[dataOffset]);
        }
        dataOffset += cpixelSize;
        return color;
    };

    auto toRgb = [&](quint32 color) -> QRgb {
        const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
        const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
        const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
        return qRgb(r, g, b);
    };

    // Each tile is 64x64 pixels
    const int tileWidth = 64;
    const int tileHeight = 64;

    for (int ty = 0; ty < rect.h; ty += tileHeight) {
        const int th = qMin(tileHeight, rect.h - ty);

        for (int tx = 0; tx < rect.w; tx += tileWidth) {
            const int tw = qMin(tileWidth, rect.w - tx);

            if (dataOffset >= bufSize) {
                qCWarning(lcVncClient) << "ZRLE data truncated (subencoding)";
                return true;
            }

            const quint8 subencoding = static_cast<quint8>(buf[dataOffset++]);

            if (subencoding == 0) {
                // Raw pixels: cpixelSize * tw * th bytes
                for (int y = 0; y < th; y++)
                    for (int x = 0; x < tw; x++)
                        image.setPixel(rect.x + tx + x, rect.y + ty + y, toRgb(readCPixel()));

            } else if (subencoding == 1) {
                // Solid tile: 1 CPIXEL
                QRgb rgb = toRgb(readCPixel());
                for (int y = 0; y < th; y++)
                    for (int x = 0; x < tw; x++)
                        image.setPixel(rect.x + tx + x, rect.y + ty + y, rgb);

            } else if (subencoding >= 2 && subencoding <= 16) {
                // Packed palette: palette size = subencoding value
                const int paletteSize = subencoding;
                QVector<QRgb> palette(paletteSize);
                for (int i = 0; i < paletteSize; i++)
                    palette[i] = toRgb(readCPixel());

                const int bitsPerIndex = (paletteSize == 2) ? 1
                                       : (paletteSize <= 4) ? 2 : 4;
                const int bytesPerRow = (tw * bitsPerIndex + 7) / 8;

                for (int y = 0; y < th; y++) {
                    int rowStart = dataOffset;
                    int bitPos = 0;
                    for (int x = 0; x < tw; x++) {
                        int byteIdx = dataOffset + bitPos / 8;
                        if (byteIdx >= bufSize) break;
                        int shift = 8 - bitsPerIndex - (bitPos % 8);
                        int mask = (1 << bitsPerIndex) - 1;
                        int index = (static_cast<quint8>(buf[byteIdx]) >> shift) & mask;
                        bitPos += bitsPerIndex;
                        if (index < paletteSize)
                            image.setPixel(rect.x + tx + x, rect.y + ty + y, palette[index]);
                    }
                    dataOffset = rowStart + bytesPerRow;
                }

            } else if (subencoding == 128) {
                // Plain RLE: (CPIXEL, runLength) pairs
                const int totalPixels = tw * th;
                int pixels = 0;
                while (pixels < totalPixels) {
                    QRgb rgb = toRgb(readCPixel());
                    int runLength = 0;
                    quint8 b;
                    do {
                        if (dataOffset >= bufSize) break;
                        b = static_cast<quint8>(buf[dataOffset++]);
                        runLength += b;
                    } while (b == 255);
                    runLength += 1;

                    for (int i = 0; i < runLength && pixels < totalPixels; i++, pixels++) {
                        image.setPixel(rect.x + tx + pixels % tw,
                                       rect.y + ty + pixels / tw, rgb);
                    }
                }

            } else if (subencoding >= 130) {
                // Palette RLE: palette of (sub - 128) CPIXELs, then RLE with indices
                const int paletteSize = subencoding - 128;
                QVector<QRgb> palette(paletteSize);
                for (int i = 0; i < paletteSize; i++)
                    palette[i] = toRgb(readCPixel());

                const int totalPixels = tw * th;
                int pixels = 0;
                while (pixels < totalPixels) {
                    if (dataOffset >= bufSize) break;
                    quint8 indexByte = static_cast<quint8>(buf[dataOffset++]);

                    if (indexByte & 0x80) {
                        // Run: index = low 7 bits, followed by run length
                        int paletteIndex = indexByte & 0x7F;
                        int runLength = 0;
                        quint8 b;
                        do {
                            if (dataOffset >= bufSize) break;
                            b = static_cast<quint8>(buf[dataOffset++]);
                            runLength += b;
                        } while (b == 255);
                        runLength += 1;

                        QRgb rgb = (paletteIndex < paletteSize)
                                 ? palette[paletteIndex] : qRgb(0, 0, 0);
                        for (int i = 0; i < runLength && pixels < totalPixels; i++, pixels++) {
                            image.setPixel(rect.x + tx + pixels % tw,
                                           rect.y + ty + pixels / tw, rgb);
                        }
                    } else {
                        // Single pixel
                        QRgb rgb = (indexByte < paletteSize)
                                 ? palette[indexByte] : qRgb(0, 0, 0);
                        image.setPixel(rect.x + tx + pixels % tw,
                                       rect.y + ty + pixels / tw, rgb);
                        pixels++;
                    }
                }

            } else {
                // Unused subencodings (17-127, 129): skip tile
                qCWarning(lcVncClient) << "ZRLE unsupported subencoding:" << subencoding;
            }
        }
    }
    return true;
}

/*!
    \internal
    Translates Qt key events to VNC key events and sends them to the server.
    
    \param e The keyboard event to be processed and sent.
*/
void QVncClient::Private::keyEvent(QKeyEvent *e)
{
    if (!socket) return;
    const quint8 messageType = 0x04;
    write(messageType);
    const quint8 downFlag = e->type() == QEvent::KeyPress ? 1 : 0;
    write(downFlag);
    socket->write("  "); // padding

    const auto key = e->key();
    quint32_be code;
    if (keyMap.contains(key))
        code = keyMap.value(key);
    else if (!e->text().isEmpty())
        code = e->text().at(0).unicode();
    qCDebug(lcVncClient) << "Key event:" << e->type() << key << code;
    write(code);
}

/*!
    \internal
    Translates Qt mouse events to VNC pointer events and sends them to the server.
    
    \param e The mouse event to be processed and sent.
*/
void QVncClient::Private::pointerEvent(QMouseEvent *e)
{
    if (!socket) return;
    const quint8 messageType = 0x05;
    write(messageType);

    quint8 buttonMask = 0;
    if (e->buttons() & Qt::LeftButton) buttonMask |= 1;
    if (e->buttons() & Qt::MiddleButton) buttonMask |= 2;
    if (e->buttons() & Qt::RightButton) buttonMask |= 4;
    write(buttonMask);

    quint16_be x(qRound(e->position().x()));
    write(x);
    quint16_be y(qRound(e->position().y()));
    write(y);
}

/*!
    \class QVncClient
    \inmodule QtVncClient
    
    \brief The QVncClient class provides a VNC client implementation.
    
    QVncClient allows Qt applications to connect to VNC servers, view the remote
    desktop, and send keyboard and mouse events.
    
    \sa QTcpSocket
*/

/*!
    Constructs a VNC client with the given \a parent object.
*/
QVncClient::QVncClient(QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
}

/*!
    Destroys the VNC client and frees its resources.
*/
QVncClient::~QVncClient() = default;

/*!
    Returns the TCP socket used for the VNC connection.
    
    \sa setSocket()
*/
QTcpSocket *QVncClient::socket() const
{
    return d->socket;
}

/*!
    Sets the socket used for VNC communication to \a socket.
    
    \note The socket should be created and connected by the caller.
    The VNC protocol handshake will start automatically once the
    socket is connected.
    
    \sa socket()
*/
void QVncClient::setSocket(QTcpSocket *socket)
{
    if (d->socket == socket) return;
    d->socket = socket;
    emit socketChanged(socket);
}

/*!
    Returns the negotiated VNC protocol version.
    
    \sa protocolVersionChanged()
*/
QVncClient::ProtocolVersion QVncClient::protocolVersion() const
{
    return d->protocolVersion;
}

/*!
    \internal
    Sets the protocol version to \a protocolVersion.
    
    This method is called internally during the connection handshake.
    
    \sa protocolVersion(), protocolVersionChanged()
*/
void QVncClient::setProtocolVersion(QVncClient::ProtocolVersion protocolVersion)
{
    if (d->protocolVersion == protocolVersion) return;
    d->protocolVersion = protocolVersion;
    emit protocolVersionChanged(protocolVersion);
}

/*!
    Returns the negotiated security type for the VNC connection.
    
    \sa securityTypeChanged()
*/
QVncClient::SecurityType QVncClient::securityType() const
{
    return d->securityType;
}

/*!
    \internal
    Sets the security type to \a securityType.
    
    This method is called internally during the connection handshake.
    
    \sa securityType(), securityTypeChanged()
*/
void QVncClient::setSecurityType(QVncClient::SecurityType securityType)
{
    if (d->securityType == securityType) return;
    d->securityType = securityType;
    emit securityTypeChanged(securityType);
}

/*!
    Returns the width of the remote framebuffer in pixels.
    
    \sa framebufferHeight(), framebufferSizeChanged()
*/
int QVncClient::framebufferWidth() const
{
    return d->frameBufferWidth;
}

/*!
    Returns the height of the remote framebuffer in pixels.
    
    \sa framebufferWidth(), framebufferSizeChanged()
*/
int QVncClient::framebufferHeight() const
{
    return d->frameBufferHeight;
}

/*!
    Returns the current framebuffer image.
    
    This image represents the current state of the remote desktop.
    It is updated each time framebuffer updates are received from the server.
    
    \sa imageChanged()
*/
QImage QVncClient::image() const
{
    return d->image;
}

/*!
    Returns the password used for VNC authentication.

    \sa setPassword(), passwordChanged()
*/
QString QVncClient::password() const
{
    return d->password;
}

/*!
    Sets the password to \a password for VNC authentication.

    If the server has already sent a challenge and no password was
    previously set, the authentication response is sent immediately.

    \sa password(), passwordChanged(), passwordRequested()
*/
void QVncClient::setPassword(const QString &password)
{
    if (d->password == password) return;
    d->password = password;
    emit passwordChanged(password);
}

/*!
    Handles a keyboard event and sends it to the VNC server.
    
    This method should be called when keyboard events occur in the client
    application that should be forwarded to the remote VNC server.
    
    \param e The keyboard event to be forwarded.
*/
void QVncClient::handleKeyEvent(QKeyEvent *e)
{
    d->keyEvent(e);
}

/*!
    Handles a mouse event and sends it to the VNC server.
    
    This method should be called when mouse events occur in the client
    application that should be forwarded to the remote VNC server.
    
    \param e The mouse event to be forwarded.
*/
void QVncClient::handlePointerEvent(QMouseEvent *e)
{
    d->pointerEvent(e);
}
