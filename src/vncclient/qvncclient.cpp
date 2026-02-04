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

    /*!
        \internal
        \brief Parses the security result message (RFB 3.8).

        In RFB 3.8, the server sends a 4-byte result after security type selection.
        0 = success, non-zero = failure followed by a reason string.
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
    
    /*!
        \internal
        \brief Handles raw-encoded rectangle data.
        \param rect The rectangle dimensions.
        
        Processes uncompressed pixel data for the specified rectangle.
    */
    void handleRawEncoding(const Rectangle &rect);
    
    /*!
        \internal
        \brief Handles hextile-encoded rectangle data.
        \param rect The rectangle dimensions.
        
        Processes hextile-encoded data for the specified rectangle, which divides
        the rectangle into 16x16 tiles with various subencodings.
    */
    void handleHextileEncoding(const Rectangle &rect);
    
#ifdef USE_ZLIB
    /*!
        \internal
        \brief Handles tight-encoded rectangle data.
        \param rect The rectangle dimensions.
        
        Processes Tight-encoded data for the specified rectangle, which may use
        zlib compression, JPEG compression, or various other subencodings.
    */
    void handleTightEncoding(const Rectangle &rect);
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
    void handleZRLEEncoding(const Rectangle &rect);

private:
    QVncClient *q;                              ///< Pointer to the public class
    QTcpSocket *prev = nullptr;                 ///< Previous socket for cleanup
    HandshakingState state = ProtocolVersionState; ///< Current protocol state
    PixelFormat pixelFormat;                    ///< Current pixel format
    QMap<int, quint32> keyMap;                  ///< Map from Qt keys to VNC key codes
public:
    QTcpSocket *socket = nullptr;               ///< Socket for VNC communication
#ifdef USE_ZLIB
    QScopedPointer<TightData> tightData;        ///< Data for Tight encoding
#endif
    ProtocolVersion protocolVersion = ProtocolVersionUnknown; ///< Current protocol version
    SecurityType securityType = SecurityTypeUnknwon;         ///< Current security type
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
}

void QVncClient::Private::reset()
{
    state = ProtocolVersionState;
    q->setProtocolVersion(ProtocolVersionUnknown);
    q->setSecurityType(SecurityTypeUnknwon);
    frameBufferWidth = 0;
    frameBufferHeight = 0;
    image = QImage(); // Clear the image buffer
    emit q->framebufferSizeChanged(0, 0);
}

/*!
    \internal
    Main state machine dispatcher for handling incoming socket data based on the current protocol state.
*/
void QVncClient::Private::read()
{
    switch (state) {
    case ProtocolVersionState:
        parseProtocolVersion();
        break;
    case SecurityState:
        parseSecurity();
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
}

#ifdef USE_ZLIB
/*!
    \internal
    Handles Tight-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    Tight encoding is a complex encoding that can use zlib compression, JPEG compression,
    or various subencodings for efficient representation of framebuffer data.
*/
void QVncClient::Private::handleTightEncoding(const Rectangle &rect)
{
    // Read the compression control byte
    quint8 compControl = 0;
    if (socket->bytesAvailable() < 1) {
        if (!socket->waitForReadyRead(1000)) {
            qCWarning(lcVncClient) << "Timeout waiting for Tight compression control byte";
            framebufferUpdateRequest();
            return;
        }
    }
    socket->read(reinterpret_cast<char*>(&compControl), 1);
    
    // Check for basic compression type
    bool resetStream = (compControl & 0x80) != 0;
    int streamId = compControl & 0x03;
    
    // Check for JPEG compression
    if ((compControl & 0x0F) == 0x09) {
        int length = 0;
        quint8 lenByte = 0;
        
        // Read the JPEG data length
        if (socket->bytesAvailable() < 1) {
            if (!socket->waitForReadyRead(1000)) {
                qCWarning(lcVncClient) << "Timeout waiting for JPEG length byte";
                framebufferUpdateRequest();
                return;
            }
        }
        socket->read(reinterpret_cast<char*>(&lenByte), 1);
        
        if (lenByte & 0x80) {
            // 3-byte length
            quint8 lenMid, lenLow;
            if (socket->bytesAvailable() < 2) {
                socket->waitForReadyRead();
            }
            socket->read(reinterpret_cast<char*>(&lenMid), 1);
            socket->read(reinterpret_cast<char*>(&lenLow), 1);
            length = ((lenByte & 0x7F) << 16) | (lenMid << 8) | lenLow;
        } else {
            // 1-byte length
            length = lenByte;
        }
        
        // Handle JPEG compression
        if (!handleTightJpeg(rect, length)) {
            // If JPEG handling fails, request a new update
            framebufferUpdateRequest();
        }
        return;
    }
    
    // Non-JPEG compression
    // Reset the zlib stream if requested
    if (resetStream && tightData->zlibStreamActive[streamId]) {
        inflateEnd(&tightData->zlibStream[streamId]);
        tightData->zlibStreamActive[streamId] = false;
    }
    
    // Initialize stream if not active
    if (!tightData->zlibStreamActive[streamId]) {
        tightData->zlibStream[streamId].zalloc = Z_NULL;
        tightData->zlibStream[streamId].zfree = Z_NULL;
        tightData->zlibStream[streamId].opaque = Z_NULL;
        inflateInit(&tightData->zlibStream[streamId]);
        tightData->zlibStreamActive[streamId] = true;
    }
    
    // Read the uncompressed length
    int length = 0;
    if ((compControl & 0x80) == 0) {
        quint8 len;
        if (socket->bytesAvailable() < 1) {
            socket->waitForReadyRead();
        }
        socket->read(reinterpret_cast<char*>(&len), 1);
        length = len;
    } else {
        quint8 lenHigh, lenMid, lenLow;
        if (socket->bytesAvailable() < 3) {
            socket->waitForReadyRead();
        }
        socket->read(reinterpret_cast<char*>(&lenHigh), 1);
        socket->read(reinterpret_cast<char*>(&lenMid), 1);
        socket->read(reinterpret_cast<char*>(&lenLow), 1);
        length = (lenHigh << 16) | (lenMid << 8) | lenLow;
    }
    
    // Read compressed data
    QByteArray compressedData;
    compressedData.resize(length);
    
    int totalRead = 0;
    while (totalRead < length) {
        if (socket->bytesAvailable() < 1 && totalRead < length) {
            socket->waitForReadyRead();
        }
        int bytesRead = socket->read(compressedData.data() + totalRead, length - totalRead);
        if (bytesRead <= 0) {
            qCWarning(lcVncClient) << "Failed to read compressed data for Tight encoding";
            framebufferUpdateRequest(); // Request a new frame
            return;
        }
        totalRead += bytesRead;
    }
    
    // Calculate expected uncompressed size
    int expectedBytes = rect.w * rect.h * (pixelFormat.bitsPerPixel / 8);
    
    // Decompress data
    QByteArray uncompressedData = decompressTightData(streamId, compressedData, expectedBytes);
    if (uncompressedData.isEmpty()) {
        qCWarning(lcVncClient) << "Failed to decompress Tight encoded data, requesting new update";
        framebufferUpdateRequest(); // Request a new frame
        return;
    }
    
    // Update the framebuffer with the decompressed data
    const unsigned char* data = reinterpret_cast<const unsigned char*>(uncompressedData.constData());
    
    for (int y = 0; y < rect.h; y++) {
        for (int x = 0; x < rect.w; x++) {
            int offset = (y * rect.w + x) * (pixelFormat.bitsPerPixel / 8);
            quint32 color = 0;
            
            // Read pixel data according to bpp
            if (pixelFormat.bitsPerPixel == 32) {
                color = *reinterpret_cast<const quint32*>(data + offset);
            } else if (pixelFormat.bitsPerPixel == 24) {
                color = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16);
            } else if (pixelFormat.bitsPerPixel == 16) {
                color = *reinterpret_cast<const quint16*>(data + offset);
            } else if (pixelFormat.bitsPerPixel == 8) {
                color = data[offset];
            }
            
            // Convert to RGB and set pixel
            const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
            const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
            const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
            image.setPixel(rect.x + x, rect.y + y, qRgb(r, g, b));
        }
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
    // Read JPEG data
    QByteArray jpegData;
    jpegData.resize(dataLength);
    
    int totalRead = 0;
    while (totalRead < dataLength) {
        if (socket->bytesAvailable() < 1 && totalRead < dataLength) {
            socket->waitForReadyRead();
        }
        int bytesRead = socket->read(jpegData.data() + totalRead, dataLength - totalRead);
        if (bytesRead <= 0) {
            qCWarning(lcVncClient) << "Failed to read JPEG data for Tight encoding";
            return false;
        }
        totalRead += bytesRead;
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
    if (securityTypes.contains(SecurityTypeNone))
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
    Parses the security result message sent by the server in RFB 3.8.

    The server sends a 4-byte status code: 0 indicates success, any other value
    indicates failure followed by a reason string.
*/
void QVncClient::Private::parseSecurityResult()
{
    if (socket->bytesAvailable() < 4) {
        qCDebug(lcVncClient) << "Waiting for security result:" << socket->peek(4);
        return;
    }
    quint32_be result;
    read(&result);
    if (result == 0) {
        state = ClientInitState;
        clientInit();
    } else {
        parseSecurityReason();
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
        RawEncoding,
        Hextile,
        ZRLE,
#ifdef USE_ZLIB
        Tight,
#endif
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
    while (socket->bytesAvailable() < 3)
        socket->waitForReadyRead();
    socket->read(1); // padding
    quint16_be numberOfRectangles;
    read(&numberOfRectangles);
    for (int i = 0; i < numberOfRectangles; i++) {
        while (socket->bytesAvailable() < 12)
            socket->waitForReadyRead();
        Rectangle rect;
        read(&rect);
        qint32_be encodingType;
        read(&encodingType);

        switch (static_cast<int>(encodingType)) {
            case ZRLE:
                handleZRLEEncoding(rect);
                break;
#ifdef USE_ZLIB
            case Tight:
                handleTightEncoding(rect);
                break;
#endif
            case Hextile:
                handleHextileEncoding(rect);
                break;
            case RawEncoding:
                handleRawEncoding(rect);
                break;
            default:
                qCWarning(lcVncClient) << "Unsupported encoding:" << encodingType;
                // Skip this rectangle as we don't understand the encoding
                continue; // Use continue instead of return to process remaining rectangles
        }
        emit q->imageChanged(QRect(rect.x, rect.y, rect.w, rect.h));
    }
    framebufferUpdateRequest();
}

/*!
    \internal
    Handles raw-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    Raw encoding sends uncompressed pixel data for each pixel in the rectangle.
*/
void QVncClient::Private::handleRawEncoding(const Rectangle &rect)
{
    while (socket->bytesAvailable() < rect.w * rect.h * pixelFormat.bitsPerPixel / 8) {
        socket->waitForReadyRead();
    }
    
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
                // Skip this pixel format as we don't support it
                return;
            }
        }
        emit q->imageChanged(QRect(rect.x, rect.y, rect.w, rect.h));
    }
    framebufferUpdateRequest();
}

/*!
    \internal
    Handles hextile-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    Hextile encoding divides the rectangle into 16x16 tiles, each with its own
    subencoding that can include background colors, foreground colors, and subrectangles.
*/
void QVncClient::Private::handleHextileEncoding(const Rectangle &rect)
{
    const int tileWidth = 16;
    const int tileHeight = 16;
    
    quint32 backgroundColor = 0;
    quint32 foregroundColor = 0;
    
    // Process the rectangle tile by tile
    for (int ty = 0; ty < rect.h; ty += tileHeight) {
        const int th = qMin(tileHeight, rect.h - ty);
        
        for (int tx = 0; tx < rect.w; tx += tileWidth) {
            const int tw = qMin(tileWidth, rect.w - tx);
            
            // Read the subencoding mask
            quint8 subencoding;
            read(&subencoding);
            
            // If raw bit is set, the tile is sent in raw encoding
            if (subencoding & HextileSubencoding::RawSubencoding) {
                for (int y = 0; y < th; y++) {
                    for (int x = 0; x < tw; x++) {
                        if (pixelFormat.bitsPerPixel == 32) {
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
            
            // Background specified
            if (subencoding & HextileSubencoding::BackgroundSpecified) {
                if (pixelFormat.bitsPerPixel == 32) {
                    quint32_le bg;
                    read(&bg);
                    backgroundColor = bg;
                }
            }
            
            // Fill the background
            for (int y = 0; y < th; y++) {
                for (int x = 0; x < tw; x++) {
                    const auto r = (backgroundColor >> pixelFormat.redShift) & pixelFormat.redMax;
                    const auto g = (backgroundColor >> pixelFormat.greenShift) & pixelFormat.greenMax;
                    const auto b = (backgroundColor >> pixelFormat.blueShift) & pixelFormat.blueMax;
                    image.setPixel(rect.x + tx + x, rect.y + ty + y, qRgb(r, g, b));
                }
            }
            
            // Foreground specified & any subrects
            if (subencoding & HextileSubencoding::AnySubrects) {
                // Foreground color specified
                if (subencoding & HextileSubencoding::ForegroundSpecified) {
                    if (pixelFormat.bitsPerPixel == 32) {
                        quint32_le fg;
                        read(&fg);
                        foregroundColor = fg;
                    }
                }
                
                // Read number of subrectangles
                quint8 numSubrects;
                read(&numSubrects);
                
                // Process each subrectangle
                for (int i = 0; i < numSubrects; i++) {
                    quint32 color = foregroundColor;
                    
                    // If colored subrects, read the color
                    if (subencoding & HextileSubencoding::SubrectsColoured) {
                        if (pixelFormat.bitsPerPixel == 32) {
                            quint32_le c;
                            read(&c);
                            color = c;
                        }
                    }
                    
                    // Read subrect position and size (x, y, w, h)
                    quint8 xy, wh;
                    read(&xy);
                    read(&wh);
                    
                    const int sx = (xy >> 4) & 0xf;
                    const int sy = xy & 0xf;
                    const int sw = ((wh >> 4) & 0xf) + 1;
                    const int sh = (wh & 0xf) + 1;
                    
                    // Draw the subrectangle
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
    }
}

/*!
    \internal
    Handles ZRLE-encoded rectangle data.
    
    \param rect The rectangle dimensions.
    
    ZRLE (Zlib Run-Length Encoding) compresses the pixel data using zlib and
    uses various subencodings for efficient representation.
*/
void QVncClient::Private::handleZRLEEncoding(const Rectangle &rect)
{
    // First read the length of the zlib-compressed data
    if (socket->bytesAvailable() < 4) return;
    quint32_be zlibDataLength;
    read(&zlibDataLength);

    if (zlibDataLength == 0)
        return; // No data for this rectangle

    // Read the compressed data
    if (socket->bytesAvailable() < zlibDataLength) {
        // Wait for more data
        while (socket->bytesAvailable() < zlibDataLength) {
            if (!socket->waitForReadyRead(5000)) {
                qCWarning(lcVncClient) << "Timeout waiting for ZRLE data";
                break; // Break out but don't return - allows more frames to be processed
            }
        }
    }
    
    QByteArray compressedData = socket->read(zlibDataLength);
    
    // Use Qt's own QByteArray-based zlib decompression
    QByteArray uncompressedData = qUncompress(compressedData);
    if (uncompressedData.isEmpty()) {
        qCWarning(lcVncClient) << "Failed to decompress ZRLE data, requesting new update";
        // Request a new frame instead of returning
        framebufferUpdateRequest();
        return;
    }
    
    // Process the decompressed data
    int dataOffset = 0;
    
    // Each tile is 64x64 pixels
    const int tileWidth = 64;
    const int tileHeight = 64;
    
    // Determine bytes per pixel (always 1 in ZRLE)
    const int bytesPerPixel = pixelFormat.bitsPerPixel / 8;
    
    // Process each tile
    for (int ty = 0; ty < rect.h; ty += tileHeight) {
        const int th = qMin(tileHeight, rect.h - ty);
        
        for (int tx = 0; tx < rect.w; tx += tileWidth) {
            const int tw = qMin(tileWidth, rect.w - tx);

            // Read subencoding type (one byte) 
            // 0=raw, 1=solid, 2=packed palette, 3=RLE palette, 8-127=plain RLE
            if (dataOffset >= uncompressedData.size()) {
                qCWarning(lcVncClient) << "ZRLE data truncated (subencoding)";
                return;
            }
            
            quint8 subencoding = static_cast<quint8>(uncompressedData.at(dataOffset++));
            
            // Handle the different subencodings
            if (subencoding == 0) { // Raw pixels
                // Raw pixel data
                int expectedBytes = tw * th * 4; // ZRLE always uses 32bpp
                
                if (dataOffset + expectedBytes > uncompressedData.size()) {
                    qCWarning(lcVncClient) << "ZRLE data truncated (raw data)";
                    continue;
                }
                
                for (int y = 0; y < th; y++) {
                    for (int x = 0; x < tw; x++) {
                        quint32 color = 0;
                        
                        // Read pixel data according to bpp
                        if (bytesPerPixel == 4) {
                            color = *reinterpret_cast<const quint32*>(uncompressedData.constData() + dataOffset);
                            dataOffset += 4;
                        } else if (bytesPerPixel == 3) {
                            color = *reinterpret_cast<const quint8*>(uncompressedData.constData() + dataOffset) |
                                   (*reinterpret_cast<const quint8*>(uncompressedData.constData() + dataOffset + 1) << 8) |
                                   (*reinterpret_cast<const quint8*>(uncompressedData.constData() + dataOffset + 2) << 16);
                            dataOffset += 3;
                        } else if (bytesPerPixel == 2) {
                            color = *reinterpret_cast<const quint16*>(uncompressedData.constData() + dataOffset);
                            dataOffset += 2;
                        } else if (bytesPerPixel == 1) {
                            color = *reinterpret_cast<const quint8*>(uncompressedData.constData() + dataOffset);
                            dataOffset += 1;
                        }
                        
                        // Convert to RGB and set pixel
                        const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
                        const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
                        const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
                        image.setPixel(rect.x + tx + x, rect.y + ty + y, qRgb(r, g, b));
                    }
                }
            } else if (subencoding == 1) {
                // Solid tile - single color for all pixels
                if (dataOffset + bytesPerPixel > uncompressedData.size()) {
                    qCWarning(lcVncClient) << "ZRLE data truncated (solid color)";
                    continue;
                }
                
                quint32 color = *reinterpret_cast<const quint32*>(uncompressedData.constData() + dataOffset);
                dataOffset += 4;
                
                const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
                const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
                const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
                QRgb rgbColor = qRgb(r, g, b);
                
                // Fill the entire tile with this color
                for (int y = 0; y < th; y++) {
                    for (int x = 0; x < tw; x++) {
                        image.setPixel(rect.x + tx + x, rect.y + ty + y, rgbColor);
                    }
                }
            } else if (subencoding == 2) {
                // Packed Palette encoding
                // First byte is the palette size (1-127)
                if (dataOffset >= uncompressedData.size()) {
                    qCWarning(lcVncClient) << "ZRLE data truncated (palette size)";
                    continue;
                }
                
                quint8 paletteSize = static_cast<quint8>(uncompressedData.at(dataOffset++));
                if (paletteSize == 0 || dataOffset + (paletteSize * 4) > uncompressedData.size()) {
                    qCWarning(lcVncClient) << "ZRLE data truncated (palette colors)";
                    continue;
                }
                
                // Read the palette
                QVector<QRgb> palette(paletteSize);
                for (int i = 0; i < paletteSize; i++) {
                    quint32 color = *reinterpret_cast<const quint32*>(uncompressedData.constData() + dataOffset);
                    dataOffset += 4;
                    
                    const auto r = (color >> pixelFormat.redShift) & pixelFormat.redMax;
                    const auto g = (color >> pixelFormat.greenShift) & pixelFormat.greenMax;
                    const auto b = (color >> pixelFormat.blueShift) & pixelFormat.blueMax;
                    palette[i] = qRgb(r, g, b);
                }
                
                // Determine bits per palette entry
                int bitsPerPaletteEntry;
                if (paletteSize <= 2) {
                    bitsPerPaletteEntry = 1;
                } else if (paletteSize <= 4) {
                    bitsPerPaletteEntry = 2;
                } else if (paletteSize <= 16) {
                    bitsPerPaletteEntry = 4;
                } else {
                    bitsPerPaletteEntry = 8;
                }
                
                // Calculate bytes needed for packed palette data
                int bytesPerLine = (tw * bitsPerPaletteEntry + 7) / 8;
                int totalBytes = bytesPerLine * th;
                
                if (dataOffset + totalBytes > uncompressedData.size()) {
                    qCWarning(lcVncClient) << "ZRLE data truncated (packed data)";
                    continue;
                }
                
                // Process each pixel
                int byteOffset = 0;
                for (int y = 0; y < th; y++) {
                    int bitOffset = 0;
                    
                    for (int x = 0; x < tw; x++) {
                        // Extract palette index from packed data
                        int index = 0;
                        
                        if (bitsPerPaletteEntry == 1) {
                            // 1 bit per entry (palette size <= 2)
                            quint8 byte = static_cast<quint8>(uncompressedData.at(dataOffset + byteOffset));
                            index = (byte >> (7 - bitOffset)) & 0x01;
                            bitOffset++;
                            if (bitOffset == 8) {
                                bitOffset = 0;
                                byteOffset++;
                            }
                        } else if (bitsPerPaletteEntry == 2) {
                            // 2 bits per entry (palette size <= 4)
                            quint8 byte = static_cast<quint8>(uncompressedData.at(dataOffset + byteOffset));
                            index = (byte >> (6 - bitOffset)) & 0x03;
                            bitOffset += 2;
                            if (bitOffset == 8) {
                                bitOffset = 0;
                                byteOffset++;
                            }
                        } else if (bitsPerPaletteEntry == 4) {
                            // 4 bits per entry (palette size <= 16)
                            quint8 byte = static_cast<quint8>(uncompressedData.at(dataOffset + byteOffset));
                            index = (byte >> (4 - bitOffset)) & 0x0f;
                            bitOffset += 4;
                            if (bitOffset == 8) {
                                bitOffset = 0;
                                byteOffset++;
                            }
                        } else { // bitsPerPaletteEntry == 8
                            // 8 bits per entry (palette size <= 127)
                            index = static_cast<quint8>(uncompressedData.at(dataOffset + byteOffset++)) & 0x7f;
                        }
                        
                        // Set the pixel color from the palette
                        if (index < paletteSize) {
                            image.setPixel(rect.x + tx + x, rect.y + ty + y, palette[index]);
                        }
                    }
                    
                    // Move to the next complete line
                    if (bitsPerPaletteEntry < 8 && bitOffset > 0) {
                        byteOffset++;
                        bitOffset = 0;
                    }
                }
                
                dataOffset += totalBytes;
            } else if (subencoding == 3) {
                // RLE Palette encoding - skip for now
                qCWarning(lcVncClient) << "RLE Palette encoding (type 3) not fully implemented";
                continue;
            } else {
                // Plain RLE (8-127) - skip for now
                qCWarning(lcVncClient) << "Plain RLE encoding (types 8-127) not implemented";
                continue;
            }
        }
    }
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
