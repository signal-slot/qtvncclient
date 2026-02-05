// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API.  It exists purely as an
// implementation detail.  This header file may change from version to
// version without notice, or even be removed.
//
// We mean it.
//

//
// Self-contained DES implementation for VNC authentication.
// VNC uses a non-standard DES variant where each byte of the key
// has its bits reversed before use.
//
// This avoids depending on OpenSSL, where DES is in the "legacy"
// provider (OpenSSL 3.x) and not loaded by default.
//

#ifndef QVNCDES_P_H
#define QVNCDES_P_H

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <cstring>

QT_BEGIN_NAMESPACE

// Initial Permutation (IP)
static const int IP_TABLE[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
};

// Final Permutation (IP^-1)
static const int FP_TABLE[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
};

// Expansion permutation (E)
static const int E_TABLE[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
};

// Permutation (P)
static const int P_TABLE[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
};

// Permuted Choice 1 (PC-1)
static const int PC1_TABLE[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
};

// Permuted Choice 2 (PC-2)
static const int PC2_TABLE[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

// Key rotation schedule
static const int KEY_SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

// S-boxes
static const int S_BOXES[8][4][16] = {
    // S1
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
    },
    // S2
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
    },
    // S3
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
    },
    // S4
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
    },
    // S5
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
    },
    // S6
    {
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
    },
    // S7
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
    },
    // S8
    {
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
    },
};

// Get bit at 1-indexed position from byte array
static inline int desGetBit(const quint8 *data, int pos)
{
    return (data[(pos - 1) / 8] >> (7 - ((pos - 1) % 8))) & 1;
}

// Set bit at 1-indexed position in byte array
static inline void desSetBit(quint8 *data, int pos, int val)
{
    const int byteIdx = (pos - 1) / 8;
    const int bitIdx = 7 - ((pos - 1) % 8);
    if (val)
        data[byteIdx] |= quint8(1 << bitIdx);
    else
        data[byteIdx] &= quint8(~(1 << bitIdx));
}

// Generate 16 round subkeys from 8-byte key
static void desKeySchedule(const quint8 key[8], quint8 subkeys[16][6])
{
    // Apply PC-1: 64 bits -> 56 bits
    quint8 pc1[7];
    memset(pc1, 0, 7);
    for (int i = 0; i < 56; i++) {
        if (desGetBit(key, PC1_TABLE[i]))
            desSetBit(pc1, i + 1, 1);
    }

    // Extract C and D as 28-bit values
    quint32 c = 0, d = 0;
    for (int i = 0; i < 28; i++) {
        if (desGetBit(pc1, i + 1))
            c |= (1u << (27 - i));
        if (desGetBit(pc1, i + 29))
            d |= (1u << (27 - i));
    }

    for (int round = 0; round < 16; round++) {
        // Left rotate C and D
        const int shift = KEY_SHIFTS[round];
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFFu;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFFu;

        // Reconstitute 56-bit CD
        quint8 cd[7];
        memset(cd, 0, 7);
        for (int i = 0; i < 28; i++) {
            if (c & (1u << (27 - i)))
                desSetBit(cd, i + 1, 1);
            if (d & (1u << (27 - i)))
                desSetBit(cd, i + 29, 1);
        }

        // Apply PC-2: 56 bits -> 48-bit subkey
        memset(subkeys[round], 0, 6);
        for (int i = 0; i < 48; i++) {
            if (desGetBit(cd, PC2_TABLE[i]))
                desSetBit(subkeys[round], i + 1, 1);
        }
    }
}

// Feistel function: takes 32-bit R and 48-bit subkey, produces 32-bit output
static void desFeistel(const quint8 right[4], const quint8 subkey[6], quint8 output[4])
{
    // Expansion: 32 bits -> 48 bits
    quint8 expanded[6];
    memset(expanded, 0, 6);
    for (int i = 0; i < 48; i++) {
        if (desGetBit(right, E_TABLE[i]))
            desSetBit(expanded, i + 1, 1);
    }

    // XOR with subkey
    for (int i = 0; i < 6; i++)
        expanded[i] ^= subkey[i];

    // S-box substitution: 48 bits -> 32 bits
    quint8 sboxOut[4];
    memset(sboxOut, 0, 4);
    for (int i = 0; i < 8; i++) {
        const int bit = i * 6 + 1;
        const int row = desGetBit(expanded, bit) * 2 + desGetBit(expanded, bit + 5);
        const int col = desGetBit(expanded, bit + 1) * 8
                      + desGetBit(expanded, bit + 2) * 4
                      + desGetBit(expanded, bit + 3) * 2
                      + desGetBit(expanded, bit + 4);
        const int val = S_BOXES[i][row][col];

        const int outBit = i * 4 + 1;
        desSetBit(sboxOut, outBit,     (val >> 3) & 1);
        desSetBit(sboxOut, outBit + 1, (val >> 2) & 1);
        desSetBit(sboxOut, outBit + 2, (val >> 1) & 1);
        desSetBit(sboxOut, outBit + 3,  val       & 1);
    }

    // P permutation: 32 bits -> 32 bits
    memset(output, 0, 4);
    for (int i = 0; i < 32; i++) {
        if (desGetBit(sboxOut, P_TABLE[i]))
            desSetBit(output, i + 1, 1);
    }
}

// Encrypt a single 8-byte block with an 8-byte key using DES-ECB
static void desEncryptBlock(const quint8 key[8], const quint8 input[8], quint8 output[8])
{
    quint8 subkeys[16][6];
    desKeySchedule(key, subkeys);

    // Initial permutation
    quint8 ip[8];
    memset(ip, 0, 8);
    for (int i = 0; i < 64; i++) {
        if (desGetBit(input, IP_TABLE[i]))
            desSetBit(ip, i + 1, 1);
    }

    // Split into left (32 bits) and right (32 bits)
    quint8 left[4], right[4];
    memcpy(left, ip, 4);
    memcpy(right, ip + 4, 4);

    // 16 Feistel rounds
    for (int round = 0; round < 16; round++) {
        quint8 fResult[4];
        desFeistel(right, subkeys[round], fResult);

        quint8 newRight[4];
        for (int i = 0; i < 4; i++)
            newRight[i] = left[i] ^ fResult[i];

        memcpy(left, right, 4);
        memcpy(right, newRight, 4);
    }

    // Pre-output: R16 || L16 (swap halves)
    quint8 preOutput[8];
    memcpy(preOutput, right, 4);
    memcpy(preOutput + 4, left, 4);

    // Final permutation
    memset(output, 0, 8);
    for (int i = 0; i < 64; i++) {
        if (desGetBit(preOutput, FP_TABLE[i]))
            desSetBit(output, i + 1, 1);
    }
}

// Reverse bits in a byte (VNC uses non-standard bit ordering for DES keys)
static inline quint8 desReverseBits(quint8 b)
{
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
    return b;
}

// Encrypt a 16-byte VNC challenge using the password.
// The password is truncated/padded to 8 chars, with each byte's bits reversed.
// The 16-byte challenge is encrypted as two DES-ECB blocks.
static inline QByteArray vncEncryptChallenge(const QString &password, const QByteArray &challenge)
{
    Q_ASSERT(challenge.size() == 16);

    // Prepare key: password truncated/padded to 8 bytes, bits reversed per byte
    quint8 key[8];
    memset(key, 0, 8);
    const QByteArray pwd = password.toLatin1();
    for (int i = 0; i < qMin(pwd.size(), 8); i++)
        key[i] = desReverseBits(static_cast<quint8>(pwd.at(i)));

    // Encrypt two 8-byte blocks
    QByteArray response(16, '\0');
    desEncryptBlock(key,
                    reinterpret_cast<const quint8 *>(challenge.constData()),
                    reinterpret_cast<quint8 *>(response.data()));
    desEncryptBlock(key,
                    reinterpret_cast<const quint8 *>(challenge.constData() + 8),
                    reinterpret_cast<quint8 *>(response.data() + 8));

    return response;
}

QT_END_NAMESPACE

#endif // QVNCDES_P_H
