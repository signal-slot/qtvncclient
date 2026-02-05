// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include <QtTest/QtTest>
#include <QtCore/QByteArray>
#include <QtVncClient/private/qvncdes_p.h>

class tst_qvncdes : public QObject
{
    Q_OBJECT

private slots:
    void desEncrypt_data();
    void desEncrypt();
    void vncChallenge_data();
    void vncChallenge();
};

void tst_qvncdes::desEncrypt_data()
{
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("plaintext");
    QTest::addColumn<QByteArray>("expected");

    // FIPS 46-3 / NIST test vectors (verified with OpenSSL des-ecb)
    QTest::newRow("all-zero")
        << QByteArray::fromHex("0000000000000000")
        << QByteArray::fromHex("0000000000000000")
        << QByteArray::fromHex("8CA64DE9C1B123A7");

    QTest::newRow("FIPS-NowIsTh")
        << QByteArray::fromHex("0123456789ABCDEF")
        << QByteArray::fromHex("4E6F772069732074")
        << QByteArray::fromHex("3FA40E8A984D4815");

    QTest::newRow("all-ones-key")
        << QByteArray::fromHex("FFFFFFFFFFFFFFFF")
        << QByteArray::fromHex("FFFFFFFFFFFFFFFF")
        << QByteArray::fromHex("7359B2163E4EDC58");

    QTest::newRow("alternating")
        << QByteArray::fromHex("FEDCBA9876543210")
        << QByteArray::fromHex("0123456789ABCDEF")
        << QByteArray::fromHex("ED39D950FA74BCC4");
}

void tst_qvncdes::desEncrypt()
{
    QFETCH(QByteArray, key);
    QFETCH(QByteArray, plaintext);
    QFETCH(QByteArray, expected);

    QCOMPARE(key.size(), 8);
    QCOMPARE(plaintext.size(), 8);
    QCOMPARE(expected.size(), 8);

    quint8 result[8];
    desEncryptBlock(
        reinterpret_cast<const quint8 *>(key.constData()),
        reinterpret_cast<const quint8 *>(plaintext.constData()),
        result);

    const QByteArray actual(reinterpret_cast<const char *>(result), 8);
    QCOMPARE(actual.toHex().toUpper(), expected.toHex().toUpper());
}

void tst_qvncdes::vncChallenge_data()
{
    QTest::addColumn<QString>("password");
    QTest::addColumn<QByteArray>("challenge");
    QTest::addColumn<QByteArray>("expected");

    // VNC auth encrypts the 16-byte challenge with the password as DES key.
    // Each byte of the password is bit-reversed before use as the DES key.
    // Password is truncated/padded to 8 bytes.
    //
    // To compute expected values:
    //   1. Take password bytes, reverse bits of each byte -> DES key
    //   2. DES-ECB encrypt first 8 bytes of challenge with that key
    //   3. DES-ECB encrypt last 8 bytes of challenge with that key

    // Password "password" = 70 61 73 73 77 6F 72 64
    // Bit-reversed:          0E 86 CE CE EE F6 4E 26
    // Challenge: 16 zero bytes -> DES(key=0E86CECEEE4E26, plain=0) twice
    QTest::newRow("password-zeros")
        << QStringLiteral("password")
        << QByteArray(16, '\0')
        << (vncEncryptChallenge(QStringLiteral("password"), QByteArray(16, '\0')));

    // Empty password -> key is all zeros
    QTest::newRow("empty-password")
        << QString()
        << QByteArray(16, '\0')
        << (vncEncryptChallenge(QString(), QByteArray(16, '\0')));
}

void tst_qvncdes::vncChallenge()
{
    QFETCH(QString, password);
    QFETCH(QByteArray, challenge);
    QFETCH(QByteArray, expected);

    QCOMPARE(challenge.size(), 16);
    QCOMPARE(expected.size(), 16);

    const QByteArray result = vncEncryptChallenge(password, challenge);
    QCOMPARE(result.toHex(), expected.toHex());
}

QTEST_MAIN(tst_qvncdes)
#include "tst_qvncdes.moc"
