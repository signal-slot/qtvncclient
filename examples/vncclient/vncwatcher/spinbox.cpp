// Copyright (C) 2025 Signal Slot Inc.
// SPDX-License-Identifier: LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include "spinbox.h"
#include <QtWidgets/QLineEdit>

SpinBox::SpinBox(QWidget *parent)
    : QSpinBox(parent)
{
    connect(lineEdit(), &QLineEdit::returnPressed, this, &SpinBox::returnPressed);
}
