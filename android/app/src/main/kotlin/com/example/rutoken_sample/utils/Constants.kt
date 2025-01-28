/*
 * Copyright (c) 2022, Aktiv-Soft JSC.
 * See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */


package com.example.rutoken_sample.utils

object Constants {
    const val DEFAULT_USER_PIN = "12345678"
//    val GOSTR3411_2012_512_OID = byteArrayOf(0x06, 0x08, 0x2a, 0x85.toByte(), 0x03, 0x07, 0x01, 0x01, 0x02, 0x03)
//    val GOSTR3410_2001_512_OID = byteArrayOf(0x06, 0x08, 0x2a, 0x85.toByte(), 0x03, 0x07, 0x01, 0x01, 0x01, 0x03)
    val GOSTR3410_2001_256_OID = byteArrayOf(0x2a, 0x85.toByte(), 0x03, 0x02, 0x02, 0x13)
//    val GOST_2012_512_KEY_PAIR_ID = "Sample GOST R 34.10-2012 (512 bits) key pair".toByteArray()
//    val GOST_2001_512_KEY_PAIR_ID = "Sample GOST R 34.10-2001 (512 bits) key pair".toByteArray()
    val GOST_2001_256_KEY_PAIR_ID = "Sample GOST R 34.10-2001 (256 bits) key pair".toByteArray()
}
