package com.example.rutoken_sample.createobjects


import com.example.rutoken_sample.utils.Constants.GOSTR3410_2001_256_OID
import com.example.rutoken_sample.utils.Constants.GOST_2001_256_KEY_PAIR_ID

enum class GostKeyPairParams(
    val paramset3411: ByteArray,
    val id: ByteArray
) {
    GOST_2001_256(
        GOSTR3410_2001_256_OID,
        GOST_2001_256_KEY_PAIR_ID
    );
}
