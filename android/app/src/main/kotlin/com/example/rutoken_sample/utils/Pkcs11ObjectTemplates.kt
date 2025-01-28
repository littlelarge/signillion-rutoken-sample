/*
 * Copyright (c) 2023, Aktiv-Soft JSC.
 * See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package com.example.rutoken_sample.utils

import ru.rutoken.pkcs11wrapper.attribute.IPkcs11AttributeFactory
import ru.rutoken.pkcs11wrapper.attribute.Pkcs11Attribute
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11AttributeType.*
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11CertificateCategory.CK_CERTIFICATE_CATEGORY_TOKEN_USER
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11CertificateType.CKC_X_509
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11KeyType.CKK_RSA
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11ObjectClass.*

object Pkcs11ObjectTemplates {
    fun makeRsaPublicKeyTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        modulusBits: ByteArray,
        publicExponent: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
            attributeFactory.makeAttribute(CKA_KEY_TYPE, CKK_RSA),
            attributeFactory.makeAttribute(CKA_MODULUS, modulusBits),
            attributeFactory.makeAttribute(CKA_PUBLIC_EXPONENT, publicExponent)
        )
    }

    fun makeGostPublicKeyBaseTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        publicKeyValue: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
            attributeFactory.makeAttribute(CKA_VALUE, publicKeyValue)
        )
    }

    fun makeCertificateTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        id: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(CKA_CLASS, CKO_CERTIFICATE),
            attributeFactory.makeAttribute(CKA_CERTIFICATE_TYPE, CKC_X_509),
            attributeFactory.makeAttribute(CKA_ID, id),
            attributeFactory.makeAttribute(CKA_CERTIFICATE_CATEGORY, CK_CERTIFICATE_CATEGORY_TOKEN_USER.asLong)
        )
    }

    fun makePrivateKeyBaseTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        privateKeyId: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
            attributeFactory.makeAttribute(CKA_ID, privateKeyId)
        )
    }
}
