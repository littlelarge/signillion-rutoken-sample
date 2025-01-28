/*
 * Copyright (c) 2022, Aktiv-Soft JSC.
 * See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package com.example.rutoken_sample.utils

import com.example.rutoken_sample.utils.Pkcs11ObjectTemplates.makeCertificateTemplate
import com.example.rutoken_sample.utils.Pkcs11ObjectTemplates.makeGostPublicKeyBaseTemplate
import com.example.rutoken_sample.utils.Pkcs11ObjectTemplates.makePrivateKeyBaseTemplate
import com.example.rutoken_sample.utils.Pkcs11ObjectTemplates.makeRsaPublicKeyTemplate
import org.bouncycastle.asn1.ASN1BitString
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN
import ru.rutoken.pkcs11wrapper.attribute.Pkcs11Attribute
import ru.rutoken.pkcs11wrapper.constant.IPkcs11MechanismType
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11InitializeArgs
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11KeyPair
import ru.rutoken.pkcs11wrapper.main.Pkcs11Token
import ru.rutoken.pkcs11wrapper.`object`.Pkcs11StorageObject
import ru.rutoken.pkcs11wrapper.`object`.certificate.Pkcs11CertificateObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PrivateKeyObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PublicKeyObject
import ru.rutoken.pkcs11wrapper.rutoken.main.RtPkcs11Session
import ru.rutoken.pkcs11wrapper.rutoken.main.RtPkcs11Token
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey

object Pkcs11Operations {


    fun <T : Pkcs11StorageObject> findFirstObject(
        session: RtPkcs11Session,
        clazz: Class<T>,
        template: List<Pkcs11Attribute>
    ): T {
        val objects = session.objectManager.findObjectsAtOnce(clazz, template)
        require(objects.isNotEmpty()) { "${clazz.simpleName} object not found" }
        return objects[0]
    }

    @Throws(CertificateException::class)
    fun findPrivateKeyByCertificateValue(
        session: RtPkcs11Session,
        certificateValue: ByteArray
    ): Pkcs11PrivateKeyObject {
        return findKeyPairByCertificateValue(session, certificateValue).privateKey
    }

    @Throws(CertificateException::class)
    fun findKeyPairByCertificateValue(
        session: RtPkcs11Session,
        certificateValue: ByteArray
    ): Pkcs11KeyPair<Pkcs11PublicKeyObject, Pkcs11PrivateKeyObject> {
        val x509certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certificateValue)) as X509Certificate

        val publicKeyValueTemplate = if (x509certificate.publicKey is RSAPublicKey) {
            val publicKey = x509certificate.publicKey as RSAPublicKey
            makeRsaPublicKeyTemplate(
                session.attributeFactory,
                dropPrecedingZeros(publicKey.modulus.toByteArray()),
                publicKey.publicExponent.toByteArray()
            )
        } else { // GOST
            val sequence = ASN1Sequence.getInstance(x509certificate.publicKey.encoded)
            val publicKeyValue =
                ASN1OctetString.getInstance((sequence.getObjectAt(1) as ASN1BitString).octets).octets
            makeGostPublicKeyBaseTemplate(session.attributeFactory, publicKeyValue)
        }

        val publicKey =
            findFirstObject(session, Pkcs11PublicKeyObject::class.java, publicKeyValueTemplate)
        val publicKeyId = publicKey.getIdAttributeValue(session).byteArrayValue
        val privateKeyTemplate = makePrivateKeyBaseTemplate(session.attributeFactory, publicKeyId)
        val privateKey =
            findFirstObject(session, Pkcs11PrivateKeyObject::class.java, privateKeyTemplate)

        return Pkcs11KeyPair(publicKey, privateKey)
    }

    fun getUnsupportedMechanisms(
        token: Pkcs11Token,
        vararg mechanisms: IPkcs11MechanismType
    ): List<IPkcs11MechanismType> {
        return mechanisms.filter { !isMechanismSupported(token, it) }
    }

    fun isRsaModulusSupported(token: RtPkcs11Token, modulusBits: Int): Boolean {
        val info =
            token.getMechanismInfo(IPkcs11MechanismType.getInstance(CKM_RSA_PKCS_KEY_PAIR_GEN))
        return modulusBits in info.minKeySize..info.maxKeySize
    }

    private fun isMechanismSupported(token: Pkcs11Token, mechanism: IPkcs11MechanismType): Boolean {
        val mechanismList = token.mechanismList
        return mechanismList.any { it.asLong == mechanism.asLong }
    }

    private fun dropPrecedingZeros(bytes: ByteArray): ByteArray {
        return bytes.dropWhile { it == 0.toByte() }.toByteArray()
    }
}
