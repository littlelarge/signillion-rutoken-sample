package com.example.rutoken_sample

import android.app.AlertDialog
import android.os.Bundle
import com.sun.jna.Native
import io.flutter.Log
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugins.GeneratedPluginRegistrant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.bouncycastle.asn1.ASN1BitString
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import ru.rutoken.pkcs11jna.Pkcs11
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKC_X_509
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKG_MGF1_SHA256
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_RSA
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKM_SHA256
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CK_CERTIFICATE_CATEGORY_TOKEN_USER
import ru.rutoken.pkcs11wrapper.attribute.IPkcs11AttributeFactory
import ru.rutoken.pkcs11wrapper.attribute.Pkcs11Attribute
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11AttributeType
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11MechanismType
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11ObjectClass
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11UserType
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11InitializeArgs
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11KeyPair
import ru.rutoken.pkcs11wrapper.lowlevel.jna.Pkcs11JnaLowLevelApi
import ru.rutoken.pkcs11wrapper.lowlevel.jna.Pkcs11JnaLowLevelFactory
import ru.rutoken.pkcs11wrapper.main.Pkcs11Api
import ru.rutoken.pkcs11wrapper.main.Pkcs11BaseModule
import ru.rutoken.pkcs11wrapper.main.Pkcs11Exception
import ru.rutoken.pkcs11wrapper.main.Pkcs11Session
import ru.rutoken.pkcs11wrapper.main.Pkcs11Token
import ru.rutoken.pkcs11wrapper.mechanism.Pkcs11Mechanism
import ru.rutoken.pkcs11wrapper.mechanism.parameter.CkRsaPkcsPssParams
import ru.rutoken.pkcs11wrapper.`object`.Pkcs11StorageObject
import ru.rutoken.pkcs11wrapper.`object`.certificate.Pkcs11CertificateObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PrivateKeyObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PublicKeyObject
import ru.rutoken.rtpcscbridge.RtPcscBridge
import ru.rutoken.rttransport.RtTransport
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey


class MainActivity : FlutterFragmentActivity() {
    // Data to sign
    private val DATA_TO_SIGN = byteArrayOf(0x01.toByte(), 0x02.toByte(), 0x03.toByte())

    /**
     * We will find certificate by its ID. Change this field to your certificate ID.
     */

    /**
     * Change this flag to false if you want to digest data by yourself.
     */
    private val SIGN_WITH_DIGEST = true

    /**
     * Change this flag to false if you want to use PKCS1 padding instead of PSS padding.
     */
    private val USE_PSS_PADDING = true

    val RSA_KEY_PAIR_ID: ByteArray = "Sample RSA key pair".toByteArray()

    private val TAG = this::class.qualifiedName.toString()

    private val module = Module()

    private val pcscReaderObserver = object : RtTransport.PcscReaderObserver {
        override fun onReaderAdded(reader: RtTransport.PcscReader) {
            showAlertDialog(
                "Reader ${reader.name} Connected",
                "A PC/SC reader has been connected."
            )
        }

        override fun onReaderRemoved(reader: RtTransport.PcscReader) {
            showAlertDialog(
                "Reader ${reader.name} Disconnected",
                "The PC/SC reader device has been removed."
            )
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        GeneratedPluginRegistrant.registerWith(flutterEngine)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        System.setProperty("jna.nosys", "true")

        // Add PC/SC readers observer to RtTransport
        RtPcscBridge.getTransport().addPcscReaderObserver(pcscReaderObserver)
    }

    override fun onStart() {
        super.onStart()
        try {
            /*
             * Create a coroutine that will call the Pkcs11Module#waitForSlotEvent method.
             *
             * WARNING: We use GlobalScope for simplicity and strongly recommend against using it in
             * production code
             */
            GlobalScope.launch(Dispatchers.IO) {
                // Pkcs11Module#waitForSlotEvent needs initialized module
                module.initializeModule(Pkcs11InitializeArgs.Builder().setOsLockingOk(true).build())

                while (isActive) {
                    try {
                        val slot = module.waitForSlotEvent(false)
                        if (slot?.slotInfo?.isTokenPresent == true) {
                            handleSlotFromWaitForSlotEvent(slot.token)
                            // Break the loop when a slot with a present token is found
                            break
                        }
                    } catch (e: Pkcs11Exception) {
                        Log.e(TAG, "Error while waiting for slot event", e)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize rtpkcs11ecp.", e)
        }
    }

    override fun onStop() {
        super.onStop()
        try {
            if (!isChangingConfigurations) {
                /*
                 * WARNING: We use GlobalScope for simplicity and strongly recommend against using
                 * it in production code
                 */
                GlobalScope.launch(Dispatchers.IO) {
                    module.finalizeModule()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to finalize rtpkcs11ecp.", e)
        }
    }

    // Will be called when Pkcs11Module#waitForSlotEvent returns the slot with the present token
    private fun handleSlotFromWaitForSlotEvent(token: Pkcs11Token) {
        try {
            doPkcs11Operation(token)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle slot from wait for slot event.", e)
        }
    }

    /*
     * Should be called ONLY if guaranteed that the token is already connected and all permissions
     * is granted. Otherwise, Pkcs11Module#getSlotList returns an empty list
     */
    private fun handleSlotFromGetSlotList() {
        try {
            val slots = module.getSlotList(true)
            if (slots.isNotEmpty())
                doPkcs11Operation(slots.first().token)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle slot from get slot list.", e)
        }
    }

    private fun doPkcs11Operation(token: Pkcs11Token) {
        val signMechanismType = Pkcs11MechanismType.CKM_SHA256_RSA_PKCS
        val digestMechanismType = Pkcs11MechanismType.CKM_RSA_PKCS_KEY_PAIR_GEN
        token.openSession(true).use { session ->
            session.login(Pkcs11UserType.CKU_USER, "12345678").use {
                println("Finding signer certificate")
                val signerCertificate = findCertificateById(session, RSA_KEY_PAIR_ID)
                val signerCertificateValue =
                    signerCertificate.getByteArrayAttributeValue(
                        session,
                        Pkcs11AttributeType.CKA_VALUE
                    ).byteArrayValue

                val keyPair =
                    findKeyPairByCertificateValue(session, signerCertificateValue)

                val signMechanism: Pkcs11Mechanism
                var dataToSign = DATA_TO_SIGN

                if (SIGN_WITH_DIGEST) {
                    signMechanism = if (USE_PSS_PADDING) {
                        Pkcs11Mechanism.make(
                            signMechanismType,
                            CkRsaPkcsPssParams(
                                CKM_SHA256.toLong(),
                                CKG_MGF1_SHA256.toLong(),
                                0
                            )
                        )
                    } else {
                        Pkcs11Mechanism.make(signMechanismType)
                    }
                } else {
                    val digest = session.digestManager.digestAtOnce(
                        DATA_TO_SIGN,
                        Pkcs11Mechanism.make(digestMechanismType)
                    )

                    signMechanism = if (USE_PSS_PADDING) {
                        dataToSign = digest
                        Pkcs11Mechanism.make(
                            signMechanismType,
                            CkRsaPkcsPssParams(
                                CKM_SHA256.toLong(),
                                CKG_MGF1_SHA256.toLong(),
                                digest.size.toLong()
                            )
                        )
                    } else {
                        val digestInfo = DigestInfo(
                            AlgorithmIdentifier(
                                NISTObjectIdentifiers.id_sha256,
                                DERNull.INSTANCE
                            ), digest
                        )
                        dataToSign = digestInfo.encoded
                        Pkcs11Mechanism.make(signMechanismType)
                    }
                }

                val signature = session.signManager.signAtOnce(
                    dataToSign,
                    signMechanism,
                    keyPair.privateKey
                )
                showAlertDialog("Successfully signed", signature.toString())

                println("Verifying RSA signature")
                val result = session.verifyManager.verifyAtOnce(
                    dataToSign,
                    signature,
                    signMechanism,
                    keyPair.publicKey
                )

                if (result) {
                    println("RSA signature is valid")
                } else {
                    throw IllegalStateException("RSA signature is invalid")
                }
            }
        }
    }

    fun findCertificateById(session: Pkcs11Session, id: ByteArray): Pkcs11CertificateObject {
        val certificateTemplate = makeCertificateTemplate(session.attributeFactory, id)
        // Для простоты, мы находим первый объект, который соответствует шаблону. В продакшн-версии
        // обычно следует проверять, что только один объект соответствует шаблону.
        return findFirstObject(session, Pkcs11CertificateObject::class.java, certificateTemplate)
    }

    fun makeCertificateTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        id: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_CLASS, CKO_CERTIFICATE),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_CERTIFICATE_TYPE, CKC_X_509),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_ID, id),
            attributeFactory.makeAttribute(
                Pkcs11AttributeType.CKA_CERTIFICATE_CATEGORY,
                CK_CERTIFICATE_CATEGORY_TOKEN_USER.toLong()
            )
        )
    }

    fun <T : Pkcs11StorageObject> findFirstObject(
        session: Pkcs11Session,
        clazz: Class<T>,
        template: List<Pkcs11Attribute>
    ): T {
        val objects = session.objectManager.findObjectsAtOnce(clazz, template)
        if (objects.size < 1) {
            throw IllegalStateException("${clazz.simpleName} object not found")
        }
        return objects[0]
    }

    @Throws(CertificateException::class)
    fun findKeyPairByCertificateValue(
        session: Pkcs11Session,
        certificateValue: ByteArray
    ): Pkcs11KeyPair<Pkcs11PublicKeyObject, Pkcs11PrivateKeyObject> {
        // Find corresponding public key handle for certificate
        val x509certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certificateValue)) as X509Certificate

        val publicKeyValueTemplate: List<Pkcs11Attribute>
        if (x509certificate.publicKey is RSAPublicKey) {
            val publicKey = x509certificate.publicKey as RSAPublicKey

            publicKeyValueTemplate = makeRsaPublicKeyTemplate(
                session.attributeFactory,
                dropPrecedingZeros(publicKey.modulus.toByteArray()),
                publicKey.publicExponent.toByteArray()
            )
        } else { // GOST
            val sequence = ASN1Sequence.getInstance(x509certificate.publicKey.encoded)
            val publicKeyValue = ASN1OctetString.getInstance(
                (sequence.getObjectAt(1) as ASN1BitString).octets
            ).octets

            publicKeyValueTemplate =
                makeGostPublicKeyBaseTemplate(session.attributeFactory, publicKeyValue)
        }

        // For simplicity, we find first object matching template, in production you should generally check that
        // only single object matches template.
        val publicKey =
            findFirstObject(session, Pkcs11PublicKeyObject::class.java, publicKeyValueTemplate)

        // Using public key we can find private key handle
        val publicKeyId = publicKey.getIdAttributeValue(session).byteArrayValue
        val privateKeyTemplate = makePrivateKeyBaseTemplate(session.attributeFactory, publicKeyId)

        // For simplicity, we find first object matching template, in production you should generally check that
        // only single object matches template.
        val privateKey =
            findFirstObject(session, Pkcs11PrivateKeyObject::class.java, privateKeyTemplate)

        return Pkcs11KeyPair(publicKey, privateKey)
    }

    fun makeRsaPublicKeyTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        modulusBits: ByteArray,
        publicExponent: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(
                Pkcs11AttributeType.CKA_CLASS,
                Pkcs11ObjectClass.CKO_PUBLIC_KEY
            ),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_KEY_TYPE, CKK_RSA),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_MODULUS, modulusBits),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_PUBLIC_EXPONENT, publicExponent)
        )
    }

    fun makeGostPublicKeyBaseTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        publicKeyValue: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(
                Pkcs11AttributeType.CKA_CLASS,
                Pkcs11ObjectClass.CKO_PUBLIC_KEY
            ),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_VALUE, publicKeyValue)
        )
    }

    fun makePrivateKeyBaseTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        privateKeyId: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(
                Pkcs11AttributeType.CKA_CLASS,
                Pkcs11ObjectClass.CKO_PRIVATE_KEY
            ),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_ID, privateKeyId)
        )
    }

    fun dropPrecedingZeros(array: ByteArray): ByteArray {
        if (array.isEmpty()) return array

        val numPrecedingZeros = array.indexOfFirst { it != 0.toByte() }.takeIf { it >= 0 } ?: -1

        return array.copyOfRange(numPrecedingZeros, array.size)
    }

    private class Module : Pkcs11BaseModule(
        Pkcs11Api(
            Pkcs11JnaLowLevelApi(
                pkcs11Library,
                Pkcs11JnaLowLevelFactory.Builder().build()
            )
        )
    ) {
        companion object {
            val pkcs11Library: Pkcs11 = Native.load("rtpkcs11ecp", Pkcs11::class.java)
        }
    }

    private fun showAlertDialog(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("OK") { dialog, _ -> dialog.dismiss() }
            .create()
            .show()
    }
}
