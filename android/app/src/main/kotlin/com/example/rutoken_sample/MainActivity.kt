package com.example.rutoken_sample

import android.app.AlertDialog
import android.os.Bundle
import com.example.rutoken_sample.createobjects.GostKeyPairParams
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugins.GeneratedPluginRegistrant
import org.bouncycastle.asn1.ASN1BitString
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKC_X_509
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKK_RSA
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE
import ru.rutoken.pkcs11jna.Pkcs11Constants.CK_CERTIFICATE_CATEGORY_TOKEN_USER
import ru.rutoken.pkcs11wrapper.attribute.IPkcs11AttributeFactory
import ru.rutoken.pkcs11wrapper.attribute.Pkcs11Attribute
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11AttributeType
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11AttributeType.CKA_VALUE
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11ObjectClass
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11UserType
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11KeyPair
import ru.rutoken.pkcs11wrapper.main.Pkcs11Exception
import ru.rutoken.pkcs11wrapper.main.Pkcs11Session
import ru.rutoken.pkcs11wrapper.main.Pkcs11Token
import ru.rutoken.pkcs11wrapper.mechanism.Pkcs11Mechanism
import ru.rutoken.pkcs11wrapper.`object`.Pkcs11StorageObject
import ru.rutoken.pkcs11wrapper.`object`.certificate.Pkcs11CertificateObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PrivateKeyObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PublicKeyObject
import ru.rutoken.pkcs11wrapper.rutoken.main.RtPkcs11Token
import ru.rutoken.rtpcscbridge.RtPcscBridge
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey

class MainActivity : FlutterFragmentActivity() {
    private val DATA_TO_SIGN =
        "Hello Rutoken! This is simple sample of sign hash data".toByteArray(
            Charsets.UTF_8
        )

    /**
     * We will find certificate by its ID. Change this field to your certificate ID.
     * Also change GOST key algorithm by setting field [GOST_KEY_PAIR_PARAMS]
     */
    private val CERTIFICATE_ID = GostKeyPairParams.GOST_2001_256.id
    private val GOST_KEY_PAIR_PARAMS = GostKeyPairParams.GOST_2001_256

    /**
     * Change this flag to false if you want to digest data by yourself.
     */

    /**
     * Change this flag to true if you want to digest data on the CPU and not on the token.
     * This flag is available if [SIGN_WITH_DIGEST] == false.
     */
    private val USE_PROGRAM_HASH = false

    private val module = Module()

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        GeneratedPluginRegistrant.registerWith(flutterEngine)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        System.setProperty("jna.nosys", "true")

        initializeRtPcscBridge()

    }

    private fun initializeRtPcscBridge() {
        val transport = RtPcscBridge.getTransport()
        transport.initialize(this)
        transport?.addPcscReaderObserver(ReaderObserver(this))
    }

    // Will be called when Pkcs11Module#waitForSlotEvent returns the slot with the present token
    private fun handleSlotFromWaitForSlotEvent(token: RtPkcs11Token) {
        try {
            doPkcs11Operation(token)
        } catch (e: Exception) {
            showUsbDialog("Failed to handle slot from wait for slot event.", e.toString())
        }
    }

    /*
     * Should be called ONLY if guaranteed that the token is already connected and all permissions
     * is granted. Otherwise, Pkcs11Module#getSlotList returns an empty list
     */
    fun handleSlotFromGetSlotList() {
        try {
            module.initializeModule(null) // resolved the error

            val slots = module.getSlotList(true)
            if (slots.isNotEmpty())
                doPkcs11Operation(slots.first().token)
        } catch (e: Exception) {
            showUsbDialog("Failed to handle slot from get slot list.", e.toString())
        }
    }

    private fun doPkcs11Operation(token: Pkcs11Token) {

        try {
            token.openSession(true).use { session ->
                var signMechanism: Pkcs11Mechanism? = null
                var digestMechanism: Pkcs11Mechanism? = null
                when (GOST_KEY_PAIR_PARAMS) {

                    GostKeyPairParams.GOST_2001_256 -> {
                        signMechanism = Pkcs11Mechanism.make(token.mechanismList[23])
                        digestMechanism = Pkcs11Mechanism.make(token.mechanismList[29])
                    }
                }

                println("Механизм: ${signMechanism.mechanismType}")

                try {
                    session.login(Pkcs11UserType.CKU_USER, "214021").use {
                        try {
                            val allCertificates = session.objectManager.findObjectsAtOnce(
                                Pkcs11CertificateObject::class.java,
                                listOf(
                                    session.attributeFactory.makeAttribute(
                                        Pkcs11AttributeType.CKA_CLASS,
                                        CKO_CERTIFICATE
                                    ),
                                )
                            )

                            showUsbDialog("Finding signer certificate", "")
                            val signerCertificate = allCertificates.first()
                            val signerCertificateValue = signerCertificate
                                .getByteArrayAttributeValue(session, CKA_VALUE)
                                .byteArrayValue

                            val keyPair =
                                findKeyPairByCertificateValue(session, signerCertificateValue)
                            showUsbDialog("Data to sign:", DATA_TO_SIGN.toString())
                            val dataToSign =
                                session.digestManager.digestAtOnce(DATA_TO_SIGN, digestMechanism)

                            val signature = session.signManager.signAtOnce(
                                dataToSign,
                                signMechanism,
                                keyPair.privateKey
                            )
                            showUsbDialog("Signed data:", signature.toString())

                            showUsbDialog("Verifying GOST signature", "")
                            val result = session.verifyManager.verifyAtOnce(
                                dataToSign,
                                signature,
                                signMechanism,
                                keyPair.publicKey
                            )

                            if (result) {
                                showUsbDialog("GOST signature is valid", "")
                            } else {
                                throw IllegalStateException("GOST signature is invalid")
                            }
                        } catch (e: Exception) {
                            showUsbDialog(
                                "Error",
                                "An unexpected error occurred while trying to sign: ${e.message}"
                            )
                        }
                    }
                } catch (e: Pkcs11Exception) {
                    if (e.message?.contains("CKR_PIN_INCORRECT") == true) {
                        showUsbDialog("Error", "Invalid password provided.")
                    } else {
                        showUsbDialog("Error", "An unexpected error occurred: ${e.message}")
                        throw e
                    }
                }
            }
        } catch (e: Exception) {
            println(e)
        } finally {
            module.finalizeModule()
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
        if (objects.isEmpty()) {
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

    fun showUsbDialog(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("OK") { dialog, _ -> dialog.dismiss() }
            .create()
            .show()
    }
}
