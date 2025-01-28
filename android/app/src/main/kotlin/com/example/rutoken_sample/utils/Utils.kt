/*
 * Copyright (c) 2022, Aktiv-Soft JSC.
 * See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package com.example.rutoken_sample.utils

import android.os.Build
import androidx.annotation.RequiresApi
import ru.rutoken.pkcs11wrapper.constant.IPkcs11MechanismType
import ru.rutoken.pkcs11wrapper.main.Pkcs11Token
import ru.rutoken.pkcs11wrapper.rutoken.main.RtPkcs11Token
import java.util.*
import java.util.stream.IntStream

object Utils {
    fun println(text: String = "") {
        kotlin.io.println(text)
    }

    fun printf(format: String, vararg args: Any) {
        kotlin.io.print(format.format(*args))
    }

    fun printlnf(format: String, vararg args: Any) {
        printf(format, *args)
        println()
    }

    fun <T> printSuccessfulExit(clazz: Class<T>) {
        println("${clazz.simpleName} has been completed successfully")
    }

    fun <T> printError(clazz: Class<T>, e: Exception) {
        System.err.println("${clazz.simpleName} has failed:")
        e.printStackTrace()
    }

    fun printHex(label: String, data: ByteArray) {
        println(label)
        data.forEachIndexed { index, byte ->
            printf(" %02X", byte)
            if ((index + 1) % 16 == 0) println()
        }
        println()
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun printCsr(csrDer: ByteArray) {
        println("CSR:")

        val lineWidth = 64
        val csrBase64 = Base64.getEncoder().encodeToString(csrDer)

        var k = 0
        while (k < csrBase64.length / lineWidth) {
            println(csrBase64.substring(k * lineWidth, (k + 1) * lineWidth))
            k++
        }
        println(csrBase64.substring(k * lineWidth))
    }

    fun printString(label: String, data: String) {
        println(label)
        println(data)
    }

    fun readCertificate(): String {
        val regexHeader = ".*-----BEGIN[^-]*(-[^-]+)*-----".toRegex()
        val regexFooter = "-----END[^-]*(-[^-]+)*-----.*".toRegex()
        val scanner = Scanner(System.`in`)
        val certificate = StringBuilder()

        var currentLine: String? = scanner.nextLine()
        while (!currentLine.isNullOrEmpty()) {
            certificate.append(currentLine)
            currentLine = scanner.nextLine()
        }

        return certificate.toString().replaceFirst(regexHeader, "").replaceFirst(regexFooter, "")
    }

    fun <T> TODO(reason: String): T {
        throw UnsupportedOperationException(reason)
    }

    fun contains(arrays: List<ByteArray>, element: ByteArray): Boolean {
        return arrays.any { Arrays.equals(it, element) }
    }

    fun dropPrecedingZeros(array: ByteArray): ByteArray {
        if (array.isEmpty()) return array

        val numPrecedingZeros = IntStream.range(0, array.size)
            .filter { index -> array[index] != 0.toByte() }
            .findFirst().orElse(-1)

        return array.copyOfRange(numPrecedingZeros, array.size)
    }

    fun <T> hasUnsupportedMechanisms(
        clazz: Class<T>,
        token: Pkcs11Token,
        vararg mechanisms: IPkcs11MechanismType
    ): Boolean {
        val unsupportedMechanisms = Pkcs11Operations.getUnsupportedMechanisms(token, *mechanisms)
        if (unsupportedMechanisms.isEmpty()) return false

        printf("${clazz.simpleName} cannot be run as ")
        unsupportedMechanisms.dropLast(1).forEach {
            printf("$it, ")
        }
        printlnf("${unsupportedMechanisms.last()} not supported by token")

        return true
    }

    fun <T> isRsaModulusUnsupported(clazz: Class<T>, token: RtPkcs11Token, modulusBits: Int): Boolean {
        if (!Pkcs11Operations.isRsaModulusSupported(token, modulusBits)) {
            println("${clazz.simpleName} cannot be run as RSA modulus $modulusBits is not supported by the token")
            return true
        }
        return false
    }

    fun printSampleDelimiter() {
        println("--------------------------------------------------------")
        println("--------------------------------------------------------")
    }

    fun <T> printSampleLaunchMessage(clazz: Class<T>) {
        println("Launch ${clazz.simpleName}")
    }
}
