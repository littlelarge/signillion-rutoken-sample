package com.example.rutoken_sample

import com.sun.jna.Native
import ru.rutoken.pkcs11jna.Pkcs11
import ru.rutoken.pkcs11wrapper.main.Pkcs11Api
import ru.rutoken.pkcs11wrapper.main.Pkcs11BaseModule
import ru.rutoken.pkcs11wrapper.lowlevel.jna.Pkcs11JnaLowLevelApi
import ru.rutoken.pkcs11wrapper.lowlevel.jna.Pkcs11JnaLowLevelFactory

class Module : Pkcs11BaseModule(
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
