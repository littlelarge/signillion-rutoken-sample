package com.example.rutoken_sample

import android.app.Application
import ru.rutoken.rtpcscbridge.RtPcscBridge

class App : Application(){
    override fun onCreate() {
        super.onCreate()
        RtPcscBridge.setAppContext(this)
        RtPcscBridge.getTransportExtension().attachToLifecycle(this, true)
    }
}