package com.example.rutoken_sample

import android.app.AlertDialog
import android.os.Bundle
import androidx.lifecycle.lifecycleScope
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugins.GeneratedPluginRegistrant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11InitializeArgs
import ru.rutoken.rtpcscbridge.RtPcscBridge

class MainActivity : FlutterFragmentActivity() {

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
        transport?.addPcscReaderObserver(ReaderObserver(this))
    }

    fun handlePkcsModule(slotId: Long) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val module = Module()
                module.initializeModule(Pkcs11InitializeArgs.Builder().setOsLockingOk(true).build())

                val slot = module.getSlotList(true).find { it.id == slotId }
                slot?.let {
                    val session = it.token.openSession(true)

                    withContext(Dispatchers.Main) {
                        showUsbDialog("Slot Found", "Token detected in slot: $slotId")
                    }

                    // Handle PKCS#11 operations here

                } ?: run {
                    withContext(Dispatchers.Main) {
                        showUsbDialog("Error", "No token found in the specified slot.")
                    }
                }

                module.finalizeModule()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showUsbDialog("Error", e.localizedMessage ?: "An error occurred.")
                }
            }
        }
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
