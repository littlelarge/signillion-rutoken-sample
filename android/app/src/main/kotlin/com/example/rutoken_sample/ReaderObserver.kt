package com.example.rutoken_sample

import ru.rutoken.rttransport.RtTransport

class ReaderObserver(private val activity: MainActivity) : RtTransport.PcscReaderObserver {
    override fun onReaderAdded(reader: RtTransport.PcscReader) {
        activity.showUsbDialog("Reader added: ${reader.name}", "")
        activity.handlePkcsModule(0)
    }

    override fun onReaderRemoved(reader: RtTransport.PcscReader) {
        activity.showUsbDialog("Reader removed: ${reader.name}}", "")
    }
}
