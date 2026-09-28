package me.ibrahimrafi.bwphone

import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.flow.MutableStateFlow
import me.ibrahimrafi.bwphone.ui.BwTheme
import me.ibrahimrafi.bwphone.ui.PairScreen
import uniffi.bwphone_android.FrameDecoder
import uniffi.bwphone_android.Handshake
import uniffi.bwphone_android.StaticKey
import uniffi.bwphone_android.decodeQr
import uniffi.bwphone_android.encodePairConfirm
import uniffi.bwphone_android.encodePairHello
import uniffi.bwphone_android.frameEncode
import uniffi.bwphone_android.helloKey
import uniffi.bwphone_android.pairingId
import uniffi.bwphone_android.pairingTranscript
import uniffi.bwphone_android.pairingWords
import uniffi.bwphone_android.parsePairConfirm

/**
 * Pairing, once. Scan the PC's QR, run `Noise_NKpsk0` with its token as
 * the PSK (so a relay cannot complete the handshake), send our X25519 key
 * in the PairHello, show the six words, and commit only when both sides
 * have sent and received `true`.
 */
class PairActivity : BaseActivity() {
    sealed interface Ui {
        object Scanning : Ui
        data class Connecting(val ip: String) : Ui
        data class Confirm(val ip: String, val words: List<String>) : Ui
        data class WaitingForPc(val ip: String) : Ui
        data class Paired(val ip: String) : Ui
        object Cancelled : Ui
        data class Failed(val reason: String) : Ui
        object AlreadyPaired : Ui
    }

    private val ui = MutableStateFlow<Ui>(Ui.Scanning)
    private var answer: CompletableFuture<Boolean>? = null
    private lateinit var prefs: Prefs

    private val scanner = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents
        if (text == null) { finish(); return@registerForActivityResult }
        Thread { pair(text) }.start()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        setContent {
            BwTheme {
                val state by ui.collectAsStateWithLifecycle()
                PairScreen(
                    ui = state,
                    onMatch = { answer?.complete(true) },
                    onNoMatch = { answer?.complete(false) },
                    onScanAgain = { ui.value = Ui.Scanning; scan() },
                    onClose = { answer?.complete(false); finish() },
                )
            }
        }
        if (prefs.isPaired) {
            // Exactly one pairing: a second requires Revoke all first.
            ui.value = Ui.AlreadyPaired
            return
        }
        if (savedInstanceState == null) scan()
    }

    override fun onDestroy() {
        // Leaving mid-confirmation is a "no": nothing is stored.
        answer?.complete(false)
        super.onDestroy()
    }

    private fun scan() {
        scanner.launch(ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt(getString(R.string.pair_scan_prompt))
            setBeepEnabled(false)
            setOrientationLocked(false)
        })
    }

    private fun pair(qrText: String) {
        val qr = try { decodeQr(qrText) } catch (e: Exception) { ui.value = Ui.Failed(getString(R.string.pair_not_qr)); return }
        val cm = Net.cm(this)
        val network = Net.wifiNetwork(cm) ?: run { ui.value = Ui.Failed(getString(R.string.pair_no_wifi)); return }
        ui.value = Ui.Connecting(qr.ip)
        try {
            val socket = Socket()
            network.bindSocket(socket)
            socket.connect(InetSocketAddress(qr.ip, qr.pairPort.toInt()), 10_000)
            socket.soTimeout = 30_000
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            val decoder = FrameDecoder()
            fun send(m: ByteArray) { output.write(frameEncode(m)); output.flush() }
            fun next(): ByteArray {
                val buf = ByteArray(4096)
                while (true) {
                    decoder.nextFrame()?.let { return it }
                    val n = input.read(buf)
                    if (n < 0) throw java.io.EOFException()
                    decoder.push(buf.copyOf(n))
                }
            }

            val key = StaticKey.generate()
            val hs = Handshake.pairInitiator(qr.pcPub, qr.token)
            while (!hs.isFinished()) { if (hs.isMyTurn()) send(hs.writeMessage()) else hs.readMessage(next()) }
            val t = hs.intoTransport()

            // The first transport message; its exact bytes go into the transcript.
            val label = Build.MODEL ?: "phone"
            val helloBytes = encodePairHello(key.public(), prefs.listenPort.toUShort(), label)
            send(t.seal(helloBytes))
            val transcript = pairingTranscript(t.handshakeHash(), helloBytes)
            val words = pairingWords(transcript)

            // Blocks this thread on the person's answer.
            val future = CompletableFuture<Boolean>()
            answer = future
            ui.value = Ui.Confirm(qr.ip, words)
            val confirmed = future.get()
            send(t.seal(encodePairConfirm(confirmed)))
            if (confirmed) ui.value = Ui.WaitingForPc(qr.ip)
            socket.soTimeout = 120_000
            val pcConfirmed = parsePairConfirm(t.open(next()))
            socket.close()

            if (confirmed && pcConfirmed) {
                prefs.commitPairing(
                    phonePrivate = key.private(),
                    pcPublic = qr.pcPub,
                    pairingId = pairingId(transcript),
                    helloKey = helloKey(transcript),
                    pcAddress = qr.ip,
                    helloPort = qr.helloPort.toInt(),
                    listenPort = prefs.listenPort,
                )
                ui.value = Ui.Paired(qr.ip)
                ListenerService.start(this)
            } else {
                ui.value = Ui.Cancelled
            }
        } catch (e: Exception) {
            if (ui.value !is Ui.Cancelled) ui.value = Ui.Failed(e.message ?: e.toString())
        }
    }
}
