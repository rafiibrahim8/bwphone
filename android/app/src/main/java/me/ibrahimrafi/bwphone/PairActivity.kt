package me.ibrahimrafi.bwphone

import android.app.Application
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.lifecycle.AndroidViewModel
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
 *
 * The session lives in [PairModel], not the activity: turning the phone or
 * any other configuration change rebuilds the screen, and that must neither
 * answer "no" for the person nor cut the new screen off from the session.
 * Only leaving the screen for good does that.
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

    private val model: PairModel by viewModels()

    private val scanner = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents
        if (text == null) { finish(); return@registerForActivityResult }
        model.start(text)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BwTheme {
                val state by model.ui.collectAsStateWithLifecycle()
                PairScreen(
                    ui = state,
                    onMatch = { model.answer(true) },
                    onNoMatch = { model.answer(false) },
                    onScanAgain = { model.ui.value = Ui.Scanning; scan() },
                    onClose = { model.answer(false); finish() },
                )
            }
        }
        // A rebuilt screen picks up where the session is; only a fresh one starts.
        if (savedInstanceState != null) return
        if (Prefs(this).isPaired) {
            // Exactly one pairing: a second requires Revoke all first.
            model.ui.value = Ui.AlreadyPaired
            return
        }
        scan()
    }

    private fun scan() {
        scanner.launch(ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt(getString(R.string.pair_scan_prompt))
            setBeepEnabled(false)
            setOrientationLocked(false)
        })
    }
}

/**
 * One pairing session, outliving any single [PairActivity] instance. Cleared
 * only when the screen is left for good, which answers "no" if the person
 * had not answered yet, so nothing is stored.
 */
class PairModel(app: Application) : AndroidViewModel(app) {
    val ui = MutableStateFlow<PairActivity.Ui>(PairActivity.Ui.Scanning)
    @Volatile
    private var answer: CompletableFuture<Boolean>? = null
    @Volatile
    private var running = false
    /** Set once the screen is gone for good: the session must stop, not wait for an answer. */
    @Volatile
    private var cleared = false
    @Volatile
    private var socket: Socket? = null

    /** One session at a time; a scan result delivered twice does not start a second. */
    @Synchronized
    fun start(qrText: String) {
        if (running) return
        running = true
        Thread({ try { pair(qrText) } finally { running = false } }, "bwphone-pair").start()
    }

    fun answer(confirmed: Boolean) {
        answer?.complete(confirmed)
    }

    override fun onCleared() {
        // Leaving mid-confirmation is a "no": nothing is stored. Closing the
        // socket ends a session still connecting or waiting on the PC.
        cleared = true
        answer?.complete(false)
        try { socket?.close() } catch (_: Exception) {}
    }

    private fun pair(qrText: String) {
        val app = getApplication<Application>()
        val prefs = Prefs(app)
        val qr = try { decodeQr(qrText) } catch (e: Exception) { ui.value = PairActivity.Ui.Failed(app.getString(R.string.pair_not_qr)); return }
        val cm = Net.cm(app)
        val network = Net.wifiNetwork(cm) ?: run { ui.value = PairActivity.Ui.Failed(app.getString(R.string.pair_no_wifi)); return }
        ui.value = PairActivity.Ui.Connecting(qr.ip)
        val socket = Socket()
        this.socket = socket
        try {
            if (cleared) return
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
            // The screen may have gone before there was anything to answer.
            if (cleared) future.complete(false)
            ui.value = PairActivity.Ui.Confirm(qr.ip, words)
            val confirmed = future.get()
            send(t.seal(encodePairConfirm(confirmed)))
            if (confirmed) ui.value = PairActivity.Ui.WaitingForPc(qr.ip)
            socket.soTimeout = 120_000
            val pcConfirmed = parsePairConfirm(t.open(next()))

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
                ui.value = PairActivity.Ui.Paired(qr.ip)
                ListenerService.start(app)
            } else {
                ui.value = PairActivity.Ui.Cancelled
            }
        } catch (e: Exception) {
            if (ui.value !is PairActivity.Ui.Cancelled) ui.value = PairActivity.Ui.Failed(e.message ?: e.toString())
        } finally {
            try { socket.close() } catch (_: Exception) {}
            this.socket = null
        }
    }
}
