package me.ibrahimrafi.bwphone

import android.util.Log
import java.net.Socket
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.bwphone_android.FrameDecoder
import uniffi.bwphone_android.Handshake
import uniffi.bwphone_android.PhoneRequest
import uniffi.bwphone_android.PhoneStatus
import uniffi.bwphone_android.StaticKey
import uniffi.bwphone_android.Transport
import uniffi.bwphone_android.emojiIndex
import uniffi.bwphone_android.encodeResponse
import uniffi.bwphone_android.frameEncode
import uniffi.bwphone_android.parseRequest
import uniffi.bwphone_android.phoneChoices
import uniffi.bwphone_android.phoneNonce
import uniffi.bwphone_android.shortFingerprint

/**
 * One accepted connection: handshake, one request, one or two replies.
 *
 * Nothing visible happens before a valid request whose `rsa_ct` matches
 * the pin: a connection that fails the handshake, sends garbage, or asks
 * for a ciphertext we did not pin is answered (or not) and closed with no
 * notification, sound or screen wake. That is what makes any-Wi-Fi safe.
 *
 * Two rules against someone holding the PC's key:
 * - The whole pre-auth phase (handshake plus the request) must finish within
 *   an absolute deadline from accept; a peer that trickles bytes cannot hold
 *   a session open.
 * - A session that completes the handshake and then never asks for anything
 *   is recorded as "unexplained". A legitimate PC always asks; an
 *   attacker grinding sessions for a particular emoji does not. The count is
 *   shown on the next prompt.
 *
 * Nothing the request says is ever displayed. The PC's `host` field is
 * caller-supplied text and is only logged.
 */
class Session(
    private val socket: Socket,
    private val prefs: Prefs,
    private val phoneKey: StaticKey,
    private val rate: RateLimit,
    private val hooks: Hooks,
) {
    /** What the service does for a session: show the prompt, take it down, keep the CPU awake. */
    interface Hooks {
        fun showPrompt(pending: PendingRequest.Pending)
        fun hidePrompt()
        fun withWakeLock(block: () -> Unit)
        /** The keyguard is showing: nobody has unlocked the phone to look at it. */
        fun phoneLocked(): Boolean
    }

    private val decoder = FrameDecoder()
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    private val acceptedAt = System.currentTimeMillis()
    private var handshakeDone = false
    private var requestSeen = false

    fun run() {
        try {
            val pcPub = prefs.pcPublic ?: return
            val pairingId = prefs.pairingId ?: return
            val hs = Handshake.kkResponder(phoneKey, pcPub, pairingId)
            while (!hs.isFinished()) {
                if (hs.isMyTurn()) send(hs.writeMessage()) else hs.readMessage(nextFrame())
            }
            handshakeDone = true
            val transport = hs.intoTransport()
            val req = parseRequest(transport.open(nextFrame()))
            requestSeen = true
            // Authenticated from here on; the request itself decides what happens next.
            socket.soTimeout = 0
            handle(transport, req.reqId, req.request)
        } catch (e: Exception) {
            // Pre-auth failures and malformed requests are closed silently, by design.
            Log.d(TAG, "session ended: $e")
        } finally {
            if (handshakeDone && !requestSeen) rate.recordUnexplained()
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private fun handle(t: Transport, reqId: String, request: PhoneRequest) {
        when (request) {
            is PhoneRequest.Ping -> reply(t, reqId, PhoneStatus.PONG)
            is PhoneRequest.Unwrap -> unwrap(t, reqId, request)
            is PhoneRequest.EnrolBegin -> enrolBegin(t, reqId, request)
            is PhoneRequest.SetPin -> setPin(t, reqId, request)
        }
    }

    private fun unwrap(t: Transport, reqId: String, r: PhoneRequest.Unwrap) {
        val id = Prefs.hex(r.account)
        Log.i(TAG, "unwrap for $id from host=${r.host.take(64)}")
        if (!prefs.hasAccount(id)) { reply(t, reqId, PhoneStatus.UNKNOWN_ACCOUNT); return }
        val pin = prefs.pin(id)
        if (pin == null || !MessageDigest.isEqual(pin, sha256(r.rsaCt))) {
            // The one ciphertext this key will ever decrypt is not this one. No prompt.
            reply(t, reqId, PhoneStatus.PIN_MISMATCH); return
        }
        if (prefs.invalidated.contains(id) || !Keystore.probe(id)) {
            prefs.addInvalidated(id)
            reply(t, reqId, PhoneStatus.INVALIDATED); return
        }
        // The PC may ask for less; never more than the extension's own timeout.
        val expiresInMs = r.expiresInMs.toLong().coerceIn(1_000L, MAX_HUMAN_MS)

        // Our half of the emoji derivation, chosen only now that the PC's is committed.
        val myNonce = phoneNonce()
        val realIndex = emojiIndex(t.handshakeHash(), r.nonce, myNonce).toInt()
        val choices = phoneChoices(realIndex.toUInt()).map { it.toInt() }
        val pending = PendingRequest.Pending(
            accountHex = id,
            label = prefs.label(id),
            rsaCt = r.rsaCt,
            choices = choices,
            realIndex = realIndex,
            deadlineMillis = System.currentTimeMillis() + expiresInMs,
            suspicious = rate.suspicious(),
            unexplainedSessions = rate.unexplainedLastHour(),
        )
        if (!PendingRequest.begin(pending)) { reply(t, reqId, PhoneStatus.BUSY); return }
        // Only a request that is actually about to prompt spends rate budget.
        if (!rate.allow(id)) { PendingRequest.end(); reply(t, reqId, PhoneStatus.RATE_LIMITED); return }

        try {
            hooks.withWakeLock {
                reply(t, reqId, PhoneStatus.PROMPT_POSTED, nonce = myNonce)
                hooks.showPrompt(pending)
                // If the PC gives up (Use password, or it died), it closes the
                // connection; take the prompt down rather than leave it up for nothing.
                val watcher = Thread({
                    try { if (input.read() < 0) pending.result.complete(PendingRequest.Outcome.Cancelled) }
                    catch (_: Exception) { pending.result.complete(PendingRequest.Outcome.Cancelled) }
                }, "bwphone-drop-watch").apply { isDaemon = true; start() }
                val outcome = runBlocking {
                    withTimeoutOrNull(expiresInMs) { pending.result.await() }
                }
                hooks.hidePrompt()
                // After an enrolment, this is the PC's self-test; the Enrol screen shows how it went.
                EnrolState.selfTestFinished(id, pending.label, ok = outcome is PendingRequest.Outcome.KWrap)
                when (outcome) {
                    is PendingRequest.Outcome.KWrap -> {
                        prefs.recordUnlock(id)
                        prefs.addHistory(pending.label, "ok")
                        reply(t, reqId, PhoneStatus.OK, kWrap = outcome.bytes)
                        outcome.bytes.fill(0)
                    }
                    PendingRequest.Outcome.Denied -> { prefs.addHistory(pending.label, "denied"); reply(t, reqId, PhoneStatus.DENIED) }
                    PendingRequest.Outcome.Rejected -> { prefs.addHistory(pending.label, "rejected"); reply(t, reqId, PhoneStatus.REJECTED) }
                    PendingRequest.Outcome.Invalidated -> {
                        prefs.addInvalidated(id)
                        prefs.addHistory(pending.label, "invalidated")
                        reply(t, reqId, PhoneStatus.INVALIDATED)
                    }
                    PendingRequest.Outcome.Error -> { prefs.addHistory(pending.label, "error"); reply(t, reqId, PhoneStatus.ERROR) }
                    // The PC is gone; nobody to reply to.
                    PendingRequest.Outcome.Cancelled -> prefs.addHistory(pending.label, "cancelled by PC")
                    // The deadline ran out: the prompt is cancelled and no K_wrap is ever sent.
                    PendingRequest.Outcome.Expired, null -> {
                        pending.result.complete(PendingRequest.Outcome.Expired)
                        prefs.addHistory(pending.label, "expired")
                        reply(t, reqId, PhoneStatus.EXPIRED)
                    }
                }
            }
        } finally {
            PendingRequest.end()
        }
    }

    private fun enrolBegin(t: Transport, reqId: String, r: PhoneRequest.EnrolBegin) {
        val id = Prefs.hex(r.account)
        // A window that ran out with an unpinned key: clear it before judging this request.
        EnrolState.expireIfNeeded(prefs)
        if (EnrolState.pendingAccount != null || prefs.hasAccount(id) || Keystore.hasKey(id)) {
            reply(t, reqId, PhoneStatus.NOT_ALLOWED); return
        }
        // Never with the phone locked (the unlock screen over the keyguard counts as the app
        // being in front), and never over an unlock that is waiting for the person.
        if (hooks.phoneLocked() || PendingRequest.current != null) {
            reply(t, reqId, PhoneStatus.NOT_ALLOWED); return
        }
        // The window before anything else: outside one, every refusal looks the same, so
        // the PC's key alone cannot learn which account names this phone holds.
        if (!EnrolState.isOpen()) {
            // With the app in front, the person is looking at it: open the window
            // and bring up the Enrol screen. Otherwise the PC cannot start one.
            if (!AppState.inForeground) { reply(t, reqId, PhoneStatus.NOT_ALLOWED); return }
            EnrolState.open(prefs)
            EnrolState.autoOpen.value = true
        }
        // The PC's --label is final; the reply must go out within its reach budget.
        val label = r.labelHint.trim().take(32).ifEmpty { "Account" }
        // One name, one account: a second "Work" could pose as the first in the prompt.
        if (prefs.accountIds().any { prefs.label(it).equals(label, ignoreCase = true) }) {
            EnrolState.phase.value = EnrolState.Phase.Failed(
                "This phone already has an account named $label. Revoke it first, or enrol with another --label."
            )
            // Its own status, so the PC can say exactly this.
            reply(t, reqId, PhoneStatus.LABEL_TAKEN); return
        }
        EnrolState.phase.value = EnrolState.Phase.Creating(label)
        val rsaPub = try {
            Keystore.generate(id)
        } catch (e: Exception) {
            EnrolState.phase.value = EnrolState.Phase.Failed("Couldn't create the key: ${e.message ?: e}")
            reply(t, reqId, PhoneStatus.ERROR); return
        }
        if (!EnrolState.adoptKey(prefs, id, label, shortFingerprint(rsaPub))) {
            // Cancelled, or the window ran out, while the key was being made: undo it, and tell the PC no.
            Keystore.delete(id)
            reply(t, reqId, PhoneStatus.NOT_ALLOWED); return
        }
        reply(t, reqId, PhoneStatus.OK, rsaPub = rsaPub, label = label)
    }

    private fun setPin(t: Transport, reqId: String, r: PhoneRequest.SetPin) {
        reply(t, reqId, EnrolState.pin(prefs, Prefs.hex(r.account), r.pin))
    }

    private fun reply(
        t: Transport,
        reqId: String,
        status: PhoneStatus,
        nonce: ByteArray? = null,
        kWrap: ByteArray? = null,
        rsaPub: ByteArray? = null,
        label: String? = null,
    ) {
        send(t.seal(encodeResponse(reqId, status, nonce, kWrap, rsaPub, label)))
    }

    private fun send(message: ByteArray) {
        output.write(frameEncode(message))
        output.flush()
    }

    /**
     * Blocks until a whole frame has arrived. Before the request is in, every
     * read is bounded by what is left of the absolute pre-auth deadline, so
     * neither a silent peer nor a byte-at-a-time one can hold the session.
     */
    private fun nextFrame(): ByteArray {
        val buf = ByteArray(4096)
        while (true) {
            decoder.nextFrame()?.let { return it }
            if (!requestSeen) {
                val left = acceptedAt + PRE_AUTH_TIMEOUT_MS - System.currentTimeMillis()
                if (left <= 0) throw java.net.SocketTimeoutException("pre-auth deadline")
                socket.soTimeout = left.toInt()
            }
            val n = input.read(buf)
            if (n < 0) throw java.io.EOFException("peer closed")
            decoder.push(buf.copyOf(n))
        }
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    companion object {
        private const val TAG = "bwphone.session"
        /** Handshake plus request, from accept, or the connection is dropped. */
        const val PRE_AUTH_TIMEOUT_MS = 5_000L
        /** The extension gives up after 60 s; a longer prompt could never be answered in time. */
        const val MAX_HUMAN_MS = 60_000L
    }
}
