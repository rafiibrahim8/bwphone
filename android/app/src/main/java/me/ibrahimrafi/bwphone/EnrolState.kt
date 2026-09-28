package me.ibrahimrafi.bwphone

import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import uniffi.bwphone_android.PhoneStatus

/**
 * The enrol window. `enrol_begin` and `set_pin` are refused unless the
 * person has opened the Enrol screen recently, or has the app in front when
 * the PC asks: the PC alone cannot create a key or pin a ciphertext
 * on a phone nobody is looking at.
 *
 * It is a time window, not "the screen is in the foreground": between the
 * two messages the PC pauses for the person to compare a fingerprint,
 * and the phone's screen may well turn off meanwhile. The window closes
 * early on Cancel or Done, and on its own once a pin has been set — one enrolment
 * per opening. `set_pin` is only accepted for the account `enrol_begin`
 * created in this window.
 *
 * The account's name is the PC's `--label`, final: the phone replies to
 * `enrol_begin` within the PC's reach budget, so there is no time to ask.
 *
 * A window that runs out after `enrol_begin` but before `set_pin` is undone
 * like Cancel: the key can never be pinned now, so it and its account are
 * deleted rather than left as an unfinished entry that would also block the
 * next `enrol_begin`.
 */
object EnrolState {
    const val WINDOW_MS = 3 * 60_000L

    sealed interface Phase {
        /** Window open, nothing from the PC yet. */
        object Waiting : Phase
        data class Creating(val label: String) : Phase
        /** Key created and sent; the PC asks you to compare the fingerprint. */
        data class Compare(val label: String, val fingerprint: String) : Phase
        /** Pinned; the PC runs a full unlock through the phone next. */
        data class SelfTest(val label: String, val fingerprint: String) : Phase
        data class Done(val label: String) : Phase
        data class Failed(val message: String) : Phase
    }

    private val _openUntil = MutableStateFlow(0L)
    val openUntil: StateFlow<Long> = _openUntil

    val phase = MutableStateFlow<Phase>(Phase.Waiting)

    /** The account `enrol_begin` created in this window, if any. */
    @Volatile
    var pendingAccount: String? = null

    /** The account pinned in this window, until the PC's self-test unlock answers. */
    @Volatile
    var selfTestAccount: String? = null

    /**
     * Set when the PC's `enrol_begin` arrived with the app in front and no
     * Enrol screen open: whichever screen is showing opens the Enrol screen.
     */
    val autoOpen = MutableStateFlow(false)

    fun isOpen(): Boolean = System.currentTimeMillis() < _openUntil.value

    private val main = Handler(Looper.getMainLooper())

    @Synchronized
    fun open(prefs: Prefs) {
        expireIfNeeded(prefs)
        val until = System.currentTimeMillis() + WINDOW_MS
        _openUntil.value = until
        pendingAccount = null
        selfTestAccount = null
        phase.value = Phase.Waiting
        // Clean up after this window even if nothing else touches it again.
        main.postDelayed({ expireIfNeeded(prefs) }, until - System.currentTimeMillis() + 500)
    }

    @Synchronized
    fun close() {
        _openUntil.value = 0L
        pendingAccount = null
    }

    /**
     * The window has run out with a key still waiting for its pin: nothing
     * can pin it now, so delete it and its account, as Cancel would.
     * Called on a timer and wherever the window is consulted, so a missed
     * timer (the process was frozen) is caught up on the next use.
     */
    @Synchronized
    fun expireIfNeeded(prefs: Prefs) {
        if (isOpen()) return
        val orphan = pendingAccount ?: return
        pendingAccount = null
        Keystore.delete(orphan)
        prefs.removeAccount(orphan)
        if (phase.value is Phase.Creating || phase.value is Phase.Compare) {
            phase.value = Phase.Failed(
                "The enrol window closed before the PC pinned the key, so the key was deleted. " +
                    "Run bwphone enroll again."
            )
        }
    }

    /**
     * Cancel: close the window and undo what it created on the phone, a key
     * made but not yet pinned, or pinned and awaiting the self-test. The
     * PC's next message is then refused, and it discards its side.
     */
    /**
     * `enrol_begin`'s key now exists: record it as this window's, unless the
     * window closed while it was being made (then the caller deletes it).
     * One step under the lock, so the expiry timer finds either no key or a
     * recorded one, never a key it cannot see yet.
     */
    @Synchronized
    fun adoptKey(prefs: Prefs, id: String, label: String, fingerprint: String): Boolean {
        if (!isOpen()) return false
        prefs.addAccount(id, label)
        pendingAccount = id
        phase.value = Phase.Compare(label, fingerprint)
        return true
    }

    /**
     * `set_pin`: check the window, pin, and close the window, as one step
     * under the lock, so the expiry timer cannot delete the key between the
     * check and the pin and leave the PC told `ok` for a key that is gone.
     */
    @Synchronized
    fun pin(prefs: Prefs, id: String, pin: ByteArray): PhoneStatus {
        expireIfNeeded(prefs)
        if (!isOpen() || pendingAccount != id) return PhoneStatus.NOT_ALLOWED
        if (!prefs.hasAccount(id) || !Keystore.hasKey(id)) return PhoneStatus.UNKNOWN_ACCOUNT
        if (!prefs.setPinOnce(id, pin)) return PhoneStatus.NOT_ALLOWED
        // One enrolment per window: pinned, so the window is done. The PC's
        // self-test unlock comes next, and the Enrol screen waits for it.
        val fingerprint = (phase.value as? Phase.Compare)?.fingerprint.orEmpty()
        close()
        selfTestAccount = id
        phase.value = Phase.SelfTest(prefs.label(id), fingerprint)
        return PhoneStatus.OK
    }

    @Synchronized
    fun cancel(prefs: Prefs) {
        val created = pendingAccount ?: selfTestAccount
        close()
        selfTestAccount = null
        if (created != null) {
            Keystore.delete(created)
            prefs.removeAccount(created)
        }
        phase.value = Phase.Waiting
    }

    /** The PC's self-test unlock for [accountHex] finished. */
    @Synchronized
    fun selfTestFinished(accountHex: String, label: String, ok: Boolean) {
        if (selfTestAccount != accountHex) return
        selfTestAccount = null
        phase.value = if (ok) Phase.Done(label) else Phase.Failed(
            "The self-test unlock didn't finish, so the PC discarded this enrolment. " +
                "Revoke $label on this phone, then enrol it again."
        )
    }
}
