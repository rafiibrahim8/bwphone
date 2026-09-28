package me.ibrahimrafi.bwphone

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

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

    fun open() {
        _openUntil.value = System.currentTimeMillis() + WINDOW_MS
        pendingAccount = null
        selfTestAccount = null
        phase.value = Phase.Waiting
    }

    fun close() {
        _openUntil.value = 0L
        pendingAccount = null
    }

    /**
     * Cancel: close the window and undo what it created on the phone, a key
     * made but not yet pinned, or pinned and awaiting the self-test. The
     * PC's next message is then refused, and it discards its side.
     */
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
    fun selfTestFinished(accountHex: String, label: String, ok: Boolean) {
        if (selfTestAccount != accountHex) return
        selfTestAccount = null
        phase.value = if (ok) Phase.Done(label) else Phase.Failed(
            "The self-test unlock didn't finish, so the PC discarded this enrolment. " +
                "Revoke $label on this phone, then enrol it again."
        )
    }
}
