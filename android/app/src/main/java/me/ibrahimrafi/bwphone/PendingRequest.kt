package me.ibrahimrafi.bwphone

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The one unlock request in flight, shared between the session thread that
 * owns the socket and the [UnlockActivity] that owns the screen. The
 * session creates it, posts the notification, and awaits [Pending.result]
 * until the deadline; the activity reads it and completes it.
 *
 * It is observable: any of our screens that is in front when a request
 * arrives, or comes to the front while one is waiting (the app opened
 * without tapping the notification), opens the unlock screen for it.
 *
 * Nothing in here came from the request except `rsaCt` (already pinned)
 * and the deadline: the label, counts and warnings are the phone's own.
 */
object PendingRequest {
    sealed class Outcome {
        class KWrap(val bytes: ByteArray) : Outcome()
        object Denied : Outcome()
        object Rejected : Outcome()
        object Expired : Outcome()
        /** The PC closed the connection before answering. */
        object Cancelled : Outcome()
        object Invalidated : Outcome()
        object Error : Outcome()
    }

    class Pending(
        val accountHex: String,
        val label: String,
        val rsaCt: ByteArray,
        /** Indices into `emojiList()`, in display order; the real one is among them. */
        val choices: List<Int>,
        val realIndex: Int,
        val deadlineMillis: Long,
        /** Requests arriving faster than plausible. */
        val suspicious: Boolean,
        /** Sessions in the last hour that completed the handshake and never asked for anything. */
        val unexplainedSessions: Int,
        val result: CompletableDeferred<Outcome> = CompletableDeferred(),
        /** The whole human phase, for the countdown. */
        val totalMillis: Long = (deadlineMillis - System.currentTimeMillis()).coerceAtLeast(1),
    ) {
        val remainingMillis: Long get() = deadlineMillis - System.currentTimeMillis()

        /** Still waiting for the person: not answered, not expired. */
        val isOpen: Boolean get() = !result.isCompleted && remainingMillis > 0
    }

    private val _state = MutableStateFlow<Pending?>(null)
    val state: StateFlow<Pending?> = _state

    val current: Pending? get() = _state.value

    /** Called by the activity to learn when the session gave up (deadline). */
    @Volatile
    var onFinished: (() -> Unit)? = null

    @Synchronized
    fun begin(p: Pending): Boolean {
        if (_state.value != null) return false
        _state.value = p
        return true
    }

    fun complete(outcome: Outcome) {
        current?.result?.complete(outcome)
    }

    @Synchronized
    fun end() {
        _state.value = null
        onFinished?.invoke()
        onFinished = null
    }
}
