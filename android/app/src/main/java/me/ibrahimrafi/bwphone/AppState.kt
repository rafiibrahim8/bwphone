package me.ibrahimrafi.bwphone

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * Process-wide state the screens watch: whether one of our screens is in
 * front, whether stored state changed, and what the listener is doing.
 */
object AppState {
    /**
     * True while any of our activities is visible. A request that arrives then
     * opens its screen directly, since the person is already looking at the app;
     * with the phone locked or the app in the background, nothing opens on its own.
     */
    @Volatile
    var inForeground = false
        private set

    private val _changes = MutableStateFlow(0L)

    /** Ticks on every write to [Prefs], so the screens can reload. */
    val changes: StateFlow<Long> = _changes

    fun changed() = _changes.update { it + 1 }

    sealed interface Listener {
        object Stopped : Listener
        object NotPaired : Listener
        object OffWifi : Listener
        data class Listening(val address: String, val port: Int) : Listener
    }

    val listener = MutableStateFlow<Listener>(Listener.Stopped)

    fun init() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(LifecycleEventObserver { owner, _ ->
            inForeground = owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        })
    }
}
