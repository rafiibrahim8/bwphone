package me.ibrahimrafi.bwphone

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import me.ibrahimrafi.bwphone.ui.BwTheme
import me.ibrahimrafi.bwphone.ui.EnrolScreen

/**
 * The Enrol screen. Opening it opens a three-minute window in which the
 * PC may ask for one new account key (`enrol_begin`) and pin its
 * ciphertext (`set_pin`); Cancel, Done, or a successful pin closes it. Back
 * and the close button only leave the screen: the window keeps running, and
 * opening the screen again shows where it is. It also
 * opens by itself when the PC starts an enrolment while the app is in
 * front. The account's name is the PC's `--label`, shown as it
 * arrives; the new key's fingerprint is shown for comparison with the
 * PC. The screen stays on while it is showing.
 */
class EnrolActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        // A fresh opening starts a fresh window, unless one is already running
        // (the PC started it) or the last one is waiting on its self-test.
        val prefs = Prefs(this)
        EnrolState.expireIfNeeded(prefs)
        if (savedInstanceState == null && !EnrolState.isOpen() && EnrolState.phase.value !is EnrolState.Phase.SelfTest) {
            EnrolState.open(prefs)
        }
        setContent {
            BwTheme {
                val phase by EnrolState.phase.collectAsStateWithLifecycle()
                val openUntil by EnrolState.openUntil.collectAsStateWithLifecycle()
                EnrolScreen(
                    phase = phase,
                    openUntil = openUntil,
                    onClose = { finish() },
                    onDone = { EnrolState.close(); finish() },
                    onCancel = { EnrolState.cancel(prefs); finish() },
                    onReopen = { EnrolState.open(prefs) },
                )
            }
        }
    }
}
