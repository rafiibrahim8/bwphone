package me.ibrahimrafi.bwphone

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch

/**
 * Every screen of the app. While one is visible, a request the PC sends
 * opens its own screen: an unlock request opens the emoji pick (also when
 * the app is opened while one waits, without tapping the notification), and
 * an enrolment the PC starts opens the Enrol screen — from any screen but
 * the unlock pick, which must never be pushed away by the PC.
 *
 * AppCompatActivity because BiometricPrompt needs a FragmentActivity host.
 */
open class BaseActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                if (this@BaseActivity !is UnlockActivity) launch {
                    PendingRequest.state.collect { pending ->
                        if (pending != null && pending.isOpen) startActivity(UnlockActivity.intent(this@BaseActivity))
                    }
                }
                if (this@BaseActivity !is EnrolActivity && this@BaseActivity !is UnlockActivity) launch {
                    EnrolState.autoOpen.collect { requested ->
                        if (requested && EnrolState.autoOpen.compareAndSet(true, false)) {
                            startActivity(Intent(this@BaseActivity, EnrolActivity::class.java))
                        }
                    }
                }
            }
        }
    }
}
