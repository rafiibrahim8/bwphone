package me.ibrahimrafi.bwphone

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import me.ibrahimrafi.bwphone.ui.BwTheme
import me.ibrahimrafi.bwphone.ui.UnlockScreen
import uniffi.bwphone_android.emojiList

/**
 * The emoji pick, then the fingerprint. Opens over the lock screen from the
 * notification, or by itself when the app is in front. Nothing on this
 * screen comes from the request: the label, the count, the last time and
 * the warnings are the phone's own.
 */
class UnlockActivity : BaseActivity() {
    private var answered = false
    /** The request this screen shows; leaving without answering denies it and nothing else. */
    private var mine: PendingRequest.Pending? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        val pending = PendingRequest.current
        if (pending == null || !pending.isOpen) { finish(); return }
        mine = pending
        PendingRequest.onFinished = { runOnUiThread { finish() } }

        val prefs = Prefs(this)
        val emojis = emojiList()
        val count = prefs.unlockCount(pending.accountHex)
        val last = prefs.lastUnlock(pending.accountHex)
        setContent {
            BwTheme {
                UnlockScreen(
                    pending = pending,
                    emojis = pending.choices.map { emojis[it] },
                    unlockCount = count,
                    lastUnlock = last,
                    onPick = { i -> pick(pending, pending.choices[i]) },
                    onNone = { answer(PendingRequest.Outcome.Rejected) },
                    onExpired = { answer(PendingRequest.Outcome.Expired) },
                )
            }
        }
    }

    private fun pick(pending: PendingRequest.Pending, index: Int) {
        if (answered) return
        if (index != pending.realIndex) { answer(PendingRequest.Outcome.Denied); return }
        val cipher = try {
            Keystore.decryptCipher(pending.accountHex)
        } catch (e: KeyPermanentlyInvalidatedException) {
            answer(PendingRequest.Outcome.Invalidated); return
        } catch (e: Keystore.KeyMissing) {
            answer(PendingRequest.Outcome.Invalidated); return
        } catch (e: java.security.InvalidAlgorithmParameterException) {
            // This phone's Keystore won't run our OAEP parameters with this key.
            answer(PendingRequest.Outcome.Invalidated); return
        }
        if (BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            answer(PendingRequest.Outcome.Error); return
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.prompt_title, pending.label))
            .setSubtitle(getString(R.string.prompt_subtitle))
            // No device credential: the phone PIN must never unwrap the vault.
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.cancel))
            .setConfirmationRequired(false)
            .build()
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher ?: run { answer(PendingRequest.Outcome.Error); return }
                try {
                    // The fingerprint authorised exactly this operation.
                    answer(PendingRequest.Outcome.KWrap(c.doFinal(pending.rsaCt)))
                } catch (e: Exception) {
                    answer(PendingRequest.Outcome.Error)
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                // Lockout, cancel, dismiss: all a denial from the PC's point of view.
                answer(PendingRequest.Outcome.Denied)
            }
        })
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun answer(outcome: PendingRequest.Outcome) {
        if (answered) return
        answered = true
        mine?.result?.complete(outcome)
        finish()
    }

    override fun onDestroy() {
        // Leaving without answering is a denial; the session must not wait out the deadline for nothing.
        if (!answered && !isChangingConfigurations) mine?.result?.complete(PendingRequest.Outcome.Denied)
        super.onDestroy()
    }

    companion object {
        fun intent(context: Context): Intent = Intent(context, UnlockActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
}
