package me.ibrahimrafi.bwphone

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import me.ibrahimrafi.bwphone.ui.BwTheme
import me.ibrahimrafi.bwphone.ui.SettingsScreen

/**
 * Settings, from the menu on Home. Each change is saved as it is made and
 * read back through [Prefs], so the screen shows what [RateLimit] will
 * enforce on the next request.
 */
class SettingsActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = Prefs(this)
        setContent {
            BwTheme {
                var perAccount by remember { mutableIntStateOf(prefs.limitPerAccount) }
                var overall by remember { mutableIntStateOf(prefs.limitOverall) }
                fun save(a: Int, o: Int) {
                    prefs.setLimits(a, o)
                    perAccount = prefs.limitPerAccount
                    overall = prefs.limitOverall
                }
                SettingsScreen(
                    perAccount = perAccount,
                    overall = overall,
                    // Raising the per-account cap past the overall one lifts that too.
                    onPerAccount = { save(it, maxOf(overall, it)) },
                    onOverall = { save(perAccount, it) },
                    onReset = { save(RateLimit.DEFAULT_PER_ACCOUNT, RateLimit.DEFAULT_OVERALL) },
                    onNotificationSettings = {
                        startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
                    },
                    onClose = { finish() },
                )
            }
        }
    }
}
