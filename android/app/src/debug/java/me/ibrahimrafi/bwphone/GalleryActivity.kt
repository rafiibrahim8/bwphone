package me.ibrahimrafi.bwphone

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import me.ibrahimrafi.bwphone.ui.BwTheme
import me.ibrahimrafi.bwphone.ui.EnrolScreen
import me.ibrahimrafi.bwphone.ui.HomeActions
import me.ibrahimrafi.bwphone.ui.HomeData
import me.ibrahimrafi.bwphone.ui.HomeScreen
import me.ibrahimrafi.bwphone.ui.PairScreen
import me.ibrahimrafi.bwphone.ui.UnlockScreen

/**
 * Debug builds only. Shows one screen with sample data, no PC needed:
 *
 *     adb shell am start -n me.ibrahimrafi.bwphone/.GalleryActivity --es screen unlock --ez dark true
 *
 * screen: home, home-new, unlock, unlock-warn, pair, pair-wait, enrol, enrol-compare, enrol-test, enrol-done, revoke
 */
class GalleryActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val screen = intent.getStringExtra("screen") ?: "home"
        val dark = intent.getBooleanExtra("dark", false)
        val now = System.currentTimeMillis()
        val hour = 3_600_000L
        val home = HomeData(
            paired = true,
            pcAddress = "192.168.1.42",
            accounts = listOf(
                HomeData.Account("a1", "Work", 47, now - hour, invalidated = false, unfinished = false),
                HomeData.Account("a2", "Personal", 12, now - 11 * hour, invalidated = false, unfinished = false),
                HomeData.Account("a3", "Family", 3, now - 72 * hour, invalidated = true, unfinished = false),
            ),
            history = listOf(
                HomeData.Event(now - hour, "Work", "ok"),
                HomeData.Event(now - hour - 1_300_000, "Work", "denied"),
                HomeData.Event(now - 11 * hour, "Personal", "ok"),
                HomeData.Event(now - 14 * hour, "Personal", "rejected"),
                HomeData.Event(now - 15 * hour, "Work", "expired"),
                HomeData.Event(now - 40 * hour, "Work", "ok"),
            ),
            batteryExempt = true,
            notificationsAllowed = true,
        )
        val actions = object : HomeActions {
            override fun pair() {}
            override fun enrol() {}
            override fun fixBattery() {}
            override fun fixNotifications() {}
            override fun notificationSettings() {}
            override fun revoke(accountHex: String) {}
            override fun revokeAll() {}
        }
        fun pending(warn: Boolean) = PendingRequest.Pending(
            accountHex = "a1", label = "Work", rsaCt = ByteArray(0),
            choices = listOf(0, 1, 2, 3, 4), realIndex = 1,
            deadlineMillis = now + 38_000, suspicious = false,
            unexplainedSessions = if (warn) 2 else 0, totalMillis = 45_000,
        )
        val fp = "3f9a 7c21 e0b4 91d6 58c3"
        setContent {
            BwTheme(dark = dark) {
                val cs = MaterialTheme.colorScheme
                Box(Modifier.fillMaxSize().background(cs.surface)) {
                    when (screen) {
                        "home" -> HomeScreen(home, AppState.Listener.Listening("192.168.1.23", 8731), actions)
                        "home-new" -> HomeScreen(
                            home.copy(paired = false, pcAddress = null, accounts = emptyList(), history = emptyList(), batteryExempt = false),
                            AppState.Listener.NotPaired, actions,
                        )
                        "revoke" -> HomeScreen(home, AppState.Listener.Listening("192.168.1.23", 8731), actions, revoking = "Work")
                        "unlock", "unlock-warn" -> {
                            // Stand-in for the lock screen the real window shows through.
                            Box(Modifier.fillMaxSize().background(Brush.linearGradient(listOf(Color(0xFF2C4F63), Color(0xFF0B1112)))))
                            UnlockScreen(
                                pending = pending(screen == "unlock-warn"),
                                emojis = listOf("🥑", "🍩", "😎", "🌽", "🤠"),
                                unlockCount = 47, lastUnlock = now - hour,
                                onPick = {}, onNone = {}, onExpired = {},
                            )
                        }
                        "pair" -> PairScreen(PairActivity.Ui.Confirm("192.168.1.42", listOf("orbit", "velvet", "canyon", "timber", "lunar", "harvest")), {}, {}, {}, {})
                        "pair-wait" -> PairScreen(PairActivity.Ui.WaitingForPc("192.168.1.42"), {}, {}, {}, {})
                        "enrol" -> EnrolScreen(EnrolState.Phase.Waiting, now + 152_000, {}, {}, {}, {})
                        "enrol-compare" -> EnrolScreen(EnrolState.Phase.Compare("Family", fp), now + 152_000, {}, {}, {}, {})
                        "enrol-test" -> EnrolScreen(EnrolState.Phase.SelfTest("Family", fp), 0, {}, {}, {}, {})
                        "enrol-done" -> EnrolScreen(EnrolState.Phase.Done("Family"), 0, {}, {}, {}, {})
                    }
                }
            }
        }
    }
}
