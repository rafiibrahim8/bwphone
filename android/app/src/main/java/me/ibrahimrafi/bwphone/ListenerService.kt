package me.ibrahimrafi.bwphone

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.RejectedExecutionException
import uniffi.bwphone_android.StaticKey

/**
 * The foreground service: a TCP listener bound to the Wi-Fi network's
 * address, and nothing else while off Wi-Fi. It does not keep the phone
 * awake; the battery-optimisation exemption (a Home setup check) is what
 * keeps the network up in Doze, and it also lets the service start from the
 * background on Android 12 and later.
 */
class ListenerService : Service() {
    private lateinit var prefs: Prefs
    private lateinit var cm: ConnectivityManager
    private lateinit var hello: Hello
    private lateinit var rate: RateLimit
    private var phoneKey: StaticKey? = null

    private var server: ServerSocket? = null
    private var acceptThread: Thread? = null
    /** At most [MAX_SESSIONS] connections in flight; more are refused at accept, not queued. */
    private val sessions = ThreadPoolExecutor(0, MAX_SESSIONS, 30, TimeUnit.SECONDS, SynchronousQueue())
    private var wifi: Network? = null
    /** The address the listener is bound to; null while it holds no socket. */
    private var boundIp: Inet4Address? = null

    /** Accepts per source address in the current minute: one stranger cannot use up the PC's share. */
    private val attemptsBySource = HashMap<String, Int>()
    private var attemptsMinute = 0L

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (!Net.isWifi(cm, network)) return
            wifi = network
            bind(network)
        }

        /**
         * The address can come after `onAvailable` (DHCP still running), or
         * change on the same network (a new lease): follow it, or the listener
         * stays bound to an address the phone no longer has.
         */
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            if (network != wifi) return
            if (Net.ipv4(cm, network) != boundIp) bind(network)
        }

        override fun onLost(network: Network) {
            if (network == wifi) {
                wifi = null
                unbind()
                AppState.listener.value = AppState.Listener.OffWifi
                updateNotification(getString(R.string.not_on_wifi))
            }
        }
    }

    /** A screen unlock is one of the two moments the phone asks where the PC is. */
    private val userPresent = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val n = wifi ?: return
            val ip = Net.ipv4(cm, n) ?: return
            announce { hello.announce(n, ip, server?.localPort ?: prefs.listenPort) }
        }
    }

    // The service-type constant is inlined at compile time; ServiceCompat drops it below Android 10.
    @SuppressLint("InlinedApi")
    override fun onCreate() {
        super.onCreate()
        prefs = Prefs(this)
        cm = Net.cm(this)
        hello = Hello(this, prefs)
        rate = RateLimit(prefs)
        ServiceCompat.startForeground(this, NOTIF_ID, notification(getString(R.string.not_on_wifi)), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        AppState.listener.value = AppState.Listener.OffWifi
        phoneKey = prefs.phonePrivate?.let { StaticKey.fromPrivate(it) }
        probeKeys()
        cm.registerNetworkCallback(Net.wifiRequest(), networkCallback)
        registerReceiver(userPresent, IntentFilter(Intent.ACTION_USER_PRESENT))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (phoneKey == null) phoneKey = prefs.phonePrivate?.let { StaticKey.fromPrivate(it) }
        return START_STICKY
    }

    override fun onDestroy() {
        cm.unregisterNetworkCallback(networkCallback)
        unregisterReceiver(userPresent)
        unbind()
        sessions.shutdownNow()
        AppState.listener.value = AppState.Listener.Stopped
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Both invalidation paths surface at `cipher.init`; find out now, not while someone watches a spinner. */
    private fun probeKeys() {
        val bad = prefs.accountIds().filterNot { Keystore.probe(it) }.toSet()
        if (bad.isNotEmpty()) prefs.addInvalidated(bad)
    }

    @Synchronized
    private fun bind(network: Network) {
        unbind()
        if (phoneKey == null) {
            AppState.listener.value = AppState.Listener.NotPaired
            updateNotification(getString(R.string.not_paired))
            return
        }
        val ip = Net.ipv4(cm, network)
        if (ip == null) {
            // No IPv4 address yet: onLinkPropertiesChanged binds once one arrives.
            AppState.listener.value = AppState.Listener.OffWifi
            updateNotification(getString(R.string.not_on_wifi))
            Log.i(TAG, "on Wi-Fi without an IPv4 address yet")
            return
        }
        val s = ServerSocket()
        s.reuseAddress = true
        try {
            try {
                s.bind(InetSocketAddress(ip, prefs.listenPort), 8)
            } catch (e: Exception) {
                s.bind(InetSocketAddress(ip, 0), 8)   // port taken: an ephemeral one, announced in the hello
            }
        } catch (e: Exception) {
            // Thrown here it would take the app down on the system's network thread.
            try { s.close() } catch (_: Exception) {}
            AppState.listener.value = AppState.Listener.OffWifi
            updateNotification(getString(R.string.not_on_wifi))
            Log.w(TAG, "could not listen on $ip: $e")
            return
        }
        server = s
        boundIp = ip
        acceptThread = Thread({ acceptLoop(s) }, "bwphone-accept").apply { isDaemon = true; start() }
        AppState.listener.value = AppState.Listener.Listening(ip.hostAddress ?: "", s.localPort)
        updateNotification(getString(R.string.listening))
        announce { hello.announce(network, ip, s.localPort) }
        Log.i(TAG, "listening on ${s.localSocketAddress}")
    }

    @Synchronized
    private fun unbind() {
        try { server?.close() } catch (_: Exception) {}
        server = null
        boundIp = null
        acceptThread = null
    }

    private fun acceptLoop(s: ServerSocket) {
        while (!s.isClosed) {
            val socket = try { s.accept() } catch (e: Exception) { break }
            val source = socket.inetAddress?.hostAddress ?: "?"
            if (!allowAttempt(source)) { try { socket.close() } catch (_: Exception) {}; continue }
            val key = phoneKey
            if (key == null) { try { socket.close() } catch (_: Exception) {}; continue }
            try {
                sessions.execute { Session(socket, prefs, key, rate, hooks).run() }
            } catch (e: RejectedExecutionException) {
                // Every slot is busy: a flood, or many parked handshakes. Drop, do not queue.
                try { socket.close() } catch (_: Exception) {}
            }
        }
    }

    /**
     * A hello, on a session thread. When every slot is busy (a flood of
     * connections from the network) the pool refuses it; that must not throw
     * on the system thread that called us and take the whole app down. The
     * next network change or screen unlock sends a hello again.
     */
    private fun announce(block: () -> Unit) {
        try {
            sessions.execute(block)
        } catch (e: RejectedExecutionException) {
            Log.w(TAG, "every session slot is busy; hello skipped")
        }
    }

    /** Per source address and per minute, so a flood from one host leaves the PC's share intact. */
    @Synchronized
    private fun allowAttempt(source: String): Boolean {
        val minute = System.currentTimeMillis() / 60_000
        if (minute != attemptsMinute) { attemptsMinute = minute; attemptsBySource.clear() }
        val n = (attemptsBySource[source] ?: 0) + 1
        attemptsBySource[source] = n
        return n <= MAX_HANDSHAKES_PER_MINUTE_PER_SOURCE
    }

    private val hooks = object : Session.Hooks {
        override fun showPrompt(pending: PendingRequest.Pending) {
            val intent = Intent(this@ListenerService, UnlockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            val pi = PendingIntent.getActivity(this@ListenerService, 1, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val nm = getSystemService(NotificationManager::class.java)
            val body = if (pending.suspicious) getString(R.string.notif_suspicious_body) else getString(R.string.notif_unlock_body)
            val n = NotificationCompat.Builder(this@ListenerService, App.CHANNEL_UNLOCK)
                .setSmallIcon(R.drawable.ic_stat_key)
                .setContentTitle(getString(R.string.notif_unlock_title, pending.label))
                .setContentText(body)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                // With the app in front the unlock screen opens by itself; the
                // notification stays as the way back to it, without the heads-up.
                .setSilent(AppState.inForeground)
                .setOngoing(true)
                .setAutoCancel(false)
                .setContentIntent(pi)
                .setTimeoutAfter(pending.remainingMillis)
                .build()
            nm.notify(UNLOCK_NOTIF_ID, n)
        }

        override fun hidePrompt() {
            getSystemService(NotificationManager::class.java).cancel(UNLOCK_NOTIF_ID)
        }

        override fun phoneLocked(): Boolean =
            getSystemService(android.app.KeyguardManager::class.java).isKeyguardLocked

        override fun withWakeLock(block: () -> Unit) {
            val pm = getSystemService(PowerManager::class.java)
            val lock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "bwphone:prompt")
            lock.acquire(60_000)
            try { block() } finally { if (lock.isHeld) lock.release() }
        }
    }

    private fun notification(text: String): Notification =
        Notification.Builder(this, App.CHANNEL_LISTENER)
            .setSmallIcon(R.drawable.ic_stat_key)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            )
            .build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification(text))
    }

    companion object {
        private const val TAG = "bwphone.service"
        const val NOTIF_ID = 1
        const val UNLOCK_NOTIF_ID = 2
        const val MAX_HANDSHAKES_PER_MINUTE_PER_SOURCE = 10
        const val MAX_SESSIONS = 8

        fun start(context: Context) {
            context.startForegroundService(Intent(context, ListenerService::class.java))
        }
    }
}
