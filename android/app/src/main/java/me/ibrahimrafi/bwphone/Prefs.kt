package me.ibrahimrafi.bwphone

import android.content.Context
import android.util.Base64

/**
 * Everything the phone keeps, sealed under a Keystore key ([SealedPrefs])
 * and excluded from backup: the channel identity, what pairing derived, and
 * per-account state. Nothing Bitwarden-specific is ever stored: an account
 * is a random 16-byte id and the label the person chose.
 *
 * Sessions run on several threads at once, and each screen makes its own
 * `Prefs`, so every read-modify-write here holds one process-wide lock:
 * the write-once pin must not be set twice by two racing `set_pin`s, and
 * account lists, counts, the hello `seq` and history must not lose updates.
 */
class Prefs(context: Context) {
    private val prefs = SealedPrefs(context, "bwphone")

    val isPaired: Boolean get() = prefs.contains(K_PHONE_PRIVATE)

    var phonePrivate: ByteArray?
        get() = bytes(K_PHONE_PRIVATE)
        set(v) = putBytes(K_PHONE_PRIVATE, v)

    var pcPublic: ByteArray?
        get() = bytes(K_PC_PUB)
        set(v) = putBytes(K_PC_PUB, v)

    var pairingId: ByteArray?
        get() = bytes(K_PAIRING_ID)
        set(v) = putBytes(K_PAIRING_ID, v)

    var helloKey: ByteArray?
        get() = bytes(K_HELLO_KEY)
        set(v) = putBytes(K_HELLO_KEY, v)

    /** Where the PC was last seen (QR address at pairing, then mDNS answers). */
    var pcAddress: String?
        get() = prefs.getString(K_PC_ADDR, null)
        set(v) = prefs.edit().putString(K_PC_ADDR, v).apply()

    var helloPort: Int
        get() = prefs.getInt(K_HELLO_PORT, 8732)
        set(v) = prefs.edit().putInt(K_HELLO_PORT, v).apply()

    var listenPort: Int
        get() = prefs.getInt(K_LISTEN_PORT, 8731)
        set(v) = prefs.edit().putInt(K_LISTEN_PORT, v).apply()

    /**
     * The unlock limits per hour, from the Settings screen. Read clamped, so a
     * value outside the range (or one that no longer opens) cannot switch the
     * cap off; the overall cap is never below the per-account one.
     */
    val limitPerAccount: Int
        get() = prefs.getInt(K_LIMIT_ACCOUNT, RateLimit.DEFAULT_PER_ACCOUNT).coerceIn(1, RateLimit.MAX_PER_ACCOUNT)

    val limitOverall: Int
        get() = prefs.getInt(K_LIMIT_OVERALL, RateLimit.DEFAULT_OVERALL).coerceIn(limitPerAccount, RateLimit.MAX_OVERALL)

    fun setLimits(perAccount: Int, overall: Int) = synchronized(lock) {
        val a = perAccount.coerceIn(1, RateLimit.MAX_PER_ACCOUNT)
        prefs.edit()
            .putInt(K_LIMIT_ACCOUNT, a)
            .putInt(K_LIMIT_OVERALL, overall.coerceIn(a, RateLimit.MAX_OVERALL))
            .apply()
    }

    /** Monotonic; the PC ignores anything not higher than the last one it saw. */
    fun nextHelloSeq(): Long = synchronized(lock) {
        val next = prefs.getLong(K_HELLO_SEQ, 0L) + 1
        prefs.edit().putLong(K_HELLO_SEQ, next).apply()
        next
    }

    /** Commit a pairing atomically; nothing is written on a cancelled one. */
    fun commitPairing(
        phonePrivate: ByteArray,
        pcPublic: ByteArray,
        pairingId: ByteArray,
        helloKey: ByteArray,
        pcAddress: String,
        helloPort: Int,
        listenPort: Int,
    ) {
        prefs.edit()
            .putString(K_PHONE_PRIVATE, b64(phonePrivate))
            .putString(K_PC_PUB, b64(pcPublic))
            .putString(K_PAIRING_ID, b64(pairingId))
            .putString(K_HELLO_KEY, b64(helloKey))
            .putString(K_PC_ADDR, pcAddress)
            .putInt(K_HELLO_PORT, helloPort)
            .putInt(K_LISTEN_PORT, listenPort)
            .putLong(K_HELLO_SEQ, 0L)
            .apply()
    }

    /** Revoke all: the pairing and every account. Keystore keys are deleted by the caller. */
    fun clearEverything() {
        prefs.edit().clear().apply()
    }

    fun accountIds(): Set<String> = prefs.getStringSet(K_ACCOUNTS, emptySet())

    fun hasAccount(id: String) = accountIds().contains(id)

    fun addAccount(id: String, label: String) = synchronized(lock) {
        prefs.edit()
            .putStringSet(K_ACCOUNTS, accountIds() + id)
            .putString("acc.$id.label", label)
            .apply()
    }

    fun removeAccount(id: String) = synchronized(lock) {
        val e = prefs.edit()
            .putStringSet(K_ACCOUNTS, accountIds() - id)
            .putStringSet(K_INVALIDATED, invalidated - id)
        for (k in prefs.keys()) if (k.startsWith("acc.$id.")) e.remove(k)
        e.remove("rate.$id").apply()
    }

    fun label(id: String): String = prefs.getString("acc.$id.label", null) ?: id.take(8)

    /** `H(rsa_ct)`: the one ciphertext this account's key will decrypt. Write-once. */
    fun pin(id: String): ByteArray? = bytes("acc.$id.pin")

    /**
     * Returns false if a pin is already set: the PC cannot re-pin. Check and
     * write are one step under the lock, and the pin is on disk before the PC
     * hears `ok`, so a crash cannot leave it pinned on one side only.
     */
    fun setPinOnce(id: String, pin: ByteArray): Boolean = synchronized(lock) {
        if (prefs.contains("acc.$id.pin")) return false
        prefs.edit().putString("acc.$id.pin", b64(pin)).commit()
    }

    fun unlockCount(id: String) = prefs.getInt("acc.$id.count", 0)
    fun lastUnlock(id: String) = prefs.getLong("acc.$id.last", 0L)

    fun recordUnlock(id: String) = synchronized(lock) {
        prefs.edit()
            .putInt("acc.$id.count", unlockCount(id) + 1)
            .putLong("acc.$id.last", System.currentTimeMillis())
            .apply()
    }

    val invalidated: Set<String>
        get() = prefs.getStringSet(K_INVALIDATED, emptySet())

    fun addInvalidated(ids: Set<String>) = synchronized(lock) {
        prefs.edit().putStringSet(K_INVALIDATED, invalidated + ids).apply()
    }

    fun addInvalidated(id: String) = addInvalidated(setOf(id))

    fun timestamps(key: String): List<Long> =
        prefs.getString("rate.$key", "")!!.split(',').filter { it.isNotEmpty() }.map { it.toLong() }

    fun putTimestamps(key: String, ts: List<Long>) {
        prefs.edit().putString("rate.$key", ts.joinToString(",")).apply()
    }

    fun history(): List<String> = prefs.getString(K_HISTORY, "")!!.lines().filter { it.isNotEmpty() }

    fun addHistory(label: String, result: String) = synchronized(lock) {
        val line = "${System.currentTimeMillis()}|$label|$result"
        val lines = (listOf(line) + history()).take(50)
        prefs.edit().putString(K_HISTORY, lines.joinToString("\n")).apply()
    }

    private fun bytes(key: String): ByteArray? = prefs.getString(key, null)?.let { Base64.decode(it, Base64.NO_WRAP) }

    private fun putBytes(key: String, v: ByteArray?) {
        prefs.edit().apply { if (v == null) remove(key) else putString(key, b64(v)) }.apply()
    }

    private fun b64(v: ByteArray) = Base64.encodeToString(v, Base64.NO_WRAP)

    companion object {
        /** One for the process: every `Prefs` is a view of the same file. */
        private val lock = Any()

        private const val K_PHONE_PRIVATE = "phone.private"
        private const val K_PC_PUB = "pc.pub"
        private const val K_PAIRING_ID = "pairing.id"
        private const val K_HELLO_KEY = "hello.key"
        private const val K_PC_ADDR = "pc.addr"
        private const val K_HELLO_PORT = "hello.port"
        private const val K_LISTEN_PORT = "listen.port"
        private const val K_HELLO_SEQ = "hello.seq"
        private const val K_ACCOUNTS = "accounts"
        private const val K_INVALIDATED = "invalidated"
        private const val K_HISTORY = "history"
        private const val K_LIMIT_ACCOUNT = "limit.account"
        private const val K_LIMIT_OVERALL = "limit.overall"

        fun hex(id: ByteArray) = id.joinToString("") { "%02x".format(it) }
    }
}
