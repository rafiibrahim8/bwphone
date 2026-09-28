package me.ibrahimrafi.bwphone

/**
 * A hard cap per hour: overall, and per account, so spreading requests
 * across accounts buys no extra attempts. Counts every request that reaches
 * the prompt stage, approved or not; survives restarts.
 *
 * Also keeps the count of "unexplained" sessions: connections that finished
 * the Noise handshake — so they held the PC's key — and then asked for
 * nothing. The real PC always asks. Someone holding a copy of its key
 * and opening sessions until one has the emoji they want does not.
 */
class RateLimit(private val prefs: Prefs) {
    /** Records the attempt and says whether it may proceed. */
    @Synchronized
    fun allow(accountHex: String): Boolean {
        val now = System.currentTimeMillis()
        val overall = prune(prefs.timestamps("overall"), now)
        val account = prune(prefs.timestamps(accountHex), now)
        prefs.putTimestamps("overall", overall + now)
        prefs.putTimestamps(accountHex, account + now)
        return overall.size < OVERALL_PER_HOUR && account.size < ACCOUNT_PER_HOUR
    }

    /** Faster than a person plausibly unlocks: the prompt should look different. */
    fun suspicious(): Boolean {
        val now = System.currentTimeMillis()
        return prune(prefs.timestamps("overall"), now).count { it > now - 60_000 } >= SUSPICIOUS_PER_MINUTE
    }

    @Synchronized
    fun recordUnexplained() {
        val now = System.currentTimeMillis()
        prefs.putTimestamps("unexplained", prune(prefs.timestamps("unexplained"), now) + now)
    }

    fun unexplainedLastHour(): Int = prune(prefs.timestamps("unexplained"), System.currentTimeMillis()).size

    private fun prune(ts: List<Long>, now: Long) = ts.filter { it > now - 3_600_000 }

    companion object {
        const val OVERALL_PER_HOUR = 30
        const val ACCOUNT_PER_HOUR = 10
        const val SUSPICIOUS_PER_MINUTE = 3
    }
}
