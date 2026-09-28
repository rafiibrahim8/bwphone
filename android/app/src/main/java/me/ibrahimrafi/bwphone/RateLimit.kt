package me.ibrahimrafi.bwphone

/**
 * A hard cap per hour: overall, and per account, so spreading requests
 * across accounts buys no extra attempts. The two numbers are set on the
 * phone's Settings screen (never by the PC). Counts every request that reaches
 * the prompt stage, approved or not; survives restarts. A request refused
 * here is not counted: otherwise someone asking once every few minutes
 * would keep the window full, and every real unlock refused, for good.
 *
 * Also keeps the count of "unexplained" sessions: connections that finished
 * the Noise handshake — so they held the PC's key — and then asked for
 * nothing. The real PC always asks. Someone holding a copy of its key
 * and opening sessions until one has the emoji they want does not.
 */
class RateLimit(private val prefs: Prefs) {
    /** Whether a prompt may be shown now; records it only if so. */
    @Synchronized
    fun allow(accountHex: String): Boolean {
        val now = System.currentTimeMillis()
        val overall = prune(prefs.timestamps("overall"), now)
        val account = prune(prefs.timestamps(accountHex), now)
        if (overall.size >= prefs.limitOverall || account.size >= prefs.limitPerAccount) {
            // Refused: keep the pruned windows, add nothing, so they drain.
            prefs.putTimestamps("overall", overall)
            prefs.putTimestamps(accountHex, account)
            return false
        }
        prefs.putTimestamps("overall", overall + now)
        prefs.putTimestamps(accountHex, account + now)
        return true
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
        /** Prompts per hour, as the Settings screen sets them; these are the defaults. */
        const val DEFAULT_OVERALL = 30
        const val DEFAULT_PER_ACCOUNT = 20
        /** The most either can be set to: past this a cap no longer bounds anything. */
        const val MAX_OVERALL = 100
        const val MAX_PER_ACCOUNT = 50
        const val SUSPICIOUS_PER_MINUTE = 3
    }
}
