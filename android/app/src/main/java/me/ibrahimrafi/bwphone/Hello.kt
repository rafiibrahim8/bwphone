package me.ibrahimrafi.bwphone

import android.content.Context
import android.net.Network
import android.net.wifi.WifiManager
import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import uniffi.bwphone_android.mdnsNameNow
import uniffi.bwphone_android.sealHello

/**
 * Telling the PC where we are. Two steps, both event-driven (network
 * joined, screen unlocked), never on a timer:
 *
 * 1. One mDNS query for today's rotating name, QU bit set so the answer
 *    comes unicast to us, under a MulticastLock held for at most 2 s.
 *    Only the paired PC can compute the name; a forged answer only
 *    swallows the hello.
 * 2. One UDP packet: `nonce || XChaCha20-Poly1305(hello_key, {ip, port, seq})`.
 *    No plaintext identifier; `seq` is monotonic so a replay cannot point
 *    the PC at an old address.
 */
class Hello(private val context: Context, private val prefs: Prefs) {

    fun announce(network: Network, myIp: Inet4Address, listenPort: Int) {
        val helloKey = prefs.helloKey ?: return
        val found = try {
            queryPc(network, helloKey)
        } catch (e: Exception) {
            Log.i(TAG, "mdns query failed: $e"); null
        }
        if (found != null) prefs.pcAddress = found.hostAddress
        val target = found?.hostAddress ?: prefs.pcAddress ?: return
        try {
            val seq = prefs.nextHelloSeq()
            val packet = sealHello(helloKey, myIp.hostAddress!!, listenPort.toUShort(), seq.toULong())
            DatagramSocket().use { s ->
                network.bindSocket(s)
                s.send(DatagramPacket(packet, packet.size, InetSocketAddress(target, prefs.helloPort)))
            }
            Log.i(TAG, "hello sent seq=$seq")
        } catch (e: Exception) {
            Log.i(TAG, "hello failed: $e")
        }
    }

    private fun queryPc(network: Network, helloKey: ByteArray): Inet4Address? {
        val name = mdnsNameNow(helloKey, System.currentTimeMillis() / 1000)
        val wifi = context.applicationContext.getSystemService(WifiManager::class.java)
        val lock = wifi.createMulticastLock("bwphone-mdns").apply { setReferenceCounted(false) }
        lock.acquire()
        try {
            DatagramSocket().use { s ->
                network.bindSocket(s)
                s.soTimeout = 2000
                val query = buildQuery(name)
                s.send(DatagramPacket(query, query.size, InetSocketAddress(InetAddress.getByName(MDNS_GROUP), MDNS_PORT)))
                val deadline = System.currentTimeMillis() + 2000
                val buf = ByteArray(1500)
                while (System.currentTimeMillis() < deadline) {
                    val p = DatagramPacket(buf, buf.size)
                    try {
                        s.receive(p)
                    } catch (e: SocketTimeoutException) {
                        return null
                    }
                    val a = parseAnswer(p.data.copyOf(p.length), name)
                    if (a != null) return a
                }
                return null
            }
        } finally {
            lock.release()
        }
    }

    /** A plain DNS query: one question, type A, class IN with the QU bit. */
    private fun buildQuery(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        val id = SecureRandom().nextInt(0x10000)
        out.write(id shr 8); out.write(id and 0xff)
        out.write(0); out.write(0)                // flags: standard query
        out.write(0); out.write(1)                // QDCOUNT
        out.write(0); out.write(0); out.write(0); out.write(0); out.write(0); out.write(0)
        for (label in name.trimEnd('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0)
        out.write(0); out.write(1)                // QTYPE A
        out.write(0x80); out.write(1)             // QCLASS IN, QU bit
        return out.toByteArray()
    }

    /** The first A record for `name` in a response, if this is one. */
    private fun parseAnswer(pkt: ByteArray, name: String): Inet4Address? {
        if (pkt.size < 12) return null
        val flags = u16(pkt, 2)
        if (flags and 0x8000 == 0) return null      // not a response
        val qd = u16(pkt, 4); val an = u16(pkt, 6)
        var off = 12
        repeat(qd) { off = skipName(pkt, off) + 4 }
        val want = name.trimEnd('.').lowercase()
        repeat(an) {
            val (rname, next) = readName(pkt, off)
            off = next
            if (off + 10 > pkt.size) return null
            val type = u16(pkt, off); val rdlen = u16(pkt, off + 8)
            off += 10
            if (type == 1 && rdlen == 4 && rname.lowercase() == want && off + 4 <= pkt.size) {
                return InetAddress.getByAddress(pkt.copyOfRange(off, off + 4)) as Inet4Address
            }
            off += rdlen
        }
        return null
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    private fun skipName(b: ByteArray, start: Int): Int {
        var i = start
        while (i < b.size) {
            val len = b[i].toInt() and 0xff
            if (len == 0) return i + 1
            if (len and 0xC0 == 0xC0) return i + 2
            i += 1 + len
        }
        return i
    }

    /** Name with compression pointers followed; returns (name, offset after it). */
    private fun readName(b: ByteArray, start: Int): Pair<String, Int> {
        val labels = ArrayList<String>()
        var i = start
        var end = -1
        var hops = 0
        while (i < b.size && hops < 16) {
            val len = b[i].toInt() and 0xff
            if (len == 0) { if (end < 0) end = i + 1; break }
            if (len and 0xC0 == 0xC0) {
                if (end < 0) end = i + 2
                i = ((len and 0x3F) shl 8) or (b[i + 1].toInt() and 0xff)
                hops++
                continue
            }
            labels.add(String(b, i + 1, len, Charsets.US_ASCII))
            i += 1 + len
        }
        return labels.joinToString(".") to (if (end < 0) i else end)
    }

    companion object {
        private const val TAG = "bwphone.hello"
        private const val MDNS_GROUP = "224.0.0.251"
        private const val MDNS_PORT = 5353
    }
}
