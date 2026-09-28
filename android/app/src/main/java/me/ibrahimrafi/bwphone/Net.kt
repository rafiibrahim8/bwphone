package me.ibrahimrafi.bwphone

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.net.Inet4Address

/**
 * The one network we ever use: Wi-Fi, not VPN, not cellular. The listener
 * binds to its IPv4 address and comes and goes with it.
 */
object Net {
    fun cm(context: Context): ConnectivityManager = context.getSystemService(ConnectivityManager::class.java)

    /** A request that only Wi-Fi networks satisfy; VPNs carry TRANSPORT_VPN and are left out. */
    fun wifiRequest(): NetworkRequest = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    fun isWifi(cm: ConnectivityManager, network: Network): Boolean {
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    }

    fun wifiNetwork(cm: ConnectivityManager): Network? =
        @Suppress("DEPRECATION")
        cm.allNetworks.firstOrNull { isWifi(cm, it) }

    fun ipv4(cm: ConnectivityManager, network: Network): Inet4Address? =
        cm.getLinkProperties(network)?.linkAddresses
            ?.map { it.address }
            ?.filterIsInstance<Inet4Address>()
            ?.firstOrNull { !it.isLoopbackAddress && !it.isLinkLocalAddress }
}
