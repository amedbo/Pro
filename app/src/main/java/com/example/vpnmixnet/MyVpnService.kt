package com.example.vpnmixnet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.wireguard.android.backend.GoBackend
import com.wireguard.config.Config
import com.wireguard.config.InetEndpoint
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MyVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var backend: GoBackend? = null

    companion object {
        private const val NOTIFICATION_CHANNEL_ID = "VpnMixnetChannel"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createNotificationChannel()
        val notification = createNotification()
        startForeground(1, notification)

        // Start the VPN connection in a background coroutine
        CoroutineScope(Dispatchers.IO).launch {
            startVpnTunnel()
        }

        return START_STICKY
    }

    private suspend fun startVpnTunnel() {
        try {
            // STEP 1: Create the WireGuard configuration
            val wgConfig = createWireGuardConfig()

            // STEP 2: Create the backend
            // Using GoBackend as it's the userspace implementation, robust for all phones.
            backend = GoBackend(this)
            val tunnelName = backend!!.apply(wgConfig, null) // null state means it's a new tunnel

            // STEP 3: Build the VpnService interface
            val builder = Builder()
            builder.setSession("VpnMixnet")
            builder.addAddress("10.0.0.2", 32) // Client's IP in the VPN
            builder.addRoute("0.0.0.0", 0)    // Route all traffic through the VPN
            builder.setMtu(1420)                   // Standard WireGuard MTU

            // Establish the VPN interface
            withContext(Dispatchers.Main) {
                vpnInterface = builder.establish()
                backend!!.setTunnelState(tunnelName, com.wireguard.android.backend.Tunnel.State.UP)
            }

        } catch (e: Exception) {
            // Handle exceptions (e.g., logging)
            e.printStackTrace()
            stopVpn()
        }
    }

    private fun createWireGuardConfig(): Config {
        val anInterface = Interface.Builder()
            .addAddress("10.0.0.2/32")
            // This is the key we generated on the server for the client
            .setPrivateKey("WP/Ed+zFOTIvJRM70F2Ne6ksmWeHttvAC1vIuhb1Eks=")
            .build()

        val aPeer = Peer.Builder()
            // This is the server's public key
            .setPublicKey("Y+HjmQt7ESeTfqVO3V2HSD66Cinb9HqEOZCCH3W7VQs=")
            // IMPORTANT: Replace with your server's public IP address and port
            .setEndpoint(InetEndpoint.parse("YOUR_SERVER_IP:51820"))
            .addAllowedIp("0.0.0.0/0") // We want to route all traffic through this peer
            .build()

        return Config.Builder()
            .setInterface(anInterface)
            .addPeer(aPeer)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "VpnMixnet Service"
            val descriptionText = "VPN service status"
            val importance = NotificationManager.IMPORTANCE_DEFAULT
            val channel = NotificationChannel(NOTIFICATION_CHANNEL_ID, name, importance).apply {
                description = descriptionText
            }
            val notificationManager: NotificationManager =
                getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("VpnMixnet Active")
            .setContentText("Your connection is secured.")
            .setSmallIcon(R.mipmap.ic_launcher) // You'll need to add an icon
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun stopVpn() {
        backend?.let {
            val tunnelName = it.runningTunnelNames.firstOrNull()
            if (tunnelName != null) {
                it.setTunnelState(tunnelName, com.wireguard.android.backend.Tunnel.State.DOWN)
            }
        }
        vpnInterface?.close()
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }
}
