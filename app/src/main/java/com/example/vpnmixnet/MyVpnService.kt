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
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class MyVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var backend: GoBackend? = null
    private val scope = CoroutineScope(Dispatchers.IO)

    companion object {
        const val BROADCAST_ACTION_STATE = "com.example.vpnmixnet.VPN_STATE"
        const val EXTRA_VPN_STATE = "vpn_state"
        private const val NOTIFICATION_CHANNEL_ID = "VpnMixnetChannel"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createNotificationChannel()
        val notification = createNotification()
        startForeground(1, notification)

        sendVpnStateBroadcast(VpnState.CONNECTING)

        // Start the VPN connection in a background coroutine
        scope.launch {
            startVpnTunnel()
        }

        return START_STICKY
    }

    private suspend fun startVpnTunnel() {
        try {
            // STEP 1: Load the WireGuard configuration from storage
            val config = VpnConfigStore.getConfig(this)
            if (config.endpoint.isBlank() || config.clientPrivateKey.isBlank() || config.serverPublicKey.isBlank()) {
                // Config is missing, stop the service
                sendVpnStateBroadcast(VpnState.ERROR)
                stopVpn()
                return
            }
            val wgConfig = createWireGuardConfig(config)

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
                sendVpnStateBroadcast(VpnState.CONNECTED)
            }

        } catch (e: Exception) {
            // Handle exceptions (e.g., logging)
            e.printStackTrace()
            sendVpnStateBroadcast(VpnState.ERROR)
            stopVpn()
        }
    }

    private fun createWireGuardConfig(config: VpnConfig): Config {
        val anInterface = Interface.Builder()
            .addAddress("10.0.0.2/32")
            .setPrivateKey(config.clientPrivateKey)
            .build()

        val aPeer = Peer.Builder()
            .setPublicKey(config.serverPublicKey)
            .setEndpoint(InetEndpoint.parse(config.endpoint))
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
        sendVpnStateBroadcast(VpnState.DISCONNECTED)
        stopVpn()
    }

    private fun sendVpnStateBroadcast(state: VpnState) {
        val intent = Intent(BROADCAST_ACTION_STATE).apply {
            putExtra(EXTRA_VPN_STATE, state.name)
        }
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }
}
