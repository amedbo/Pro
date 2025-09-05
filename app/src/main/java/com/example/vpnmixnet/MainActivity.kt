package com.example.vpnmixnet

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class MainActivity : AppCompatActivity() {

    private lateinit var connectButton: Button
    private lateinit var statusText: TextView
    private var isVpnRunning = false

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent?.getStringExtra(MyVpnService.EXTRA_VPN_STATE)?.let { stateStr ->
                val state = VpnState.valueOf(stateStr)
                updateUiForState(state)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        connectButton = findViewById(R.id.connect_button)
        statusText = findViewById(R.id.status_text)

        connectButton.setOnClickListener {
            toggleVpn()
        }

        LocalBroadcastManager.getInstance(this).registerReceiver(
            vpnStateReceiver,
            IntentFilter(MyVpnService.BROADCAST_ACTION_STATE)
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        LocalBroadcastManager.getInstance(this).unregisterReceiver(vpnStateReceiver)
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    private fun toggleVpn() {
        if (isVpnRunning) {
            stopVpnService()
        } else {
            prepareVpn()
        }
    }

    private fun prepareVpn() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, MyVpnService::class.java)
        startService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, MyVpnService::class.java)
        stopService(intent)
    }

    private fun updateUiForState(state: VpnState) {
        isVpnRunning = when (state) {
            VpnState.CONNECTED -> true
            VpnState.CONNECTING -> true
            VpnState.DISCONNECTED, VpnState.ERROR -> false
        }

        connectButton.isEnabled = state != VpnState.CONNECTING

        when (state) {
            VpnState.CONNECTED -> {
                connectButton.text = getString(R.string.disconnect)
                statusText.text = getString(R.string.status_connected)
            }
            VpnState.DISCONNECTED -> {
                connectButton.text = getString(R.string.connect)
                statusText.text = getString(R.string.status_disconnected)
            }
            VpnState.CONNECTING -> {
                connectButton.text = getString(R.string.disconnect)
                statusText.text = getString(R.string.status_connecting)
            }
            VpnState.ERROR -> {
                connectButton.text = getString(R.string.connect)
                statusText.text = getString(R.string.status_error)
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }
            R.id.action_privacy_policy -> {
                val url = "https://your-privacy-policy-url.com" // IMPORTANT: Replace with your actual URL
                val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))
                startActivity(intent)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}
