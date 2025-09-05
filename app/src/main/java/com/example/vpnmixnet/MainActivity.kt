package com.example.vpnmixnet

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var connectButton: Button
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        connectButton = findViewById(R.id.connect_button)
        statusText = findViewById(R.id.status_text)

        connectButton.setOnClickListener {
            toggleVpn()
        }
    }

    // A simple flag to keep track of the VPN state.
    // In a real app, this should be managed more robustly, perhaps with a BroadcastReceiver.
    private var isVpnRunning = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            statusText.text = getString(R.string.status_disconnected)
            updateUiState()
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
        isVpnRunning = true
        updateUiState()
        val intent = Intent(this, MyVpnService::class.java)
        startService(intent)
    }

    private fun stopVpnService() {
        isVpnRunning = false
        updateUiState()
        val intent = Intent(this, MyVpnService::class.java)
        stopService(intent)
    }

    private fun updateUiState() {
        if (isVpnRunning) {
            connectButton.text = getString(R.string.disconnect)
            statusText.text = getString(R.string.status_connected)
        } else {
            connectButton.text = getString(R.string.connect)
            statusText.text = getString(R.string.status_disconnected)
        }
    }
}
