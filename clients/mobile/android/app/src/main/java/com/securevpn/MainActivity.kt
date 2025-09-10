// clients/mobile/android/app/src/main/java/com/securevpn/MainActivity.kt
package com.securevpn

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.securevpn.databinding.ActivityMainBinding
import com.securevpn.viewmodel.VpnViewModel
import com.securevpn.model.ThreatInfo
import android.content.Intent
import androidx.appcompat.app.AlertDialog

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var vpnViewModel: VpnViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        vpnViewModel = ViewModelProvider(this).get(VpnViewModel::class.java)

        setupUI()
        setupObservers()
        checkPermissions()
    }

    private fun setupUI() {
        binding.connectButton.setOnClickListener {
            vpnViewModel.toggleConnection()
        }

        binding.settingsButton.setOnClickListener {
            openAdvancedSettings()
        }

        binding.aiProtectionSwitch.setOnCheckedChangeListener { _, isChecked ->
            vpnViewModel.setAIProtectionEnabled(isChecked)
        }

        binding.bitcoinPaymentButton.setOnClickListener {
            openBitcoinPaymentDialog()
        }

        binding.threatLogButton.setOnClickListener {
            openThreatLog()
        }
    }

    private fun setupObservers() {
        vpnViewModel.connectionStatus.observe(this) { status ->
            when (status) {
                VpnViewModel.ConnectionStatus.CONNECTED -> {
                    binding.connectButton.text = getString(R.string.disconnect)
                    binding.statusText.text = getString(R.string.connected_secure)
                    binding.connectionIndicator.setBackgroundColor(getColor(R.color.connected_green))
                }
                VpnViewModel.ConnectionStatus.DISCONNECTED -> {
                    binding.connectButton.text = getString(R.string.connect)
                    binding.statusText.text = getString(R.string.disconnected)
                    binding.connectionIndicator.setBackgroundColor(getColor(R.color.disconnected_red))
                }
                VpnViewModel.ConnectionStatus.CONNECTING -> {
                    binding.connectButton.text = getString(R.string.connecting)
                    binding.statusText.text = getString(R.string.establishing_connection)
                    binding.connectionIndicator.setBackgroundColor(getColor(R.color.connecting_yellow))
                }
                VpnViewModel.ConnectionStatus.BLOCKED -> {
                    binding.connectButton.text = getString(R.string.reconnect)
                    binding.statusText.text = getString(R.string.connection_blocked)
                    binding.connectionIndicator.setBackgroundColor(getColor(R.color.blocked_orange))
                }
            }
        }

        vpnViewModel.threatDetected.observe(this) { threatInfo ->
            threatInfo?.let {
                showThreatAlert(it)
            }
        }

        vpnViewModel.networkStats.observe(this) { stats ->
            binding.downloadSpeed.text = String.format("%.1f MB/s", stats.downloadSpeedMbps)
            binding.uploadSpeed.text = String.format("%.1f MB/s", stats.uploadSpeedMbps)
            binding.dataUsed.text = String.format("%.2f GB", stats.dataUsedGB)
        }

        vpnViewModel.currentRoute.observe(this) { route ->
            binding.currentRoute.text = route?.getDisplayName() ?: getString(R.string.no_route)
        }
    }

    private fun checkPermissions() {
        // Check and request necessary VPN and network permissions
        if (!VpnHelper.hasVpnPermission(this)) {
            VpnHelper.requestVpnPermission(this)
        }
    }

    private fun openAdvancedSettings() {
        val intent = Intent(this, AdvancedSettingsActivity::class.java)
        startActivity(intent)
    }

    private fun openBitcoinPaymentDialog() {
        val dialog = BitcoinPaymentDialogFragment()
        dialog.show(supportFragmentManager, "BitcoinPayment")
    }

    private fun openThreatLog() {
        val intent = Intent(this, ThreatLogActivity::class.java)
        startActivity(intent)
    }

    private fun showThreatAlert(threatInfo: ThreatInfo) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.threat_detected))
            .setMessage(getString(R.string.threat_detected_message, threatInfo.description))
            .setPositiveButton(getString(R.string.protect_me)) { _, _ ->
                vpnViewModel.activateCountermeasures()
            }
            .setNegativeButton(getString(R.string.ignore), null)
            .setNeutralButton(getString(R.string.view_details)) { _, _ ->
                openThreatDetails(threatInfo)
            }
            .show()
    }

    private fun openThreatDetails(threatInfo: ThreatInfo) {
        val intent = Intent(this, ThreatDetailActivity::class.java).apply {
            putExtra("threat_info", threatInfo)
        }
        startActivity(intent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        // Handle permission results
        if (requestCode == VpnHelper.VPN_PERMISSION_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                vpnViewModel.retryConnection()
            } else {
                binding.statusText.text = getString(R.string.permission_denied)
            }
        }
    }
}
