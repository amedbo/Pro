package com.example.vpnmixnet

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {

    private lateinit var endpointEditText: EditText
    private lateinit var clientPrivateKeyEditText: EditText
    private lateinit var serverPublicKeyEditText: EditText
    private lateinit var saveButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        title = getString(R.string.settings_title)

        endpointEditText = findViewById(R.id.edit_text_endpoint)
        clientPrivateKeyEditText = findViewById(R.id.edit_text_client_private_key)
        serverPublicKeyEditText = findViewById(R.id.edit_text_server_public_key)
        saveButton = findViewById(R.id.save_button)

        loadSettings()

        saveButton.setOnClickListener {
            saveSettings()
        }
    }

    private fun loadSettings() {
        val config = VpnConfigStore.getConfig(this)
        endpointEditText.setText(config.endpoint)
        clientPrivateKeyEditText.setText(config.clientPrivateKey)
        serverPublicKeyEditText.setText(config.serverPublicKey)
    }

    private fun saveSettings() {
        val newConfig = VpnConfig(
            endpoint = endpointEditText.text.toString(),
            clientPrivateKey = clientPrivateKeyEditText.text.toString(),
            serverPublicKey = serverPublicKeyEditText.text.toString()
        )
        VpnConfigStore.saveConfig(this, newConfig)
        Toast.makeText(this, getString(R.string.settings_saved_toast), Toast.LENGTH_SHORT).show()
        finish() // Close the activity and go back to MainActivity
    }
}
