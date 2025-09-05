package com.example.vpnmixnet

import android.content.Context
import android.content.SharedPreferences

// A simple data class to hold our configuration
data class VpnConfig(
    val endpoint: String,
    val clientPrivateKey: String,
    val serverPublicKey: String
)

// An object to handle saving and loading the configuration from SharedPreferences
object VpnConfigStore {

    private const val PREFS_NAME = "VpnConfigPrefs"
    private const val KEY_ENDPOINT = "endpoint"
    private const val KEY_CLIENT_PRIVATE_KEY = "client_private_key"
    private const val KEY_SERVER_PUBLIC_KEY = "server_public_key"

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun saveConfig(context: Context, config: VpnConfig) {
        getPrefs(context).edit()
            .putString(KEY_ENDPOINT, config.endpoint)
            .putString(KEY_CLIENT_PRIVATE_KEY, config.clientPrivateKey)
            .putString(KEY_SERVER_PUBLIC_KEY, config.serverPublicKey)
            .apply()
    }

    fun getConfig(context: Context): VpnConfig {
        val prefs = getPrefs(context)
        return VpnConfig(
            endpoint = prefs.getString(KEY_ENDPOINT, "") ?: "",
            clientPrivateKey = prefs.getString(KEY_CLIENT_PRIVATE_KEY, "") ?: "",
            serverPublicKey = prefs.getString(KEY_SERVER_PUBLIC_KEY, "") ?: ""
        )
    }
}
