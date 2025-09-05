# VPN + Mixnet (Tor) Prototype

This project is a proof-of-concept demonstrating how to build a system that tunnels traffic from an Android VPN client through a custom server, which then forwards the traffic through the Tor network for an extra layer of privacy.

## How It Works

The traffic flow is designed as follows:

`Android Phone -> WireGuard Tunnel -> Your VPS -> Tor SOCKS Proxy -> Tor Network -> Internet`

1.  The Android app uses `VpnService` to capture all device traffic.
2.  It establishes an encrypted WireGuard tunnel to your VPS.
3.  The VPS receives the traffic on the `wg0` interface.
4.  An `iptables` rule redirects all incoming TCP traffic from the VPN to a `redsocks` process.
5.  `redsocks` forwards this traffic to the local Tor SOCKS proxy.
6.  Tor anonymizes the traffic by routing it through its network before it exits to the public internet.

---

## 1. Server Setup Instructions

These steps configure a Linux server (tested on Ubuntu) to act as the VPN-to-Tor gateway.

### a. Install WireGuard, Tor, and Redsocks
```bash
sudo apt-get update
sudo apt-get install -y wireguard wireguard-go tor redsocks
```
*Note: We install `wireguard-go` as a fallback for environments where the kernel module is not available.*

### b. Configure WireGuard
1.  **Generate Keys:**
    ```bash
    sudo mkdir -p /etc/wireguard
    wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
    wg genkey | sudo tee /etc/wireguard/client_private.key | wg pubkey | sudo tee /etc/wireguard/client_public.key
    sudo chmod 600 /etc/wireguard/*_private.key
    ```

2.  **Create `/etc/wireguard/wg0.conf`:**
    Replace `<SERVER_PRIVATE_KEY>` and `<CLIENT_PUBLIC_KEY>` with the keys you just generated.
    ```ini
    [Interface]
    Address = 10.0.0.1/24
    SaveConfig = true
    PrivateKey = <SERVER_PRIVATE_KEY>
    ListenPort = 51820
    PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -t nat -A PREROUTING -i %i -p tcp -j REDIRECT --to-port 12345
    PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; iptables -t nat -D PREROUTING -i %i -p tcp -j REDIRECT --to-port 12345

    [Peer]
    PublicKey = <CLIENT_PUBLIC_KEY>
    AllowedIPs = 10.0.0.2/32
    ```

### c. Configure Redsocks
Create the file `/etc/redsocks.conf` with the following content:
```ini
base {
    log_info = on;
    log = "file:/var/log/redsocks.log";
    daemon = on;
    user = redsocks;
    group = redsocks;
}
redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = 127.0.0.1;
    port = 9050; // Tor's SOCKS port
    type = socks5;
}
```

### d. Start Services
```bash
# Enable IP Forwarding
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p

# Start and enable all services
sudo systemctl start tor redsocks
sudo wg-quick up wg0
sudo systemctl enable tor redsocks wg-quick@wg0.service
```

---

## 2. Android Client Setup

The source code for the Android client is included in this repository.

### a. Prerequisites
- Android Studio
- An Android device or emulator

### b. Build and Install
1.  Open the project directory in Android Studio.
2.  Navigate to the file `app/src/main/java/com/example/vpnmixnet/MyVpnService.kt`.
3.  Find the line `setEndpoint(InetEndpoint.parse("YOUR_SERVER_IP:51820"))` and replace `YOUR_SERVER_IP` with the public IP address of your server.
4.  Replace the hardcoded `PrivateKey` in the `Interface.Builder` and `PublicKey` in the `Peer.Builder` with the client/server keys you generated.
5.  Build the app: `Build > Build Bundle(s) / APK(s) > Build APK(s)`.
6.  Install the generated APK on your device.

### c. Test the Connection
1.  Open the app and tap "Connect".
2.  Accept the Android system's VPN permission request.
3.  On the server, run `sudo wg show` to confirm a handshake has occurred.
4.  On your phone's browser, visit a site like `https://check.torproject.org/`. It should confirm you are using Tor.

---

## 3. Future Improvements

This project is a prototype and has some limitations that should be addressed in a production version:

-   **Configuration Management:** The server IP and WireGuard keys are currently hardcoded in the Android client's source code (`MyVpnService.kt`). A robust solution would fetch this configuration from a secure API endpoint or use a more dynamic method for configuration.
-   **UI State:** The UI state in the app is managed by a simple boolean flag. For better accuracy, the `VpnService` should communicate its real-time status (connecting, connected, disconnected, error) back to the `MainActivity` using a `BroadcastReceiver` or similar mechanism.
