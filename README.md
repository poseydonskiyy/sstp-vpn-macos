# SSTP VPN for macOS

A native macOS client for SSTP VPNs using MS‑CHAPv2. The Universal app runs on Apple Silicon and Intel with macOS 15 or later. It includes a modified build of the open-source `sstpc` client and uses the system `pppd`. The interface is in Russian.

## Install and connect

1. Download the Universal ZIP from Releases, extract it, and move `SSTP VPN.app` to Applications. The ZIP includes the license and dependency notices.
2. Open the app, then enter your server and credentials or choose **Импорт PowerShell…** to import a Windows VPN profile.
3. Click **Подключить** and approve the macOS administrator prompt for the network helper. The app manages and disconnects its tunnel directly.

Local builds use ad hoc signing by default. If macOS blocks a downloaded build, review the download and its checksum before following Apple’s instructions for opening an app from an unidentified developer. [Apple Support](https://support.apple.com/en-us/102445)

## Windows profile import

Paste PowerShell configuration commands or select a `.ps1` or `.txt` file. The app parses the supported options as text.

```powershell
Add-VpnConnection -Name Office -ServerAddress vpn.example.com -TunnelType SSTP -AuthenticationMethod MSCHAPv2 -EncryptionLevel Optional -SplitTunneling -RememberCredential -DnsSuffix corp.example.com
Add-VpnConnectionRoute -ConnectionName Office -DestinationPrefix "192.0.2.0/24"
Add-VpnConnectionTriggerDnsConfiguration -ConnectionName Office -DnsSuffix "corp.example.com" -DnsIPAddress "192.0.2.53"
```

Enter your username and password after import. The app can remember the password in the macOS Keychain. To update routes and DNS for an existing profile, import the same name and server again. To delete a profile, select it and choose **Удалить профиль…**.

## Routes and DNS

- **Split tunnel** sends the routes in the **Маршруты** tab through the VPN. Add individual IPv4 hosts or CIDR networks. For a Windows import, `-SplitTunneling` selects this mode.
- **Full tunnel** sends internet-bound IPv4 traffic through the VPN and temporarily blocks ordinary IPv6 internet routes. More specific routes still take precedence. Full tunnel requires an available system default route and VPN server internet forwarding to change your public IPv4. A tunnel route scoped to its own interface does not prevent connecting.
- `-DnsSuffix` sets a search domain and uses VPN-provided DNS for that domain. Explicit DNS rules from `Add-VpnConnectionTriggerDnsConfiguration` apply after connecting. The app removes its DNS settings on disconnect. Imported Windows route metrics have no effect on macOS.

## Server trust and diagnostics

The default **Системное доверие macOS** mode validates the server name and TLS certificate chain using macOS trust settings. For a private certificate authority, select **Пользовательский комплект CA** in **Сертификаты** and import its root and any required intermediates in PEM or DER format. This local bundle can be updated or replaced and is shared by profiles that select it.

**Журнал** shows connection progress through DNS, IPv4 routing, TCP, TLS, SSTP, PPP, and MS‑CHAPv2. Full tunnel has an optional internet check that makes HTTPS requests to Cloudflare. The app closes its tunnel when you quit.

## Build from source

Install Command Line Tools for Xcode with `xcode-select --install`, then run `./build.sh`. The output is `build/SSTP VPN.app`. The first build compiles OpenSSL and libevent for both architectures from the checksum-verified source archives in `Engine/Vendor`. Set `SSTP_SIGN_IDENTITY` to choose a macOS code signing identity.

The sstp-client changes are in `Engine/macos.patch` and `Engine/sstp-macos-trust.h`. The application bundle includes the dependencies’ license texts. [sstp-client](https://gitlab.com/sstp-project/sstp-client) · [OpenSSL](https://www.openssl-library.org/) · [libevent](https://libevent.org/)

## License

SSTP VPN for macOS is available under GPL‑3.0‑or‑later. The upstream sstp-client sources retain their GPL‑2.0‑or‑later notices. This distribution builds the modified engine under GPLv3 or later and links it with OpenSSL (Apache‑2.0) and libevent (BSD‑3‑Clause). See [LICENSE](LICENSE) and the notices in the dependency archives and application bundle.
