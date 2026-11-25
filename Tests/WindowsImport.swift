import Foundation

@main
struct WindowsImportTests {
    static func main() throws {
        if CommandLine.arguments.contains("--check-helper") {
            L10n.use(.en)
            precondition(L("Для VPN требуется разрешение администратора macOS.") ==
                         "macOS administrator authorization is required for the VPN.")
            print("The helper can load the app's English resources")
            return
        }
        if CommandLine.arguments.contains("--check-english") {
            precondition(L10n.language == .en)
            precondition(L("Нет профилей") == "No profiles")
            let suffix = "{2}"
            precondition(L("DNS-правило для \(suffix) уже задано.") == "A DNS rule for {2} already exists.")
            do {
                _ = try WindowsConfig.parse("Add-VpnConnection 'Office' -TunnelType SSTP")
                preconditionFailure("Accepted a profile without a server")
            } catch {
                precondition(error.localizedDescription.hasPrefix("Line 1:"), error.localizedDescription)
            }
            print("English language preference, interpolated strings, and import errors passed")
            return
        }
        precondition(L10n.language == .ru && L("Нет профилей") == "Нет профилей")
        let input = #"""
            <# DNS and routes for a multi-step setup #>
            $name = 'Office 1'
            $server = "vpn.example.com"
            $allowSplit = $true
            $servers = @(
                '192.0.2.53'
                '192.0.2.54'
            )
            $profile = @{
                Name = $name
                ServerAddress = $server
                TunnelType = 'SSTP'
                AuthenticationMethod = @('MSChapv2', 'Chap', 'Pap')
                EncryptionLevel = 'Optional'
                SplitTunneling = $allowSplit
                RememberCredential = $true
                DnsSuffix = 'corp.example.com.'
            }
            VPNClient\Add-VpnConnection @profile -ErrorAction Stop | Out-Null
            Add-VpnConnectionRoute $name '192.0.2.10/24' 20 –PassThru
            Add-VpnConnectionRoute -ConnectionName $name -DestinationPrefix '198.51.100.20/32'
            Remove-VpnConnectionRoute $name '192.0.2.0/24' -Confirm:$false
            Add-VpnConnectionRoute $name '203.0.113.0/24' -WhatIf
            Add-VpnConnectionTriggerDnsConfiguration $name 'corp.example.com' $servers
            Set-VpnConnectionTriggerDnsConfiguration $name 'corp.example.com' -DnsIPAddress 192.0.2.55, 192.0.2.56
            Add-VpnConnectionTriggerDnsConfiguration $name 'unused.example.com' '192.0.2.53'
            Remove-VpnConnectionTriggerDnsConfiguration $name 'unused.example.com'
            Set-VpnConnection -Name $name -ServerAddress:'vpn.example.com:4443' -SplitTunneling:$false -IdleDisconnectSeconds 120
            """#
        for data in [Data(input.utf8), input.replacingOccurrences(of: "\n", with: "\r\n").data(using: .utf16)!] {
            let parsed = try WindowsConfig.parse(WindowsConfig.decode(data))
            precondition(parsed.map(\.name) == ["Office 1"])
            let profile = parsed[0].settings
            precondition(profile.server == "vpn.example.com" && profile.port == "4443")
            precondition(profile.dnsSuffix == "corp.example.com")
            precondition(profile.dnsRules?.map(\.servers) == [["192.0.2.55", "192.0.2.56"]])
            precondition(profile.routes == "host 198.51.100.20")
            precondition(profile.fullTunnel == true && profile.remember)
            precondition(profile.idleDisconnectSeconds == 120)
            precondition(profile.authentication == [.mschapv2, .chap, .pap])
            precondition(profile.authenticationOptions == ["refuse-eap", "refuse-mschap"])
        }
        let old = try JSONDecoder().decode(Profile.self, from: Data(
            #"{"server":"vpn.example.com","port":"443","login":"","routes":"","remember":false}"#.utf8
        ))
        precondition(old.authentication == [.mschapv2])
        precondition(Set(old.authenticationOptions) == ["refuse-eap", "refuse-pap", "refuse-chap", "refuse-mschap"])
        let simple = try WindowsConfig.parse("""
            Add-VpnConnection 'Office' vpn.example.com SSTP -AuthenticationMethod Pap -EncryptionLevel NoEncryption
            """)
        precondition(simple[0].settings.authentication == [.pap])
        for expression in ["-ServerAddress (Read-Host)", "-ServerAddress $env:SSTP_HOST",
                           "-AuthenticationMethod Eap", "-L2tpPsk example", "| Invoke-Expression"] {
            let prep = expression.hasPrefix("-ServerAddress") ? "" : "-ServerAddress vpn.example.com"
            do {
                _ = try WindowsConfig.parse("Add-VpnConnection 'Office' -TunnelType SSTP \(prep) \(expression)")
                preconditionFailure("Accepted \(expression)")
            } catch {
                precondition(error.localizedDescription.hasPrefix("Строка 1"), error.localizedDescription)
            }
        }
        let duplicated = String(repeating: "$list = $list, $list\n", count: 12)
        do {
            _ = try WindowsConfig.parse("$list = 'fixture'\n" + duplicated + input)
            preconditionFailure("Expanded an oversized PowerShell array")
        } catch {
            precondition(error.localizedDescription.contains("128 элементов"), error.localizedDescription)
        }
        let noReply = ConnectionTrace { _ in }
        noReply.engine("PPP client -> server CHAP Response")
        noReply.engine("TLS read failed: unexpected eof while reading")
        precondition(noReply.exitMessage(255).contains("до результата аутентификации PPP"))
        let rejected = ConnectionTrace { _ in }
        rejected.engine("PPP client -> server PAP Request")
        rejected.engine("PPP server -> client PAP Nak")
        rejected.engine("TLS read failed: unexpected eof while reading")
        precondition(rejected.exitMessage(255).contains("Сервер отклонил аутентификацию PPP"))
        print("PowerShell import, profile migration, authentication selection, and failure diagnostics passed")
    }
}
