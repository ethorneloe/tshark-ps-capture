# Overview
This repo contains a module that demonstrates how to capture packets with `tshark` into `PowerShell` objects.  In particular, traffic relating to DNS, TLS, and TCP resets are captured as a way to facilitate the capture of cipher suites, TLS versions, and flows that might help troubleshoot HTTPS connectivity issues or confirm TLS configuration.
# Goals
To provide an example of how `PowerShell` can be used to automate a `tshark` capture and supply relevant data organized into objects that can be queried/filtered.
# Config Guide
## Requirements
- Machine with `Wireshark` and `PowerShell` installed.
- Note that this module was developed for `Windows` systems and at present the `tshark.exe` filepath is baked into the module function based on default Wireshark install parameters for a `Windows` machine.  You might need to alter this for your specific scenario.
- Make sure to set the `InterfaceName` parameter accordingly when using the `Invoke-TLSCapture` function.

## Steps to Perform Capture
1. Clone this repo and copy the module folder into `PSModulePath` or a local folder of your choice.
1. Open PowerShell and import the module into your session.
1. Create a `ScriptBlock` containing the PowerShell actions you want to perform and execute the capture.  For example:
  ```
  $captureActions = {

        $urls = @(
            "https://github.com",
            "https://azure.microsoft.com",
            "https://google.com"
        )

        $urls | ForEach-Object {
            try {
                Invoke-WebRequest $_  | Out-Null
            }
            catch {
                Write-Error "An error occurred - capture actions - $_"
            }
        }
    }

    # Call Invoke-TLSCapture with the script block
    $traceData = Invoke-TLSCapture -InterfaceName "Ethernet0" -ScriptBlock $captureActions -FlushDNS

    # View and filter out the various objects collected from the capture
    $traceData.ClientHellos | Select-Object CipherSuites
    $traceData.ServerHellos | Where-Object {$_.SupportedVersions -match '1.3'}
    $traceData.DNSResponses | Where-Object {$_.DNSResponseType -contains 'CNAME'}
    $traceData.DNSQueries
    $traceData.TCPResets

  ```

1. You can also set the `ScriptBlock` to only execute `Start-Sleep` and then perform various UI actions to trigger traffic as needed.

## Filtering Data for a Specific Domain
The module includes a function called `Get-TraceDataByDomain` which can be used with the results from `Invoke-TLSCapture` to display data relating to a specific domain such as `www.google.com` as shown below.  Note that DNS names are added to output objects only when the DNS reponse traffic takes place during the capture.

```
PS C:\Dev\tshark-ps-capture> Get-TraceDataByDomain -TraceData $traceData -Domain "www.google.com"

Timestamp       : May 31, 2024 13:55:04.923082000 E. Australia Standard Time
Protocol        : dns
SourceIP        : 10.0.1.192
DestinationIP   : 8.8.8.8
DNSResponseFlag : query
DNSQueryName    : www.google.com

Timestamp          : May 31, 2024 13:55:04.984656000 E. Australia Standard Time
Protocol           : dns
SourceIP           : 8.8.8.8
DestinationIP      : 10.0.1.192
DNSResponseFlag    : response
DNSQueryName       : www.google.com
DNSResponseName    : {www.google.com}
DNSResponseType    : A
DNSResponseCname   : {}
DNSResponseAddress : {142.250.204.100}

Timestamp               : May 31, 2024 13:55:05.048219000 E. Australia Standard Time
Protocol                : tls
SourceIP                : 10.0.1.192
DestinationIP           : 142.250.204.100
HandshakeType           : Client Hello
RecordVersion           : TLS 1.0
HandShakeVersion        : TLS 1.2
CipherSuites            : {TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256…}
SupportedVersions       : {TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0}
SignatureHashAlgorithms : {rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, rsa_pkcs1_sha256…}
ServerName              : www.google.com

Timestamp               : May 31, 2024 13:55:05.125474000 E. Australia Standard Time
Protocol                : tls
SourceIP                : 142.250.204.100
DestinationIP           : 10.0.1.192
HandshakeType           : Server Hello
RecordVersion           : TLS 1.2
HandShakeVersion        : TLS 1.2
CipherSuites            : TLS_AES_256_GCM_SHA384
SupportedVersions       : TLS 1.3
SignatureHashAlgorithms :
ServerName              : www.google.com
```

