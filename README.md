# Overview
This repo contains a module that demonstrates how to capture packets with `tshark` into `PowerShell` objects.  In particular, traffic relating to DNS, TLS, and TCP resets are captured as a way to facilitate the capture of cipher suites, TLS versions, and flows that might help troubleshoot HTTPS connectivity issues or confirm TLS configuration.
# Goals
To provide an example of how `PowerShell` can be used to automate a `tshark` capture and supply relevant data organized into objects that can be queried/filtered.
# Config Guide
## Requirements
- Server with `Wireshark` and `PowerShell` installed.
- Note that this module was developed for `Windows` systems and at present the `tshark.exe` filepath is baked into the module function based on default Wireshark install parameters for a `Windows` machine.  You might need to alter this for your specific scenario.
- Make sure to set the `InterfaceName` parameter accordingly.

## Steps to Perform Capture
1. Clone this repo and copy the module folder into `PSModulePath` or a local folder of your choice.
1. Open PowerShell and import the module into your session.
1. Create a scriptblock containing the PowerShell actions you want to perform and execute the capture.  For example:
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
                Write-Error "An error occured - capture actions - $_"
            }
        }
    }

    # Call Invoke-TLSCapture with the script block
    $results = Invoke-TLSCapture -InterfaceName "Ethernet0" -ScriptBLock $captureActions -FlushDNS

    # View and filter out the various objects collected from the capture
    $results.ClientHellos | Select-Object CipherSuites
    $results.ServerHellos | Where-Object {$_.SupportedVersions -match '1.3'}
    $results.DNSResponses | Where-Object {$_.DNSResponseType -contains 'CNAME'}
    $results.DNSQueries
    $results.TCPResets

  ```

1. You can also simply set the scriptblock to use `Start-Sleep` and then perform various UI actions to trigger traffic as needed.
