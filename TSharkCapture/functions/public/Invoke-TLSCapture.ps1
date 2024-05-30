<#
.SYNOPSIS
    Captures TLS handshake and DNS data using tshark and parses it into PowerShell objects.

.DESCRIPTION
    This function starts a tshark capture for TLS handshakes and DNS queries/responses on a specified network interface.  It then executes the code in the provided scriptblock.
    The output is then parsed and converted into a collection of PowerShell objects which are returned as an object of arraylists(client hellos, server hellos, dns queries, dns responses).

.PARAMETER InterfaceName
    The name of the network interface on which to capture traffic.

.PARAMETER ScriptBlock
    The code you want to run while tshark is capturing.

.PARAMETER FlushDNS
    Add this switch to flush the dns cache at each run, which will ensure the IP lookup table is built properly each time, and output objects have names added.

.EXAMPLE
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

    $results.ClientHellos | Select-Object CipherSuites
    $results.ServerHellos | Where-Object {$_.SupportedVersions -match '1.3'}
    $results.DNSResponses | Where-Object {$_.DNSResponseType -contains 'CNAME'}
    $results.DNSQueries
    $results.TCPResets

.EXAMPLE

    #This will simply run the capture for 10 minutes.

    $captureActions = {
        # Sleep for 10 Minutes
        Start-Sleep -Seconds 600
    }

    $results = Invoke-TLSCapture -InterfaceName "Ethernet0" -ScriptBLock $captureActions

.NOTES
  This function depends on the following supporting functions in this module:
    1. Convert-CipherSuiteFromHex
    2. Convert-SigHashAlgoFromHex
    3. Convert-TLSContentTypeFromHex
    4. Convert-TLSVersionFromHex
#>
Function Invoke-TLSCapture {
    param (

        [Parameter()]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [string]$InterfaceName,

        [Parameter()]
        [switch]$FlushDNS
    )

    if ($FlushDNS) {
        $commandOutput = ipconfig /flushdns
        if ($commandOutput -match "elevation") {
            throw "Run this function again with elevation to ensure ipconfig /flushdns succeeds."
        }
    }

    # Configure tshark params
    $outputFile = New-TemporaryFile
    $maxCaptureTime = 600
    $tsharkPath = "C:\Program Files\Wireshark\tshark.exe"

    $tsharkArgs = "-i $InterfaceName " +
    "-Y `"tls.handshake.type == 1 || tls.handshake.type == 2 || dns.flags.opcode == 0 || tcp.flags.reset == 1`" " +
    "-T fields " +
    "-e frame.time " +
    "-e frame.protocols " +
    "-e ip.src " +
    "-e ip.dst " +
    "-e tls.handshake.type " +
    "-e tls.record.version " +
    "-e tls.handshake.version " +
    "-e tls.handshake.ciphersuite " +
    "-e tls.handshake.extensions.supported_version " +
    "-e tls.handshake.sig_hash_alg " +
    "-e tls.handshake.extensions_server_name " +
    "-e dns.flags.response " +
    "-e dns.qry.name " +
    "-e dns.resp.name " +
    "-e dns.resp.type " +
    "-e dns.cname " +
    "-e dns.a " +
    "-e tcp.flags.reset " +
    "-E separator=`"|`" " +
    "-E occurrence=a " +
    "-a duration:$($maxCaptureTime) " +
    "-l" # This flushes std out which ensures the information reaches the output file as soon as a packet is sent/received.

    $tsharkProcess = Start-Process -FilePath $tsharkPath -ArgumentList $tsharkArgs -RedirectStandardOutput $outputFile -PassThru -WindowStyle hidden

    # Small time buffer before starting the scriptblock
    Start-Sleep -Seconds 5

    try {
        Invoke-Command -ScriptBlock $ScriptBlock
    }
    catch {
        Write-Error "An error occurred: $_"
    }
    finally {

        # Small time buffer just in case some extra capture time is needed after the scriptblock is done
        Start-Sleep -Seconds 5

        if (!$tsharkProcess.HasExited) {
            Stop-Process -Id $tsharkProcess.Id -Force
        }

        # Parse the output file into PowerShell objects

        $ClientHellos = New-Object System.Collections.ArrayList
        $ServerHellos = New-Object System.Collections.ArrayList
        $DNSQueries = New-Object System.Collections.ArrayList
        $DNSResponses = New-Object System.Collections.ArrayList
        $TCPResets = New-Object System.Collections.ArrayList

        # For holding IP mappings to names based on DNS responses as the trace is parsed for faster lookup
        $IPNameMap = @{}

        Get-Content $outputFile | ForEach-Object {

            # No pipe so it's not a line we are interested in
            if ($_ -notmatch "\|") { continue }

            # Seperate out the fields
            $fields = $_ -split '\|'

            $protocols = $fields[1]

            # Create different objects based on the protocol and type
            if ($protocols -match 'tls') {
                $handShakeType = ($fields[4] -split ',').trim() | Convert-TLSContentTypeFromDecimal

                if ($handShakeType -eq "Client Hello") {

                    $obj = [PSCustomObject]@{
                        Timestamp               = $fields[0]
                        Protocol                = 'tls'
                        SourceIP                = $fields[2]
                        DestinationIP           = $fields[3]
                        HandshakeType           = $handShakeType
                        RecordVersion           = ($fields[5] -split ',').trim() | Select-Object -First 1 | Convert-TLSVersionFromHex
                        HandShakeVersion        = ($fields[6] -split ',').trim() | Convert-TLSVersionFromHex
                        CipherSuites            = ($fields[7] -split ',').trim() | Convert-CipherSuiteFromHex
                        SupportedVersions       = ($fields[8] -split ',').trim() | Convert-TLSVersionFromHex
                        SignatureHashAlgorithms = ($fields[9] -split ',').trim() | Convert-SigHashAlgoFromHex
                        ServerName              = $fields[10]
                    }
                    $ClientHellos.Add($obj) | Out-Null
                }
                elseif ($handShakeType -eq "Server Hello") {

                    $obj = [PSCustomObject]@{
                        Timestamp               = $fields[0]
                        Protocol                = 'tls'
                        SourceIP                = $fields[2]
                        DestinationIP           = $fields[3]
                        HandshakeType           = $handShakeType
                        RecordVersion           = ($fields[5] -split ',').trim() | Select-Object -First 1 | Convert-TLSVersionFromHex
                        HandShakeVersion        = ($fields[6] -split ',').trim() | Convert-TLSVersionFromHex
                        CipherSuites            = ($fields[7] -split ',').trim() | Convert-CipherSuiteFromHex
                        SupportedVersions       = ($fields[8] -split ',').trim() | Convert-TLSVersionFromHex
                        SignatureHashAlgorithms = ($fields[9] -split ',').trim() | Convert-SigHashAlgoFromHex
                        ServerName              = ''
                    }
                    $ServerHellos.Add($obj) | Out-Null
                }
            }
            elseif ($protocols -match 'dns') {

                $DNSResponseFlag = $fields[11]

                if ($DNSResponseFlag -eq '0') {

                    $obj = [PSCustomObject]@{
                        Timestamp       = $fields[0]
                        Protocol        = 'dns'
                        SourceIP        = $fields[2]
                        DestinationIP   = $fields[3]
                        DNSResponseFlag = @{ '0' = "query"; '1' = "response" }[$DNSResponseFlag]
                        DNSQueryName    = $fields[12]
                    }

                    $DNSQueries.Add($obj) | Out-Null
                }
                elseif ($DNSResponseFlag -eq '1') {

                    # If there are IPs in the response, add to the mapping using the DNS query name
                    $DNSResponseAddresses = $fields[16] -split ','
                    $DNSResponseAddresses | ForEach-Object {
                        $IPNameMap[$_] = $fields[12]
                    }

                    $obj = [PSCustomObject]@{
                        Timestamp          = $fields[0]
                        Protocol           = 'dns'
                        SourceIP           = $fields[2]
                        DestinationIP      = $fields[3]
                        DNSResponseFlag    = @{ '0' = "query"; '1' = "response" }[$DNSResponseFlag]
                        DNSQueryName       = $fields[12]
                        DNSResponseName    = $fields[13] -split ','
                        DNSResponseType    = $fields[14] -split ',' | ForEach-Object { @{ "1" = "A"; "5" = "CNAME" }[$_] }
                        DNSResponseCname   = $fields[15] -split ','
                        DNSResponseAddress = $DNSResponseAddresses
                    }

                    $DNSResponses.Add($obj) | Out-Null
                }
            }
            elseif ($protocols.EndsWith('tcp')) {

                # Check if it is a reset - needs to be done last as all protocol strings earlier contain 'tcp'
                if ($fields[17] -eq '1') {
                    $obj = [PSCustomObject]@{
                        Timestamp     = $fields[0]
                        Protocol      = 'tcp'
                        SourceIP      = $fields[2]
                        DestinationIP = $fields[3]
                        ServerName    = ''
                    }
                    $TCPResets.Add($obj) | Out-Null
                }
            }
        }

        try {
            # Clean up temporary files.  This will clean all trace files in the current profile temp dir
            $outputFile | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
            Get-ChildItem -Path "$env:TEMP" -Filter "*.pcapng" -Recurse -File | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            throw "Unable to remove $outputFile and temp files under $($env:TEMP) - $($_.exception.message)"
        }
    }

    # Perform a lookup on the IPs in the Server Hellos and add the ServerName
    $ServerHellos | ForEach-Object {
        $_.ServerName = $IPNameMap[$_.SourceIP]
    }

    # Same thing for the TCP Resets. Assumes the reset comes from the IP that was contained in a DNS Response.
    $TCPResets | ForEach-Object {
        if ($IPNameMap[$_.SourceIP]) {
            $_.ServerName = $IPNameMap[$_.SourceIP]
        }
        elseif ($IPNameMap[$_.DestinationIP]) {
            $_.ServerName = $IPNameMap[$_.DestinationIP]
        }
    }

    $results = [PSCustomObject]@{
        DNSQueries   = $DNSQueries
        DNSResponses = $DNSResponses
        ClientHellos = $ClientHellos
        ServerHellos = $ServerHellos
        TCPResets    = $TCPResets
    }

    return $results
}