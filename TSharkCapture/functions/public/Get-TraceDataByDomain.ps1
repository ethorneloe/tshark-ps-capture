<#
.SYNOPSIS
    Extracts trace data from a PSCustomObject containing multiple arraylists by matching DNSQueryName or ServerName properties to a specified domain name.

.DESCRIPTION
    The function Get-TraceDataByDomain accepts a PSCustomObject with arraylists of trace data and a domain name to search for.
    It collects all items within the arraylists that have either a DNSQueryName or ServerName property matching the specified domain name.

.PARAMETER TraceData
    A PSCustomObject containing multiple arraylists of trace data.

.PARAMETER Domain
    The domain name to search for in the DNSQueryName or ServerName properties.

.OUTPUTS
    Returns an ArrayList of PSCustomObjects that match the specified domain name.

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
                Write-Error "An error occurred - capture actions - $_"
            }
        }
    }

    # Call Invoke-TLSCapture with the script block
    $traceData = Invoke-TLSCapture -InterfaceName "Ethernet0" -ScriptBLock $captureActions

    # Extract the domain specific trace data
    $traceDataByDomain = Get-TraceDataByDomain -TraceData $traceData -Domain "google.com"
    $traceDataByDomain
#>

function Get-TraceDataByDomain {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$TraceData,

        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Initialize an empty ArrayList to store the results
    $results = New-Object System.Collections.ArrayList

    # Iterate over each property in the PSCustomObject
    $TraceData.PSObject.Properties | ForEach-Object {
        $property = $_.Value

        # Check if the property is an arraylist
        if ($property -is [System.Collections.ArrayList]) {
            # Iterate over each item in the arraylist
            foreach ($item in $property) {
                # Check if the item has DNSQueryName or ServerName resembling the specified domain
                if ($item.DNSQueryName -match [regex]::Escape($Domain) -or $item.ServerName -match [regex]::Escape($Domain)) {
                    # Add the item to the results ArrayList
                    [void]$results.Add($item)
                }
            }
        }
    }

    # Output the results ArrayList
    return $results
}
