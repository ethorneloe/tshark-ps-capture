<#
.SYNOPSIS
Converts decimal TLS content type codes to their descriptive string equivalents.

.DESCRIPTION
This function takes a decimal code as input and returns the corresponding TLS content type name. It supports a set of predefined TLS content types involved in the handshake and communication processes.

.EXAMPLE
PS> Convert-TLSContentTypeFromDecimal -Code "20"
Change Cipher Spec

This example shows how to convert the decimal code "20" to its corresponding TLS content type name, "Change Cipher Spec".

.PARAMETERS
-Code
The decimal code representing a TLS content type.

.NOTES
The function provides a straightforward mapping for common TLS content types used during the SSL/TLS handshake and data transmission. If the decimal code does not correspond to a known content type, the function returns the input code.

Values taken from examining traces in the Wireshark interface.  More info can be found at https://www.iana.org/assignments/tls-parameters/
#>
function Convert-TLSContentTypeFromDecimal {

    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]$Code
    )

    begin {
        $TLSContentTypeMapping = @{
            "1"  = "Client Hello"
            "2"  = "Server Hello"
            "11" = "Certificate"
            "12" = "Server Key Exchange"
            "14" = "Server Hello Done"
            "20" = "Change Cipher Spec"
            "22" = "Certificate Status"
            "23" = "Application Data"
        }
    }

    process {
        if ($TLSContentTypeMapping.ContainsKey($Code)) {
            $TLSContentTypeMapping[$Code]
        }
        else {
            $Code
        }
    }
}