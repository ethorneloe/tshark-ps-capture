<#
.SYNOPSIS
Converts hexadecimal signature hash algorithm codes to their descriptive string equivalents.

.DESCRIPTION
This function takes a hexadecimal code as input and returns the corresponding signature hash algorithm name. It supports a variety of RSA, ECDSA, and other algorithm types, mapping each hexadecimal code to its descriptive string representation.

.EXAMPLE
PS> Convert-SigHashAlgoFromHex -HexCode "0x0401"
rsa_pkcs1_sha256

This example shows how to convert the hexadecimal code "0x0401" to its corresponding signature hash algorithm name.

.PARAMETERS
-HexCode
The hexadecimal code representing a signature hash algorithm.

.NOTES
The function supports a range of signature hash algorithms, including RSA, ECDSA, EdDSA, and others. If the hexadecimal code does not correspond to a known algorithm, the function returns the input hexadecimal code.

Values taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme

#>
function Convert-SigHashAlgoFromHex {

    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]$HexCode
    )

    begin {
        $SigHashAlgoMapping = @{
            "0x0201" = "rsa_pkcs1_sha1"
            "0x0202" = "reserved-for-backward-compatibility"
            "0x0203" = "ecdsa_sha1"
            "0x0401" = "rsa_pkcs1_sha256"
            "0x0403" = "ecdsa_secp256r1_sha256"
            "0x0420" = "rsa_pkcs1_sha256_legacy"
            "0x0501" = "rsa_pkcs1_sha384"
            "0x0503" = "ecdsa_secp384r1_sha384"
            "0x0520" = "rsa_pkcs1_sha384_legacy"
            "0x0601" = "rsa_pkcs1_sha512"
            "0x0603" = "ecdsa_secp521r1_sha512"
            "0x0620" = "rsa_pkcs1_sha512_legacy"
            "0x0704" = "eccsi_sha256"
            "0x0705" = "iso_ibs1"
            "0x0706" = "iso_ibs2"
            "0x0708" = "sm2sig_sm3"
            "0x070F" = "gostr34102012_512c"
            "0x0804" = "rsa_pss_rsae_sha256"
            "0x0805" = "rsa_pss_rsae_sha384"
            "0x0806" = "rsa_pss_rsae_sha512"
            "0x0807" = "ed25519"
            "0x0808" = "ed448"
            "0x0809" = "rsa_pss_pss_sha256"
            "0x080A" = "rsa_pss_pss_sha384"
            "0x080B" = "rsa_pss_pss_sha512"
            "0x081A" = "ecdsa_brainpoolP256r1tls13_sha256"
            "0x081B" = "ecdsa_brainpoolP384r1tls13_sha384"
            "0x081C" = "ecdsa_brainpoolP512r1tls13_sha512"
        }
    }

    process {
        if ($SigHashAlgoMapping.ContainsKey($HexCode)) {
            $SigHashAlgoMapping[$HexCode]
        }
        else {
            $HexCode
        }
    }
}