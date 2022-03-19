# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.Synopsis
    Analysis of TLS 1.2 compatibility for Azure DevOps.

    Version 2022-03-19

.Description
    This script aims to help customers in preparation to deprecation of TLS 1.0 and TLS 1.1 protocols and weak cipher suites by Azure DevOps Services.
    The script performs read-only operations, does not execute any mitigations.
    The script runs on Windows client / server OS and detects well-known causes of TLS 1.2 or cipher suite incompatibilities.

    Lowest OS version where this script has been tested on is Windows Server 2012 R2.
#>


function Write-OK { param($str) Write-Host -ForegroundColor green $str } 
function Write-nonOK { param($str) Write-Host -ForegroundColor red $str } 
function Write-Info { param($str) Write-Host -ForegroundColor yellow $str } 
function Write-Break { Write-Host -ForegroundColor Gray "********************************************************************************" }
function Write-Title 
{ 
    param($str) 
    Write-Host -ForegroundColor blue ("=" * ($str.Length + 4))
    Write-Host -ForegroundColor blue "| $str |" 
    Write-Host -ForegroundColor blue ("=" * ($str.Length + 4))
} 

function TryToSecureConnect
{
    param($connectHost)
    $client = New-Object Net.Sockets.TcpClient
    try 
    {
        try 
        {
            $client.Connect($connectHost, 443) # if we fail here, it is not SSL/TLS issue
        } 
        catch # case of network/DNS error (no TLS problem)
        {
            return $null
        }
        $stream = New-Object Net.Security.SslStream $client.GetStream(), $true, ([System.Net.Security.RemoteCertificateValidationCallback]{ $true })
        $remoteEndpoint = $client.Client.RemoteEndPoint
        try
        {
            $stream.AuthenticateAsClient("")
            return ($true, $remoteEndpoint)
        }    
        catch [System.IO.IOException] # case of failed TLS negotation
        {
            return ($false, $remoteEndpoint)
        }         
    }
    finally 
    {
        $stream.Dispose()
        $client.Dispose()
    }    
}


function Probe
{
    param ($domain, $tlsSetupDesc)
    
    Write-Info "Probing: $domain"
    
    ($success, $remoteAddress) = TryToSecureConnect $domain
    switch ($success)
    {
        $null { Write-nonOK "Failed to reach the destination. This is connectivity or DNS problem, *not* TLS incompatibility." }
        $true { Write-OK "Probe succeeded. Connection negotiated successfully to $remoteAddress" }
        $false { Write-nonOK "Probe failed when TLS-negotiating to $remoteAddress. This may be TLS compatibility issue."}
    } 

    Write-Break    
}

Write-Title "Probing Azure DevOps sites"
Probe "status.dev.azure.com" # This domain requires TLS 1.2 with strong cipher suites.

# We're skipping probes to other Azure DevOps domains, because their TLS setting has not been fixed yet:
# - IPv6 has been switched to TLS 1.2 with strong cipher suites, 
# - IPv4 is on TLS 1.0+ or TLS 1.2 with strong cipher suites depending on rollout of Legacy TLS deprecation.
# Therefore, the probe result is function of current date, DNS resolution choice of IPv4 or IPv6 and actual TLS compatibility of the client.
#
# Probe "dev.azure.com"
# Probe "whatever.visualstudio.com"

Write-Title "Analysis of TLS 1.2 compatibility"
$PSversionTable

$netFwkVersionPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
# Mapping table from the above Release number to .NET version here: 
# https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#detect-net-framework-45-and-later-versions
if (Test-Path -Path $netFwkVersionPath)
{
    $fwkRelease = (Get-ItemProperty -Path $netFwkVersionPath).Release
    if ($fwkRelease -lt 460000)
    {
        Write-nonOK ".NET Framework 4.7+ not installed (release $fwkRelease). This may cause TLS-compatibility issues to .NET applications."
    }
    else
    {
        Write-OK ".NET Framework release is 4.7+ (release $fwkRelease)"
    }
}
else
{
    Write-nonOK ".NET Framework 4.7+ not installed (version below 4.5 seem to be installed)"
}

# List of TLS 1.2 cipher suites required by Azure DevOps
$requiredTls12CipherSuites = (
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
)
# List (not necessarily complete) of TLS 1.2-specific cipher suites not supported by Azure DevOps
 $otherTls12CipherSuites = (
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256"    
)

function GetEnabledCipherSuites 
{ 
    param($csList) 
    $result = $false    
    foreach ($csItem in $csList) 
    { 
        $csArray = (Get-TlsCipherSuite -Name $csItem)
        if ($csArray.Count -gt 0)
        {
            Write-Detail "Cipher suite enabled: $csItem"
            $result = $true
        }
    }
    return $result
}

if ($PSversionTable.BuildVersion.Major -ge 10)
{
    if ((GetEnabledCipherSuites $requiredTls12CipherSuites)) 
    { 
        Write-OK "At least one of the TLS 1.2 cipher suites required by Azure DevOps enabled on the machine" 
    }
    elseif ((GetEnabledCipherSuites $otherTls12CipherSuites)) 
    {
        Write-nonOK "ISSUE FOUND: TLS 1.2 is supported but none of the TLS 1.2 cipher suites required by Azure DevOps are enalbed on the machine."
    }
    else 
    { 
        Write-nonOK "ISSUE FOUND: TLS 1.2 does not seem to be supported (no TLS 1.2 cipher suites enabled)" 
    }
}
else
{
    Write-Info "Skipping `Get-TlsCipherSuite` due to version of OS lower than WS 2016"
}

function CheckFunctionsList
{
    param ($path, $valueList)

    if (Test-Path -Path $path)
    {
        $list = (Get-ItemProperty -Path $path).Functions
        if ($list)
        {
            $result = @()
            foreach ($item in $valueList)
            {
                if ($list.Contains($item)) { $result = $result + $item }
            }
            return $result
        }
    }
    return $null
}

# Source: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs#enabling-or-disabling-additional-cipher-suites
$localCiphersPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
$allowedCipherSuitesList = CheckFunctionsList $localCiphersPath $requiredTls12CipherSuites
if ($allowedCipherSuitesList -ne $null -and ($allowedCipherSuitesList.Count -lt $requiredTls12CipherSuites.Count))
{
    if ($allowedCipherSuitesList.Count -eq 0) 
    {
        Write-nonOK "ISSUE FOUND: All TLS 1.2 cipher suites required by Azure DevOps are not supported/enabled locally."
    }
    else 
    {
        Write-nonOK "POTENTIAL ISSUE FOUND: Some of TLS 1.2 cipher suites required by Azure DevOps are not supported/enabled locally."
        Write-Detail "Allowed cipher suites: {$allowedCipherSuitesList}"
    }
}

# Source: https://docs.microsoft.com/en-us/skypeforbusiness/manage/topology/disable-tls-1.0-1.1
$gpolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$allowedCipherSuitesList = CheckFunctionsList $gpolicyPath $requiredTls12CipherSuites
if ($allowedCipherSuitesList -ne $null -and ($allowedCipherSuitesList.Count -lt $requiredTls12CipherSuites.Count))
{
    if ($allowedCipherSuitesList.Count -eq 0) 
    {
        Write-nonOK "ISSUE FOUND: All TLS 1.2 cipher suites required by Azure DevOps are disabled by group policy"
    }
    else
    {
        Write-nonOK "POTENTIAL ISSUE FOUND: Some of the TLS 1.2 cipher suites required by Azure DevOps are disabled (maybe by group policy)"
        Write-Detail "Allowed cipher suites: {$allowedCipherSuitesList}"
    }
}

# Source: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
$tls12ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
if (Test-Path -Path $tls12ClientPath)
{
    if ((Get-ItemProperty -Path $tls12ClientPath).Enabled -eq 0) { Write-nonOK "ISSUE FOUND: Client TLS 1.2 protocol usage disabled" }
    if ((Get-ItemProperty -Path $tls12ClientPath).DisabledByDefault -ne 0) { Write-nonOK "ISSUE FOUND: Client TLS 1.2 protocol usage disabled by default" }
}

function CheckRegistryDefined
{
    param($path, $property)
    if (-not (Test-Path -Path $path)) { return $null }
    return Get-ItemProperty -Path $path
}

function CheckStrongCrypto 
{
    param($path, $desc)
    $isStrongCryptoEnforced = 
        (($propertyObject = (CheckRegistryDefined $path)) -and
        (($propertyObject.SchUseStrongCrypto -ne $null) -and ($propertyObject.SchUseStrongCrypto -ne 0)) -and
        (($propertyObject.SystemDefaultTlsVersions -ne $null) -and ($propertyObject.SystemDefaultTlsVersions -ne 0)))

    if ($isStrongCryptoEnforced)
    {
        Write-OK "TLS 1.2 enforced for applications targetting $desc"
    }
    else
    {
        Write-Info "TLS 1.2 not enforced for applications targetting $desc"
    }
}

# Source: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client
CheckStrongCrypto "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" ".NET Framework 4.0/4.5.x"
CheckStrongCrypto "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" ".NET Framework 4.0/4.5.x (32bit app on 64bit OS)"
CheckStrongCrypto "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" ".NET Framework 3.5"
CheckStrongCrypto "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" ".NET Framework 3.5 (32bit app on 64bit OS)"
