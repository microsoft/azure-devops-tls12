# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.Synopsis
    Analysis of TLS 1.2 compatibility for Azure DevOps.
.Description
    This script aims to help customers in preparation to deprecation of TLS 1.0 and TLS 1.1 protocols and weak cipher suites by Azure DevOps Services.
    The script is read-only, does not execute any mitigations.
    The script runs on Windows client / server OS and detects well-known causes of TLS 1.2 or cipher suite incompatibilities.
#>


function Write-OK { param($str) Write-Host -ForegroundColor green $str } 
function Write-nonOK { param($str) Write-Host -ForegroundColor red $str } 
function Write-Info { param($str) Write-Host -ForegroundColor yellow $str } 

function Probe
{
    param ($uri)
    Write-Info "$uri --> ping"
    $domain = ([System.Uri]$uri).Host
    ping $domain
    Write-Info "$uri --> https"
    $status = (Invoke-WebRequest -Uri $uri).StatusCode
    if ($status -lt 500) {Write-OK "$uri --> OK" } else { Write-nonOK "$uri --> Unexpected 50x response" }
}


Write-Info "Probing Azure DevOps site on TLS 1.2"
Probe "https://status.dev.azure.com/"
Write-Info "Probing other Azure DevOps sites (on TLS 1.0+ or TLS 1.2 depending on actual state of Legacy TLS deprecation)"
Probe "https://dev.azure.com/tfspfcusctest/"
Probe "https://marketplace.visualstudio.com/"


Write-Info "Starting analysis of TLS 1.2 compatibility..."
$PSversionTable

$netFwkVersion = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
if (Test-Path -Path $netFwkVersion)
{
    $fwkRelease = (Get-ItemProperty -Path $netFwkVersion).Release
    Write-Info "Installed .NET Framework release: $fwkRelease"
    # Mapping table from the above Release number to .NET version here: 
    # https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#detect-net-framework-45-and-later-versions
}
else 
{
    Write-nonOK ".NET Framework 4.5+ does not seem to be installed"
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
            Write-Info "Cipher suite enabled: $csItem"
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
        Write-nonOK "None of the TLS 1.2 cipher suites required by Azure DevOps enalbed on the machine, but there are other TLS 1.2 cipher suites enabled."
    }
    else 
    { 
        Write-nonOK "No TLS 1.2 cipher suite found to be enabled on the machine" 
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
    Write-nonOK "Some of the TLS 1.2 cipher suites required by Azure DevOps are not supported/enabled locally."
    Write-Info "Allowed cipher suites: {$allowedCipherSuitesList}"
}

# Source: https://docs.microsoft.com/en-us/skypeforbusiness/manage/topology/disable-tls-1.0-1.1
$gpolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$allowedCipherSuitesList = CheckFunctionsList $gpolicyPath $requiredTls12CipherSuites
if ($allowedCipherSuitesList -ne $null -and ($allowedCipherSuitesList.Count -lt $requiredTls12CipherSuites.Count))
{
    Write-nonOK "Some of the TLS 1.2 cipher suites required by Azure DevOps are disabled by group policy"
    Write-Info "Allowed cipher suites: {$allowedCipherSuitesList}"
}

# Source: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
$tls12ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
if (Test-Path -Path $tls12ClientPath)
{
    if ((Get-ItemProperty -Path $tls12ClientPath).Enabled -eq 0) { Write-nonOK "Client TLS 1.2 disabled" }
    if ((Get-ItemProperty -Path $tls12ClientPath).DisabledByDefault -ne 0) { Write-nonOK "Client TLS 1.2 disabled by default" }
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
        (($propertyObject = (CheckRegistryDefined $fwkPath40)) -and
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
