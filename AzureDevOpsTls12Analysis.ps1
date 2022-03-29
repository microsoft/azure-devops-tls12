# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.Synopsis
    Analysis of TLS 1.2 compatibility for Azure DevOps.

.Description
    This script aims to help customers in preparation to deprecation of TLS 1.0 and TLS 1.1 protocols and weak cipher suites by Azure DevOps Services.
    The script performs read-only analysis, does not execute any mitigations.
    The script runs on Windows client / server OS and detects well-known causes of TLS 1.2 and cipher suite incompatibilities.

    Lowest OS version where this script has been tested on: Windows Server 2008 R2.
#>

$version = "2022-03-29"

function Write-OK { param($str) Write-Host -ForegroundColor green $str } 
function Write-nonOK { param($str) Write-Host -ForegroundColor red $str } 
function Write-Warning { param($str) Write-Host -ForegroundColor magenta $str } 
function Write-Info { param($str) Write-Host -ForegroundColor yellow $str } 
function Write-Detail { param($str) Write-Host -ForegroundColor gray $str } 
function Write-Break { Write-Host -ForegroundColor Gray "********************************************************************************" }
function Write-Title 
{ 
    param($str) 
    Write-Host -ForegroundColor Yellow ("=" * ($str.Length + 4))
    Write-Host -ForegroundColor Yellow "| $str |" 
    Write-Host -ForegroundColor Yellow ("=" * ($str.Length + 4))
} 

Write-Detail "Azure DevOps TLS 1.2 transition readiness checker v. $version"

#
#
#
Write-Title "Probing Azure DevOps sites"
#
#
#

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
            $askedProtocols = [System.Security.Authentication.SslProtocols](3072) # TLS 1.2
            $stream.AuthenticateAsClient($connectHost, $null, $askedProtocols, $false)
            return ($true, $remoteEndpoint, $null)
        }
        catch [System.IO.IOException],[System.ComponentModel.Win32Exception] # case of failed TLS negotation
        {
            # Seen exceptions here:
            #   Error: The client and server cannot communicate, because they do not possess a common algorithm.
            #   Error: Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.

            return ($false, $remoteEndpoint, $_)
        }        
        finally {$stream.Dispose()}
    }
    finally 
    {
        $client.Dispose()
    }    
}


function Probe
{
    param ($domain, $tlsSetupDesc)
    
    Write-Info "Probing: $domain"
    
    ($success, $remoteAddress, $handshakeException) = TryToSecureConnect $domain
    switch ($success)
    {
        $null { Write-nonOK "Failed to reach the destination. This is connectivity or DNS problem, *not* TLS compatibility issue." }
        $true { Write-OK "Probe succeeded. Connection negotiated successfully to $remoteAddress" }
        $false 
        {
             Write-nonOK "ISSUE FOUND: This may be TLS compatibility issue!"
             Write-nonOK  "Probe failed when TLS-negotiating to $remoteAddress. Error: $handshakeException"
        }
    } 

    Write-Break    
}

Probe "status.dev.azure.com" # This domain requires TLS 1.2 with strong cipher suites.

# We're skipping probes to other Azure DevOps domains, because their TLS setting has not been fixed yet:
# - IPv6 has been switched to TLS 1.2 with strong cipher suites, 
# - IPv4 is on TLS 1.0+ or TLS 1.2 with strong cipher suites depending on rollout of Legacy TLS deprecation.
# Therefore, the probe result is function of current date, DNS resolution choice of IPv4 or IPv6 and actual TLS compatibility of the client.
#
# Probe "dev.azure.com"
# Probe "whatever.visualstudio.com"


# 
#
#
Write-Title "Analysis of TLS 1.2 compatibility: OS"
#
#
#

$winBuildVersion = [System.Environment]::OSVersion.Version

Write-Host "PS Version:" $PSversionTable.PSVersion
Write-Host "PS Edition: " $PSversionTable.PSEdition
Write-Host "Win Build Version: "$winBuildVersion
Write-Host "CLR Version: " $PSversionTable.CLRVersion

Write-Break

function CheckValueIsExpected
{
    param($path, $propertyName, $expectedBoolValue, $undefinedMeansExpectedValue)
    if (Test-Path -Path $path)
    {
        $value =  Get-ItemProperty -Path $path | Select-Object -ExpandProperty $propertyName -ErrorAction SilentlyContinue
        if ($value -eq $null) 
        { 
            return $undefinedMeansExpectedValue
        }
        else 
        {
            return [bool]$value -eq [bool]$expectedBoolValue
        }
    }
    else
    {
        return $undefinedMeansExpectedValue
    }
}


$tls12ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

$clientCheckOK = $true 
$mitigations = @()

if (-not (CheckValueIsExpected $tls12ClientPath "Enabled" 1 $true))
{
    $mitigations = $mitigations + "[$tls12ClientPath] 'Enabled'=dword:1"
    $clientCheckOK = $false   
}

$undefinedMeansEnabled = $true
if (($winBuildVersion.Major -lt 6) -or ($winBuildVersion.Major -eq 6 -and $winBuildVersion.Minor -le 2)) 
{ 
    # source: https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392
    # source: https://support.microsoft.com/en-us/topic/update-to-add-support-for-tls-1-1-and-tls-1-2-in-windows-server-2008-sp2-windows-embedded-posready-2009-and-windows-embedded-standard-2009-b6ab553a-fa8f-3f5e-287c-e752eb3ce5f4
    Write-Detail "For old Windows versions (WS 2012, Windows 7 and older) TLS 1.2 must be explicitly enabled..."
    $undefinedMeansEnabled = $false 
}
if (-not (CheckValueIsExpected $tls12ClientPath "DisabledByDefault" 0 $undefinedMeansEnabled))
{
    $mitigations = $mitigations + "[$tls12ClientPath] 'DisabledByDefault'=dword:0"
    $clientCheckOK = $false
}
if ($clientCheckOK)
{
    Write-OK "TLS 1.2 client usage enabled."
}
else
{
    Write-nonOK "ISSUE FOUND: TLS 1.2 protocol client usage disabled"
    Write-nonOK "MITIGATION: per https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs" 
    $mitigations | & { process { Write-nonOK("    $_") } } 
}
Write-Break

# List of TLS 1.2 cipher suites required by Azure DevOps Services
$requiredTls12CipherSuites = (
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
)
# This is subset of above list with cipher suites which are known to be supported at WS 2008 R2+ (when patched properly)
$minimallySupportedTls12CipherSuites = (
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
)

function GetAllCipherSuitesByBCryptAPI
{
    # source: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumcontextfunctions
    try
    {
        $definitionFunc = 
@'
        [DllImport(@"Bcrypt.dll",CharSet = CharSet.Unicode)] 
        public static extern uint BCryptEnumContextFunctions(uint dwTable, string pszContext, uint dwInterface, ref uint pcbBuffer, ref IntPtr ppBuffer);
        [DllImport("Bcrypt.dll")]
        public static extern void BCryptFreeBuffer(IntPtr pvBuffer);
'@
        $definitionStruct = 
@'
            using System;
            using System.Runtime.InteropServices;

            [StructLayout(LayoutKind.Sequential)]
            public struct CRYPT_CONTEXT_FUNCTIONS
            {
                public uint cFunctions;
                public IntPtr rgpszFunctions;
            }
'@

        $CRYPT_LOCAL = [uint32]"0x00000001"
        $NCRYPT_SCHANNEL_INTERFACE = [uint32]"0x00010002"
        $CRYPT_PRIORITY_TOP = [uint32]"0x00000000"
        $CRYPT_PRIORITY_BOTTOM = [uint32]"0xFFFFFFFF"

        $guid = [System.Guid]::NewGuid().ToString().Replace('-', '_')
        $typeFunc = Add-Type -MemberDefinition $definitionFunc -Name "T$guid" -PassThru

        if (-not ([System.Management.Automation.PSTypeName]'CRYPT_CONTEXT_FUNCTIONS').Type)
        {
            Add-Type $definitionStruct
        }
        $struct = New-Object CRYPT_CONTEXT_FUNCTIONS
        $typeStruct = $struct.GetType()
        
        $cbBuffer = [uint32]0
        $ppBuffer = [IntPtr]::Zero;
        $ret = $typeFunc::BCryptEnumContextFunctions($CRYPT_LOCAL, "SSL", $NCRYPT_SCHANNEL_INTERFACE, [ref]$cbBuffer, [ref]$ppBuffer)

        $cipherSuitesResult = @()
        if ($ret -eq 0)
        {
            $functions = [system.runtime.interopservices.marshal]::PtrToStructure($ppBuffer,[System.Type]$typeStruct)
            $pStr = $functions.rgpszFunctions
            for ($i = 0; $i -lt $functions.cFunctions; $i = $i + 1)
            {
                $str = [system.runtime.interopservices.marshal]::PtrToStringUni([system.runtime.interopservices.marshal]::ReadIntPtr($pStr))
                $cipherSuitesResult = $cipherSuitesResult + $str
                $offset = $pStr.ToInt64() + [system.IntPtr]::Size
                $pStr = New-Object System.IntPtr $offset
            }
            $typeFunc::BCryptFreeBuffer($ppBuffer);
            return $cipherSuitesResult
        }
        else
        {
            Write-nonOK "Error when retrieving list of cipher suites by BCript API - return code $ret"
        }
        
    }
    catch { Write-nonOK "Error when retrieving list of cipher suites by BCript API: $_" }
}

$gettlsciphersuiteAnalysisDone = $flase
$requiredEnabledCipherSuites = @()
$allEnabledCipherSuites = @()
if ($winBuildVersion.Major -ge 10) 
{
    Write-Detail "Running Get-TlsCipherCuite check..."

    $allEnabledCipherSuiteObjs = Get-TlsCipherSuite
    $allEnabledCipherSuites = $allEnabledCipherSuiteObjs.Name
    $tls12protocolCode = 771
    $tls12EnabledCipherSuites = $allEnabledCipherSuiteObjs | & {
            process {
                if (($_.Protocols | Where-Object { $_ -eq $tls12protocolCode }).Count -gt 0) { $_.Name }
            }
        }
    Write-Detail "All enabled TLS 1.2 cipher suites: $tls12EnabledCipherSuites"

    $requiredEnabledCipherSuites = $requiredTls12CipherSuites | Where-Object { $allEnabledCipherSuites -contains $_ }    
    Write-Detail "Matching cipher suites: $requiredEnabledCipherSuites"

    if ($requiredEnabledCipherSuites)
    { 
        Write-OK "At least one of the TLS 1.2 cipher suites required by Azure DevOps enabled on the machine."        
        $gettlsciphersuiteAnalysisDone = $true
    }
    elseif ($tls12EnabledCipherSuites) 
    {
        Write-nonOK "ISSUE FOUND: None of the TLS 1.2 cipher suites required by Azure DevOps are enabled."
        $gettlsciphersuiteAnalysisDone = $true
    }
    else 
    { 
        Write-nonOK "UNEXPECTED ISSUE FOUND: TLS 1.2 does not seem to be supported (no TLS 1.2 cipher suites enabled)" 
        Write-Detail "All enabled cipher suites: $allEnabledCipherSuites"
        # No mitigation here: in this branch of the code we're running on Windows Server 2016+, Windows 10+ ==> TLS 1.2 should be supported out of the box
    }
    Write-Break
}

if (-not $gettlsciphersuiteAnalysisDone)
{
    Write-Detail "Running BCrypt check..."
    $allEnabledCipherSuites = GetAllCipherSuitesByBCryptAPI
    $requiredEnabledCipherSuites = $requiredTls12CipherSuites | Where-Object { $allEnabledCipherSuites -contains $_ }
    if ($requiredEnabledCipherSuites)
    {
        Write-OK "At least one of the TLS 1.2 cipher suites required by Azure DevOps enabled on the machine."
        Write-Detail "Matching cipher suites: $requiredEnabledCipherSuites"
    }
    else
    {
        Write-nonOK "ISSUE FOUND: None of the TLS 1.2 cipher suites required by Azure DevOps are enabled."
        Write-Detail "All enabled cipher suites: $allEnabledCipherSuites"
    }
    Write-Break
}

Write-Detail "Running registry check..."

function GetFunctionsList
{
    param ($path)

    if (Test-Path -Path $path)
    {
        $list = (Get-ItemProperty -Path $path).Functions
        $list = if ($list -is [string]) {$list -split ","} else {$list}
        if ($list) { return ($true, $list) }
    }
    return ($false, @())
}


$expectedCipherSuitesConsideringOS = if ($winBuildVersion.Major -lt 10) { $minimallySupportedTls12CipherSuites } else { $requiredTls12CipherSuites }
$gpolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
($isDefined, $allowedCipherSuitesListPerGroupPolicy) = GetFunctionsList $gpolicyPath

if ($isDefined)
{
    $missingCipherSuitesConsideringOS = $expectedCipherSuitesConsideringOS | Where-Object { -not ($allowedCipherSuitesListPerGroupPolicy -contains $_) }    
    Write-Detail "Group Policy cipher suites override defined: $allowedCipherSuitesListPerGroupPolicy"
    Write-Detail "Missing cipher suites: $missingCipherSuitesConsideringOS"

    $suggestedFunctionsContent = ($missingCipherSuitesConsideringOS + $allowedCipherSuitesListPerGroupPolicy) -join ','    

    if ($requiredEnabledCipherSuites -eq $null -or $requiredEnabledCipherSuites.Length -eq 0)
    {
        Write-nonOK "MITIGATION A: via Local Group Policy setting"
        Write-nonOK "    Run gpedit.msc: "
        Write-nonOK "    - Navigate to ""Computer Config/Administrative Templates/Network/SSL Config Settings"""
        Write-nonOK "    - Choose setting ""SSL Cipher Suite Order"" -> Edit"
        Write-nonOK "    - If 'Enabled' is not checked, then cipher suite setting is possibly enforced by domain GPO (consult domain administrator)"
        Write-nonOK "    - If 'Enabled' is checked:"
        Write-nonOK "      - *either* change to 'Not configured' (resets to OS-default setting)"""
        Write-nonOK "      - *or* keep 'Enabled' and in field 'SSL Cipher Suites' add items to comma-separated list: $missingCipherSuitesConsideringOS"
        Write-nonOK "    - Press 'OK' button"
        Write-nonOK "    Restart the computer"
        Write-nonOK ""
        Write-nonOK "MITIGATION B: via registry change"
        Write-nonOK "    # Run the below powershell scipt AS ADMINISTRATOR. Restart the computer after the change."
        Write-nonOK "    [microsoft.win32.registry]::LocalMachine.OpenSubKey(""Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"", `$true).DeleteValue(""Functions"")"
        Write-nonOK ""
        Write-nonOK "MITIGATION C: if the above does not work (or works temporarily) ask your domain administrator if the cipher suites are enforced via domain GPO."        
    }
    else
    {
        Write-Detail "No need to change the GP override since cipher suites required by Azure DevOps are already enabled."
    }
}
else
{
    if ($requiredEnabledCipherSuites -eq $null -or $requiredEnabledCipherSuites.Length -eq 0)
    {
        Write-Detail "No Group Policy cipher suites override defined and cipher suites required by Azure DevOps are not enabled." 
        
        if ($winBuildVersion.Major -ge 10) 
        {
            Write-nonOK "MITIGATION A: per https://docs.microsoft.com/en-us/powershell/module/tls/enable-tlsciphersuite?view=windowsserver2022-ps"
            Write-nonOK "    # Run the below powershell scipt AS ADMINISTRATOR. Restart the readiness checker scipt in new PowerShell console to see effects."
            Write-nonOK "    # Continue to mitigations B/C only if all the below calls return 'Not Effective'"
            $requiredTls12CipherSuites | & { process { Write-NonOK "    Enable-TlsCipherSuite -Name $_; if (Get-TlsCipherSuite -Name $_) {'Enabled!'} else {'Not effective.'}" } }
            Write-nonOK ""
        }
        else
        {
            Write-nonOK "MITIGATION A: omitted (not supported by the OS)"
            Write-nonOK ""
        }

        $suggestedFunctionsContent = ($expectedCipherSuitesConsideringOS + $allEnabledCipherSuites) -join ','

        Write-nonOK "MITIGATION B: create an override via Local Group Policy setting"
        Write-nonOK "    Run gpedit.msc: "
        Write-nonOK "    - Navigate to ""Computer Config/Administrative Templates/Network/SSL Config Settings"""
        Write-nonOK "    - Choose setting ""SSL Cipher Suite Order"" -> Edit"
        Write-nonOK "    - Set as 'Enabled'"
        Write-nonOK "    - Set 'SSL Cipher Suites' to value (without quotes): ""$suggestedFunctionsContent"""
        Write-nonOK "    - Press 'OK' button"
        Write-nonOK "    Restart the computer"
        Write-nonOK ""
        Write-nonOK "MITIGATION C: via registry change"
        Write-nonOK "    # Run the below powershell scipt AS ADMINISTRATOR, RESTART the computer after change."
        Write-nonOK "    [microsoft.win32.registry]::SetValue(""HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"", ""Functions"",""$suggestedFunctionsContent"")"
    }
    else
    {
        Write-Detail "No Group Policy cipher suites override defined. No need to create the GP override since cipher suites required by Azure DevOps are already enabled."
    }
}

#
#
#
Write-Title "Analysis of TLS 1.2 compatibility: .NET Framework"
#
#
#

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
        Write-Warning "Warning: TLS 1.2 not enforced for applications targetting $desc"
        return "[$path] 'SchUseStrongCrypto'=dword:1, 'SystemDefaultTlsVersions'=dword:1"
    }
}

Write-Info "If you do not use legacy .NET applications you can ignore below warnings (if any detected). Always fix issues found in the above OS-based analysis first."
$mitigations = @()
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" ".NET Framework 4.0/4.5.x")
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" ".NET Framework 4.0/4.5.x (32bit app on 64bit OS)")
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" ".NET Framework 3.5")
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" ".NET Framework 3.5 (32bit app on 64bit OS)")
$mitigations = $mitigations | Where-Object { $_ -ne $null } 
if ($mitigations.Count -gt 0)
{
    Write-Warning "MITIGATIONS: per https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client"
    $mitigations | & { process { Write-Warning "    $_" } } 
}
