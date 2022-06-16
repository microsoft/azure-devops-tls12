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

$version = "2022-06-16"

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



#
# Functions shared by Analysis part of the script
#

function GetRegSetValueString
{
    param ($path, $propName, $value)
    $path = $path.replace("HKLM:\", "HKEY_LOCAL_MACHINE\")
    return "[microsoft.win32.registry]::SetValue(""$path"", ""$propName"", $value)"
}

function OutputMitigationToPs1 
{
    param ($mitigationId, $script, $printDone = $true)
    $fileName = ".\Mitigation-$mitigationId.ps1"
    $cmt = "# This PowerShell script was generated as a mitigation by Azure DevOps TLS 1.2 transition readiness checker."
    $lines = @($cmt) + $script
    if ($printDone) { $lines += @("'Done!'") }
    $lines | Out-File -FilePath $fileName -Force
    return $fileName
}


$boolCheck = { param($left, $right) return ([bool]$left -eq [bool]$right) }
$exactCheck = { param($left, $right) return ($left -eq $right) }

function CheckRegValueIsExpected
{
    param($path, $propertyName, $expectedBoolValue, $undefinedMeansExpectedValue, $predicate)
    $path = $path.replace("HKEY_LOCAL_MACHINE\", "HKLM:\")
    if (Test-Path -Path $path)
    {
        $value =  Get-ItemProperty -Path $path | Select-Object -ExpandProperty $propertyName -ErrorAction SilentlyContinue
        if ($value -eq $null) 
        { 
            return $undefinedMeansExpectedValue
        }
        else 
        {
            return $predicate.Invoke($value, $expectedBoolValue)
        }
    }
    else
    {
        return $undefinedMeansExpectedValue
    }
}


# 
#
#
Write-Title "Analysis of TLS 1.2 compatibility: OS"
#
#
#

Write-Detail "Getting environment info..."

$envOsVersion = [System.Environment]::OSVersion.Version # if OS went through update (W8 -> W8.1 -> W10 ...), this may return pre-update version (https://stackoverflow.com/questions/33328739/system-environment-osversion-returns-wrong-version) 
$winVersionRex = "([0-9]+\.)+[0-9]+"
$systemInfoVersion = $null
if ((systeminfo /fo csv | ConvertFrom-Csv | Select-Object -Property "OS Version")."OS Version" -match $winVersionRex) { $systemInfoVersion = [version]$Matches[0] } # systeminfo command is considered obsolete but gives up to date version
$osVersion = if ($envOsVersion -gt $systemInfoVersion) { $envOsVersion } else { $systemInfoVersion } # Take the highest OS version seen

Write-Host "PS Version:" $PSversionTable.PSVersion
Write-Host "PS Edition: " $PSversionTable.PSEdition
Write-Host "CLR Version: " $PSversionTable.CLRVersion
Write-Host "OS Version: system.environment: $envOsVersion, systeminfo: $systemInfoVersion --> $osVersion"

Write-Break

Write-Detail "Running Hot Fix check..."

function CheckHotfix {
    param ($hotfixId)
    
    Write-Detail "Checking $hotfixId..."
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq $hotfixId } 
    if ($hotfix)
    {
        Write-Detail "Hotfix $hotfixId found: $hotfix"
        return $true
    }
    else
    {
        Write-Detail "Hotfix $hotfixId not installed."
        return $false
    }
}

if ($osVersion.Major -ge 10)
{
    Write-OK "No hot fixes are necessary for TLS 1.2 support on this OS version."
}
elseif ($osVersion -ge [version]"6.3")
{
    $hotfixId = "KB2919355"
    $found = CheckHotfix $hotfixId    
    if ($found)
    {
        Write-OK "Hotfix check passed."
    }
    else
    {
        Write-nonOK "ISSUE FOUND: $hotfixId missing, see https://docs.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-8-1"
    }
}
elseif ($osVersion -ge [version]"6.1")
{
    $hotfixId = "KB3140245"
    $found = CheckHotfix $hotfixId    
    if ($found)
    {
        Write-OK "Hotfix check passed."
    }
    else
    {
        Write-nonOK "ISSUE FOUND: $hotfixId missing, see https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392"
    }
}
else
{
    Write-Error "This version of OS is not supported by the troubleshooting script (supported: Windows Server 2008 R2+, Windows 7+)"
}

Write-Break

$tls12ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
$clientCheckOK = $true 
$mitigations = @()

if (-not (CheckRegValueIsExpected $tls12ClientPath "Enabled" 1 $true $boolCheck))
{
    $mitigations += GetRegSetValueString $tls12ClientPath "Enabled" 1
    $clientCheckOK = $false   
}

$undefinedMeansEnabled = $true
if ($osVersion -lt [version]"6.3") 
{ 
    # source: https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392
    # source: https://support.microsoft.com/en-us/topic/update-to-add-support-for-tls-1-1-and-tls-1-2-in-windows-server-2008-sp2-windows-embedded-posready-2009-and-windows-embedded-standard-2009-b6ab553a-fa8f-3f5e-287c-e752eb3ce5f4
    Write-Detail "For old Windows versions (WS 2012, Windows 7 and older) TLS 1.2 must be explicitly enabled..."
    $undefinedMeansEnabled = $false
}
if (-not (CheckRegValueIsExpected $tls12ClientPath "DisabledByDefault" 0 $undefinedMeansEnabled $boolCheck))
{
    $mitigations += GetRegSetValueString $tls12ClientPath "DisabledByDefault" 0
    $clientCheckOK = $false
}
if ($clientCheckOK)
{
    Write-OK "TLS 1.2 client usage enabled."
}
else
{
    $mitigationName = "RegTlsClientEnable"
    $scriptFile = OutputMitigationToPs1 $mitigationName $mitigations
    Write-nonOK "ISSUE FOUND: TLS 1.2 client usage disabled."
    Write-nonOK "MITIGATION '$mitigationName': per https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs"
    Write-nonOK "    Mitigation script generated at $scriptFile"
    Write-nonOK "    Run the mitigation script as Administrator and restart the computer."
}
Write-Break

# List of TLS 1.2 cipher suites honoured by Azure DevOps Services.
# In this hash map for each cipher suite we have lowest Windows OS build version which supports it (when properly patched).
$serverHonouredTls12CipherSuites = @{
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" = [version]"10.0";
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" = [version]"10.0";
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" =   [version]"10.0";
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" =   [version]"6.1" 
}
# List of ECC curves relevant for ECDHE cipher suites
$requiredEccs = (
    "NistP256",
    "NistP384"
)

$localOsSupportedServerHonouredTls12CipherSuites = $serverHonouredTls12CipherSuites.Keys | Where-Object { $osVersion -ge $serverHonouredTls12CipherSuites[$_] }


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

$gettlsciphersuiteAnalysisDone = $false
$requiredEnabledCipherSuites = @()
$allEnabledCipherSuites = @()
if ($osVersion.Major -ge 10) 
{
    Write-Detail "Running Cipher Suite check (Get-TlsCipherCuite)..."

    $allEnabledCipherSuiteObjs = Get-TlsCipherSuite
    $allEnabledCipherSuites = $allEnabledCipherSuiteObjs.Name
    $tls12protocolCode = 771
    $tls12EnabledCipherSuites = $allEnabledCipherSuiteObjs | & {
            process {
                if (($_.Protocols | Where-Object { $_ -eq $tls12protocolCode }).Count -gt 0) { $_.Name }
            }
        }
    Write-Detail "All enabled TLS 1.2 cipher suites: $tls12EnabledCipherSuites"

    $requiredEnabledCipherSuites = $localOsSupportedServerHonouredTls12CipherSuites | Where-Object { $allEnabledCipherSuites -contains $_ }
    Write-Detail "Matching cipher suites: $requiredEnabledCipherSuites"

    if ($requiredEnabledCipherSuites)
    { 
        Write-OK "Cipher Suite check passed: at least one of the TLS 1.2 cipher suites supported by Azure DevOps is enabled."
        $gettlsciphersuiteAnalysisDone = $true
    }
    elseif ($tls12EnabledCipherSuites) 
    {
        Write-nonOK "ISSUE FOUND: None of the TLS 1.2 cipher suites supported by Azure DevOps are enabled."
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
    Write-Detail "Running Cipher Suite check (BCrypt)..."
    $allEnabledCipherSuites = GetAllCipherSuitesByBCryptAPI
    Write-Detail "All enabled cipher suites: $allEnabledCipherSuites"
    $requiredEnabledCipherSuites = $serverHonouredTls12CipherSuites.Keys | Where-Object { $allEnabledCipherSuites -contains $_ }
    $unsupportedEnabledCipherSuites = $requiredEnabledCipherSuites | Where-Object { $localOsSupportedServerHonouredTls12CipherSuites -notcontains $_ }
    if ($unsupportedEnabledCipherSuites)
    {
        Write-Warning "Warning: Excluding TLS 1.2 cipher suites which are supported by Azure DevOps but not working on this OS version: $unsupportedEnabledCipherSuites"
        $requiredEnabledCipherSuites = $requiredEnabledCipherSuites | Where-Object { $localOsSupportedServerHonouredTls12CipherSuites -contains $_ }
    }

    if ($requiredEnabledCipherSuites)
    {
        Write-OK "At least one of the TLS 1.2 cipher suites supported by Azure DevOps is enabled and working."
        Write-Detail "Matching cipher suites: $requiredEnabledCipherSuites"
    }
    else
    {
        Write-nonOK "ISSUE FOUND: None of the TLS 1.2 cipher suites supported by Azure DevOps are enabled."
    }
    Write-Break
}


Write-Detail "Running Group Policy check..."

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

$gpolicyPath = "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
($isDefined, $allowedCipherSuitesListPerGroupPolicy) = GetFunctionsList "HKLM:\$gpolicyPath"

if ($isDefined)
{
    $missingCipherSuitesConsideringOS = $localOsSupportedServerHonouredTls12CipherSuites | Where-Object { -not ($allowedCipherSuitesListPerGroupPolicy -contains $_) }
    Write-Detail "Group Policy cipher suites override defined: $allowedCipherSuitesListPerGroupPolicy"
    Write-Detail "Missing cipher suites: $missingCipherSuitesConsideringOS"

    if ((-not $requiredEnabledCipherSuites) -and $missingCipherSuitesConsideringOS)
    {
        $mitigation1Name = "GpeditREM"
        Write-nonOK "MITIGATION '$mitigation1Name': via Local Group Policy setting"
        Write-nonOK "    Run gpedit.msc: "
        Write-nonOK "    - Navigate to ""Computer Config/Administrative Templates/Network/SSL Config Settings"""
        Write-nonOK "    - Choose setting ""SSL Cipher Suite Order"" -> Edit"
        Write-nonOK "    - If 'Enabled' is not checked, then continue to the next mitigation below."
        Write-nonOK "    - If 'Enabled' is checked:"
        Write-nonOK "      - *either* change to 'Not configured' (resets to OS-default setting)"""
        Write-nonOK "      - *or* keep 'Enabled' and in field 'SSL Cipher Suites' add at least one of the following items to comma-separated list:"
        foreach ($cs in $missingCipherSuitesConsideringOS) { Write-nonOK "        $cs" }
        Write-nonOK "    - Press 'OK' button"
        Write-nonOK "    Restart the computer"
        Write-nonOK ""

        $scriptCode = @()
        $scriptCode += "`$regPath = ""$gpolicyPath"""
        $scriptCode += @"
`$value = [microsoft.win32.registry]::GetValue("HKEY_LOCAL_MACHINE\`$regPath", "Functions", `$null)
if (`$value) {
    "Deleting..."
    [microsoft.win32.registry]::LocalMachine.OpenSubKey(`$regPath, `$true).DeleteValue("Functions")
}
gpupdate /target:computer /force
`$value = [microsoft.win32.registry]::GetValue("HKEY_LOCAL_MACHINE\`$regPath", "Functions", `$null)
if (`$value) { "Mitigation was not effective! Local cipher suite list is being overriden by group policies." }
else { "Done! Please restart computer." }
"@
        $mitigation2Name = "RegFunctionsDEL"
        $scriptFile = OutputMitigationToPs1 "$mitigation2Name" $scriptCode $false
        Write-nonOK "MITIGATION '$mitigation2Name': deletion of cipher suite list in registry"
        Write-nonOK "    Mitigation script generated at $scriptFile"
        Write-nonOK "    Run the mitigation script as Administrator:"
        Write-nonOK "    - If 'Done!' is printed, then operation was successfull."
        Write-nonOK "    - If 'Mitigation was not effective!' is printed, then cipher suites are enforced via domain GPO - talk to your domain administrator."
        Write-nonOK ""
    }
    else
    {
        Write-Detail "No need to change the GP override since cipher suites required by Azure DevOps are already enabled."
    }
}
else
{
    if (-not $requiredEnabledCipherSuites)
    {
        Write-Detail "No Group Policy cipher suites override defined and cipher suites required by Azure DevOps are not enabled." 
        
        $mitigation1Name = "EnableTlsCipherSuite"
        if ($osVersion.Major -ge 10) 
        {
            $script = $localOsSupportedServerHonouredTls12CipherSuites | & { process { "Enable-TlsCipherSuite -Name $_; if (Get-TlsCipherSuite -Name $_) {'Enabled!'} else {'Not effective.'}" } }
            $scriptFile = OutputMitigationToPs1 $mitigation1Name $script
            Write-nonOK "MITIGATION '$mitigation1Name': per https://docs.microsoft.com/en-us/powershell/module/tls/enable-tlsciphersuite?view=windowsserver2022-ps"
            Write-nonOK "    Mitigation script generated at $scriptFile"
            Write-nonOK "    Run the mitigation script as Administrator:"
            Write-nonOK "    - If any line printed is 'Enabled!' then this mitigation was effective."
            Write-nonOK "    - If all the lines printed are 'Not Effective' then continue with applying further mitigations listed below."
            Write-nonOK ""
        }
        else
        {
            Write-nonOK "MITIGATION '$mitigation1Name': mitigation omitted (not supported by this OS version)"
            Write-nonOK ""
        }

        $mitigation2Name = "GpeditSET"
        Write-nonOK "MITIGATION '$mitigation2Name' (apply if the '$mitigation1Name' doesn't help or not applicable): create an override via Local Group Policy setting"
        Write-nonOK "    Run gpedit.msc: "
        Write-nonOK "    - Navigate to ""Computer Config/Administrative Templates/Network/SSL Config Settings"""
        Write-nonOK "    - Choose setting ""SSL Cipher Suite Order"" -> Edit"
        Write-nonOK "    - Set as 'Enabled'"
        Write-nonOK "    - 'SSL Cipher Suites' field pre-populates with comma-separated list of cipher suites."
        Write-nonOK "    - If the list does not contain any of the following cipher suites, then insert at least one of them:"
        foreach ($cs in $localOsSupportedServerHonouredTls12CipherSuites) { Write-nonOK "        $cs" }
        Write-nonOK "    - Press 'OK' button"
        Write-nonOK "    Restart the computer"
        Write-nonOK ""
    }
    else
    {
        Write-Detail "No Group Policy cipher suites override defined. No need to create the GP override since cipher suites required by Azure DevOps are already enabled."
    }
}

Write-Break

Write-Detail "Running Key Exchange check..."

function CheckKeyExchangeEnabled
{
    param ($name, $path, $ciphersuiteSegment, $enabledCipherSuites)

    $enabledValue = [System.Convert]::ToUInt32("FFFFFFFF", 16)
    $isExpected = CheckRegValueIsExpected $path "Enabled" $enabledValue $true $exactCheck
    if ($isExpected)
    {
        Write-Detail "$name key exchange allowed."
        return $enabledCipherSuites
    }
    else
    {    
        $filtered = $enabledCipherSuites | Where-Object { -not ($_ -match "_$($ciphersuiteSegment)_") }
        if ($enabledCipherSuites.Length -eq $filtered.Length)
        {
            Write-Detail "$name key exchange disabled but none of the enabled cipher suites requires it anyway."
        }
        else
        {
            Write-Warning "Warning: $name key exchange disabled. Enabled cipher suites after filtering: $filtered"
            if ($filtered.Length -eq 0)
            {    
                Write-nonOK "ISSUE FOUND: No TLS 1.2 cipher suites required by Azure DevOps remain enabled after applying $name disablement."

                $mitigationCode =  @()
                $mitigationCode += GetRegSetValueString $path "Enabled" "0xFFFFFFFF"

                if ($ciphersuiteSegment -eq "DHE")
                {
                    # https://docs.microsoft.com/en-us/security-updates/securityadvisories/2016/3174644
                    $mitigationCode += GetRegSetValueString $path "ServerMinKeyBitLength" 0x00000800
                }

                $mitigationName = "Reg$ciphersuiteSegment"
                $scriptFile = OutputMitigationToPs1 $mitigationName $mitigationCode
                Write-nonOK "MITIGATION '$mitigationName': enabling of key exchange schema $name in registry."
                Write-nonOK "    Mitigation script generated at $scriptFile"
                Write-nonOK "    Run the mitigation script as Administrator and restart the computer."
            }
        }
        return $filtered
    }
}

$keyexchangeFilteredCipherSuites = CheckKeyExchangeEnabled "Diffie-Hellman" "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" "DHE" $requiredEnabledCipherSuites

if ($osVersion.Major -ge 10) 
{ 
    $keyexchangeFilteredCipherSuites = CheckKeyExchangeEnabled "Elliptic-curve Diffie–Hellman" "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" "ECDHE" $keyexchangeFilteredCipherSuites
}

if ($keyexchangeFilteredCipherSuites.Length -gt 0)
{
    Write-OK "Key Exchange check passed."
}

Write-Break


Write-Detail "Running Elliptic Curve check..."

if ($osVersion.Major -lt 10)
{
    Write-Detail "Skipping elliptic curve check due to OS version."
}
else
{
    $allEnabledEccs = Get-TlsEccCurve
    Write-Detail "All enabled elliptic curves: $allEnabledEccs"
    $matchingEccs = $allEnabledEccs | Where-Object { $requiredEccs -contains $_ }
    Write-Detail "Matching elliptic curves: $matchingEccs"
    $ecdheCipherSuites = $keyexchangeFilteredCipherSuites | Where-Object { $_ -match "TLS_ECDH" }
    
    if ($matchingEccs.Length -gt 0)
    {
        Write-OK "Elliptic curve check passed: at least one elliptic curve supported by Azure DevOps is enabled."
        $eccFilteredCipherSuites = $keyexchangeFilteredCipherSuites
    }
    else
    {
        $eccFilteredCipherSuites = $keyexchangeFilteredCipherSuites | Where-Object { $ecdheCipherSuites -notcontains $_}        
        $reasonMsg = "All elliptic curves supported by Azure DevOps are disabled. This makes ECDHE cipher suites unusable for connection."
        if ($keyexchangeFilteredCipherSuites.Length -gt 0 -and $eccFilteredCipherSuites.Length -eq 0)
        {
            Write-nonOK "ISSUE FOUND: $reasonMsg There are no enabled cipher suites left."
            
            $script = $requiredEccs | & { process { "Enable-TlsEccCurve -Name $_; if (Get-TlsEccCurve -Name $_) {'Enabled!'} else {'Not effective.'}" } }
            $scriptFile = OutputMitigationToPs1 "EccEnable" $script
            Write-nonOK "MITIGATION 'cmdletEccEnable': https://docs.microsoft.com/de-ch/powershell/module/tls/enable-tlsecccurve"
            Write-nonOK "    Mitigation script generated at $scriptFile"
            Write-nonOK "    Run the mitigation script as Administrator:"
            Write-nonOK "    - If any printed line is 'Enabled!' then this mitigation was effective."
            Write-nonOK "    - If all the printed lines are 'Not Effective' then continue with applying the mitigation below."
            Write-nonOK ""

            Write-nonOK "MITIGATION 'GpeditEccSET' (try if 'cmdletEccEnable' doesn't help): edit an override via Local Group Policy setting"
            Write-nonOK "    Run gpedit.msc: "
            Write-nonOK "    - Navigate to ""Computer Config/Administrative Templates/Network/SSL Config Settings"""
            Write-nonOK "    - Choose setting ""ECC Curve Order"" -> Edit"
            Write-nonOK "    - If 'Enabled' is not checked, then ellptic curve setting is possibly enforced by domain GPO (consult domain administrator)"
            Write-nonOK "    - If 'Enabled' is checked:"
            Write-nonOK "      - *either* change to 'Not configured' (resets to OS-default setting)"""
            Write-nonOK "      - *or* keep 'Enabled' and in field 'ECC Curve Order' add at least one of the items: $requiredEccs"        
            Write-nonOK "    - Press 'OK' button"
            Write-nonOK "    Restart the computer"
            Write-nonOK ""
        }
        else 
        {
            if ($keyexchangeFilteredCipherSuites.Length -lt $eccFilteredCipherSuites.Length)
            {
                Write-Warning "Warning: $reasonMsg Remaining cipher suites: $eccFilteredCipherSuites"
            }
            else
            {
                Write-Warning "Warning: $reasonMsg This has no effect here because ECDHE cipher suites are not enabled."
            }
        }
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
        $result = @(
            (GetRegSetValueString $path "SchUseStrongCrypto" 1),
            (GetRegSetValueString $path "SystemDefaultTlsVersions" 1)
        )
        return $result
    }
}

$mitigations = @()
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" ".NET Framework 4.0/4.5.x")
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" ".NET Framework 4.0/4.5.x (32bit app on 64bit OS)")
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" ".NET Framework 3.5")
$mitigations = $mitigations + (CheckStrongCrypto "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" ".NET Framework 3.5 (32bit app on 64bit OS)")
$mitigations = $mitigations | Where-Object { $_ -ne $null } 
if ($mitigations.Count -gt 0)
{
    $scriptFile = OutputMitigationToPs1 "NetFramework" $mitigations
    
    Write-Info "Follow the below mitigations when the OS analysis is without issues and there are still applications with TLS-connectivity issues on the computer."
    Write-Warning "MITIGATIONS: per https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client"    
    Write-Warning "    Mitigation script generated at $scriptFile"
    Write-Warning "    Run the mitigation script as Administrator and restart the computer."
}
else
{
    Write-OK "All mitigations required to ensure TLS 1.2-compatibility of legacy .NET applications are in place."
}
