Enum SupportedWinSsprLogonScreenWindowsVersion {
  NotSupported
  RS4
  RS5
  R19H1
  R19H2
  R20H1
  R20H2
  R21H2
  R22H2
  Win1121H2
  Win1122H2
}

# Pre-PS5 compatible version for when we support Win7
#Add-Type -TypeDefinition @"
#   public enum SupportedWinSsprLogonScreenWindowsVersion
#   {
#     NotSupported,
#     RS4,
#     RS5
#   }
#"@

class Windows10ReleaseId {
  static [int]$RS4 = 1803
  static [int]$RS5 = 1809
  static [int]$R19H1 = 1903
  static [int]$R19H2 = 1909
  static [int]$R20H1 = 2004
  static [int]$R20H2 = 19042
  static [int]$R21H2 = 19044
  static [int]$R22H2 = 19045
}

class Windows11BuildId {
  static [int]$Win1121H2 = 22000 
  static [int]$Win1122H2 = 22621 
}

$Windows10Releases = @{
  [Windows10ReleaseId]::RS4 = [SupportedWinSsprLogonScreenWindowsVersion]::RS4;
  [Windows10ReleaseId]::RS5 = [SupportedWinSsprLogonScreenWindowsVersion]::RS5;
  [Windows10ReleaseId]::R19H1 = [SupportedWinSsprLogonScreenWindowsVersion]::R19H1;
  [Windows10ReleaseId]::R19H2 = [SupportedWinSsprLogonScreenWindowsVersion]::R19H2;
  [Windows10ReleaseId]::R20H1 = [SupportedWinSsprLogonScreenWindowsVersion]::R20H1;
  [Windows10ReleaseId]::R20H2 = [SupportedWinSsprLogonScreenWindowsVersion]::R20H2;
  [Windows10ReleaseId]::R21H2 = [SupportedWinSsprLogonScreenWindowsVersion]::R21H2;
  [Windows10ReleaseId]::R22H2 = [SupportedWinSsprLogonScreenWindowsVersion]::R22H2;
};

$Windows11Builds = @{
  [Windows11BuildId]::Win1121H2 = [SupportedWinSsprLogonScreenWindowsVersion]::Win1121H2;
  [Windows11BuildId]::Win1122H2 = [SupportedWinSsprLogonScreenWindowsVersion]::Win1122H2;
}

# Reg Paths #
$HKLMSoftwarePoliciesMicrosoftRegPath = "HKLM:\SOFTWARE\Policies\Microsoft"
$HKLMWinNTCurrentVersionRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$HKLMWindowsCurrentVersionRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
$HKCUWindowsCurrentVersionRegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"
$HKCUWinNTCurrentVersionRegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"

$PersonalizationRegPath = $HKLMSoftwarePoliciesMicrosoftRegPath + "\Windows\Personalization"
$AppxPath = $HKLMSoftwarePoliciesMicrosoftRegPath + "\Windows\Appx"
$WinLogonRegPath = $HKLMWinNTCurrentVersionRegPath + "\Winlogon"
$NotificationsSettigsRegPath = $HKCUWinNTCurrentVersionRegPath + "\Notifications\Settings"
$HKLMPoliciesSystemRegPath = $HKLMWindowsCurrentVersionRegPath + "\Policies\System"
$HKCUPoliciesSystemRegPath = $HKCUWindowsCurrentVersionRegPath + "\Policies\System"
$CredentialProvidersPath = $HKLMWindowsCurrentVersionRegPath + "\Authentication\Credential Providers"
$LostModePath = $WinLogonRegPath + "\LostMode"
$AzureADAccountRegPath = $HKLMSoftwarePoliciesMicrosoftRegPath + "\AzureADAccount"

# Known Windows 10 Credential Providers #
[string[]]$defaultWin10CredentialProviders =
'01A30791-40AE-4653-AB2E-FD210019AE88', # Automatic Redeployment Credential Provider
'1b283861-754f-4022-ad47-a5eaaa618894', # Smartcard Reader Selection Provider
'1ee7337f-85ac-45e2-a23c-37c753209769', # Smartcard WinRT Provider
'2135f72a-90b5-4ed3-a7f1-8bb705ac276a', # PicturePasswordLogonProvider
'25CBB996-92ED-457e-B28C-4774084BD562', # GenericProvider
'27FBDB57-B613-4AF2-9D7E-4FA7A66C21AD', # TrustedSignal Credential Provider
'2D8B3101-E025-480D-917C-835522C7F628', # FIDO Credential Provider
'3dd6bec0-8193-4ffe-ae25-e08e39ea4063', # NPProvider
'48B4E58D-2791-456C-9091-D524C6C706F2', # Secondary Authentication Factor Credential Provider
'600e7adb-da3e-41a4-9225-3c0399e88c0c', # CngCredUICredentialProvider
'60b78e88-ead8-445c-9cfd-0b87f74ea6cd', # PasswordProvider / Logon PasswordReset
'8AF662BF-65A0-4D0A-A540-A338A999D36F', # FaceCredentialProvider
'8FD7E19C-3BF7-489B-A72C-846AB3678C96', # Smartcard Credential Provider
'94596c7e-3744-41ce-893e-bbf09122f76a', # Smartcard Pin Provider
'A910D941-9DA9-4656-8933-AA1EAE01F76E', # Remote NGC Credential Provider
'BEC09223-B018-416D-A0AC-523971B639F5', # WinBio Credential Provider
'C5D7540A-CD51-453B-B22B-05305BA03F07', # Cloud Experience Credential Provider
'C885AA15-1764-4293-B82A-0586ADD46B35', # IrisCredentialProvider
'cb82ea12-9f71-446d-89e1-8d0924e1256e', # PINLogonProvider
'D6886603-9D2F-4EB2-B667-1971041FA96B', # NGC Credential Provider
'e74e57b0-6c6d-44d5-9cda-fb2df5ed7435', # CertCredProvider
'F8A0B131-5F68-486c-8040-7E8FC3C85BB6', # WLIDCredentialProvider
'F8A1793B-7873-4046-B2A7-1F318747F427', # FIDO Credential Provider
'f64945df-4fa9-4068-a2fb-61af319edd33'  # RdpCredentialProvider

$DefaultWindowsCredentialProviders = [System.Collections.Generic.HashSet[Guid]]::new()
Foreach ($credProviderId in $defaultWin10CredentialProviders) {
  $DefaultWindowsCredentialProviders.Add([System.Guid]::New($credProviderId)) | out-null
}

# Global issue counter and methods that operate on it
$global:TotalIssuesFound = 0

Function Trace-PotentialBreakingIssue($description) {
  Write-Warning $description
  $global:TotalIssuesFound++
}

Function Write-DiagnosticsResults {
  if ($global:TotalIssuesFound -eq 0) {
    Write-Host "No issues detected!"
  }
  else {
    Write-Warning "$global:TotalIssuesFound issue(s) found that may prevent SSPR on the logon screen from working!"
  }
}

#Type Definitions
Add-Type -TypeDefinition @"
namespace SsprDiagnosticsTool
{
  using System;
  using System.Runtime.InteropServices;
  using System.Security.Principal;
  using System.Security.Permissions;
  using Microsoft.Win32.SafeHandles;
  using System.Runtime.ConstrainedExecution;
  using System.Security;

  public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
  {
      private SafeTokenHandle()
          : base(true)
      {
      }

      [DllImport("kernel32.dll")]
      [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
      [SuppressUnmanagedCodeSecurity]
      [return: MarshalAs(UnmanagedType.Bool)]
      private static extern bool CloseHandle(IntPtr handle);

      protected override bool ReleaseHandle()
      {
          return CloseHandle(handle);
      }
  }

  public class LogonUserHelper
  {
      [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
      public static extern bool LogonUser(
          String lpszUsername,
          String lpszDomain,
          String lpszPassword,
          int dwLogonType,
          int dwLogonProvider,
          out SafeTokenHandle phToken);

      [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]
      public static SafeTokenHandle LogonUser(
          string userName,
          string domainName,
          string password,
          int logonType,
          int logonProvider)
      {
          SafeTokenHandle safeTokenHandle;

          bool returnValue = LogonUser(
              userName,
              domainName,
              password,
              logonType,
              logonProvider,
              out safeTokenHandle);

          if (false == returnValue)
          {
              int ret = Marshal.GetLastWin32Error();
              throw new System.ComponentModel.Win32Exception(ret);
          }

          return safeTokenHandle;
      }
  }
}
"@

# For GeneratePassword #
Add-Type -AssemblyName System.web

# Policy Checks #
Function Get-WindowsVersionSupportedForSsprLogonScreenExperience {
  $osVersion = [System.Environment]::OSVersion.Version

  If (-NOT ($osVersion.Major -eq 10)) {
    Write-Error "Windows 10 RS4 or greater is required for Azure AD password reset from the login screen"
    return [SupportedWinSsprLogonScreenWindowsVersion]::NotSupported
  }

  $releaseId = $(Get-ItemProperty -Path $HKLMWinNTCurrentVersionRegPath).releaseid
  $buildId = $(Get-ItemProperty -Path $HKLMWinNTCurrentVersionRegPath).currentbuildnumber
  If ($releaseId -lt [Windows10ReleaseId]::RS4) {
    Write-Error "Windows 10 RS4 or greater is required for Azure AD password reset from the login screen"
    return [SupportedWinSsprLogonScreenWindowsVersion]::NotSupported
  }

  # Check Win10 Releases
  foreach($Windows10Release in $Windows10Releases.Keys | Sort-Object) {
    if ($releaseId -le $Windows10Release) {
      Write-Verbose "Windows 10 $($Windows10Releases[$Windows10Release]) detected"
      return $Windows10Releases[$Windows10Release]
    }
  }

  # Check Win11 Builds
  foreach($Windows11Build in $Windows11Builds.Keys | Sort-Object) {
    if ($buildId -le $Windows11Build) {
      Write-Verbose "Windows 11 $($Windows11Builds[$Windows11Build]) detected"
      return $Windows11Builds[$Windows11Build]
    }
  }

  Write-Warning "Unrecognized new version of Windows detected. Proceeding with the Windows 10 22H2 checks"
  return [SupportedWinSsprLogonScreenWindowsVersion]::R22H2
}

Function Test-IsRunningAsSystem {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  If ($currentIdentity.Name -ne "NT AUTHORITY\SYSTEM") {
    Write-Warning "Script is not running as NT AUTHORITY\SYSTEM. Results may not be accurate"
  }
}

Function Test-IsRunningAsAdmin {
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $isInAdminRole = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  If (-Not $isInAdminRole) {
    Write-Warning "Script is not running as admin. You may encounter issues running this script"
  }
}

Function Test-NotificationsDisabledOnLockscreen($SupportedWinSsprLogonScreenWindowsVersion) {
  If ($SupportedWinSsprLogonScreenWindowsVersion -ne [SupportedWinSsprLogonScreenWindowsVersion]::RS4) {
    Write-Verbose "Skipping Lockscreen Notification Disabled Checks. This was fixed in RS5 onward"
    return
  }

  $allowNotificationsOnLockScreenKeyName = "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK"
  If (Test-RegistryKeyExists $NotificationsSettigsRegPath $allowNotificationsOnLockScreenKeyName) {
    $allowNotificationsOnLockScreenKeyValue = Get-RegistryKeyValue $NotificationsSettigsRegPath $allowNotificationsOnLockScreenKeyName
    If ($allowNotificationsOnLockScreenKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "Lock Screen notifications are disabled. This is a known issue on Win10 RS4 that may prevent SSPR from working"
    }
  }
}

Function Test-FastUserSwitchingDisabled {
  $hideFastSwitchingKeyName = "HideFastUserSwitching"
  If (Test-RegistryKeyExists $HKLMPoliciesSystemRegPath $hideFastSwitchingKeyName) {
    $hideFastSwitchingKeyValue = Get-RegistryKeyValue $HKLMPoliciesSystemRegPath $hideFastSwitchingKeyName
    If ($hideFastSwitchingKeyValue -ne 0) {
      Trace-PotentialBreakingIssue "Fast user switching is disabled. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-UACNotificationsDisabled {
  $enableLUAKeyName = "EnableLUA"
  If (Test-RegistryKeyExists $HKLMPoliciesSystemRegPath $enableLUAKeyName) {
    $enableLUAKeyValue = Get-RegistryKeyValue $HKLMPoliciesSystemRegPath $enableLUAKeyName
    If ($enableLUAKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "Windows UAC notifications are disabled (EnableLUA registry key is set to 0). This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-DontDisplayLastUsernameOnLogonScreen {
  $dontDisplayLastUserNameKeyName = "DontDisplayLastUserName"
  If (Test-RegistryKeyExists $HKLMPoliciesSystemRegPath $dontDisplayLastUserNameKeyName) {
    $dontDisplayLastUserNameKeyValue = Get-RegistryKeyValue $HKLMPoliciesSystemRegPath $dontDisplayLastUserNameKeyName
    If ($dontDisplayLastUserNameKeyValue -ne 0) {
      Trace-PotentialBreakingIssue "Last logged on username not being displayed on logon screen. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-LockScreenDisabled {
  $noLockScreenKeyName = "NoLockScreen"
  If (Test-RegistryKeyExists $PersonalizationRegPath $noLockScreenKeyName) {
    $noLockScreenKeyValue = Get-RegistryKeyValue $PersonalizationRegPath $noLockScreenKeyName
    If ($noLockScreenKeyValue -ne 0) {
      Trace-PotentialBreakingIssue "The lock screen is disabled. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-CtrlAltDeleteRequiredOnLockscreen($SupportedWinSsprLogonScreenWindowsVersion) {
  If ($SupportedWinSsprLogonScreenWindowsVersion -ne [SupportedWinSsprLogonScreenWindowsVersion]::RS4) {
    Write-Verbose "Skipping lockscreen disabled checks. This was fixed in RS5 onward"
    return
  }

  $disableCADKeyName = "DisableCAD"
  If (Test-RegistryKeyExists $WinLogonRegPath $disableCADKeyName) {
    $disableCADKeyValue = Get-RegistryKeyValue $WinLogonRegPath $disableCADKeyName
    If ($disableCADKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "Ctrl+Alt+Del is required on the logon screen. This is a known issue on Win10 RS4 that may prevent SSPR from working"
    }
  }
}

Function Test-SystemShellReplaced {
  $shellKeyName = "Shell"
  If (Test-RegistryKeyExists $WinLogonRegPath $shellKeyName) {
    $shellKeyValue = Get-RegistryKeyValue $WinLogonRegPath $shellKeyName
    If ($shellKeyValue -ne "explorer.exe") {
      Trace-PotentialBreakingIssue "System shell has been replaced. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-3rdPartyCredentialProviders {
  $credentialProvidersKeys = Get-ChildItem $CredentialProvidersPath
  ForEach ($credentialProvidersKey in $credentialProvidersKeys) {
    $credProviderId = [System.Guid]::New($credentialProvidersKey.PSChildName)
    If (-Not ($DefaultWindowsCredentialProviders.Contains($credProviderId))) {
      Trace-PotentialBreakingIssue (Get-CredentialProvidersDetailsString $credentialProvidersKey)
    }
  }
}

Function Get-CredentialProvidersDetailsString($credentialProvidersKey) {
  $providerName = (Get-ItemProperty -LiteralPath ("Registry::" + $credentialProvidersKey)).'(default)'
  $providerPath = $credentialProvidersKey
  $customDetailsObject += [pscustomobject]@{Name = $providerName; Path = $providerPath }
  $detailsTable = ($customDetailsObject | Format-List | Out-String).Trim()
  $warningString =
  @"
Unrecognized Credential Provider found. Some 3rd party Credential Providers may prevent SSPR from working.
{0}
"@ -f $detailsTable

  return $warningString
}

Function Test-LostModeEnabled {
  $enableLostModeKeyName = "EnableLostMode"
  If (Test-RegistryKeyExists $LostModePath $enableLostModeKeyName) {
    $enableLostModeKeyValue = Get-RegistryKeyValue $LostModePath $enableLostModeKeyName
    If ($enableLostModeKeyValue -ne 0) {
      Trace-PotentialBreakingIssue "Lost Mode is enabled. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-BlockNonAdminAppPackageInstallEnabled {
  $blockNonAdminUserInstallKeyName = "BlockNonAdminUserInstall"
  If (Test-RegistryKeyExists $AppxPath $blockNonAdminUserInstallKeyName) {
    $blockNonAdminUserInstallKeyValue = Get-RegistryKeyValue $AppxPath $blockNonAdminUserInstallKeyName
    If ($blockNonAdminUserInstallKeyValue -ne 0) {
      Trace-PotentialBreakingIssue "Non-admins are unable to initiate installation of Windows app packages (policy: BlockNonAdminUserInstall). This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-IsDeviceAADOrHybridJoined {
  $azureAdJoinedKeyName = "AzureAdJoined"
  $azureAdJoinedExpectedStatus = "AzureAdJoined : YES"
  $dsregCmdOutput = dsregcmd /status 
  if ($lastexitcode -ne 0) {
    Write-Error "dsregcmd.exe failed with error code $lastexitcode. Bailing on Test-IsDeviceAADOrHybridJoined check"
    return
  }
  
  $azureAdJoinedStatus = $dsregCmdOutput | Select-String -Pattern $azureAdJoinedKeyName
  if ($azureAdJoinedStatus -notmatch $azureAdJoinedExpectedStatus)
  {
    Trace-PotentialBreakingIssue "Current device is neither AAD-Joined nor Hybrid-Joined. This is a requirement for SSPR from the logon screen"
  }
}

Function Test-UsersNotInAllowLogonLocally {
  $isUsersInAllowedLogonLocally = $false
  $tmpFileName = [System.IO.Path]::GetTempFileName()

  secedit.exe /export /cfg "$($tmpFileName)" | Out-Null
  if ($lastexitcode -ne 0) {
    Write-Error "secedit.exe failed with error code $lastexitcode. Bailing on Test-UsersNotInAllowLogonLocally check"
    return
  }

  $tmpFileContent = Get-Content -Path $tmpFileName
  foreach ($entry in $tmpFileContent) {
    # The entry will look something like the following:
    # SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
    if ( $entry -like "SeInteractiveLogonRight*") {
      $rightSide = $entry.Split("=")[1]
      $interactiveLogonRightMembersList = $rightSide.Split(",")
      foreach ($sid in $interactiveLogonRightMembersList) {
        $sidTrimmed = $sid.Trim()
        if ($sidTrimmed -like "*S-1-5-32-545") {
          $isUsersInAllowedLogonLocally = $true
          break
        }
      }
    }
  }

  if (-Not ($isUsersInAllowedLogonLocally)) {
    Trace-PotentialBreakingIssue '"Users" not in "Allow log on locally" policy. This is a known issue that may prevent SSPR from working"'
  }
}

Function Test-BackButtonEnabled {
  $disableBackButtonKeyName = "DisableBackButton"
  If (Test-RegistryKeyExists $WinLogonRegPath $disableBackButtonKeyName) {
    $disableBackButtonKeyValue = Get-RegistryKeyValue $WinLogonRegPath $disableBackButtonKeyName
    If ($disableBackButtonKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "The Winlogon DisableBackButton key is set to false. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-PasswordResetNotEnabled {
  $allowPasswordResetKeyName = "AllowPasswordReset"
  If (Test-RegistryKeyExists $AzureADAccountRegPath $allowPasswordResetKeyName) {
    $allowPasswordResetKeyValue = Get-RegistryKeyValue $AzureADAccountRegPath $allowPasswordResetKeyName
    If ($allowPasswordResetKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "The AllowPasswordReset registry key is set to 0. SSPR is not configured to run on this machine"
    }
  }
  else {
    Trace-PotentialBreakingIssue "Could not find AllowPasswordReset registry key. SSPR is not configured to run on this machine"
  }
}

Function Test-DelayedDesktopSwitchTimeout {
  # Note: This test requires checking against this key in both HKLM and HKCU
  $delayedDesktopSwitchTimeoutKeyName = "DelayedDesktopSwitchTimeout"

  If (Test-RegistryKeyExists $HKLMPoliciesSystemRegPath $delayedDesktopSwitchTimeoutKeyName) {
    $delayedDesktopSwitchTimeoutKeyValue = Get-RegistryKeyValue $HKLMPoliciesSystemRegPath $delayedDesktopSwitchTimeoutKeyName
    If ($delayedDesktopSwitchTimeoutKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "DelayedDesktopSwitchTimeout is set to 0 in HKLM. This is a known issue that may prevent SSPR from working"
    }
  }
  If (Test-RegistryKeyExists $HKCUPoliciesSystemRegPath $delayedDesktopSwitchTimeoutKeyName) {
    $delayedDesktopSwitchTimeoutKeyValue = Get-RegistryKeyValue $HKCUPoliciesSystemRegPath $delayedDesktopSwitchTimeoutKeyName
    If ($delayedDesktopSwitchTimeoutKeyValue -eq 0) {
      Trace-PotentialBreakingIssue "DelayedDesktopSwitchTimeout is set to 0 in HKCU. This is a known issue that may prevent SSPR from working"
    }
  }
}

Function Test-FirstLogonTimeout {
  $firstLogonKeyName = "FirstLogon"
  If (Test-RegistryKeyExists $WinLogonRegPath $firstLogonKeyName) {
    $firstLogonKeyValue = Get-RegistryKeyValue $WinLogonRegPath $firstLogonKeyName
    If ($firstLogonKeyValue -eq 1) {
      $firstLogonTimeoutKeyName = "FirstLogonTimeout"
      If (Test-RegistryKeyExists $HKLMPoliciesSystemRegPath $firstLogonTimeoutKeyName) {
        $firstLogonTimeoutKeyValue = Get-RegistryKeyValue $HKLMPoliciesSystemRegPath $firstLogonTimeoutKeyName
        If ($firstLogonTimeoutKeyValue -eq 0) {
          Trace-PotentialBreakingIssue "FirstLogonTimeout is set to 0. This is a known issue that may prevent SSPR from working"
        }
      }
    }
  }
}

# Utility Functions #
Function Test-RegistryKeyExists($path, $name) {
  Try {
    Get-ItemProperty -Path $path -Name $name
    return $true
  }
  Catch [System.Management.Automation.PSArgumentException] {
    Write-Debug "Registry Key Property missing"
    return $false
  }
  Catch [System.Management.Automation.ItemNotFoundException] {
    Write-Debug "Registry Key missing"
    return $false
  }
}

Function Get-RegistryKeyValue($path, $name) {
  return (Get-ItemProperty -Path $path -Name $name).$name
}

Function New-StrongPassword {
  $passwordLength = 14
  $numberOfNonAlphanumericCharacters = 6
  return [System.Web.Security.Membership]::GeneratePassword($passwordLength, $numberOfNonAlphanumericCharacters)
}

### Connectivity checks ###
Function Test-ConnectivityToAllNecessaryEndpoints {
  try {
    $pw = New-StrongPassword
    $testUserAccount = New-SsprLogonUserAccount $pw
    $userToken = Get-LocalUserAccountToken $testUserAccount.Name $pw
    $testUserWindowsIdentity = New-Object -TypeName System.Security.Principal.WindowsIdentity -ArgumentList $userToken.DangerousGetHandle()
    $testUserWindowsImpersonationContext = $testUserWindowsIdentity.Impersonate()

    Test-HttpEndpointConnectivity "https://passwordreset.microsoftonline.com/ok"
    # ToDo: Don't hardcode the JQuery version in the future
    Test-HttpEndpointConnectivity "https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.3.1.min.js"
  }
  catch {
    Write-Error $_.Exception.Message
  }
  finally {
    Invoke-DisposeIfNotNull $testUserWindowsImpersonationContext
    Invoke-DisposeIfNotNull $testUserWindowsIdentity
    Invoke-DisposeIfNotNull $userToken
    Remove-SsprLogonUserAccount $testUserAccount
  }
}

Function Invoke-DisposeIfNotNull($obj) {
  if ($null -ne $obj) {
    $obj.Dispose()
  }
}
Function Test-HttpEndpointConnectivity($uri) {
  $requestSucceeded = $false
  try {
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -ErrorAction Stop
    $requestSucceeded = $true
    $StatusCode = $response.StatusCode
  }
  catch {
    $requestException = $_.Exception

    $warningString =
    @"
  "Unexpected error received while contacting {0} :"
    {1}
"@ -f $uri, $requestException

    Trace-PotentialBreakingIssue $warningString
  }
  If ($requestSucceeded) {
    If ($StatusCode -eq 200) {
      Write-Verbose "Successfully connected to $uri"
    }
    Else {
      Trace-PotentialBreakingIssue "Unexpected status code ($StatusCode) received while contacting $uri"
    }
  }
}

Function Test-RdpStatusCheck {
  $users = (quser) -ireplace '\s{2,}',',' | convertfrom-csv
  $sessionname = $users.sessionname

  if ($sessionname -like "rdp-tcp*") {
    Trace-PotentialBreakingIssue "Script running on RDP session. SSPR on Windows will not work on Remote Desktop or Hyper-V enhanced sessions."
  }
}

Function New-SsprLogonUserAccount($pw) {
  $passwordSecureString = ConvertTo-SecureString $pw -AsPlainText -Force
  $testAccountExpiryTime = (Get-Date).AddMinutes(2)
  $accountNameSuffixGuid = [System.Guid]::newguid().ToString().ToUpper()
  # strip out any non-alphanumeric characters
  $accountNameSuffixGuid -replace '[^A-Z0-9]', ''
  $accountName = "SSPR_TEST_" + $accountNameSuffixGuid.Substring($accountNameSuffixGuid.Length - 4);

  $user = New-LocalUser -Name $accountName `
    -Password $passwordSecureString `
    -AccountExpires $testAccountExpiryTime `
    -Description "Sspr Diagnostics Tool Test Account" `
    -UserMayNotChangePassword

  $user | Set-LocalUser -PasswordNeverExpires $true

  return $user
}

Function Remove-SsprLogonUserAccount($testUserAccount) {
  if ($null -ne $testUserAccount) {
    Remove-LocalUser -Name $testUserAccount.Name
  }
}

Function Get-LocalUserAccountToken($userName, $pw) {
  $LOGON32_PROVIDER_DEFAULT = 0
  $LOGON32_LOGON_INTERACTIVE = 2
  $domain = "."   # Local Account

  #Attempt a logon using this credential
  return [SsprDiagnosticsTool.LogonUserHelper]::LogonUser(
    $userName,
    $domain,
    $pw,
    $LOGON32_LOGON_INTERACTIVE,
    $LOGON32_PROVIDER_DEFAULT)
}

### START ###
$ErrorActionPreference = "Stop"
$windowsVersion = Get-WindowsVersionSupportedForSsprLogonScreenExperience
If ($windowsVersion -eq [SupportedWinSsprLogonScreenWindowsVersion]::NotSupported) {
  exit
}

### System Checks ###
Test-RdpStatusCheck
Test-IsRunningAsSystem
Test-IsRunningAsAdmin
Test-NotificationsDisabledOnLockscreen $windowsVersion
Test-CtrlAltDeleteRequiredOnLockscreen $windowsVersion
Test-FastUserSwitchingDisabled
Test-DontDisplayLastUsernameOnLogonScreen
Test-LockScreenDisabled
Test-SystemShellReplaced
Test-3rdPartyCredentialProviders
Test-LostModeEnabled
Test-UsersNotInAllowLogonLocally
Test-BackButtonEnabled
Test-DelayedDesktopSwitchTimeout
Test-PasswordResetNotEnabled
Test-FirstLogonTimeout
Test-UACNotificationsDisabled
Test-BlockNonAdminAppPackageInstallEnabled
Test-IsDeviceAADOrHybridJoined

### Connectivity Checks ###
Test-ConnectivityToAllNecessaryEndpoints

### Summary ###
Write-DiagnosticsResults
# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAtYikfz51YMGOd
# G4kjfHkzfQu39IKAAA9AkE1YrkNYh6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIC6uWh9mC5oURq3hYjS3qzoD
# EdeikV00wGDp3rDVxTsVMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAOVvHBDZ5epXUKYGMYdttNJOdRwXJOkSFnN+V/ZMEvnrXi1pLdSYIqxEJ
# Zd2zdSSpCYu35gUfuyBhwYj4PWlOmzsWzyhNhqV1VvrgydYWjSYpCghHgTfdSBhg
# ud2JSK1JHudh0AkIMGM2T84M8zCuaUv1r6FuHkUiBINQ3qmbADsIB4gvvhCIRfl5
# mtCOr71QKMSlx6gwThWlu+fQU+ZdNmrcybmcelYoB/mVypl7k9BFM9tQ9TCXEcuu
# Kh0eNGjoxOLts0Lw86RPzEUOLeNaHXG7//dJjjUxiOEgaGRBoiIPDw1sEy1fa77F
# G4QwIkQup9T2r9VA4GoYhB5dWOG5sqGCFyswghcnBgorBgEEAYI3AwMBMYIXFzCC
# FxMGCSqGSIb3DQEHAqCCFwQwghcAAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCUh4Rcc3Szy7o1pTRNHC+m5nAhtFtweJBcLTm3LPG0kQIGZJLymZ/F
# GBMyMDIzMDYyMTE4MTQ1Ni4wODlaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjA4NDItNEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIRejCCBycwggUPoAMCAQICEzMAAAGybkADf26plJIAAQAAAbIwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIw
# OTIwMjAyMjAxWhcNMjMxMjE0MjAyMjAxWjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjowODQyLTRC
# RTYtQzI5QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMqiZTIde/lQ4rC+Bml5f/Wu
# q/xKTxrfbG23HofmQ+qZAN4GyO73PF3y9OAfpt7Qf2jcldWOGUB+HzBuwllYyP3f
# x4MY8zvuAuB37FvoytnNC2DKnVrVlHOVcGUL9CnmhDNMA2/nskjIf2IoiG9J0qLY
# r8duvHdQJ9Li2Pq9guySb9mvUL60ogslCO9gkh6FiEDwMrwUr8Wja6jFpUTny8tg
# 0N0cnCN2w4fKkp5qZcbUYFYicLSb/6A7pHCtX6xnjqwhmJoib3vkKJyVxbuFLRhV
# XxH95b0LHeNhifn3jvo2j+/4QV10jEpXVW+iC9BsTtR69xvTjU51ZgP7BR4YDEWq
# 7JsylSOv5B5THTDXRf184URzFhTyb8OZQKY7mqMh7c8J8w1sEM4XDUF2UZNy829N
# VCzG2tfdEXZaHxF8RmxpQYBxyhZwY1rotuIS+gfN2eq+hkAT3ipGn8/KmDwDtzAb
# nfuXjApgeZqwgcYJ8pDJ+y/xU6ouzJz1Bve5TTihkiA7wQsQe6R60Zk9dPdNzw0M
# K5niRzuQZAt4GI96FhjhlUWcUZOCkv/JXM/OGu/rgSplYwdmPLzzfDtXyuy/GCU5
# I4l08g6iifXypMgoYkkceOAAz4vx1x0BOnZWfI3fSwqNUvoN7ncTT+MB4Vpvf1QB
# ppjBAQUuvui6eCG0MCVNAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUmfIngFzZEZlP
# kjDOVluBSDDaanEwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBANxHtu3FzIabaDbW
# qswdKBlAhKXRCN+5CSMiv2TYa4i2QuWIm+99piwAhDhADfbqor1zyLi95Y6GQnvI
# WUgdeC7oL1ZtZye92zYK+EIfwYZmhS+CH4infAzUvscHZF3wlrJUfPUIDGVP0lCY
# Vse9mguvG0dqkY4ayQPEHOvJubgZZaOdg/N8dInd6fGeOc+0DoGzB+LieObJ2Q0A
# tEt3XN3iX8Cp6+dZTX8xwE/LvhRwPpb/+nKshO7TVuvenwdTwqB/LT6CNPaElwFe
# KxKrqRTPMbHeg+i+KnBLfwmhEXsMg2s1QX7JIxfvT96md0eiMjiMEO22LbOzmLMN
# d3LINowAnRBAJtX+3/e390B9sMGMHp+a1V+hgs62AopBl0p/00li30DN5wEQ5If3
# 5Zk7b/T6pEx6rJUDYCti7zCbikjKTanBnOc99zGMlej5X+fC/k5ExUCrOs3/VzGR
# CZt5LvVQSdWqq/QMzTEmim4sbzASK9imEkjNtZZyvC1CsUcD1voFktld4mKMjE+u
# DEV3IddD+DrRk94nVzNPSuZXewfVOnXHSeqG7xM3V7fl2aL4v1OhL2+JwO1Tx3B0
# irO1O9qbNdJk355bntd1RSVKgM22KFBHnoL7Js7pRhBiaKmVTQGoOb+j1Qa7q+ci
# xGo48Vh9k35BDsJS/DLoXFSPDl4mMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtYwggI/AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjow
# ODQyLTRCRTYtQzI5QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAjhJ+EeySRfn2KCNsjn9cF9AUSTqggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOg9cRMwIhgPMjAyMzA2MjEyMDUyMzVaGA8yMDIzMDYyMjIwNTIzNVowdjA8Bgor
# BgEEAYRZCgQBMS4wLDAKAgUA6D1xEwIBADAJAgEAAgEEAgH/MAcCAQACAhE3MAoC
# BQDoPsKTAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAK2somtNI1q6J660k
# RW7ZTE4wSx8VVqhdvoAoAz6unSek+CVcSj2pzoKtAZw3ztzWirkoCAlOTNU60FpL
# Y1KS8AhcfwW6uOfUcZdbuP8fzSYJkoFkay+C8U04FFKVblltRc5I+L7NqJiguI0R
# uJ5eOLJ7eSTDzXAXRQTC72zW+OYxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbJuQAN/bqmUkgABAAABsjANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCBzbCKdIC0CHwf5djkbtD61GP+RLEUw0N+QZx2ujDt8wDCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIFN4zjzn4T63g8RWJ5SgUpfs9XIuj+fO76G0k8Ib
# Tj41MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGy
# bkADf26plJIAAQAAAbIwIgQgetf0TJIebbRRmu+Wwsp7/sJOsbwXZu1aSdv+jLSF
# 4b0wDQYJKoZIhvcNAQELBQAEggIALwtCMJl3x895DMCx4wKIlENySvsHZUskNLrE
# RNr0Ytm1aCvqKuTw4/N7Z4iqnAKUWK2Dak5Mqi2E268xoSSFOlOiHqi698ivvnnM
# IpSstk1MIPjP3MvSkdXOmzxkUH8iOCC2zg0XaPpeqPdfQ3PKbLWn5Wz/jKpUPXx+
# bzyFPNlzrp9W0rTFpzKCFUbo7PpjQulC0Rawzt1TWpG15cpD9qQ687yc/amoNpJL
# xGOYQ/k+sE4Sd5KDcMrzIZTWPJn7nc9mvpqrOxPlUm/WN9hWY/jPaKrx14wfYxgw
# rVAaf/A2J6nFTWNs554es+AT74SXhzCZ+4S2sVbOviJj3xEzi3e0NLMIeuNzT8+W
# JxwWequQOUiXZscWL+3EX7FYbTJcNM381b9kaDfZXpX+Sgb41+2avhimKY6SS7i7
# we+3v3ryXfLLoLrXLqzPkpO46J+Xgbt0hxejcEYWKFYqmlgQ2A6PG6gXttTcLqSS
# bEAvKtGaWb2eiehFUzyNKdxhDg7Mtg/KSnpBOz4z4fx+sxQaodazvr94PZwpE3l9
# 2YKRLPUxtDfAdhSpXAftDrawCKworS3MjOPZ+wLI3F4HwN5MexBdRsoiPtA6qTOI
# Euzz3mThT0mCFlwDUE4EusEKxS3SRHEsVyDdhggS/dKt7LZkg/11jx/5ApCFn6LN
# CsM+pE8=
# SIG # End signature block
