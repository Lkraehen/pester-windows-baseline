$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"


# https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
# https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment


function securityPolicy($setting){

    $guid = New-Guid
    $secedit_ouput = "$($env:TEMP)/$($guid).txt"
    secedit /export /cfg $secedit_ouput | Out-Null
    $content = Get-content -Path $secedit_ouput
    Remove-Item -Path $secedit_ouput -Force

    $match = $content | % {if($_ | Select-String -Pattern $setting){$_}}
    if($match){
        $split = $match.Split('=')
        $vaules = $split[1].Split(',')
    }
    return  $vaules.Trim()

}



# TODO: Make these security checks even better
Describe "'Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -Tag @('windows-010') {

    BeforeAll {
        $setting = 'SeTrustedCredManAccessPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeTrustedCredManAccessPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it 'Should be ""' {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Configure 'Access this computer from the network" -Tag @('windows-011') {

    BeforeAll {
        $setting = 'SeNetworkLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeNetworkLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it 'Should be ""' {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Configure 'Access this computer from the network" -Tag @('windows-012') {

    BeforeAll {
        $setting = 'SeTcbPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeTcbPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it 'Should be ""' {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Add workstations to domain' is set to 'Administrators'" -Tag @('windows-013') {

    BeforeAll {
        $setting = 'SeMachineAccountPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeMachineAccountPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it 'Should be ""' {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'" -Tag @('windows-014') {

    BeforeAll {
        $setting = 'SeIncreaseQuotaPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeIncreaseQuotaPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Allow log on locally' is set to 'Administrators'" -Tag @('windows-015') {

    BeforeAll {
        $setting = 'SeInteractiveLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeInteractiveLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Configure 'Allow log on through Remote Desktop Services'" -Tag @('windows-016') {

    BeforeAll {
        $setting = 'SeRemoteInteractiveLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeRemoteInteractiveLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Back up files and directories' is set to 'Administrators'" -Tag @('windows-017') {

    BeforeAll {
        $setting = 'SeBackupPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeBackupPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" -Tag @('windows-018') {

    BeforeAll {
        $setting = 'SeSystemtimePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeSystemtimePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-32-544'
        }
    }
}



Describe "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" -Tag @('windows-018') {

    BeforeAll {
        $setting = 'SeSystemtimePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeSystemtimePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'" -Tag @('windows-019') {

    BeforeAll {
        $setting = 'SeTimeZonePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeTimeZonePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Create a pagefile' is set to 'Administrators'" -Tag @('windows-020') {

    BeforeAll {
        $setting = 'SeCreatePagefilePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeCreatePagefilePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Create a token object' is set to 'No One'" -Tag @('windows-021') {

    BeforeAll {
        $setting = 'SeCreateTokenPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeCreateTokenPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -Tag @('windows-022') {

    BeforeAll {
        $setting = 'SeCreateGlobalPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeCreateGlobalPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544', '*S-1-5-6'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-20', '*S-1-5-32-544', '*S-1-5-6'
        }
    }
}

Describe "'Ensure 'Create permanent shared objects' is set to 'No One'" -Tag @('windows-023') {

    BeforeAll {
        $setting = 'SeCreatePermanentPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeCreatePermanentPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Create permanent shared objects' is set to 'No One'" -Tag @('windows-024') {

    BeforeAll {
        $setting = 'SeCreateSymbolicLinkPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeCreateSymbolicLinkPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Debug programs' is set to 'Administrators'" -Tag @('windows-025') {

    BeforeAll {
        $setting = 'SeDebugPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeDebugPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Deny access to this computer from the network' is set to 'Guests'" -Tag @('windows-026') {

    BeforeAll {
        $setting = 'SeDenyNetworkLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeDenyNetworkLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-546'" {
            $securityPolicy | Should -be '*S-1-5-32-546'
        }
    }
}


Describe "Ensure 'Deny log on as a batch job' to include 'Guests'" -Tag @('windows-027') {

    BeforeAll {
        $setting = 'SeDenyBatchLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeDenyBatchLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-546'" {
            $securityPolicy | Should -be '*S-1-5-32-546'
        }
    }
}

Describe "Ensure 'Deny log on locally' to include 'Guests'" -Tag @('windows-028') {

    BeforeAll {
        $setting = 'SeDenyInteractiveLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeDenyInteractiveLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should contain '*S-1-5-32-546'" {
            $securityPolicy | Should -Contain '*S-1-5-32-546'
        }
    }
}

Describe "Ensure 'Deny log on as a service' to include 'Guests'" -Tag @('windows-029') {

    BeforeAll {
        $setting = 'SeDenyServiceLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeDenyServiceLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should contain '*S-1-5-32-546'" {
            $securityPolicy | Should -Contain '*S-1-5-32-546'
        }
    }
}

# TODO: requires params for SIDS
Describe "Configure 'Deny log on through Remote Desktop Services'" -Tag @('windows-030') {

    BeforeAll {
        $setting = 'SeDenyRemoteInteractiveLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeDenyRemoteInteractiveLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-546'" {
            $securityPolicy | Should -be '*S-1-5-32-546'
        }
    }
}

# TODO: requires params for SIDS
Describe "Configure 'Enable computer and user accounts to be trusted for delegation'" -Tag @('windows-031') {

    BeforeAll {
        $setting = 'SeEnableDelegationPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeEnableDelegationPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Force shutdown from a remote system' is set to 'Administrators'" -Tag @('windows-032') {

    BeforeAll {
        $setting = 'SeRemoteShutdownPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeRemoteShutdownPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -Tag @('windows-033') {

    BeforeAll {
        $setting = 'SeAuditPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeAuditPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-20'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-20'
        }
    }
}

Describe "Configure 'Impersonate a client after authentication'" -Tag @('windows-034') {

    BeforeAll {
        $setting = 'SeImpersonatePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeImpersonatePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Increase scheduling priority' is set to 'Administrators'" -Tag @('windows-035') {

    BeforeAll {
        $setting = 'SeIncreaseBasePriorityPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeIncreaseBasePriorityPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

# TODO: requires params for SIDS
Describe "Ensure 'Load and unload device drivers' is set to 'Administrators'" -Tag @('windows-036') {

    BeforeAll {
        $setting = 'SeLoadDriverPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeLoadDriverPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Lock pages in memory' is set to 'No One'" -Tag @('windows-037') {

    BeforeAll {
        $setting = 'SeLockMemoryPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeLockMemoryPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "'Ensure 'Log on as a batch job' is set to 'Administrators' (DC only)" -Tag @('windows-038') {

    BeforeAll {
        $setting = 'SeBatchLogonRight'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeBatchLogonRight" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}


Describe "Configure 'Manage auditing and security log'" -Tag @('windows-039') {

    BeforeAll {
        $setting = 'SeSecurityPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeSecurityPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Modify an object label' is set to 'No One'" -Tag @('windows-040') {

    BeforeAll {
        $setting = 'SeRelabelPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeRelabelPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be ''" {
            $securityPolicy | Should -be ''
        }
    }
}

Describe "Ensure 'Modify firmware environment values' is set to 'Administrators'" -Tag @('windows-041') {

    BeforeAll {
        $setting = 'SeSystemEnvironmentPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeSystemEnvironmentPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'" -Tag @('windows-042') {

    BeforeAll {
        $setting = 'SeManageVolumePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeManageVolumePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Profile single process' is set to 'Administrators'" -Tag @('windows-043') {

    BeforeAll {
        $setting = 'SeProfileSingleProcessPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeProfileSingleProcessPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'" -Tag @('windows-044') {

    BeforeAll {
        $setting = 'SeProfileSingleProcessPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeProfileSingleProcessPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544', '*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'" {
            $securityPolicy | Should -be '*S-1-5-32-544', '*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'
        }
    }
}

# TODO: requires params for SIDS
Describe "'Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -Tag @('windows-045') {

    BeforeAll {
        $setting = 'SeAssignPrimaryTokenPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeAssignPrimaryTokenPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-19', '*S-1-5-20'" {
            $securityPolicy | Should -be '*S-1-5-19', '*S-1-5-20'
        }
    }
}

Describe "Ensure 'Restore files and directories' is set to 'Administrators'" -Tag @('windows-046') {

    BeforeAll {
        $setting = 'SeRestorePrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeRestorePrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

# TODO: requires params for SIDS ??
Describe "Ensure 'Shut down the system' is set to 'Administrators'" -Tag @('windows-047') {

    BeforeAll {
        $setting = 'SeShutdownPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeShutdownPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "'Ensure 'Synchronize directory service data' is set to 'No One' (DC only)'" -Tag @('windows-048') {

    BeforeAll {
        $setting = 'SeSyncAgentPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeSyncAgentPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}


Describe "Ensure 'Take ownership of files or other objects' is set to 'Administrators'" -Tag @('windows-049') {

    BeforeAll {
        $setting = 'SeTakeOwnershipPrivilege'
        $securityPolicy = securityPolicy -setting $setting
    }
    Context "Security Policy: SeTakeOwnershipPrivilege" {
        
        it 'Should exist' {
            $securityPolicy | Should -Not -Be $null
        }

        it "Should be '*S-1-5-32-544'" {
            $securityPolicy | Should -be '*S-1-5-32-544'
        }
    }
}

Describe "Ensure 'Accounts: Administrator account status' is set to 'Disabled'" -Tag @('windows-050') {
    BeforeAll {
        $sid_pattern = 'S-1-5-21-\d+-\d+-\d+-500'
        $users = Get-LocalUser | select-object * | ForEach-Object {if([regex]::match($_.SID, $sid_pattern).Success){$_}}
    }
    Context "User with pattern: 'S-1-5-21-\d+-\d+-\d+-500'" {

        it 'Should exist' {
            $users | Should -Not -Be $null
        }

        it "Should be 'Disabled'" {
            $users |  Select-object -ExpandProperty Enabled | Should -be $false
        }
    }
}

# 51

Describe "Ensure 'Accounts: Guest account status' is set to 'Disabled'" -Tag @('windows-052') {
    BeforeAll {
        $sid_pattern = 'S-1-5-21-\d+-\d+-\d+-501'
        $users = Get-LocalUser | select-object * | ForEach-Object {if([regex]::match($_.SID, $sid_pattern).Success){$_}}
    }

    Context "User with pattern: 'S-1-5-21-\d+-\d+-\d+-501'" {

        it 'Should exist' {
            $users | Should -Not -Be $null
        }

        it "Should be 'Disabled'" {
            $users |  Select-object -ExpandProperty Enabled | Should -be $false
        }
    }
}

# 53

Describe "Configure 'Accounts: Rename administrator account'" -Tag @('windows-054') {
    BeforeAll {
        $named_user = 'Administrator'
        $users = Get-LocalUser -Name $named_user -ErrorAction 0
    }

    Context "User: Administrator" {

        it 'Should not exist' {
            $users | Should -Be $null
        }

    }
}

Describe "Configure 'Accounts: Rename guest account'" -Tag @('windows-055') {
    BeforeAll {
        $named_user = 'Guest'
        $users = Get-LocalUser -Name $named_user -ErrorAction 0
    }

    Context "User: Guest" {

        it 'Should not exist' {
            $users | Should -Be $null
        }

    }
}

Describe "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'" -Tag @('windows-056') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "SCENoApplyLegacyAuditPolicy"' {
            $Registry.Property | Should -Contain 'SCENoApplyLegacyAuditPolicy'
        }

        it 'SCENoApplyLegacyAuditPolicy Should be 1' {
            $Registry | Get-ItemPropertyValue -Name SCENoApplyLegacyAuditPolicy -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'" -Tag @('windows-057') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "CrashOnAuditFail"' {
            $Registry.Property | Should -Contain 'CrashOnAuditFail'
        }

        it 'CrashOnAuditFail Should be 0' {
            $Registry | Get-ItemPropertyValue -Name CrashOnAuditFail -ErrorAction 0 | Should -Be 0
        }
    }
}


Describe "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'" -Tag @('windows-058') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AllocateDASD"' {
            $Registry.Property | Should -Contain 'AllocateDASD'
        }

        it 'AllocateDASD Should be 0' {
            $Registry | Get-ItemPropertyValue -Name AllocateDASD -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'" -Tag @('windows-059') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AddPrinterDrivers"' {
            $Registry.Property | Should -Contain 'AddPrinterDrivers'
        }

        it 'AddPrinterDrivers Should be 1' {
            $Registry | Get-ItemPropertyValue -Name AddPrinterDrivers -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)" -Tag @('windows-060') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "SubmitControl"' {
            $Registry.Property | Should -Contain 'SubmitControl'
        }

        it 'SubmitControl Should be 0' {
            $Registry | Get-ItemPropertyValue -Name SubmitControl -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only)" -Tag @('windows-061') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LDAPServerIntegrity"' {
            $Registry.Property | Should -Contain 'LDAPServerIntegrity'
        }

        it 'LDAPServerIntegrity Should be 2' {
            $Registry | Get-ItemPropertyValue -Name LDAPServerIntegrity -ErrorAction 0 | Should -Be 2
        }
    }
}

Describe "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only)'" -Tag @('windows-062') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "RefusePasswordChange"' {
            $Registry.Property | Should -Contain 'RefusePasswordChange'
        }

        it 'RefusePasswordChange Should be 0' {
            $Registry | Get-ItemPropertyValue -Name RefusePasswordChange -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only)'" -Tag @('windows-063') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "RequireSignOrSeal"' {
            $Registry.Property | Should -Contain 'RequireSignOrSeal'
        }

        it 'RequireSignOrSeal Should be 1' {
            $Registry | Get-ItemPropertyValue -Name RequireSignOrSeal -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'" -Tag @('windows-064') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "SealSecureChannel"' {
            $Registry.Property | Should -Contain 'SealSecureChannel'
        }

        it 'SealSecureChannel Should be 1' {
            $Registry | Get-ItemPropertyValue -Name SealSecureChannel -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'" -Tag @('windows-065') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "SignSecureChannel"' {
            $Registry.Property | Should -Contain 'SignSecureChannel'
        }

        it 'SignSecureChannel Should be 1' {
            $Registry | Get-ItemPropertyValue -Name SignSecureChannel -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'" -Tag @('windows-066') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DisablePasswordChange"' {
            $Registry.Property | Should -Contain 'DisablePasswordChange'
        }

        it 'DisablePasswordChange Should be 0' {
            $Registry | Get-ItemPropertyValue -Name DisablePasswordChange -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'" -Tag @('windows-067') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "MaximumPasswordAge"' {
            $Registry.Property | Should -Contain 'MaximumPasswordAge'
        }

        it 'MaximumPasswordAge Should BeLessOrEqual 30' {
            $Registry | Get-ItemPropertyValue -Name MaximumPasswordAge -ErrorAction 0 | Should -BeLessOrEqual 30
        }

        it 'MaximumPasswordAge Should not BeLessOrEqual 0' {
            $Registry | Get-ItemPropertyValue -Name MaximumPasswordAge -ErrorAction 0 | Should -not -BeLessOrEqual 0
        }
    }
}

Describe "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'" -Tag @('windows-068') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "RequireStrongKey"' {
            $Registry.Property | Should -Contain 'RequireStrongKey'
        }

        it 'RequireStrongKey Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name RequireStrongKey -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'" -Tag @('windows-069') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DontDisplayLastUserName"' {
            $Registry.Property | Should -Contain 'DontDisplayLastUserName'
        }

        it 'DontDisplayLastUserName Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name DontDisplayLastUserName -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'" -Tag @('windows-070') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DisableCAD"' {
            $Registry.Property | Should -Contain 'DisableCAD'
        }

        it 'DisableCAD Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name DisableCAD -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'" -Tag @('windows-071') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "InactivityTimeoutSecs"' {
            $Registry.Property | Should -Contain 'InactivityTimeoutSecs'
        }

        it 'InactivityTimeoutSecs Should BeLessOrEqual 900' {
            $Registry | Get-ItemPropertyValue -Name InactivityTimeoutSecs -ErrorAction 0 | Should -BeLessOrEqual 900
        }

        it 'InactivityTimeoutSecs Should not Be 0' {
            $Registry | Get-ItemPropertyValue -Name InactivityTimeoutSecs -ErrorAction 0 | Should -not -Be 0
        }
    }
}

Describe "Configure 'Interactive logon: Message text for users attempting to log on'" -Tag @('windows-072') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LegalNoticeText"' {
            $Registry.Property | Should -Contain 'LegalNoticeText'
        }

        it 'LegalNoticeText Should Be configured' {
            $Registry | Get-ItemPropertyValue -Name LegalNoticeText -ErrorAction 0 | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Configure 'Interactive logon: Message text for users attempting to log on'" -Tag @('windows-073') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LegalNoticeCaption"' {
            $Registry.Property | Should -Contain 'LegalNoticeCaption'
        }

        it 'LegalNoticeCaption Should Be configured' {
            $Registry | Get-ItemPropertyValue -Name LegalNoticeCaption -ErrorAction 0 | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'" -Tag @('windows-074') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "CachedLogonsCount"' {
            $Registry.Property | Should -Contain 'CachedLogonsCount'
        }

        it 'CachedLogonsCount Should BeLessOrEqual 4' {
            $Registry | Get-ItemPropertyValue -Name CachedLogonsCount -ErrorAction 0 | Should -BeLessOrEqual 4
        }
    }
}

Describe "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'" -Tag @('windows-075') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "PasswordExpiryWarning"' {
            $Registry.Property | Should -Contain 'PasswordExpiryWarning'
        }

        it 'PasswordExpiryWarning Should BeLessOrEqual 14' {
            $Registry | Get-ItemPropertyValue -Name PasswordExpiryWarning -ErrorAction 0 | Should -BeLessOrEqual 14
        }

        it 'PasswordExpiryWarning Should BeGreaterOrEqual 5' {
            $Registry | Get-ItemPropertyValue -Name PasswordExpiryWarning -ErrorAction 0 | Should -BeGreaterOrEqual 5
        }
    }
}

Describe "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'" -Tag @('windows-076') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "ForceUnlockLogon"' {
            $Registry.Property | Should -Contain 'ForceUnlockLogon'
        }

        it 'ForceUnlockLogon Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name ForceUnlockLogon -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher" -Tag @('windows-077') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "ScRemoveOption"' {
            $Registry.Property | Should -Contain 'ScRemoveOption'
        }

        it 'ScRemoveOption Should Not BeNullOrEmpty' {
            $Registry | Get-ItemPropertyValue -Name ScRemoveOption -ErrorAction 0 | Should -not -BeNullOrEmpty
        }
    }
}

Describe "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'" -Tag @('windows-078') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "RequireSecuritySignature"' {
            $Registry.Property | Should -Contain 'RequireSecuritySignature'
        }

        it 'RequireSecuritySignature Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name RequireSecuritySignature -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'" -Tag @('windows-079') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "EnableSecuritySignature"' {
            $Registry.Property | Should -Contain 'EnableSecuritySignature'
        }

        it 'EnableSecuritySignature Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name EnableSecuritySignature -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'" -Tag @('windows-080') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" {

        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "EnablePlainTextPassword"' {
            $Registry.Property | Should -Contain 'EnablePlainTextPassword'
        }

        it 'EnablePlainTextPassword Should Be 0' {
            $Registry | Get-ItemPropertyValue -Name EnablePlainTextPassword -ErrorAction 0 | Should -Be 0
        }
    }
}

# https://github.com/dev-sec/windows-baseline/blob/master/controls/administrative_templates_computer.rb
Describe "'Ensure 'Prevent enabling lock screen camera' is set to 'Enabled''" -Tag @('windows-175') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "NoLockScreenCamera"' {
            $Registry.Property | Should -Contain 'NoLockScreenCamera'
        }

        it 'NoLockScreenCamera Should be 1' {
            $Registry | Get-ItemPropertyValue -Name NoLockScreenCamera -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "'Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'" -Tag @('windows-176') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "NoLockScreenSlideshow"' {
            $Registry.Property | Should -Contain 'NoLockScreenSlideshow'
        }

        it 'NoLockScreenSlideshow Should be 1' {
            $Registry | Get-ItemPropertyValue -Name NoLockScreenSlideshow -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Allow Input Personalization' is set to 'Disabled'" -Tag @('windows-177') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AllowInputPersonalization"' {
            $Registry.Property | Should -Contain 'AllowInputPersonalization'
        }

        it 'AllowInputPersonalization Should be 1' {
            $Registry | Get-ItemPropertyValue -Name AllowInputPersonalization -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Allow Input Personalization' is set to 'Disabled'" -Tag @('windows-178') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AllowOnlineTips"' {
            $Registry.Property | Should -Contain 'AllowOnlineTips'
        }

        it 'AllowInputPersonalization Should be 1' {
            $Registry | Get-ItemPropertyValue -Name AllowOnlineTips -ErrorAction 0 | Should -Be 0
        }
    }
}


Describe "Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)" -Tag @('windows-179') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DllName"' {
            $Registry.Property | Should -Contain 'DllName'
        }

        it 'DllName Should be C:\Program Files\LAPS\CSE\AdmPwd.dll' {
            $Registry | Get-ItemPropertyValue -Name DllName -ErrorAction 0 | Should -Be 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
        }
    }
}

Describe "Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)" -Tag @('windows-180') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }

    it "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd Should exist" {
        $Registry | Should -Not -Be $null
    }

    it 'Should Contain "PwdExpirationProtectionEnabled"' {
        $Registry.Property | Should -Contain 'PwdExpirationProtectionEnabled'
    }

    it 'PwdExpirationProtectionEnabled Should be 1' {
        $Registry | Get-ItemPropertyValue -Name PwdExpirationProtectionEnabled -ErrorAction 0 | Should -Be 1
    }
}

Describe "Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only)" -Tag @('windows-181') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AdmPwdEnabled"' {
            $Registry.Property | Should -Contain 'AdmPwdEnabled'
        }

        it 'PwdExpirationProtectionEnabled Should be 1' {
            $Registry | Get-ItemPropertyValue -Name AdmPwdEnabled -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)" -Tag @('windows-182') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "PasswordComplexity"' {
            $Registry.Property | Should -Contain 'PasswordComplexity'
        }

        it 'PasswordComplexity Should be 4' {
            $Registry | Get-ItemPropertyValue -Name PasswordComplexity -ErrorAction 0 | Should -Be 4
        }
    }
}

Describe "Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)" -Tag @('windows-183') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "PasswordLength"' {
            $Registry.Property | Should -Contain 'PasswordLength'
        }

        it 'PasswordLength Should be > 15' {
            $Registry | Get-ItemPropertyValue -Name PasswordLength -ErrorAction 0 | Should -BeGreaterOrEqual 15
        }
    }
}

Describe "Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)" -Tag @('windows-184') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "PasswordAgeDays"' {
            $Registry.Property | Should -Contain 'PasswordAgeDays'
        }

        it 'PasswordAgeDays Should be <= 30' {
            $Registry | Get-ItemPropertyValue -Name PasswordComplexity -ErrorAction 0 | Should -BeLessOrEqual 30
        }
    }
}

Describe "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)" -Tag @('windows-185') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System Should exist" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LocalAccountTokenFilterPolicy"' {
            $Registry.Property | Should -Contain 'LocalAccountTokenFilterPolicy'
        }

        it 'LocalAccountTokenFilterPolicy Should be 0' {
            $Registry | Get-ItemPropertyValue -Name LocalAccountTokenFilterPolicy -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'" -Tag @('windows-186') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "Start"' {
            $Registry.Property | Should -Contain 'Start'
        }

        it 'Start Should be 4' {
            $Registry | Get-ItemPropertyValue -Name Start -ErrorAction 0 | Should -Be 4
        }
    }
}

Describe "Ensure 'Configure SMB v1 server' is set to 'Disabled'" -Tag @('windows-187') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "SMB1"' {
            $Registry.Property | Should -Contain 'SMB1'
        }

        it 'SMB1 Should be 0' {
            $Registry | Get-ItemPropertyValue -Name SMB1 -ErrorAction 0 | Should -Be 0
        }
    }
}

# TODO: finish this section
# END:  https://github.com/dev-sec/windows-baseline/blob/master/controls/administrative_templates_computer.rb

# Start https://github.com/dev-sec/windows-baseline/blob/master/controls/windows_firewall_with_advanced_security.rb

Describe "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'" -Tag @('windows-120') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "EnableFirewall"' {
            $Registry.Property | Should -Contain 'EnableFirewall'
        }

        it 'EnableFirewall Should be 1' {
            $Registry | Get-ItemPropertyValue -Name EnableFirewall -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)" -Tag @('windows-121') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DefaultInboundAction"' {
            $Registry.Property | Should -Contain 'DefaultInboundAction'
        }

        it 'DefaultInboundAction Should be 1' {
            $Registry | Get-ItemPropertyValue -Name DefaultInboundAction -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)" -Tag @('windows-122') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DefaultInboundAction"' {
            $Registry.Property | Should -Contain 'DefaultInboundAction'
        }

        it 'DefaultInboundAction Should be 1' {
            $Registry | Get-ItemPropertyValue -Name DefaultInboundAction -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'" -Tag @('windows-123') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DisableNotifications"' {
            $Registry.Property | Should -Contain 'DisableNotifications'
        }

        it 'DisableNotifications Should be 1' {
            $Registry | Get-ItemPropertyValue -Name DisableNotifications -ErrorAction 0 | Should -Be 1
        }
    }
}


Describe "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'" -Tag @('windows-124') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFilePath"' {
            $Registry.Property | Should -Contain 'LogFilePath'
        }

        it 'LogFilePath Should be %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log' {
            $Registry | Get-ItemPropertyValue -Name LogFilePath -ErrorAction 0 | Should -Be '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
        }
    }
}

Describe "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'" -Tag @('windows-125') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFileSize"' {
            $Registry.Property | Should -Contain 'LogFileSize'
        }

        it 'LogFileSize Should BeGreaterOrEqual 16384' {
            $Registry | Get-ItemPropertyValue -Name LogFileSize -ErrorAction 0 | Should -BeGreaterOrEqual 16384
        }
    }
}

Describe "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'" -Tag @('windows-126') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogDroppedPackets"' {
            $Registry.Property | Should -Contain 'LogDroppedPackets'
        }

        it 'LogDroppedPackets Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogDroppedPackets -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'" -Tag @('windows-127') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogSuccessfulConnections"' {
            $Registry.Property | Should -Contain 'LogSuccessfulConnections'
        }

        it 'LogSuccessfulConnections Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogSuccessfulConnections -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'" -Tag @('windows-128') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "EnableFirewall"' {
            $Registry.Property | Should -Contain 'EnableFirewall'
        }

        it 'EnableFirewall Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name EnableFirewall -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'" -Tag @('windows-129') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DefaultInboundAction"' {
            $Registry.Property | Should -Contain 'DefaultInboundAction'
        }

        it 'DefaultInboundAction Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name DefaultInboundAction -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'" -Tag @('windows-130') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DefaultOutboundAction"' {
            $Registry.Property | Should -Contain 'DefaultOutboundAction'
        }

        it 'DefaultOutboundAction Should Be 0' {
            $Registry | Get-ItemPropertyValue -Name DefaultOutboundAction -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'" -Tag @('windows-131') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DisableNotifications"' {
            $Registry.Property | Should -Contain 'DisableNotifications'
        }

        it 'DisableNotifications Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name DisableNotifications -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'" -Tag @('windows-132') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFilePath"' {
            $Registry.Property | Should -Contain 'LogFilePath'
        }

        it 'LogFilePath Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogFilePath -ErrorAction 0 | Should -Be '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'" -Tag @('windows-133') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFileSize"' {
            $Registry.Property | Should -Contain 'LogFileSize'
        }

        it 'LogFileSize Should BeGreaterOrEqual 16384' {
            $Registry | Get-ItemPropertyValue -Name LogFileSize -ErrorAction 0 | Should -BeGreaterOrEqual 16384
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'" -Tag @('windows-134') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogDroppedPackets"' {
            $Registry.Property | Should -Contain 'LogDroppedPackets'
        }

        it 'LogDroppedPackets Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogDroppedPackets -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'" -Tag @('windows-135') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogSuccessfulConnections"' {
            $Registry.Property | Should -Contain 'LogSuccessfulConnections'
        }

        it 'LogSuccessfulConnections Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogSuccessfulConnections -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'" -Tag @('windows-136') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "EnableFirewall"' {
            $Registry.Property | Should -Contain 'EnableFirewall'
        }

        it 'LogSuccessfulConnections Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name EnableFirewall -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'" -Tag @('windows-137') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DefaultInboundAction"' {
            $Registry.Property | Should -Contain 'DefaultInboundAction'
        }

        it 'DefaultInboundAction Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name DefaultInboundAction -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'" -Tag @('windows-138') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DefaultOutboundAction"' {
            $Registry.Property | Should -Contain 'DefaultOutboundAction'
        }

        it 'DefaultOutboundAction Should Be 0' {
            $Registry | Get-ItemPropertyValue -Name DefaultOutboundAction -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'" -Tag @('windows-139') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "DisableNotifications"' {
            $Registry.Property | Should -Contain 'DisableNotifications'
        }

        it 'DisableNotifications Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name DisableNotifications -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'" -Tag @('windows-140') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AllowLocalPolicyMerge"' {
            $Registry.Property | Should -Contain 'AllowLocalPolicyMerge'
        }

        it 'AllowLocalPolicyMerge Should Be 0' {
            $Registry | Get-ItemPropertyValue -Name AllowLocalPolicyMerge -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'" -Tag @('windows-141') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "AllowLocalIPsecPolicyMerge"' {
            $Registry.Property | Should -Contain 'AllowLocalIPsecPolicyMerge'
        }

        it 'AllowLocalIPsecPolicyMerge Should Be 0' {
            $Registry | Get-ItemPropertyValue -Name AllowLocalIPsecPolicyMerge -ErrorAction 0 | Should -Be 0
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'" -Tag @('windows-142') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFilePath"' {
            $Registry.Property | Should -Contain 'LogFilePath'
        }

        it 'LogFilePath Should Be %SYSTEMROOT%\system32\logfiles\firewall\publicfw.log' {
            $Registry | Get-ItemPropertyValue -Name LogFilePath -ErrorAction 0 | Should -Be '%SYSTEMROOT%\system32\logfiles\firewall\publicfw.log'
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'" -Tag @('windows-142') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFileSize"' {
            $Registry.Property | Should -Contain 'LogFileSize'
        }

        it 'LogFileSize Should BeGreaterOrEqual 16384' {
            $Registry | Get-ItemPropertyValue -Name LogFileSize -ErrorAction 0 | Should -BeGreaterOrEqual 16384
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'" -Tag @('windows-143') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogFileSize"' {
            $Registry.Property | Should -Contain 'LogFileSize'
        }

        it 'LogFileSize Should BeGreaterOrEqual 16384' {
            $Registry | Get-ItemPropertyValue -Name LogFileSize -ErrorAction 0 | Should -BeGreaterOrEqual 16384
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'" -Tag @('windows-144') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogDroppedPackets"' {
            $Registry.Property | Should -Contain 'LogDroppedPackets'
        }

        it 'LogDroppedPackets Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogDroppedPackets -ErrorAction 0 | Should -Be 1
        }
    }
}

Describe "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'" -Tag @('windows-145') {

    BeforeAll {
        $key = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        $Registry = Get-Item Registry::$($key) -ErrorAction 0
    }
    Context "Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" {
        
        it 'Should exist' {
            $Registry | Should -Not -Be $null
        }

        it 'Should Contain "LogSuccessfulConnections"' {
            $Registry.Property | Should -Contain 'LogSuccessfulConnections'
        }

        it 'LogSuccessfulConnections Should Be 1' {
            $Registry | Get-ItemPropertyValue -Name LogSuccessfulConnections -ErrorAction 0 | Should -Be 1
        }
    }
}

# https://github.com/dev-sec/windows-baseline/blob/master/controls/windows_firewall_with_advanced_security.rb