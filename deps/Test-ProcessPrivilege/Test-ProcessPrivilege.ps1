# ************************************************************************
# *
# * Copyright 2018 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# ************************************************************************

<#
.SYNOPSIS
Tests if a process has a high level of privilege.

.DESCRIPTION
A process is assigned a privilege level based on the detected privileges.
Microsoft recommendations were obtained from the User Rights Assignment
article in the Microsoft docs.
https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment

The levels are defined below.

    (1) SYSTEM - Running as the SYSTEM user or with privileges that
    Microsoft recommends reserving for SYSTEM. A user with any of the
    privileges below can take over a machine.
        SeDebugPrivilege
	    SeTakeOwnershipPrivilege
	    SeTcbPrivilege
        SeLoadDriverPrivilege

    (2) Violation - Running with privileges Microsoft explicitly states
    never to grant to a user due to security risks.
        SeCreateTokenPrivilege
        SeCreatePermanentPrivilege
        SeTrustedCredManAccessPrivilege
        SeRelabelPrivilege
        SeSyncAgentPrivilege

    (3) Administrative - Running with privileges Microsoft recommends reserving
    for administrative users or the IT Team, exclusively.
        SeCreatePageFilePrivilege
        SeIncreaseBasePriorityPrivilege
        SeSystemEnvironmentPrivilege
        SeManageVolumePrivilege
        SeSystemProfilePrivilege
        SeMachineAccountPrivilege
        SeEnableDelegationPrivilege
        SeSecurityPrivilege

    (4) Service - Running with privileges not granted by default that are
    associated with services.
        SeAuditPrivilege
        SeImpersonatePrivilege
        SeBackupPrivilege

    (5) Operator - Privileges not granted by default that are associated with
    individual interractive users.
        SeNetworkLogonRight
        SeRemoteInteractiveLogonRight
        SeProfileSingleProcessPrivilege
        SeIncreaseQuotaPrivilege
        SeRemoteShutdownPrivilege
        SeSystemtimePrivilege
        SeShutdownPrivilege
        SeInteractiveLogonRight
        SeCreateSymbolicLinkPrivilege
        SeRestorePrivilege

    (6) Standard - No privileges detected that present increased exposure.
        SeIncreaseWorkingSetPrivilege
        SeTimeZonePrivilege
        SeChangeNotifyPrivilege
        SeCreateGlobalPrivilege
        SeUndockPrivilege

.PARAMETER ProcessId
Pass in the PID for the process.

.OUTPUTS
Returns an object with two noteproperties indicating the privileges of a 
process and the privilege level.

.EXAMPLE
$outputData = Test-ProcessPrivilege -ProcessId $pid -EA SilentlyContinue

#>
function Test-ProcessPrivilege {
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [Alias("pid")]
        [System.Int32]
        $ProcessId
    )

    if (!(IsRunningElevated)) { return FormatResponse "Skipped" "Skipped" }
    if (IsSystemProcess $ProcessID) { return FormatResponse "SYSTEM" "SYSTEM" }

    try {
        $privilegesList = EnumerateEnabledRights $ProcessID
        $privilegeLevel = GetPrivilegeLevelFromList $privilegesList
        return FormatResponse $privilegeLevel $privilegesList
    }
    catch {
        Write-Host ("Error: " + $Error[0].Exception.Message)
        return FormatResponse "ScanError" "ScanError"
    }
}

function FormatResponse 
{
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [System.String]
        $PrivilegeLevel,
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "Default")]
        [System.String[]]
        $Privileges
    )
    $privilegeInfo = New-Object PSCustomObject -Property @{
        PrivilegeLevel = $PrivilegeLevel
        Privileges = (FormatPrivileges $Privileges)
    }
    return $privilegeInfo
}

function EnumerateEnabledRights {
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [System.Int32]
        $ProcessID
    )
    $typeDefinitionFile = 'HelperPrivilege.cs'
    $typeDefinitionFilePath = Join-Path (GetScriptPath) -ChildPath $typeDefinitionFile
    $privilegeHelper = (Add-Type -Path $typeDefinitionFilePath -PassThru)[0]
    $privilegesList = $privilegeHelper::EnumRights($ProcessID)
    $privilegesList = $privilegesList | Where-Object { $null -ne $_ } | Where-Object { $_.ToUpper().Contains("ENABLED") }

    return $privilegesList
}

function GetScriptPath {
    # PSScriptRoot should provide the most reliable root for PS3+
    $scriptFolder = (Get-Variable 'PSScriptRoot' -ErrorAction 'SilentlyContinue').Value
    if (!$scriptFolder) {
        if ($MyInvocation.MyCommand.Path) { $scriptFolder = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
    }
    # Fall back to default value for dependency folder if we can not resolve root or invocation path, e.g. with PS2
    if (!$scriptFolder) {
        $scriptFolder = Join-Path $PWD -ChildPath "deps\Test-ProcessPrivilege"  
    }

    return $scriptFolder
}

function IsRunningElevated {
    $windowsPrinciple = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $IsRunningElevated = $windowsPrinciple.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    return $IsRunningElevated
}

function IsSystemProcess {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [System.Int32]
        $ProcessID
    )

    # Is System or System Idle Process?
    if($ProcessID -eq 0 -or $ProcessID -eq 4) { return $true }
    # Is running explicitly as system user?
    $systemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $systemUserName = $systemSID.Translate([System.Security.Principal.NTAccount]).Value
    $processUser = (Get-WmiObject Win32_Process -Filter ("ProcessId='{0}'" -f $ProcessID)).GetOwner() `
        | Select-Object Domain, User
    $processUserName = "{0}\{1}" -f $processUser.Domain, $processUser.User

    return [System.String]::Equals($systemUserName, $processUserName, [System.StringComparison]::OrdinalIgnoreCase)
}

function FormatPrivileges {
    [OutputType([System.String])]
    param(
        [Parameter(Position = 0, ParameterSetName = "Default")]
        [System.String[]]
        $PrivilegesList
    )

    if ($null -eq $PrivilegesList -or $PrivilegesList.Length -eq 0) { return "None" }

    return ($PrivilegesList | ForEach-Object { $_.Split("=")[0] }) -join "|"
}

function GetPrivilegeLevelFromList {
    [OutputType([System.String])]
    param(
        [Parameter(Position = 0, ParameterSetName = "Default")]
        [System.String[]]
        $PrivilegesList
    )

    if ($null -eq $PrivilegesList -or $PrivilegesList.Length -eq 0) { return "Standard User" }
  
    $privilegeLevels = @(
        @{  # You can escalate to system with any of these
            Level      = "SYSTEM"
            Privileges = @(
                "SeDebugPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeTcbPrivilege",
                "SeCreateTokenPrivilege",
                "SeLoadDriverPrivilege"
            )
        },
        @{  # MS recommends never granting to any identity
            Level      = "Violation"
            Privileges = @(
                "SeCreatePermanentPrivilege",
                "SeTrustedCredManAccessPrivilege",
                "SeRelabelPrivilege",
                "SeSyncAgentPrivilege"
            )
        },
        @{  # Privileges reserved for administrators or IT Team
            Level      = "Administrative"
            Privileges = @(
                "SeCreatePagefilePrivilege",
                "SeIncreaseBasePriorityPrivilege",
                "SeSystemEnvironmentPrivilege",
                "SeManageVolumePrivilege",
                "SeSystemProfilePrivilege",
                "SeSecurityPrivilege",
                "SeMachineAccountPrivilege",
                "SeEnableDelegationPrivilege"
            )
        }
        @{  # Privileges reserved for services
            Level      = "Service"
            Privileges = @(  
                "SeAuditPrivilege",
                "SeImpersonatePrivilege",
                "SeBackupPrivilege"
            )
        }
        @{  # Privileges reserved for operators, trusted users, or interactive users
            Level      = "Operator"
            Privileges = @(
                "SeRemoteShutdownPrivilege",
                "SeSystemtimePrivilege",
                "SeShutdownPrivilege",
                "SeInteractiveLogonRight",
                "SeCreateSymbolicLinkPrivilege",
                "SeRestorePrivilege",
                "SeNetworkLogonRight",
                "SeRemoteInteractiveLogonRight",
                "SeProfileSingleProcessPrivilege",
                "SeIncreaseQuotaPrivilege"
            )
        }
    )

    foreach ($privilegeLevel in $privilegeLevels) {
        foreach ($processPrivilege in $PrivilegesList) {
            foreach ($targetPrivilege in $privilegeLevel.Privileges) {
                if ($processPrivilege.IndexOf($targetPrivilege, [System.StringComparison]::OrdinalIgnoreCase) -gt -1) { return $privilegeLevel.Level }
            }
        }
    }

    return "Standard"
}