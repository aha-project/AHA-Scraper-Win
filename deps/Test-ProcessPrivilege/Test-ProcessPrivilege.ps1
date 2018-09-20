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

    (2) Blacklist Violation - Running with privileges Microsoft explicitly states
    never to grant to a user due to security risks.
        SeCreateTokenPrivilege
        SeCreatePermanentPrivilege
        SeTrustedCredManAccessPrivilege
        SeRelabelPrivilege
        SeSyncAgentPrivilege

    (3) Administrative User - Running with privileges Microsoft recommends reserving
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

    (6) Standard User - No privileges detected that present increased exposure.
        SeIncreaseWorkingSetPrivilege
        SeTimeZonePrivilege
        SeChangeNotifyPrivilege
        SeCreateGlobalPrivilege
        SeUndockPrivilege

.PARAMETER ProcessObjects
Pass in an arraylist of objects which, at minimum, contain noteproperties
for PID, UserName, and ProcessPath.

.OUTPUTS
Returns the original arraylist with an additional noteproperty added to
each object indicating whether or not the process has system level privilege
or the functional equivalent.

.EXAMPLE
$outputData = Test-ProcessPrivilege -ProcessObjects $outputData -EA SilentlyContinue

#>
function Test-ProcessPrivilege {

    [OutputType([System.Collections.ArrayList])]
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [System.Collections.ArrayList]
        $ProcessObjects
    )

    $systemUserName = GetSystemUserName

    [System.Collections.ArrayList]$returnData = New-Object System.Collections.ArrayList($null)

    if (!(IsRunningElevated)) {
        Write-Host "Info: Test-ProcessPrivileges requires running with elevation, skipping privilege check."
        foreach ($ProcessObject in $ProcessObjects) {
            $ProcessObject = UpdateProcessObject -ProcessObject $ProcessObject -PrivilegeLevel "Skipped" -Privileges "Skipped"
            $returnData.Add($ProcessObject) | Out-Null
        }
        return $returnData
    }

    $ProcessIDs = $ProcessObjects | Select-Object PID, UserName, ProcessPath -unique

    $PrivilegeHelper = LoadPrivilegeHelperDynamicType

    foreach ($ProcessID in $ProcessIDs) {
        # Identify trivial cases where system privileges are in place.
        if (IsSystemProcess $ProcessID $systemUserName) {
            $Privileges = "SYSTEM"
            $PrivilegeLevel = "SYSTEM"
        }
        else {
            # Retrieve privileges for the process and check
            try {
                $privilegesList = EnumerateEnabledRights $PrivilegeHelper $ProcessID
                $PrivilegeLevel = GetPrivilegeLevelProperty $privilegesList
                $Privileges = GetPrivilegesProperty $privilegesList
            }
            catch {
                $Privileges = "ScanError"
                $PrivilegeLevel = "ScanError"
                Write-Host ("Error: " + $Error[0].Exception.Message)
            }
        }

        foreach ($ProcessObject in $ProcessObjects) {
            if ($ProcessObject.PID.equals($ProcessID.PID)) {
                $ProcessObject = UpdateProcessObject -ProcessObject $ProcessObject -PrivilegeLevel $PrivilegeLevel -Privileges $Privileges
                $returnData.Add($ProcessObject) | Out-Null
            }
        }
    }

    return $returnData
}

function UpdateProcessObject
{
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [System.Object]
        $ProcessObject,
        [parameter(Mandatory = $true, Position = 1, ParameterSetName = "Default")]
        [System.String]
        $PrivilegeLevel,
        [parameter(Mandatory = $true, Position = 2, ParameterSetName = "Default")]
        [System.String]
        $Privileges
    )

    $ProcessObject | Add-Member -MemberType NoteProperty -Name PrivilegeLevel -Value $PrivilegeLevel
    $ProcessObject | Add-Member -MemberType NoteProperty -Name Privileges -Value $Privileges

    return $ProcessObject
}

function LoadPrivilegeHelperDynamicType {
    $TypeDefinitionFile = 'deps\Test-ProcessPrivilege\HelperPrivilege.cs'
    $TypeDefinitionFilePath = Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) -ChildPath $TypeDefinitionFile
    $dynamicType = Add-Type -Path $TypeDefinitionFilePath -PassThru

    return $dynamicType[0]
}
function EnumerateEnabledRights {
    param(
        [parameter(Mandatory = $false, Position = 0, ParameterSetName = "Default")]
        [System.Object]
        $DynamicType,
        [parameter(Mandatory = $true, Position = 1, ParameterSetName = "Default")]
        [System.Object]
        $ProcessID
    )

    $privilegesList = $DynamicType::EnumRights($ProcessID.PID)
    $privilegesList = $privilegesList | Where-Object { $null -ne $_ } | Where-Object { $_.ToUpper().Contains("ENABLED") }

    return $privilegesList
}

function GetSystemUserName {
    $systemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $systemUser = $systemSID.Translate([System.Security.Principal.NTAccount])

    return $systemUser.Value
}

function IsRunningElevated {
    $windowsPrinciple = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $IsRunningElevated = $windowsPrinciple.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    return $IsRunningElevated
}

function IsSystemProcess {
    [OutputType([System.Boolean])]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [System.Object]
        $ProcessID,
        [parameter(Mandatory = $false, Position = 1, ParameterSetName = "Default")]
        [System.String]
        $SystemUsername = "SYSTEM"
    )
    # System process and Idle process
    $IsSystemProcess = $ProcessID.PID -eq 0 -or $ProcessID.PID -eq 4
    # Processes explicitly marked as running as system
    $IsRunningExplicitlyAsSystem = $ProcessID.UserName.ToUpper() -eq $SystemUsername.ToUpper()
    # CurrPorts cannot get the user info for core system processes
    $NoUserInfo = [system.string]::IsNullOrEmpty($ProcessID.UserName)

    return ($IsSystemProcess -or $IsRunningExplicitlyAsSystem -or $NoUserInfo)
}

function GetPrivilegesProperty
{
    [OutputType([System.String])]
    param(
        [parameter(Position = 0, ParameterSetName = "Default")]
        [System.String[]]
        $PrivilegesList
    )

    if($null -eq $PrivilegesList -or $PrivilegesList.Length -eq 0) { return "None" }

    $PrivilegeNames = @()
    foreach ($privilege in $privilegesList)
    { $PrivilegeNames += $privilege.Split("=")[0] }

    return $PrivilegeNames -join "|"
}

function GetPrivilegeLevelProperty {
    [OutputType([System.String])]
    param(
        [parameter(Position = 0, ParameterSetName = "Default")]
        [System.String[]]
        $PrivilegesList
    )

    if($null -eq $PrivilegesList -or $PrivilegesList.Length -eq 0) { return "Standard User" }

    $levelDefinitions = @(
        @{
            Level      = "SYSTEM (Equivalent)"
            Privileges = @(
                # You can escalate to system with any of these
                "SeDebugPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeTcbPrivilege",
                "SeCreateTokenPrivilege",
                "SeLoadDriverPrivilege"
            )
        },
        @{
            Level      = "Blacklist Violation"
            Privileges = @(
                # MS recommends never giving these to anyone
                "SeCreatePermanentPrivilege",
                "SeTrustedCredManAccessPrivilege",
                "SeRelabelPrivilege",
                "SeSyncAgentPrivilege"
            )
        },
        @{
            Level      = "Administrative User"
            Privileges = @(
                # Privileges reserved for Admins
                "SeCreatePagefilePrivilege",
                "SeIncreaseBasePriorityPrivilege",
                "SeSystemEnvironmentPrivilege",
                "SeManageVolumePrivilege",
                "SeSystemProfilePrivilege",
                "SeSecurityPrivilege",
                # Privileges typically reserved for the IT Team
                "SeMachineAccountPrivilege",
                "SeEnableDelegationPrivilege"
            )
        }
        @{
            Level      = "Service"
            Privileges = @(
                # Privileges reserved for services
                "SeAuditPrivilege",
                "SeImpersonatePrivilege",
                "SeBackupPrivilege"
            )
        }
        @{
            Level      = "Operator"
            Privileges = @(
                # Privileges reserved for operators
                "SeRemoteShutdownPrivilege",
                "SeSystemtimePrivilege",
                "SeShutdownPrivilege",
                "SeInteractiveLogonRight",
                # Privileges reserved for trusted users
                "SeCreateSymbolicLinkPrivilege",
                "SeRestorePrivilege",
                # Privileges typical for a user
                "SeNetworkLogonRight",
                "SeRemoteInteractiveLogonRight",
                "SeProfileSingleProcessPrivilege",
                "SeIncreaseQuotaPrivilege"
            )
        }
    )

    # Test each level definition.
    foreach ($levelDefinition in $levelDefinitions) {
        # Check all privileges for the process.
        foreach ($privilege in $PrivilegesList) {
            $privilege = $privilege.ToUpper()
            # Check against all privileges for the current level.
            foreach ($targetPrivilege in $levelDefinition.Privileges) {
                # Return once the first match is found.
                if ($privilege.Contains($targetPrivilege.ToUpper())) {
                    return $levelDefinition.Level
                }
            }
        }
    }

    return "Standard User"
}
