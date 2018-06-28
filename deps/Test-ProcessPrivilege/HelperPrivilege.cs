#region Copyright
//  Copyright 2018  OSIsoft, LLC
// 
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
#endregion
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class HelperPrivilege
{
    enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
		TokenIntegrityLevel,
		TokenUIAccess
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint Count;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, int Access, ref IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);

    static public List<string> EnumRights(int processId)
    {
        uint tokenInfoLength = 0;
        const int TOKEN_QUERY = 0x00000008;
        const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        const UInt32 SE_PRIVILEGE_USER_FOR_ACCESS = 0x80000000;
        List<string> privilegesList = new List<string>();
        Process targetProcess = Process.GetProcessById(processId);
        if (targetProcess == null)
        { privilegesList.Add("No process found."); }
        else
        {
            IntPtr htok = IntPtr.Zero;
            bool returnValue = OpenProcessToken(targetProcess.Handle, TOKEN_QUERY, ref htok);
            bool result = GetTokenInformation(htok, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, tokenInfoLength, out tokenInfoLength);
            IntPtr tokenInformation = Marshal.AllocHGlobal(unchecked((int)tokenInfoLength));
            result = GetTokenInformation(htok, TOKEN_INFORMATION_CLASS.TokenPrivileges, tokenInformation, tokenInfoLength, out tokenInfoLength);
            if (result)
            {
                TOKEN_PRIVILEGES privileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_PRIVILEGES));
                for (int i = 0; i < privileges.Count; i++)
                {
                    IntPtr ptr = new IntPtr(tokenInformation.ToInt64() + sizeof(uint) + i * Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)));
                    LUID_AND_ATTRIBUTES privilegeInfo = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(ptr, typeof(LUID_AND_ATTRIBUTES));
                    StringBuilder name = new StringBuilder();
                    string value = "";
                    IntPtr luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
                    Marshal.StructureToPtr(privilegeInfo.Luid, luidPtr, false);
                    int nameLength = 0;
                    LookupPrivilegeName(null, luidPtr, null, ref nameLength);
                    name.EnsureCapacity(nameLength);
                    LookupPrivilegeName(null, luidPtr, name, ref nameLength);
                    if (privilegeInfo.Attributes == 0)
                    { value = "=Disabled"; }
                    if ((privilegeInfo.Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED)
                    {
                        if ((privilegeInfo.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                        { value = "=Default,Enabled"; }
                        else
                        { value = "=Enabled"; }
                    }
                    if ((privilegeInfo.Attributes & SE_PRIVILEGE_REMOVED) == SE_PRIVILEGE_REMOVED)
                    { value = "=Removed"; }
                    if ((privilegeInfo.Attributes & SE_PRIVILEGE_USER_FOR_ACCESS) == SE_PRIVILEGE_USER_FOR_ACCESS)
                    { value = "=UsedforAccess"; }
                    Marshal.FreeHGlobal(luidPtr);
                    privilegesList.Add(name.ToString() + value);
                }
            }
            Marshal.FreeHGlobal(tokenInformation);
        }
        return privilegesList;
    }
}