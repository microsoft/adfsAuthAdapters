// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace UsernamePasswordSecondFactor
{
    public class LsaLogonUserHelper
    {
        internal static bool ValidateCredentials(string domain, string username, string password)
        {
            SafeHGlobalHandle pLogonInfo = null;
            try
            {
                int logonInfoSize;
                FillUserNamePasswordLogonInfoBuffer(domain, username, password, out logonInfoSize, out pLogonInfo);
                return GetLsaLogonUserHandle(username, pLogonInfo, logonInfoSize);
            }
            finally
            {
                pLogonInfo?.Close();
            }

        }

        private static bool GetLsaLogonUserHandle(string username, SafeHGlobalHandle pLogonInfo, int logonInfoSize)
        {
            if (null == pLogonInfo)
            {
                throw new ArgumentNullException("pLogonInfo");
            }
            int status;
            SafeHGlobalHandle pSourceName = null;
            SafeHGlobalHandle pPackageName = null;
            SafeLsaLogonProcessHandle logonHandle = null;
            SafeLsaReturnBufferHandle profileHandle = null;
            SafeCloseHandle tokenHandle = null;

            try
            {
                UNICODE_INTPTR_STRING sourceName = NativeMethods.ConvertByteStringToUnicodeIntPtrString(NativeMethods.LsaSourceName, out pSourceName);
                logonHandle = NativeMethods.RegisterProcess(sourceName);

                RuntimeHelpers.PrepareConstrainedRegions();
                //get packageId
                UNICODE_INTPTR_STRING packageName = NativeMethods.ConvertByteStringToUnicodeIntPtrString(NativeMethods.LsaNegotiateName, out pPackageName);
                uint packageId = 0;
                status = NativeMethods.LsaLookupAuthenticationPackage(logonHandle, ref packageName, out packageId);
                if (status < 0) // non-negative numbers indicate success
                {
                    Trace.TraceError(string.Format("LsaLookupAuthenticationPackage failed for user {0} with status  {1}", username, status));
                    throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(status));
                }

                //get Source context
                TOKEN_SOURCE sourceContext = new TOKEN_SOURCE();
                if (!NativeMethods.AllocateLocallyUniqueId(out sourceContext.SourceIdentifier))
                {
                    int dwErrorCode = Marshal.GetLastWin32Error();
                    Trace.TraceError(string.Format("AllocateLocallyUniqueId failed for user {0} with status  {1}", username, dwErrorCode));
                    throw new Win32Exception(dwErrorCode);
                }
                sourceContext.Name = new char[8];
                sourceContext.Name[0] = 'A'; sourceContext.Name[1] = 'D'; sourceContext.Name[2] = 'F'; sourceContext.Name[2] = 'S';

                //other parameters
                QUOTA_LIMITS quotas = new QUOTA_LIMITS();
                LUID logonId = new LUID();
                uint profileBufferLength;
                int subStatus = 0;

                // Call LsaLogonUser
                status = NativeMethods.LsaLogonUser(
                    logonHandle,
                    ref sourceName,
                    SecurityLogonType.Network,
                    packageId,
                    pLogonInfo.DangerousGetHandle(),
                    (uint)logonInfoSize,
                    IntPtr.Zero,
                    ref sourceContext,
                    out profileHandle,
                    out profileBufferLength,
                    out logonId,
                    out tokenHandle,
                    out quotas,
                    out subStatus
                    );


                // LsaLogon has restriction (eg. password expired).  SubStatus indicates the reason.
                if ((uint)status == NativeMethods.STATUS_ACCOUNT_RESTRICTION && subStatus < 0)
                {
                    status = subStatus;
                    Trace.TraceError(string.Format("Authentication failed for user {0} with account restriction error {1}", username, status));
                    return false;
                }
                if (status < 0) // non-negative numbers indicate success
                {
                    Trace.TraceError(string.Format("Authentication failed for user {0} with status {1}", username, status));
                    return false;
                }
                if (subStatus < 0) // non-negative numbers indicate success
                {
                    Trace.TraceError(string.Format("Authentication failed for user {0} with subStatus {1}", username, subStatus));
                    return false;
                }

                return true;
            }
            finally
            {
                pSourceName?.Close();
                pPackageName?.Close();
                tokenHandle?.Close();
                profileHandle?.Close();
            }
        }

        private static void FillUserNamePasswordLogonInfoBuffer(string domain, string username, string password, out int logonInfoSize, out SafeHGlobalHandle pLogonInfo)
        {
            //LogonInfo
            logonInfoSize = 0;
            int domainLength = 0; int usernameLength = 0; int passwordLength = 0;
            byte[] domainBytes = null; byte[] userNameBytes = null; byte[] passwordBytes = null;
            IntPtr LogonDomainNamePtr = IntPtr.Zero;
            IntPtr UsernamePtr = IntPtr.Zero;
            IntPtr PasswordPtr = IntPtr.Zero;

            if (!String.IsNullOrEmpty(domain))
            {
                domainBytes = System.Text.Encoding.Unicode.GetBytes(domain);
                domainLength = domainBytes.Length;
            }
            if (!String.IsNullOrEmpty(username))
            {
                userNameBytes = System.Text.Encoding.Unicode.GetBytes(username);
                usernameLength = userNameBytes.Length;
            }
            if (!String.IsNullOrEmpty(password))
            {
                passwordBytes = System.Text.Encoding.Unicode.GetBytes(password);
                passwordLength = passwordBytes.Length;
            }

            logonInfoSize = checked(Marshal.SizeOf(typeof(INTERACTIVE_LOGON)) + usernameLength + passwordLength + domainLength);
            pLogonInfo = SafeHGlobalHandle.AllocHGlobal(logonInfoSize);
            unsafe
            {
                LogonDomainNamePtr = new IntPtr(pLogonInfo.DangerousGetHandle().ToInt64() + Marshal.SizeOf(typeof(INTERACTIVE_LOGON)));
                if (domainBytes != null)
                {
                    Marshal.Copy(domainBytes, 0, LogonDomainNamePtr, domainLength);
                }

                UsernamePtr = new IntPtr(pLogonInfo.DangerousGetHandle().ToInt64() + Marshal.SizeOf(typeof(INTERACTIVE_LOGON)) + domainLength);
                if (userNameBytes != null)
                {
                    Marshal.Copy(userNameBytes, 0, UsernamePtr, usernameLength);
                }

                PasswordPtr = new IntPtr(pLogonInfo.DangerousGetHandle().ToInt64() + Marshal.SizeOf(typeof(INTERACTIVE_LOGON)) + domainLength + usernameLength);
                if (passwordBytes != null)
                {
                    Marshal.Copy(passwordBytes, 0, PasswordPtr, passwordLength);
                }

                INTERACTIVE_LOGON* pInfo = (INTERACTIVE_LOGON*)pLogonInfo.DangerousGetHandle().ToPointer();
                pInfo->MessageType = (int)KERB_LOGON_SUBMIT_TYPE.KerbInteractiveLogon;
                pInfo->LogonDomainName = new UNICODE_INTPTR_STRING(domainLength, domainLength + 1, LogonDomainNamePtr);
                pInfo->UserName = new UNICODE_INTPTR_STRING(usernameLength, usernameLength + 1, UsernamePtr);
                pInfo->Password = new UNICODE_INTPTR_STRING(passwordLength, passwordLength + 1, PasswordPtr);
            }
        }

        internal static void ExtractUsernamePassword(string identity, out string domain, out string username)
        {
            username = identity;
            domain = null;
            string[] strings = identity.Split('\\');

            // The UPN case is handled with domain = null and username = UPN.
            if (strings.Length != 1)
            {
                if (strings.Length != 2 || String.IsNullOrEmpty(strings[0]))
                {
                    // Only support one slash and domain cannot be empty (consistent with windowslogon).
                    throw new ArgumentOutOfRangeException("Username contains more than one slash or domain is empty.");
                }

                // This is the downlevel case - domain\userName
                username = strings[1];
                domain = strings[0];
            }
        }
    }
}

