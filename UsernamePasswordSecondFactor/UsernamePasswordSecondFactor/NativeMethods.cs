// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Runtime.CompilerServices;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace UsernamePasswordSecondFactor
{
    internal sealed class SafeLsaReturnBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeLsaReturnBufferHandle() : base(true) { }

        // 0 is an Invalid Handle
        internal SafeLsaReturnBufferHandle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        internal static SafeLsaReturnBufferHandle InvalidHandle
        {
            get { return new SafeLsaReturnBufferHandle(IntPtr.Zero); }
        }

        override protected bool ReleaseHandle()
        {
            // LsaFreeReturnBuffer returns an NTSTATUS
            return NativeMethods.LsaFreeReturnBuffer(handle) >= 0;
        }
    }

    internal sealed class SafeCloseHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        const string KERNEL32 = "kernel32.dll";

        private SafeCloseHandle()
            : base(true)
        {
        }

        internal SafeCloseHandle(IntPtr handle, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }

        [DllImport(KERNEL32, ExactSpelling = true, SetLastError = true)]
        [SuppressUnmanagedCodeSecurity]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private extern static bool CloseHandle(IntPtr handle);
    }

    internal sealed class SafeLsaLogonProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeLsaLogonProcessHandle() : base(true) { }

        // 0 is an Invalid Handle
        internal SafeLsaLogonProcessHandle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        internal static SafeLsaLogonProcessHandle InvalidHandle
        {
            get { return new SafeLsaLogonProcessHandle(IntPtr.Zero); }
        }

        override protected bool ReleaseHandle()
        {
            // LsaDeregisterLogonProcess returns an NTSTATUS
            return NativeMethods.LsaDeregisterLogonProcess(handle) >= 0;
        }
    }

    internal sealed class SafeHGlobalHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        SafeHGlobalHandle() : base(true) { }

        // 0 is an Invalid Handle
        SafeHGlobalHandle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }

        public static SafeHGlobalHandle InvalidHandle
        {
            get { return new SafeHGlobalHandle(IntPtr.Zero); }
        }

        public static SafeHGlobalHandle AllocHGlobal(string s)
        {
            byte[] bytes = new byte[checked((s.Length + 1) * 2)];
            Encoding.Unicode.GetBytes(s, 0, s.Length, bytes, 0);
            return AllocHGlobal(bytes);
        }

        public static SafeHGlobalHandle AllocHGlobal(byte[] bytes)
        {
            SafeHGlobalHandle result = AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, result.DangerousGetHandle(), bytes.Length);
            return result;
        }

        public static SafeHGlobalHandle AllocHGlobal(uint cb)
        {
            // The cast could overflow to minus.
            // Unfortunately, Marshal.AllocHGlobal only takes int.
            return AllocHGlobal((int)cb);
        }

        public static SafeHGlobalHandle AllocHGlobal(int cb)
        {
            if (cb < 0)
            {
                throw new ArgumentOutOfRangeException("cb");
            }

            SafeHGlobalHandle result = new SafeHGlobalHandle();

            // CER 
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                IntPtr ptr = Marshal.AllocHGlobal(cb);
                result.SetHandle(ptr);
            }
            return result;
        }
    }

    enum EXTENDED_NAME_FORMAT
    {
        NameUnknown = 0,
        NameFullyQualifiedDN = 1,
        NameSamCompatible = 2,
        NameDisplay = 3,
        NameUniqueId = 6,
        NameCanonical = 7,
        NameUserPrincipalName = 8,
        NameCanonicalEx = 9,
        NameServicePrincipalName = 10,
        NameDnsDomainName = 12
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SID_AND_ATTRIBUTES
    {
        internal IntPtr Sid;
        internal uint Attributes;
        internal static readonly long SizeOf = (long)Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        internal uint LowPart;
        internal uint HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES
    {
        internal LUID Luid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGE
    {
        internal uint PrivilegeCount;
        internal LUID_AND_ATTRIBUTES Privilege;

        internal static readonly uint Size = (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGE));
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct UNICODE_INTPTR_STRING
    {
        internal UNICODE_INTPTR_STRING(int length, int maximumLength, IntPtr buffer)
        {
            this.Length = (ushort)length;
            this.MaxLength = (ushort)maximumLength;
            this.Buffer = buffer;
        }
        internal ushort Length;
        internal ushort MaxLength;
        internal IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct INTERACTIVE_LOGON
    {
        internal int MessageType;
        internal UNICODE_INTPTR_STRING LogonDomainName;
        internal UNICODE_INTPTR_STRING UserName;
        internal UNICODE_INTPTR_STRING Password;
    }


    internal enum KERB_LOGON_SUBMIT_TYPE
    {
        KerbInteractiveLogon = 2,
        KerbSmartCardLogon = 6,
        KerbWorkstationUnlockLogon = 7,
        KerbSmartCardUnlockLogon = 8,
        KerbProxyLogon = 9,
        KerbTicketLogon = 10,
        KerbTicketUnlockLogon = 11,
        KerbS4ULogon = 12,
        KerbCertificateLogon = 13,
        KerbCertificateS4ULogon = 14,
        KerbCertificateUnlockLogon = 15,
    }

    internal enum MSV1_0_LOGON_SUBMIT_TYPE
    {
        MsV1_0InteractiveLogon = 2,
        MsV1_0Lm20Logon,
        MsV1_0NetworkLogon,
        MsV1_0SubAuthLogon
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct TOKEN_SOURCE
    {
        private const int TOKEN_SOURCE_LENGTH = 8;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = TOKEN_SOURCE_LENGTH)]
        internal char[] Name;
        internal LUID SourceIdentifier;
    }



    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct QUOTA_LIMITS
    {
        internal IntPtr PagedPoolLimit;
        internal IntPtr NonPagedPoolLimit;
        internal IntPtr MinimumWorkingSetSize;
        internal IntPtr MaximumWorkingSetSize;
        internal IntPtr PagefileLimit;
        internal IntPtr TimeLimit;
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        Anonymous = 0,
        Identification = 1,
        Impersonation = 2,
        Delegation = 3,
    }

    internal enum TokenType : int
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    internal enum SecurityLogonType : int
    {
        Interactive = 2,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock
    }

    [SuppressUnmanagedCodeSecurity]
    static class NativeMethods
    {
        const string ADVAPI32 = "advapi32.dll";
        const string KERNEL32 = "kernel32.dll";
        const string SECUR32 = "secur32.dll";

        // From WinStatus.h
        internal const uint STATUS_ACCOUNT_RESTRICTION = 0xC000006E;
        internal const uint STATUS_NO_LOGON_SERVERS = 0xC000005E;

        static byte[] GetLsaName(string name)
        {
            return Encoding.ASCII.GetBytes(name);
        }

        internal static byte[] LsaSourceName = GetLsaName("ADFSUPAdapter");
        internal static byte[] LsaNegotiateName = GetLsaName("Negotiate");

        //For both Kerberos and MSV1_0, the values for MessageType (KerbInteractiveLogon, MsV1_0InteractiveLogon, KerbInteractiveProfile, MsV1_0InteractiveProfile)   
        internal static int INTERACTIVE_LOGON_MESSAGETYPE = 2;

        internal const uint KERB_CERTIFICATE_S4U_LOGON_FLAG_CHECK_LOGONHOURS = 0x2;

        // Error codes from WinError.h
        internal const int ERROR_ACCESS_DENIED = 0x5;
        internal const int ERROR_BAD_LENGTH = 0x18;
        internal const int ERROR_INSUFFICIENT_BUFFER = 0x7A;

        internal const uint SE_GROUP_ENABLED = 0x00000004;
        internal const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        internal const uint SE_GROUP_LOGON_ID = 0xC0000000;


        [DllImport(SECUR32, CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int LsaConnectUntrusted(
            [Out] out SafeLsaLogonProcessHandle lsaHandle
            );

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern int LsaNtStatusToWinError(
            [In] int status
            );

        [DllImport(SECUR32, CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int LsaLookupAuthenticationPackage(
            [In] SafeLsaLogonProcessHandle lsaHandle,
            [In] ref UNICODE_INTPTR_STRING packageName,
            [Out] out uint authenticationPackage
            );

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AllocateLocallyUniqueId(
            [Out] out LUID Luid
            );

        [DllImport(SECUR32, SetLastError = false)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        internal static extern int LsaFreeReturnBuffer(
            IntPtr handle
            );

        [DllImport(SECUR32, CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern int LsaLogonUser(
            [In] SafeLsaLogonProcessHandle LsaHandle,
            [In] ref UNICODE_INTPTR_STRING OriginName,
            [In] SecurityLogonType LogonType,
            [In] uint AuthenticationPackage,
            [In] IntPtr AuthenticationInformation,
            [In] uint AuthenticationInformationLength,
            [In] IntPtr LocalGroups,
            [In] ref TOKEN_SOURCE SourceContext,
            [Out] out SafeLsaReturnBufferHandle ProfileBuffer,
            [Out] out uint ProfileBufferLength,
            [Out] out LUID LogonId,
            [Out] out SafeCloseHandle Token,
            [Out] out QUOTA_LIMITS Quotas,
            [Out] out int SubStatus
            );

        [DllImport(SECUR32, CharSet = CharSet.Auto, SetLastError = false)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        internal static extern int LsaDeregisterLogonProcess(
            [In] IntPtr handle
            );

        internal static SafeLsaLogonProcessHandle RegisterProcess(UNICODE_INTPTR_STRING sourceName)
        {
            int status;

            RuntimeHelpers.PrepareConstrainedRegions();

            SafeLsaLogonProcessHandle logonHandle = null;
            status = NativeMethods.LsaConnectUntrusted(out logonHandle);

            // non-negative numbers indicate success
            if (status < 0)
            {
                //throw DiagnosticUtil.ExceptionUtil.ThrowHelperError( new Win32Exception( NativeMethods.LsaNtStatusToWinError( status ) ) );
                throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(status));
            }

            return logonHandle;
        }

        //callers should delete the allocated memory by closing SafeHGlobalHandle pHandle
        internal static UNICODE_INTPTR_STRING ConvertByteStringToUnicodeIntPtrString(byte[] byteString, out SafeHGlobalHandle pHandle)
        {
            pHandle = SafeHGlobalHandle.AllocHGlobal(byteString.Length + 1);
            Marshal.Copy(byteString, 0, pHandle.DangerousGetHandle(), byteString.Length);
            return new UNICODE_INTPTR_STRING(byteString.Length, byteString.Length + 1, pHandle.DangerousGetHandle());
        }
    }
}

