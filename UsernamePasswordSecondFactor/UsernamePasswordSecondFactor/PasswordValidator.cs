// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace UsernamePasswordSecondFactor
{
    public class PasswordValidator
    {
        public static bool Validate(string username, string password)
        {
            string domain = null;
            LsaLogonUserHelper.ExtractUsernamePassword(username, out domain, out username);
            return LsaLogonUserHelper.ValidateCredentials(domain, username, password);
        }
    }
}
