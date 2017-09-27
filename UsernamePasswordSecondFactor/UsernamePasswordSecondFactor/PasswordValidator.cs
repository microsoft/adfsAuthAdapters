// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.DirectoryServices.AccountManagement;

namespace UsernamePasswordSecondFactor
{
    public class PasswordValidator
    {
        static readonly PrincipalContext _ctx = new PrincipalContext(ContextType.Domain);

        public static bool Validate(string username, string password)
        {
            try
            {
                return _ctx.ValidateCredentials(username, password);
            }
            catch (Exception)
            {
                throw new UsernamePasswordValidationException("failed to validate password");
            }
        }
    }
}
