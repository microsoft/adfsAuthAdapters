// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityServer.Web.Authentication.External;

namespace UsernamePasswordSecondFactor
{
    class UsernamePasswordException : ExternalAuthenticationException
    {
        public UsernamePasswordException() : base()
        {  }

        public UsernamePasswordException(string message)
        {
        }
    }

    class UsernamePasswordValidationException : UsernamePasswordException
    {
        public UsernamePasswordValidationException() : base()
        {
        }

        public UsernamePasswordValidationException(string message) : base(message)
        {
        }

    }
}
