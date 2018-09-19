// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace UsernamePasswordSecondFactor
{
    class UsernamePasswordException : ExternalAuthenticationException
    {
        protected UsernamePasswordException()
        {  }

        public UsernamePasswordException(string message, IAuthenticationContext context) : base(message, context)
        {
        }

        public UsernamePasswordException(string message, Exception ex, IAuthenticationContext context) : base(message, ex, context)
        {
        }
    }

    class UsernamePasswordValidationException : UsernamePasswordException
    {
        private UsernamePasswordValidationException()
        { }

        public UsernamePasswordValidationException(string message, IAuthenticationContext context) : base(message, context)
        {
        }
        public UsernamePasswordValidationException(string message, Exception ex, IAuthenticationContext context) : base(message, ex, context)
        {
        }

    }
}
