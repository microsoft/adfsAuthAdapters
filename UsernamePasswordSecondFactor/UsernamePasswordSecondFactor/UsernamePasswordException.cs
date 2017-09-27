using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
