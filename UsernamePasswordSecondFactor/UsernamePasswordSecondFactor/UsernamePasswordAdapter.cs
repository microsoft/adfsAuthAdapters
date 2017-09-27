// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Net;
using Microsoft.IdentityServer.Web.Authentication.External;
using Claim = System.Security.Claims.Claim;

namespace UsernamePasswordSecondFactor
{
    public class UsernamePasswordAdapter : IAuthenticationAdapter
    {
        protected IAdapterPresentationForm CreateAdapterPresentation(string username)
        {
            return new UsernamePasswordPresentation(username);
        }

        protected IAdapterPresentationForm CreateAdapterPresentationOnError(string username, ExternalAuthenticationException ex)
        {
            return new UsernamePasswordPresentation(username, ex);
        }

        #region IAuthenticationAdapter Members

        public IAuthenticationAdapterMetadata Metadata => new UsernamePasswordMetadata();

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext authContext)
        {
            if (null == identityClaim) throw new ArgumentNullException(nameof(identityClaim));

            if (null == authContext) throw new ArgumentNullException(nameof(authContext));

            if (String.IsNullOrEmpty(identityClaim.Value))
            {
                throw new InvalidDataException(ResourceHandler.GetResource(Constants.ResourceNames.ErrorNoUserIdentity, authContext.Lcid));
            }

            return CreateAdapterPresentation(identityClaim.Value);
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            return true;
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            if (ex == null)
            {
                throw new ArgumentNullException(nameof(ex));
            }

            return CreateAdapterPresentationOnError(String.Empty,ex);
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
        }

        public void OnAuthenticationPipelineUnload()
        {
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
        {
            if (null == authContext)
            {
                throw new ArgumentNullException(nameof(authContext));
            }

            outgoingClaims = new Claim[0];

            if (proofData?.Properties == null || !proofData.Properties.ContainsKey(Constants.PropertyNames.Password))
            {
                throw new ExternalAuthenticationException(ResourceHandler.GetResource(Constants.ResourceNames.ErrorNoAnswerProvided, authContext.Lcid), authContext);
            }

            string username = (string)proofData.Properties[Constants.PropertyNames.Username];
            string password = (string)proofData.Properties[Constants.PropertyNames.Password];

            if (PasswordValidator.Validate(username, password))
            {
                outgoingClaims = new[]
                {
                    new Claim(Constants.AuthenticationMethodClaimType, Constants.UsernamePasswordMfa)
                };

                return null;
            }

            return CreateAdapterPresentationOnError(username, new UsernamePasswordValidationException());
        }

        #endregion
    }
}
