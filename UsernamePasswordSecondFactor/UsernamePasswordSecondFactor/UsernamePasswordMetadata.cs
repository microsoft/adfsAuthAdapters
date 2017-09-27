//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using Microsoft.IdentityServer.Web.Authentication.External;
using System.Collections.Generic;
using System.Globalization;

namespace UsernamePasswordSecondFactor
{
    public class UsernamePasswordMetadata : IAuthenticationAdapterMetadata
    {
        protected string GetMetadataResource(string resourceName, int lcid)
        {
            return ResourceHandler.GetResource(resourceName, lcid);
        }

        private readonly Dictionary<int, string> _descriptions = new Dictionary<int, string>();
        private readonly Dictionary<int, string> _friendlyNames = new Dictionary<int, string>();

        private readonly int[] _supportedLcids = new[] { Constants.Lcid.Enus, Constants.Lcid.Fr };

        public UsernamePasswordMetadata()
        {
            for (int index = 0; index < _supportedLcids.Length; index++)
            {
                int lcid = _supportedLcids[index];
                _descriptions.Add(lcid, GetMetadataResource(Constants.ResourceNames.Description, lcid));
                _friendlyNames.Add(lcid, GetMetadataResource(Constants.ResourceNames.FriendlyName, lcid));
            }
        }

        #region IAuthenticationHandlerMetadata Members

        public string AdminName
        {
            get { return GetMetadataResource(Constants.ResourceNames.AdminFriendlyName, CultureInfo.CurrentUICulture.LCID); }
        }

        public virtual string[] AuthenticationMethods
        {
            get { return new[] { Constants.UsernamePasswordMfa }; }
        }

        public Dictionary<int, string> Descriptions
        {
            get { return _descriptions; }
        }

        public Dictionary<int, string> FriendlyNames
        {
            get { return _friendlyNames; }
        }

        public string[] IdentityClaims
        {
            get { return new[] { Constants.UpnClaimType }; }
        }

        public bool RequiresIdentity
        {
            get { return true; }
        }

        public int[] AvailableLcids
        {
            get { return _supportedLcids; }
        }

        #endregion
    }
}
