//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using UsernamePasswordSecondFactor.Resources;
using Microsoft.IdentityServer.Web.Authentication.External;


namespace UsernamePasswordSecondFactor
{
    internal class UsernamePasswordPresentation : IAdapterPresentationForm
    {
        private readonly ExternalAuthenticationException _ex = null;

        private readonly string _username = string.Empty;

        private readonly Dictionary<string, string> _dynamicContents = new Dictionary<string, string>()
        {
            {Constants.DynamicContentLabels.markerUserName, String.Empty},
            {Constants.DynamicContentLabels.markerOverallError, String.Empty},
            {Constants.DynamicContentLabels.markerActionUrl, String.Empty},
            {Constants.DynamicContentLabels.markerPageIntroductionTitle, String.Empty},
            {Constants.DynamicContentLabels.markerPageIntroductionText, String.Empty},
            {Constants.DynamicContentLabels.markerPageTitle, String.Empty},
        };

        public UsernamePasswordPresentation(string username)
        {
            _username = username;
        }

        public UsernamePasswordPresentation(string username, ExternalAuthenticationException ex) : this(username)
        {
            _ex = ex;
        }

        /// <summary>
        /// Replace template markers with explicitly given replacements.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="replacements"></param>
        /// <returns></returns>
        private static string Replace(string input, Dictionary<string, string> replacements)
        {
            if (string.IsNullOrEmpty(input) || null == replacements)
            {
                return input;
            }

            // Use StringBuiler and allocate buffer 3 times larger
            StringBuilder sb = new StringBuilder(input, input.Length * 3);
            foreach (string key in replacements.Keys)
            {
                sb.Replace(key, replacements[key]);
            }
            return sb.ToString();
        }

        #region IAdapterPresentationForm Members

        public string GetFormHtml(int lcid)
        {
            var dynamicContents = new Dictionary<string, string>(_dynamicContents)
            {
                [Constants.DynamicContentLabels.markerPageIntroductionTitle] =
                GetPresentationResource(Constants.ResourceNames.PageIntroductionTitle, lcid),
                [Constants.DynamicContentLabels.markerPageIntroductionText] =
                GetPresentationResource(Constants.ResourceNames.PageIntroductionText, lcid),
                [Constants.DynamicContentLabels.markerPageTitle] = GetPageTitle(lcid),
                [Constants.DynamicContentLabels.markerSubmitButton] =
                GetPresentationResource(Constants.ResourceNames.SubmitButtonLabel, lcid),
                [Constants.DynamicContentLabels.markerLoginPagePasswordLabel] = string.Empty
            };

            if (_ex != null)
            {
                dynamicContents[Constants.DynamicContentLabels.markerPageIntroductionText] = GetPresentationResource(Constants.ResourceNames.FailedLogin, lcid);
            }

            dynamicContents[Constants.DynamicContentLabels.markerLoginPageUserNameExample] = _username;

            string authPageTemplate = ResourceHandler.GetResource(Constants.ResourceNames.AuthPageTemplate, lcid);

            return Replace(authPageTemplate, dynamicContents);
        }

        #endregion

        #region IAdapterPresentationIndirect Members

        public string GetFormPreRenderHtml(int lcid)
        {
            return null;
        }

        public string GetPageTitle(int lcid)
        {
            return GetPresentationResource(Constants.ResourceNames.PageTitle, lcid);
        }

        #endregion

        protected string GetPresentationResource(string resourceName, int lcid)
        {
            return ResourceHandler.GetResource(resourceName, lcid);
        }
    }
}

