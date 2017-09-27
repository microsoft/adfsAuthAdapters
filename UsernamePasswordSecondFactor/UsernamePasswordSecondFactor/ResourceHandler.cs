using System;
using System.Globalization;
using UsernamePasswordSecondFactor.Resources;

namespace UsernamePasswordSecondFactor
{
    internal static class ResourceHandler
    {
        public static string GetResource(string resourceName, int lcid)
        {
            if (String.IsNullOrEmpty(resourceName))
            {
                throw new ArgumentNullException("resourceName");
            }

            return StringResources.ResourceManager.GetString(resourceName, new CultureInfo(lcid));
        }
    }
}
