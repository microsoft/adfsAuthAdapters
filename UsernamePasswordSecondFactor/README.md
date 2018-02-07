# Username/Password MFA Authentication Adapters 

## Overview 

This project enables you to create and register an additional authentication provider in AD FS so that users can sign on with another factor (such as Azure MFA) first, then be prompted for their password second.

## Why would I want this project?

Enabling password as a secondary factor protects the account and password from attacks by making it more difficult to access the password prompt and try common passwords, for example. 

## Requirements 

- An AD FS server running Windows Server 2012 R2 or 2016
- A development box running Visual Studio.  For detailed requirements for AD FS external adapters see “Setting up the development box” in [this blog](https://blogs.msdn.microsoft.com/jenfieldmsft/2014/03/24/build-your-own-external-authentication-provider-for-ad-fs-in-windows-server-2012-r2-walk-through-part-1/).


## Getting Started 

- Build the adapter using the process detailed under “Build the adapter” in [this blog](https://blogs.msdn.microsoft.com/jenfieldmsft/2014/03/24/build-your-own-external-authentication-provider-for-ad-fs-in-windows-server-2012-r2-walk-through-part-1/).
- Copy the adapter dll to your test AD FS server and register it using the steps under “Register your provider in AD FS” in [this blog](https://blogs.msdn.microsoft.com/jenfieldmsft/2014/03/24/build-your-own-external-authentication-provider-for-ad-fs-in-windows-server-2012-r2-walk-through-part-1/).

- Example powershell command line:
```
PS C:\>$typeName = "UsernamePasswordSecondFactor. UsernamePasswordAdapter, MFAadapter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=e675eb33c62805a0, processorArchitecture=MSIL”
PS C:\>Register-AdfsAuthenticationProvider -TypeName $typeName -Name “MyMFAAdapter”
PS C:\>net stop adfssrv
PS C:\>net start adfssrv 
```

- Then create a policy that requires additional auth for sign on and give it a try.  If you’re running AD FS 2012 R2, you can use the detailed steps in the blog to test. 



## Contributing (Special Note)

If you are contributing code, please be sure that you __remove any signing key__ from any code you 
put in a pull request. This project is public, and anyone on the Internet can see it.

For the full Contributing details, please see __[the root README](../README.md)__.
