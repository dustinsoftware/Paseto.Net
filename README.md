# Paseto.Net
.NET Implementation of PASETO

[![Build status](https://ci.appveyor.com/api/projects/status/q8oefx7i9yix53m9/branch/master?svg=true)](https://ci.appveyor.com/project/dustinsoftware/paseto-net/branch/master)
[![Build Status](https://travis-ci.org/dustinsoftware/Paseto.Net.svg?branch=master)](https://travis-ci.org/dustinsoftware/Paseto.Net)
[![NuGet](https://img.shields.io/nuget/v/Paseto.svg)](https://www.nuget.org/packages/Paseto/)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dustinsoftware/paseto.net/issues)

For more information about the standard: https://github.com/paragonie/paseto

### Features:
* Supports full .NET Framework and .NET Core (Windows / OS X / Linux)
* v2 public authentication (uses Ed25519 signatures)
* v2 local authentication (uses XChaCha20-Poly1305 and Blake2b)
* No dependency on JSON.NET
* Easy token creation *and* support for raw byte arrays

### Non-goals:
* This library doesn't support v1 tokens. Per the [spec](https://github.com/paragonie/paseto/tree/9532a73d0db04d083681a859ec232d1d7ddfa5dd/docs/01-Protocol-Versions) v1 tokens should only be used on systems that can't support modern cryptography.

### Credits:
- Managed Ed25519 implementation from https://github.com/CodesInChaos/Chaos.NaCl
- A fork of [libsodium-net](https://github.com/dustinsoftware/libsodium-net/) is used for XChaCha20-Poly1305
- [simple-json](https://github.com/facebook-csharp-sdk/simple-json) for the embedded JSON parser

### Installation
```
Install-Package Paseto
```

> **Note**: If you need a managed-only implementation that does not use libsodium, install `Paseto.Public`, which only supports handling public tokens. If I can find a managed only implementation of XChaCha20-Poly1305, I'll update the main package to reference it.

### Usage
```csharp
using Paseto.Authentication;

// Creating a token
var claims = new PasteoInstance
{
	Issuer = "http://auth.example.com",
	Subject = "2986689",
	Audience = "audience",
	Expiration = now.AddMinutes(10),
	NotBefore = now.AddMinutes(-10),
	IssuedAt = now,
	AdditionalClaims = new Dictionary<string, object>
	{
		["roles"] = new[] { "Admin", "User" }
	},
	Footer = new Dictionary<string, object>
	{
		["kid"] = "dpm0"
	},
};

// Signing and parsing the token with public signing
string token = PasetoUtility.Sign(_publicKey, _privateKey, claims);
var parsedToken = PasetoUtility.Parse(_publicKey, token, validateTimes: true);
Assert.Equal(claims.Subject, parsedToken.Subject);

// Same, but with local encryption
string token = PasetoUtility.Encrypt(_symmetricKey, claims);
var parsedToken = PasetoUtility.Decrypt(_symmetricKey, token, validateTimes: true);
Assert.Equal(claims.Subject, parsedToken.Subject);

// Arbitrary byte array support with public signing
byte[] payload = Encoding.UTF8.GetBytes("Hello Paseto.Net");
string signature = PasetoUtility.SignBytes(_publicKey, _privateKey, payload); // v2.public.signature
Assert.Equal(payload, PasetoUtility.ParseBytes(_publicKey, signature).Payload);

// Same, but with local encryption
byte[] payload = Encoding.UTF8.GetBytes("Hello Paseto.Net");
string encrypted = PasetoUtility.EncryptBytes(_symmetricKey, payload, nonce);
Assert.Equal(payload, PasetoUtility.DecryptBytes(_symmetricKey, encrypted));

// Read footer without decrypting (untrusted data!)
string footerText = "Hello friend";
Assert.Equal(footerText, PasetoUtility.GetFooter(PasetoUtility.EncryptBytes(_symmetricKey, new byte[0], footerText)));

var footerJson = new Dictionary<string, object> { ["key-id"] = "key10" };
Assert.Equal(footerJson, PasetoUtility.GetFooterJson(PasetoUtility.Encrypt(_symmetricKey, new PasteoInstance { Footer = footerJson })));
```
