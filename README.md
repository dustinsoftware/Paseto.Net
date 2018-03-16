# Paseto.Net
.NET Implementation of PASETO

[![Build status](https://ci.appveyor.com/api/projects/status/q8oefx7i9yix53m9/branch/master?svg=true)](https://ci.appveyor.com/project/dustinsoftware/paseto-net/branch/master)
[![NuGet](https://img.shields.io/nuget/v/Paseto.svg)](https://www.nuget.org/packages/Paseto/)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dustinsoftware/paseto.net/issues)


For more information about the standard: https://github.com/paragonie/paseto

### Features:
* v2 public authentication (uses Ed25519 signatures)
* v2 local authentication (uses XChaCha20-Poly1305 and Blake2b)
* No dependency on JSON.NET (you need to structure the tokens yourself)

### Non-goals:
* This library doesn't support v1 handling tokens. Per the [spec](https://github.com/paragonie/paseto/tree/9532a73d0db04d083681a859ec232d1d7ddfa5dd/docs/01-Protocol-Versions) v1 tokens should only be used on systems that can't support modern cryptography.

### Credits:
- Managed Ed25519 implementation from https://github.com/CodesInChaos/Chaos.NaCl
- A fork of [libsodium-net](https://github.com/dustinsoftware/libsodium-net/) is used for XChaCha20-Poly1305

### Installation
```
Install-Package Paseto
```

> **Note**: If you need a managed-only implementation that does not use libsodium, install `Paseto.Public`, which only supports handling public tokens. If I can find a managed only implementation of XChaCha20-Poly1305, I'll update the main package to reference it.

### Usage
```
using Paseto.Authentication;

const string payload = "Hello Paseto.Net";
string signature = PasetoUtility.Sign(_publicKey, _privateKey, payload); // v2.public.signature
Assert.Equal(payload, PasetoUtility.Parse(_publicKey, signature).Payload);
```
