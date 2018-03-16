# Paseto.Net
.NET Implementation of PASETO

[![Build status](https://ci.appveyor.com/api/projects/status/q8oefx7i9yix53m9/branch/master?svg=true)](https://ci.appveyor.com/project/dustinsoftware/paseto-net/branch/master)

For more information about the standard: https://github.com/paragonie/paseto

### Features:
* v2 public authentication (based on Ed25519 signatures)
* v2 local authentication (in [this PR](https://github.com/dustinsoftware/Paseto.Net/pulls))
* No dependency on JSON.NET

### Credits:
Some cryptography utilies are included from https://github.com/CodesInChaos/Chaos.NaCl

### Supports only v2 public tokens
```
Install-Package Paseto.Public
```

### Will support both public and local v2 tokens (only public at the time of writing, based on libsodium)
```
Install-Package Paseto
```

### Usage
```
using Paseto.Authentication;

const string payload = "Hello Paseto.Net";
string signature = PasetoUtility.Sign(_publicKey, _privateKey, payload); // v2.public.signature
Assert.Equal(payload, PasetoUtility.Parse(_publicKey, signature).Payload);
```
