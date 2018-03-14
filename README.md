# Paseto.Net
.NET Implementation of PASETO

[![Build status](https://ci.appveyor.com/api/projects/status/q8oefx7i9yix53m9/branch/master?svg=true)](https://ci.appveyor.com/project/dustinsoftware/paseto-net/branch/master)

For more information about the standard: https://github.com/paragonie/paseto

### Supports:
* v2 public authentication (based on Ed25519 signatures)

Support exists for local encryption in [this PR](https://github.com/dustinsoftware/Paseto.Net/pulls), but some changes need to land in NSec before that can be merged and shipped to NuGet. You're welcome to build from source if you need local encryption today.

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
