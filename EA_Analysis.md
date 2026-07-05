# Reversing EA App's Local Encryption

## DISCLAIMER / LEGAL

This work is for educational purposes and future interoperability (GOG Galaxy EA plugin). Reverse engineering for interoperability is tolerated under EU law. [See this writeup for more information.](https://vidstromlabs.com/blog/the-legal-boundaries-of-reverse-engineering-in-the-eu/)

*Kudos to [erri120](https://github.com/erri120) for the original writeup (2023), now archived on the Internet Archive. This writeup builds on his findings and documents what has changed since.*

---

## Why?

Based on erri120's first writeup, I had implemented a piece of the GOG Galaxy plugin that was able to decipher the IS file — installation state data. Over EA App updates, that implementation broke. I wanted to understand why.

The goal was simple: recover information from EA App's locally stored data files and understand how the application derives the crypto material used to protect them. What looked opaque at first turned out to be a fairly ordinary chain of SHA3-256 hashing and AES-256-CBC, wrapped in custom C++ classes. By combining static analysis (IDA) with runtime tracing (Frida 17.2), I mapped the full flow from string constants in the binary into the final decryption path — and documented exactly where EA diverged from the original implementation.

---

## Background

The target was a set of EA App local data files under `C:\ProgramData\EA Desktop\` — clearly not plaintext. Rather than guessing blindly, I identified the process that touched the files (`EABackgroundService.exe`) and pivoted into the binary handling the relevant reads and writes.

The binary exposed useful class and symbol names via RTTI, recovered with IDA's **Class Informer** plugin. Notable entries included `eax::foundation::Sha3Hasher` and `eax::foundation::DirtyPiecewiseHasher`. This immediately suggested EA ditched direct OpenSSL imports in favor of an in-house crypto wrapper — the first hint that the protection logic was a reimplementation of standard primitives rather than a thin shim over a well-known library.

> **Important for anyone trying to reproduce this:** EA's SHA3 implementation is **statically linked** into `EABackgroundService.exe`. Do not waste time trying `Module.getExportByName("libcrypto-1_1-x64.dll", ...)` for the hashing side — it will find nothing. The correct approach is to resolve the hasher constructor via `base_address + RVA` at runtime, then walk the vtable to hook the virtual `update` and `final` methods. `libcrypto-1_1-x64.dll` is only relevant for the AES layer (see below).

---

## Filesystem Layout

Two folders exist under `C:\ProgramData\EA Desktop\`, both named after SHA3-256 hashes:

```text
C:\ProgramData\EA Desktop\
├── 530c11479fe252fc5aabc24935b9776d4900eb3ba58fdc271e0d6229413ad40e\
│   │   = SHA3-256("allUsersGenericId")         ← allUsers folder
│   ├── IS
│   ├── IQ
│   ├── CATS2
│   └── CONF-production
│
└── <SHA3-256(nucleus_id)>\                      ← Nucleus folder
    ├── NS
    └── CONF-production
```

The allUsers folder is machine-scoped. The Nucleus folder is user-scoped, named after your Nucleus ID (the account identifier used since the Origin era, recoverable from `https://gateway.ea.com/proxy/identity/pids/me`). You can verify this by computing `SHA3-256(your_nucleus_id)` — you will recognize the result as a folder name on disk.

---

## The Files

| File | Full name | Folder |
|------|-----------|--------|
| IS | Installation State | allUsers |
| IQ | Installation Queue | allUsers |
| CATS2 | Catalog Items | allUsers |
| CONF-production | Global Config (cached from EA servers) | allUsers + Nucleus |
| NS | Nucleus Entitlements State | Nucleus |

CONF-production is a locally cached copy of EA's [`globalConfig.json`](https://desktop-config.juno.ea.com/globalConfig.json). Its presence in both folders — with different key formulas — is what makes it structurally unusual compared to the other files.

---

## First Foothold: The SHA3 Hasher

The `eax::foundation::Sha3Hasher` constructor takes an algorithm ID mapping to digest
sizes:

| `alg` value | Variant  | Digest size |
|-------------|----------|-------------|
| `6`         | SHA3-128 | 16 bytes    |
| `7`         | SHA3-256 | 32 bytes    |
| `8`         | SHA3-512 | 64 bytes    |

`alg=7` is the SHA3-256 path — consistent with erri120's original findings. Knowing this mapping meant I could stop chasing every hash-related call and focus only on objects constructed with `alg=7`.

---

## The Key Derivation Helper

The real breakthrough came from a helper function responsible for building all file decryption keys. It creates an `alg=7` hasher, feeds two inputs through the virtual `update` method, finalizes once, then hashes a third component and finalizes again:

```text
IV  = SHA3-256(in1 || in2)
Key = SHA3-256(in1 || in2 || extra)
```

Both the IV and the Key come out of the **same function** — the intermediate finalization produces the IV, the second finalization produces the Key. This is why the helper performs two finalizations rather than one.

A `flag` parameter controls what `extra` is:

- `flag=0` → `extra` is a **hardcoded ASCII string** embedded in the binary
- `flag=1` → `extra` is the **machine hash** (a 40-character ASCII hex string, passed as literal text, not decoded binary)

---

## Confirming with Frida 17.2

To validate the static analysis, I hooked the SHA3 hasher constructor and the virtual `update`/`final` methods in Frida. Key notes:

- SHA3-256 returns **raw binary** — always hexdump the output buffer, never attempt UTF-8 decoding directly
- Hook virtual methods via vtable offsets, not export names
- Internal context starts at `obj + 8`, matching the constructor's object layout

One of the most informative traces:

```text
[key_derivation_helper]
  in1  = allUsersGenericId
  in2  = IS
  flag = 0

[SHA3 upd #1]  str : allUsersGenericId
[SHA3 upd #2]  str : IS
[SHA3 final #1]                          ← this output is the IV
[SHA3 upd #3]  str : <hardcoded string>
[SHA3 final #2]                          ← this output is the Key
```

### Frida 17.2 Breaking Changes

| Old API | Replacement |
|---------|-------------|
| `Module.findExportByName(mod, fn)` | `Module.getExportByName(fn)` |
| `Memory.scan(...)` with `\|` pipe patterns | Hex byte patterns only (`"48 89 ?? 24"`) |
| `Process.getCurrentThreadId()` | Removed — restructure logic accordingly |

These will manifest as `TypeError: not a function` or `invalid match pattern` and are easy to misdiagnose as a targeting problem.

---

## What Changed Since erri120's Writeup

erri120's 2023 writeup documented the following formula for all files:

```text
IV  = SHA3-256("allUsersGenericId" || filename)
Key = SHA3-256("allUsersGenericId" || filename || machine_hash)
```

This is **no longer accurate for all files**. EA made two deliberate changes:

1. **Partial decoupling from hardware binding:** IS and CATS2 now use a hardcoded* string as the `extra` chunk instead of the machine hash. This means those two files can be decrypted without knowing the machine hash — but only if you can recover the hardcoded string from the binary.

2. **New user-scoped files:** NS and the Nucleus-folder variant of CONF-production were not documented in the original writeup. These use the Nucleus ID as a prefix, binding them to a specific EA account rather than just the machine.

Both changes appear targeted at breaking third-party implementations that relied on the original formula.

---

## Key Derivation: Complete Reference

| File | Folder | IV | Key |
|------|--------|----|-----|
| IS | allUsers | `SHA3-256("allUsersGenericId" \|\| "IS")` | `SHA3-256("allUsersGenericId" \|\| "IS" \|\| hardcoded_str)` |
| CATS2 | allUsers | `SHA3-256("allUsersGenericId" \|\| "CATS2")` | `SHA3-256("allUsersGenericId" \|\| "CATS2" \|\| hardcoded_str)` |
| IQ | allUsers | `SHA3-256("allUsersGenericId" \|\| "IQ")` | `SHA3-256("allUsersGenericId" \|\| "IQ" \|\| machine_hash)` |
| CONF-production | allUsers | `SHA3-256("CONF-production")` | `SHA3-256("CONF-production" \|\| machine_hash)` |
| NS | Nucleus | `SHA3-256(nucleus_id \|\| "NS")` | `SHA3-256(nucleus_id \|\| "NS" \|\| machine_hash)` |
| CONF-production | Nucleus | `SHA3-256(nucleus_id \|\| "CONF-production")` | `SHA3-256(nucleus_id \|\| "CONF-production" \|\| machine_hash)` |

Note that CONF-production in the allUsers folder uses **no prefix** for its IV and Key — just the filename itself, unlike every other file in that folder.

---

## The Machine Hash

The machine hash is a **SHA1 digest** of a semicolon-delimited concatenation of WMI field values, in this order:

```
Win32_BaseBoard       → Manufacturer
Win32_BaseBoard       → SerialNumber
Win32_BIOS            → Manufacturer
Win32_BIOS            → SerialNumber
Win32_VideoController → PNPDeviceId
Win32_Processor       → Manufacturer
Win32_Processor       → ProcessorId
Win32_Processor       → Name
```

Additionally, the **C:\ volume serial number** — the one returned by `GetVolumeInformationW`, not `Win32_PhysicalMedia.SerialNumber` — is included in the hardware string. These are the same components documented by erri120; this part has not changed.

EA's Background Service logs emit this hash at startup — the fastest way to obtain it for validation is to read it directly from the logs rather than recomputing it.

> **Note:** Additional fields (`Win32_OperatingSystem.SerialNumber`, `InstallDate`, antivirus product name) appear in the Background Service logs alongside the machine hash. These appear to feed a separate **pcSign** token used for new-device identification with EA's servers. How pcSign is fully constructed has not been traced end-to-end and is left for future work.

---

## The AES Layer

EA Desktop uses **AES-256-CBC**. This is unchanged from erri120's original findings.

The **IV** is the 32-byte intermediate SHA3-256 digest from the key derivation helper (the output of the first finalization), truncated to 16 bytes for CBC. The **Key** is the 32-byte final SHA3-256 digest (the output of the second finalization).

Decryption in Python:

```python
from Crypto.Cipher import AES
import hashlib, sha3

def derive_iv_and_key(in1: bytes, in2: bytes, extra: bytes) -> tuple[bytes, bytes]:
    iv  = hashlib.sha3_256(in1 + in2).digest()
    key = hashlib.sha3_256(in1 + in2 + extra).digest()
    return iv[:16], key

# Example: IS file (flag=0, hardcoded string path)
# Recover <hardcoded_str> from the binary for your EA App version
iv, key = derive_iv_and_key(
    b"allUsersGenericId",
    b"IS",
    b"<hardcoded_str>"
)

with open(r"C:\ProgramData\EA Desktop\530c11479fe252fc5aabc24935b9776d4900eb3ba58fdc271e0d6229413ad40e\IS", "rb") as f:
    ciphertext = f.read()

cipher    = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
print(plaintext.decode("utf-8"))
```

---

## Why Both Analysis Methods Mattered

**Static analysis (IDA + Class Informer)** gave the map: class names, vtable layouts, algorithm IDs, the `flag` parameter controlling which `extra` chunk is used, and the two-finalization structure of the key derivation helper. Without it, Frida hooks would, have had no meaningful targets.

**Dynamic analysis (Frida 17.2)** gave the territory: the exact string inputs in the order they reached the hasher, which `flag` branch was taken for each file, and live confirmation that the SHA3 outputs fed directly into the AES key and IV slots. Without it, the static picture would have remained ambiguous — particularly for the Nucleus ID path, which would likely never have surfaced from static analysis alone.

The combination is what made this tractable. Neither alone would have been sufficient.

---

## Final Notes

EA hasn't fundamentally redesigned their crypto since erri120's writeup. They wrapped standard SHA3 and AES in custom C++ classes, added a hardcoded string fallback for some files to partially decouple them from hardware binding, and introduced user-scoped files tied to the Nucleus ID. The core primitive — SHA3-256 into AES-256-CBC — is unchanged.

The changes are modest but deliberate: targeted enough to break existing implementations without redesigning the system. The useful takeaway is the same as always — even a wrapper-heavy binary becomes predictable once you stop reading decompiled pseudocode and start logging concrete inputs, outputs, and call order at runtime.
