# Reversing EA App’s Local Encryption

# DISCLAIMER / LEGAL
The work done here is for educational purposes. In no way should you infringe/circumvent EA's current protections. The work shown is part of future interoperability measures (for GOG Galaxy's EA plugin, or for future implementations).
In the country this operation was done, the European Union allows/tolerates reverse engineering in the sole intention of interoperability. [See this writeup for more information.](https://vidstromlabs.com/blog/the-legal-boundaries-of-reverse-engineering-in-the-eu/)

# Kudos
Kudos to [erri120](https://github.com/erri120) for the first writeup, now deleted from his GitHub page (still available in the Internet Archive).

# Why ?

Based on the first writeup, I had implemented a piece of the GOG Galaxy plugin that was able to decipher the IS file, which basically was installation information. Nothing too scary or fancy in there, I've wondered why it was enciphered. Over the updates, the function became useless, and I was trying to find out why.

From this situation, a simple goal emerged: recover information from EA App’s locally stored data files and understand how the application derives the crypto material used to protect them.

What looked opaque at first turned out to be a fairly ordinary chain of hashing and AES, wrapped in custom C++ classes and helper functions. By combining static analysis with runtime tracing, I was able to map the full flow from string constants in the binary to the final decryption path.

## Background

The initial target was a set of EA App local data files that were clearly not plaintext. Rather than guessing blindly, I began by identifying the process that touched the files and then pivoted into the binary that handled the relevant reads and writes.

The binary exposed a number of useful class and symbol names, including `eax::foundation::Sha3Hasher` and `eax::foundation::DirtyPiecewiseHasher`, which immediately suggested they've ditched the library imports for an in-house solution, rather than exposing OpenSSL libraries directly.
That was the first hint that the protection logic was probably linked to a reimplementation of basic cryptography functions.

## First foothold in the binary

First, let's dive into the Sha3Hasher set of functions.

For algorithm IDs `6`, `7`, and `8`, it constructs an `eax::foundation::Sha3Hasher` object and sets digest sizes of 16, 32, and 64 bytes respectively, making `alg=7` the SHA3-256 path. I'm specifically precising this here, because if you point back to the first writeup, it was already the main hashing function being used.

That mapping mattered because it gave me a reliable runtime filter. Once I knew `alg=7` meant SHA3-256, I could stop chasing every hash-related call and focus only on the specific object family I cared about.

## The key helper function

The real breakthrough came from another function below it. That function created an `alg=7` hasher, fed two inputs through one virtual method, finalizes once through another virtual method, then hashes a third component and finalizes again.

In simplified form, the routine behaves like this:

- `intermediate = SHA3-256(in1 || in2)`
- `final = SHA3-256(in1 || in2 || extra)`

This was the moment where the static analysis became actionable. I now had a concrete function that was clearly building structured SHA3-256 digests from named string inputs instead of some generic crypto noise.

## Confirming the hash logic with Frida

To validate the static analysis, I hooked both the SHA3 hasher factory and the initializer in Frida. The runtime traces confirmed that `alg=7` objects corresponded to the 32-byte initialization path, and that the internal context began at `obj + 8`, matching the object layout implied by the constructor.

At first, I mistakenly treated the outputs as UTF-8 strings, which caused decode failures. That turned out to be expected: SHA3-256 returns a raw 32-byte binary digest, so the correct way to inspect the result was to dump the output buffer as hexadecimal instead of trying to render it as text.

Once I hooked the SHA3 virtual `update` and `final` methods, I could see the exact input chunks being fed to the hasher in order.

## What the runtime trace showed

One of the most useful traces looked like this:

```text
[sub_14051AAD0]
  in1 = allUsersGenericId
  in2 = IS
  flag = 0

[SHA3 upd #1]
  str : allUsersGenericId

[SHA3 upd #2]
  str : IS

[SHA3 final #1]

[SHA3 upd #3]
  str : l)%ge7fomILhfj*Qfi+,

[SHA3 final #2]
```

That proved two important things:

1. The first digest is built from `allUsersGenericId` and `IS`.
2. The second digest adds a third value, which in this branch is this hardcoded string `l)%ge7fomILhfj*Qfi+,`. This was different from the previous writeup, that included a hardware hash in every single file request.

In the `flag=1` branch, the third chunk was not the hardcoded fallback string but the return value of `0x1405186C0`, which my Frida hook showed as a 40-character ASCII hex string. Importantly, the hasher received that value as literal text, not decoded binary.

## Reconstructing the hash inputs

After instrumenting the helper function, the hash side was no longer a mystery. The final SHA3-256 value could be reconstructed directly from the concatenated strings in the same order the runtime trace showed them.

For example, in the `flag=0` branch, the final digest is:

```text
SHA3-256("allUsersGenericId" + "IS" + "l)%ge7fomILhfj*Qfi+,")
```

This was an important correction to my earlier thinking. EA didn't use a hardware hash in every file decipher, but used a hardcoded string in a specific flag, for specific files, in a homemade SHA3 hasher function.

## Following the data into AES

Once I had the recovered 32-byte SHA3 output, the next question was whether that material was actually being used as an AES key. 

A 32-byte value is compatible with AES-256, but compatibility alone proves nothing. I had to confirm they were still using AES-256, AES-256-CBC specifically.

The key we've found could either be an IV, or a key. If we remember Erri's previous findings, they've found the IV was a constant (yes, nothing changes, only the key used to), and the key was the IV + something else, which was pieces of hardware information (taken from WMI), hashed into SHA1.

## Has it moved since ?

Well, let me tell you it has changed. Not much, but enough that from the first writeup to today, it could break a few things. For certain files (IQ, IS, CATS2), it is **STILL** a constant, being :

```text
SHA3-256("allUsersGenericId" + file name)
```

BUT, in certain different files, it is quite a bit different. See, if you check `C:\ProgramData\EA Desktop\530c11479fe252fc5aabc24935b9776d4900eb3ba58fdc271e0d6229413ad40e` (yeah, remember that ?), we have 4 files. Which one is the file I haven't talked about ?

You've guessed it : CONF-production. This file is breaking the rules all by itself. But fear not, as it's simply a copy of [this globalConfig file from EA's servers](https://desktop-config.juno.ea.com/globalConfig.json). This one is... let's say it isn't common.

It's available in there, and in another folder, which is another big string that also look like a SHA3-256 result... well, if you thought about that, congratulations, you've found another piece of the puzzle !

Indeed, that other folder contains only 2 files: CONF-production (yet again ???) and NS. This will be extra important for the next steps, you'll find out why.

The CONF-production file in the `530c11479fe252fc5aabc24935b9776d4900eb3ba58fdc271e0d6229413ad40e` folder... does not need any prefix (yes, you've heard me right). Which means, just write the file name. Yes, just the file name. __allUsersGen-__ no-no, just CONF-production. Test it, you'll see., but the key will need you to get your wonderful machine hash ! (yes, your SHA-1 hardware information.)

Try to do this : 

```text
SHA3-256("CONF-production" + machinehash)
```

and you would get a key.

## The machine hash extravaganza

You don't know how the machine hash is made and you don't want to check again ? Check the EA Background Service logs, it blatantly shows it to you. Or recreate the string once again. It didn't change over time.

For the recall, here's how we make the machine hash : 

```
Win32_BaseBoard Manufacturer
Win32_BaseBoard SerialNumber
Win32_BIOS Manufacturer
Win32_BIOS SerialNumber
Win32_VideoController PNPDeviceId
Win32_Processor Manufacturer
Win32_Processor ProcessorId
Win32_Processor Name
```

Some of the logs also seem to point that there's a few other things being checked on the spot (eg. why does it show my antivirus ?). There's a few other things being catched here, which are as followed : 

```
Win32_OperatingSystem SerialNumber
Win32_OperatingSystem InstallDate
AntivirusProduct Name
```

The operating system data is important for the pcSign creation, which will generate a one-time token in order for the EA services to identify which computer connects (also if it's a new computer).

Anyhow, that closed the loop on the discrepancies linked to this f- 

## The other mystery

__WAIT ! You've talked about the other folder, that EXTRA IMPORTANT folder !__

Ah yes, that folder. Well, you see, I was wondering how I could have a secondary folder that looked like our beloved one. And I dug... not much actually. Because my previous script actually gave me the answer.

```
[sub_14051AAD0]
  in1 = <a number>
  in2 = CONF-production
  flag = 1
[SHA3 upd #1]
    chunk: len=13
      hex : <that same number but in hexadecimal>
      str : <that number>
[SHA3 upd #2]
    chunk: 
      hex : 434f4e462d70726f64756374696f6e
      str : CONF-production
[SHA3 final #1]
[SHA3 upd #3] 
    chunk: len=40
      hex : <machine hash in hexa>
      str : <machine hash>
[SHA3 final #2]
```

That number... it looked very familiar. You see, when I had worked on my GOG Galaxy plugin, I had to use EA's very own API, from the Origin era. And one of the APIs was user-related (if you remember, it was [this URL](https://gateway.ea.com/proxy/identity/pids/me)). 
And one of the pieces of information that it could give you is the Nucleus ID (which was the old Origin way of calling your account ID). You now understood what I'm saying here... that other piece of very important information is your Nucleus ID ! (little trick : hash your Nucleus ID in SHA3-256, you'll see the magic happen).

Yes, it now uses the Nucleus ID as an alternative choice. Either you need to use a Nucleus ID (for all files in that folder), either it uses a hardcoded string. It will all depend on the flag.

So, if we recapitulate, we have :

```text
SHA3-256("allUsersGenericId" + file name + "l)%ge7fomILhfj*Qfi+,")
```
,
```text
SHA3-256("allUsersGenericId" + file name + machine hash)
```
,
AND, for the specific CONF-production workaround,
```text
SHA3-256(Nucleus ID + file + machine hash)
```
in that nucleus ID folder, or 
```text
SHA3-256(file name + machine hash)
```
in that allUsers folder (yes, it can be very confusing).

## Why the static and dynamic analysis both mattered

Starting from the static analysis (via IDA) gave me a few pieces of very important information, to know where I should start digging further. The "Class Informer" tool gave me RTTI information about classes IDA wouldn't have named, and it simplified the searching task. From there, I could pinpoint which function called what, in which occasion it would have been called, and deduct which information was it filling out.

The dynamic analysis (via Frida) gave me what the static analysis wouldn't have done : data on the go. The other piece of mystery, unfolding into my hands. By pinpointing what to trace and sniff, it improved our efficiency in finding out what we needed.

## Final notes

In the end, it was much less mysterious than it first appeared. Thanks to Erri's first writeup, we had an idea of what we needed to look for. This writeup confirms that some things haven't changed, and that some sneaky additions were made to cut off the previous decryption techniques. Once the SHA3 helper and the AES path were instrumented, the whole mechanism reduced to a predictable sequence of cat and mice.

The useful lesson here was not just “EA hasn't changed anything”, they've did, but that they loved giving us a hard time by recoding some library functions to blur out obvious clues.
