# PKI Examples

# Overview
The tests use combinations of PKCS#12 (in-memory) and PKCS#11 (in-HSM) keystores.

# PKCS#11 dependencies
PKCS#11 keystores depend on SoftHSM2 for Windows v2.5 (or higher).
- https://github.com/disig/SoftHSM2-for-Windows/releases/tag/v2.5.0
PKCS#11 external tests depend on OpenSC pkcs11-tool 0.22 (or higher).
- https://github.com/OpenSC/OpenSC/releases/tag/0.22.0

# SoftHSM2 quick start commands to add virtual HSM tokens via Command Prompt
```
# This global environment variable is set by the install.
# Re-login to source it, other temporarily set it manually.
set SOFTHSM2_CONF=C:\SoftHSM2\etc\softhsm2.conf

# Add SoftHSM2 to the Windows PATH
set PATH=%PATH%;C:\SoftHSM2\bin\;C:\SoftHSM2\lib\
softhsm2-util.exe --show-slots

# Remove virtual slots if previously created
softhsm2-util.exe --delete-token --token "Token0"
softhsm2-util.exe --delete-token --token "Token1"
softhsm2-util.exe --delete-token --token "Token2"
softhsm2-util.exe --delete-token --token "Token3"
softhsm2-util.exe --show-slots

# Create new slots
softhsm2-util.exe --init-token --label "Token0" --pin "hsmslotpwd" --so-pin "hsmslotpwd" --free
softhsm2-util.exe --init-token --label "Token1" --pin "hsmslotpwd" --so-pin "hsmslotpwd" --free
softhsm2-util.exe --init-token --label "Token2" --pin "hsmslotpwd" --so-pin "hsmslotpwd" --free
softhsm2-util.exe --init-token --label "Token3" --pin "hsmslotpwd" --so-pin "hsmslotpwd" --free

# Caveat: SoftHSM2 assigns random slot IDs, which randomizes slotListIndex.
softhsm2-util.exe --show-slots

# Optional: Use updated slot or slotListIndex in SunPKCS11 confs and unique passwords.
```

# pkcs11-tool quick start commands to verify HSM tokens slotListIndex and login via Command Prompt
```
set PATH=%PATH%;C:\Program Files\OpenSC Project\OpenSC\tools\
pkcs11-tool --module C:\SoftHSM2\lib\softhsm2-x64.dll --list-slots
pkcs11-tool --module C:\SoftHSM2\lib\softhsm2-x64.dll --login --pin hsmslotpwd --slot-index 0 --list-objects
pkcs11-tool --module C:\SoftHSM2\lib\softhsm2-x64.dll --login --pin hsmslotpwd --slot-index 1 --list-objects
pkcs11-tool --module C:\SoftHSM2\lib\softhsm2-x64.dll --login --pin hsmslotpwd --slot-index 2 --list-objects
pkcs11-tool --module C:\SoftHSM2\lib\softhsm2-x64.dll --login --pin hsmslotpwd --slot-index 3 --list-objects

```

# pkcs11-tool list mechanisms (aka algorithms) for SoftHSM2
```
>pkcs11-tool --module C:\SoftHSM2\lib\softhsm2-x64.dll --list-mechanisms
Using slot 0 with a present token (0xf55ce51)
Supported mechanisms:
  MD5, digest
  SHA-1, digest
  SHA224, digest
  SHA256, digest
  SHA384, digest
  SHA512, digest
  MD5-HMAC, keySize={16,512}, sign, verify
  SHA-1-HMAC, keySize={20,512}, sign, verify
  SHA224-HMAC, keySize={28,512}, sign, verify
  SHA256-HMAC, keySize={32,512}, sign, verify
  SHA384-HMAC, keySize={48,512}, sign, verify
  SHA512-HMAC, keySize={64,512}, sign, verify
  RSA-PKCS-KEY-PAIR-GEN, keySize={512,16384}, generate_key_pair
  RSA-PKCS, keySize={512,16384}, encrypt, decrypt, sign, verify, wrap, unwrap
  RSA-X-509, keySize={512,16384}, encrypt, decrypt, sign, verify
  MD5-RSA-PKCS, keySize={512,16384}, sign, verify
  SHA1-RSA-PKCS, keySize={512,16384}, sign, verify
  RSA-PKCS-OAEP, keySize={512,16384}, encrypt, decrypt, wrap, unwrap
  SHA224-RSA-PKCS, keySize={512,16384}, sign, verify
  SHA256-RSA-PKCS, keySize={512,16384}, sign, verify
  SHA384-RSA-PKCS, keySize={512,16384}, sign, verify
  SHA512-RSA-PKCS, keySize={512,16384}, sign, verify
  RSA-PKCS-PSS, keySize={512,16384}, sign, verify
  SHA1-RSA-PKCS-PSS, keySize={512,16384}, sign, verify
  SHA224-RSA-PKCS-PSS, keySize={512,16384}, sign, verify
  SHA256-RSA-PKCS-PSS, keySize={512,16384}, sign, verify
  SHA384-RSA-PKCS-PSS, keySize={512,16384}, sign, verify
  SHA512-RSA-PKCS-PSS, keySize={512,16384}, sign, verify
  GENERIC-SECRET-KEY-GEN, keySize={1,-2147483648}, generate
  DES-KEY-GEN, generate
  DES2-KEY-GEN, generate
  DES3-KEY-GEN, generate
  DES-ECB, encrypt, decrypt
  DES-CBC, encrypt, decrypt
  DES-CBC-PAD, encrypt, decrypt
  DES-ECB-ENCRYPT-DATA, derive
  DES-CBC-ENCRYPT-DATA, derive
  DES3-ECB, encrypt, decrypt
  DES3-CBC, encrypt, decrypt
  DES3-CBC-PAD, encrypt, decrypt
  DES3-ECB-ENCRYPT-DATA, derive
  DES3-CBC-ENCRYPT-DATA, derive
  DES3-CMAC, sign, verify
  AES-KEY-GEN, keySize={16,32}, generate
  AES-ECB, keySize={16,32}, encrypt, decrypt
  AES-CBC, keySize={16,32}, encrypt, decrypt
  AES-CBC-PAD, keySize={16,32}, encrypt, decrypt
  AES-CTR, keySize={16,32}, encrypt, decrypt
  AES-GCM, keySize={16,32}, encrypt, decrypt
  AES-KEY-WRAP, keySize={16,-2147483648}, wrap, unwrap
  mechtype-0x210A, keySize={1,-2147483648}, wrap, unwrap
  AES-ECB-ENCRYPT-DATA, derive
  AES-CBC-ENCRYPT-DATA, derive
  AES-CMAC, keySize={16,32}, sign, verify
  DSA-PARAMETER-GEN, keySize={512,1024}, generate
  DSA-KEY-PAIR-GEN, keySize={512,1024}, generate_key_pair
  DSA, keySize={512,1024}, sign, verify
  DSA-SHA1, keySize={512,1024}, sign, verify
  DSA-SHA224, keySize={512,1024}, sign, verify
  DSA-SHA256, keySize={512,1024}, sign, verify
  DSA-SHA384, keySize={512,1024}, sign, verify
  DSA-SHA512, keySize={512,1024}, sign, verify
  DH-PKCS-KEY-PAIR-GEN, keySize={512,10000}, generate_key_pair
  DH-PKCS-PARAMETER-GEN, keySize={512,10000}, generate
  DH-PKCS-DERIVE, keySize={512,10000}, derive
  ECDSA-KEY-PAIR-GEN, keySize={112,521}, generate_key_pair, EC F_P, EC OID, EC uncompressed
  ECDSA, keySize={112,521}, sign, verify, EC F_P, EC OID, EC uncompressed
  ECDH1-DERIVE, keySize={112,521}, derive
```