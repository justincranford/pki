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