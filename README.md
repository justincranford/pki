# PKI Examples

# Overview
If SOFTHSM2_CONF environment variable is set, TestMutualTls.java will use HSM slots for KeyStores.<p>
If SOFTHSM2_CONF environment variable is absent, TestMutualTls.java will use PKCS12 in-memory KeyStores.

# Quick Start Commands
set SOFTHSM2_CONF=C:\SoftHSM2\etc\softhsm2.conf<p>
set PATH=%PATH%;C:\SoftHSM2\bin\;C:\SoftHSM2\lib\<p>
softhsm2-util.exe --show-slots<p>
softhsm2-util.exe --delete-token --token "Client"<p>
softhsm2-util.exe --delete-token --token "Server"<p>
softhsm2-util.exe --show-slots<p>
softhsm2-util.exe --init-token --label "Client" --free<p>
softhsm2-util.exe --init-token --label "Server" --free<p>
softhsm2-util.exe --show-slots

# TestMutualTls.java uses hard-coded to login to HSM slots with these passwords
slotListIndex 0 (USER PIN): "clientuser"<p>
slotListIndex 1 (USER PIN): "serveruser"
