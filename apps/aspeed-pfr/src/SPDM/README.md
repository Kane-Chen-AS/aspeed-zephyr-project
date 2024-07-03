## How to Test Secure Connection Feature
To test the secure connection, ensure the BMC code enables MCTP socket code and PFR 5 related features (e.g., BMC as I3C master). Additionally, enable the following flags on the PFR side:

```makefile
CONFIG_PFR_MCTP_I3C_5_0=y
CONFIG_I3C_TARGET=y
CONFIG_I3C_TARGET_MQUEUE=y
CONFIG_SECURE_CONNECTION_RESPONDER=y
CONFIG_SECURE_CONNECTION_REQUESTER=y
```
Note: Enabling these flags on the PFR side will cause the RAM size exceeded around 3 KB. To reduce the RAM size, consider enabling **CONFIG_SHELL_MINIMAL** for more RAM space.

Ensure the AFM firmware includes the correct I3C address in the `smbus_addr` property. This allows the PFR to send the SPDM request via this address to the CPU or BMC.

## Feature Notes
This section outlines the status of the code implementation. Items marked with the keyword `Table 26:X` are related to Intel Spec. 814910, where X denotes the index within Table 26.

* According to Intel Spec. 814910, the maximum number of sessions is set to 5 (see Table 26:1).

* PFR establishes a secure connection using SPDM 1.2 with `mutual authentication` (both requester and responder) (see Table 26:2).

* PFR code can establish a secure channel over MCTP over I3C. A secure channel can also be established via I2C/SMBus; however, since access permissions are the same as non-secure channels, using I2C/SMBus for secure communication offers no additional advantages (see Table 26:4).

* PFR code supports authenticated MCTP traffic over the I3C interface with MCTP Type 6 for mailbox messages. Once a secure channel is created, all traffic will be encrypted (see Table 26:5).

* Encryption mode used by the PFR code is AES-GCM (256 bit). The PFR code uses DHE key pairs to derive symmetric keys according to SPDM 1.2 specifications. Key derivation utilizes HKDF-expand or HMAC. The key pairs are stored in the PFR memory space (see Table 26:6).

* The PFR code uses the **KEY_EXCHANGE** method to setup a secure session between the CPU or BMC using the DHE key (see Table 26:7).

* The PFR code supports both **KEY_EXCHANGE** and **PSK_EXCHANGE** methods. As a responder, PFR supports both methods because the method used by the requester side is unknown. As a requester, PFR supports only the **KEY_EXCHANGE** method due to the absence of a property in AFM indicating the key exchange method (see Table 26:8).

* The secure message format follows the definition in DSP-277 Spec. for mailbox messages. The function `encrypt_secure_content` and `decrypt_secure_content` are used to encrypt and decrypt the secure messages (see Table 26:9).

* Vendor-defined mailbox messages are exchanged over a secure session. Currently, the PFR code supports only **SPDM MEASUREMENT** and **mailbox commands** over a secure session (see Table 26:10).

* PFR can set a lock state. When lock mode is activated, all mailbox messages must be accepted over a secure session. Two scenarios exist for setting the lock state: provisioning data provided or provisioning state locked. Use the flag **CONFIG_SECURE_LOCK_MODE** to switch between these methods. In lock mode, communications over I2C/SMBus become read-only (see Table 26:12).

* Use the `aspeed-pfr-tool` to send vendor-defined mailbox messages over a secure session. Refer to the `how_to_test_secure_connection.md` document in the OpenBMC code for more information (see Table 26:13).

* The maximum MCTP packet size is **MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY = 1 KB** in the current PFR code base. According to Intel Spec. 814910, the maximum MCTP packet size should be **2 KB** (see Table 26:14).

* The PFR code supports concurrent requester and responder roles for secure sessions. This means PFR can perform SPDM attestation with a secure session and accept requests from `aspeed-pfr-tool` simultaneously. Note that during SPDM session creation, if an endpoint attempts to establish a secure connection, some states (e.g., **FINISH**) don't finish the session key exchanging, yet. This could lead to conflicts with concurrent sessions. Sessions should be created sequentially to avoid issues (see Table 26:15).

* Use the `create_secure_session` function to decide which device should establish a secure connection. By default, PFR establishes a secure connection with an I3C device.

* Once a secure session is established, SPDM attestation will use this session for measurements. Refer to the `spdm_attestation_with_session` function for more information.

* SPDM Heartbeats are sent every **CONFIG_PFR_HEARTBEAT_PERIOD** seconds (default is 60 seconds) after a session is created. If some device doesn't support heartbeat (e.g., heartbeat period is 0), PFR will not send a heartbeat to that device.

* If an operation fails after session creation, the session will be terminated. If PFR detects a BMC or host OS reboot event, the related session will be released (see the `spdm_disable_session` function for details).

* According to Intel Spec. 814910, re-key is required if a key has been used **10K** times. The spdm-emu should be updated to include this requirement, as the original code does not have such behavior.

* For testing purposes, enable the flag **SPDM_TERMINATE_SESSION_IMMEDIATELY** to create and terminate a session with every operation.
