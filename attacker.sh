#!/usr/bin/env bash
# 1. Intercept encrypted Premaster secret from external communication
# 2. Replace it with our_c in this robot attack script
# 3. perform attack to obtain Premaster secret
# 4. Use PRF HMac SHA256 to obtain master secret from Premaster secret
#   1. see org/bouncycastle/tls/crypto/impl/jcajce/JceDefaultTlsCredentialedDecryptor.java
#   2. above class decrypts the premastersecret (using rsa privkey) and instantiates the TlsSecret class (safeDecryptPreMasterSecret method line 75)
#   3. byte[] secret supplied in hmacHash() is premaster secret 
#   4. seed = ClientHello.random + ServerHello.random (TlsImplUtils: Arrays.concatenate(securityParameters.getServerRandom(), securityParameters.getClientRandom());)
# 5. Use master secret as AES key to decrypt any followig packet 

ifconfig

sleep 3
python3 attack.py