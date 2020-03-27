from Crypto.Util.Padding import unpad
import hmac
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random


"""
Deriving the pre-master secret
"""
# a = '0002fff62666aa9b8cc8b6f733baac0bafe1bf30afc1611950d5ee9c08695aef9af3b49d166b33bf1ad00ffb3d3b3574bb47f0d80664c630bfa6da38ee183c5c2285c3608d9e3257a6ff87db38069ef0c6380a1acf97c68808219fab3137b26780a1840be6cffa2437aeba08e956c76306169821dfbd8da9974bd30e98acfde6e153bb989a430c97a2a0c99ce6cf98c63afba7af87cd09f6d1682fdac36958840724004acb6dd8b2f3d56d3315915471f62e4921ac479fe447e8faf57c83a4b5aff2f21cd93de36bf028fc6151f9de73e1e499ab4c0f9ffa5168b12376b39e1398c441b13682b360102ca1dff957009ba5bd9250b1874407c5250f8ceaa413cd'
# h = bytes.fromhex(a[-48:])
# a='a918f2ba6ee3a018012ae4ed916a78967df113612489f6c5'
a = hex(1479352532670236096337191803165862508976526821519030386320025990324010532995639537361138759746006378133278887130011059224401888231013614017449782942532993879958535204342890647323666258411586712154544699320742991646573559141130208461361116269471509743414742862779763988136304389092701388571369157528596551233158773035298395226637452021442620704285201481264907605215774051339072453184836339173679448799025247086267755326494222099925616189081434474304670893981059302670905614212206236583983026975874629468845678169268096695908141712024459264525395777176527439582173616679307726953040069289617537594054658210054181421)
print(a.find('0303'))
h = bytes.fromhex(a[-48:])


"""
Initiating Random bytes and seed
"""
# client_random = bytes.fromhex("bdee0f7c82a02e05414b024fe6866c5c5b572d1d11224966fc46b57383fa6d33")
# server_random = bytes.fromhex("89c2c49b51db7977a55bed3c31ce98e5a3c202086e1b1af7154c65798f326fd8")
# client_random = b'c1313ff251c0a18b94d2893ec9496effd49152b11ef48531f9c03e559c1100bb'
# server_random = b'66326665626139346261336566626561346634313461336433343434373132316263643933646232666331363761363966363263633337373536333539646539'
client_random = bytes.fromhex("b563b07a16ff193dc8a4e89a3c9151193ce23f15d373799f6b238c4d6f0befe3")
server_random = bytes.fromhex("0128e2178699b017e8e259df978f86ed74854649be09fb0ae1a12027c2692398")
# print(len(client_random))
seed0 = client_random + server_random # the seed to be concatenated to the label in case of PRFs, according to the RFC
print("Seed0 -> ", seed0.hex())
# tls_version = tls.TLSV1_2
# algorithm = encryption_algorithms.AES
# prf = prf(tls_version, algorithm, h, b'master secret', seed, 48)

"""
Calculating P_Hash function and deriving the master secret. In this case the master key is the first 48 bytes of P_hash
"""
label = b'master secret'
seed1 = label + seed0
print("A0 -> ", seed1.hex())
A0 = seed1
A1 = hmac.new(h, A0, digestmod=hashlib.sha256).digest()
A2 = hmac.new(h, A1, digestmod=hashlib.sha256).digest()
P_hash = hmac.new(h, A1+seed1, digestmod=hashlib.sha256).digest() + hmac.new(h, A2+seed1, digestmod=hashlib.sha256).digest()
# signature = base64.b64encode(prf).decode()
# print(len(signature))
# print(prf)
# print(len(prf))
# print(P_hash.hex())
# print(len(P_hash))
master_secret = P_hash[:48]
print("Master Secret -> ", master_secret.hex())

# the encrypted (application) data to be decrypted.
data = '0960ba5ab6337ed3afaaf1424e482f90e3e6507741626c919a25b8f147aa8fb5a24fda6979fa5c9b32953bdf77c1b1fca70dbcc01b299e4444139288c4b97a28c65f9eb22951f5ad1b1b138409a8fecd66edfbefcc031a4d63eabc324d2fe59b9fdddcd7305254dae08d61c129434d8ee36f9e5bcb4b6a4bc84bdc4aba926ec049780fa42a75eb163d3204abc1bac10f38fad9865ecb66f402eb7519eb99241f0ec067206c3eb73470b8e8c5f5393a5632ea24b6179bc53f9ddd8fccde5eab2690c78a8deb51d00075b46ab8f62e55b593d30becf87b5c42b51e099267df8bf16fb8bda21b9ad69b02fc9e174b68e8ac3b01860f9db812c99c3ece53db7a2d3c5f2dc9e14915c0385fca1b193402aff88791e034e062c08f062d7d13d3c6184b78d77b9642396ffad9e50ffeb23bb685b4373aa43f0531e2cb776916ac199be7f7d7dc4d4906b7a504433837858e1b6d60aac219ae7f9571bb68808d973c853b84997326178b472cc4ce4d544326a1e2'
app_data = bytes.fromhex(data)

"""
Deriving the AES key parameters from the master secret

To generate the key material, compute

      key_block = PRF(SecurityParameters.master_secret,
                      "key expansion",
                      SecurityParameters.server_random +
                      SecurityParameters.client_random);

until enough output has been generated.  Then, the key_block is partitioned as follows:

      client_write_MAC_key[SecurityParameters.mac_key_length]
      server_write_MAC_key[SecurityParameters.mac_key_length]
      client_write_key[SecurityParameters.enc_key_length]
      server_write_key[SecurityParameters.enc_key_length]
      client_write_IV[SecurityParameters.fixed_iv_length]
      server_write_IV[SecurityParameters.fixed_iv_length]

P_hash2 contains the required bytes for the above keys.
"""

master_seed = b'key expansion' + seed0  # seed to be used while deriving the keys from the master key
master_0 = master_seed
master_1 = hmac.new(master_secret, master_0, digestmod=hashlib.sha256).digest()
master_2 = hmac.new(master_secret, master_1, digestmod=hashlib.sha256).digest()
master_3 = hmac.new(master_secret, master_2, digestmod=hashlib.sha256).digest()
master_4 = hmac.new(master_secret, master_3, digestmod=hashlib.sha256).digest()
P_hash2 = hmac.new(master_secret, master_1+master_seed, digestmod=hashlib.sha256).digest() + hmac.new(master_secret, master_2+master_seed, digestmod=hashlib.sha256).digest()+hmac.new(master_secret, master_3+master_seed, digestmod=hashlib.sha256).digest()#+hmac.new(master_secret, master_4+master_seed, digestmod=hashlib.sha256).digest()
# print(len(P_hash2))

"""
Defining keys and the AES cipher to be used to decrypt the message
"""
client_write_key = P_hash2[32:48]
client_iv = P_hash2[64:80]
# print(len(client_iv),len(client_write_key))
cipher = AES.new(client_write_key, AES.MODE_CBC, client_iv) # defining the cipher
# d = unpad(cipher.decrypt(app_data),16) # using unpad to detect and correct the padding used in CBC mode. Currently doesn't seem to be working. :(
d = cipher.decrypt(app_data) # decrypting the message
print(d.hex())
