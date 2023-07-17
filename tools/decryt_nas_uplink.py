from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import *
from CryptoMobile.ECIES import *
from pycrate_mobile.TS24501_IE import *

import sys

# Print usage information
def print_usage():
    print("Usage: ")
    print("python my_program.py AUTN OP KEY SUPI NAS_PDU")
    print("  AUTN - the AUTN argument")
    print("  OP - the OP argument")
    print("  KEY - the KEY argument")
    print("  SUPI - the SUPI argument")
    print("  RAND - the RAND argument")
    print("  NAS_PDU - the NAS PDU argument")

# Check for help option
if len(sys.argv) > 1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
    print_usage()
    sys.exit()

# Check if all arguments are provided
if len(sys.argv) < 6:
    print("Error: not enough arguments provided!")
    print_usage()
    sys.exit()

AUTN = sys.argv[1]
OP = sys.argv[2]
KEY = sys.argv[3]
SUPI = sys.argv[4]
RAND = sys.argv[5]
NAS_PDU = sys.argv[6]


def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

OP = unhexlify(OP)
key = b'0C0A34601D4F07677303652C0462535B'
# c a 34 60 1d 4f 7 67 73 3 65 2c 4 62 53 5b 
key = unhexlify(KEY)
sqn_xor_ak = b'0' # sqn_xor_ak is the first 8 bytes of AUTN
sqn_xor_ak = unhexlify(sqn_xor_ak)
amf =  b'8000'
amf = unhexlify(amf)
mac =  b'0888d4e3e43c21ae' # mac should be the last 6 bytes of AUTN
mac = unhexlify(mac)
rand = unhexlify(RAND)
abba =  b'0000'
abba = unhexlify(abba)
supi = b'208950000000031' # this should be the SUPI in bytes

print("Creating Auth keys")
Mil = Milenage(OP)
# Mil.set_opc(make_OPc(key, OP))
Mil.set_opc(OP)
AK = Mil.f5star(key, rand)
print("AK: ", hexlify(AK))

SQN = byte_xor(AK, sqn_xor_ak)
# SQN = b'000000000600'
# SQN = unhexlify(SQN)
print("SQN: ", hexlify(SQN))

Mil.f1(key, rand, SQN=SQN, AMF=amf)
RES, CK, IK, AK  = Mil.f2345(key, rand)
print("RES: ", hexlify(RES))
print("CK: ", hexlify(CK))
print("IK: ", hexlify(IK))
print("AK: ", hexlify(AK))


sn_name = b"5G:mnc070.mcc999.3gppnetwork.org"
Res = conv_501_A4(CK, IK, sn_name, rand, RES)
print("Res: ", hexlify(Res))

# Get K_AUSF
k_ausf = conv_501_A2(CK, IK, sn_name, sqn_xor_ak)
print("K_AUSF: ", hexlify(k_ausf))
# Get K_SEAF
k_seaf = conv_501_A6(k_ausf, sn_name)
print("K_SEAF: ", hexlify(k_seaf))
# Get K_AMF
k_amf = conv_501_A7(k_seaf, supi, abba)
print("K_AMF: ", hexlify(k_amf))
# Get K_NAS_ENC
k_nas_enc = conv_501_A8(k_amf, alg_type=1, alg_id=1)
# Get least significate 16 bytes from K_NAS_ENC 32 bytes
k_nas_enc = k_nas_enc[16:]
print("K_NAS_ENC: ", hexlify(k_nas_enc))
# Get K_NAS_INT
k_nas_int = conv_501_A8(k_amf, alg_type=2, alg_id=2)
k_nas_int = k_nas_int[16:]
# k_nas_int = unhexlify('fbf4bfd78c4fe1a4dca0caabc49047f6')
print("K_NAS_INT: ", hexlify(k_nas_int))

print("..................Decoding EURANSIM generate msg...................")
EncMsg, e = parse_NAS5G(unhexlify(NAS_PDU))
print(".......................Enc Message...............................")
print(EncMsg.show())
print(".......................Enc Message...............................")

print(EncMsg.mac_verify(key=k_nas_int, dir=0, fgia=2, seqnoff=0, bearer=1))

EncMsg.decrypt(key=k_nas_enc, dir=0, fgea=2, seqnoff=0, bearer=1)

print(".......................Dec Message...............................")
print(hexlify(EncMsg._dec_msg))
print(".......................Dec Message...............................")

DecMsg, e = parse_NAS5G(EncMsg._dec_msg)
print(e)
print(".......................Dec Message...............................")
print(DecMsg.show())
print(".......................Dec Message...............................")