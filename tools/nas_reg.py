from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import *
from CryptoMobile.ECIES import *
from pycrate_mobile.TS24501_IE import *

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

AUTN=b'b54abf5b068880000888d4e3e43c21ae'
OP = b'63bfa50ee6523365ff14c1f45f88737d'
# 63 bf a5 e e6 52 33 65 ff 14 c1 f4 5f 88 73 7d 
OP = unhexlify(OP)
key = b'0c0a34601d4f07677303652c0462535b'
# c a 34 60 1d 4f 7 67 73 3 65 2c 4 62 53 5b 
key = unhexlify(key)
sqn_xor_ak =  b'b54abf5b0688'
sqn_xor_ak = unhexlify(sqn_xor_ak)
amf =  b'8000'
amf = unhexlify(amf)
mac =  b'0888d4e3e43c21ae'
mac = unhexlify(mac)
rand =  b'78c5aa53d14c2af655970a08ac5388ca'
rand = unhexlify(rand)
abba =  b'0000'
abba = unhexlify(abba)
supi = b'208950000000031'

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


sn_name = b"5G:mnc095.mcc208.3gppnetwork.org"
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
k_nas_int = conv_501_A8(k_amf, alg_type=1, alg_id=2)
k_nas_int = k_nas_int[16:]
# k_nas_int = unhexlify('fbf4bfd78c4fe1a4dca0caabc49047f6')
print("K_NAS_INT: ", hexlify(k_nas_int))

nas_pdu = "7e02fa0292e702621fd7863a5cb16bf02138d1c77922dd1f6b0525c9970799de89f71eab660dd03853ddcec0c95d3f92f9c81424be"

print("..................Decoding EURANSIM generate msg...................")
EncMsg, e = parse_NAS5G(unhexlify(nas_pdu))
print(".......................Enc Message...............................")
print(EncMsg.show())
print(".......................Enc Message...............................")

EncMsg.decrypt(key=k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)

print(".......................Dec Message...............................")
print(hexlify(EncMsg._dec_msg))
print(".......................Dec Message...............................")

DecMsg, e = parse_NAS5G(EncMsg._dec_msg)
print(".......................Dec Message...............................")
print(DecMsg.show())
print(".......................Dec Message...............................")