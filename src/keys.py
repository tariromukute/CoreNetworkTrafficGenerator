from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import *
from CryptoMobile.ECIES import *

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

AUTN=b'dfb47d96a93d800036d1a7dd22a3636d'
OP = b'63bfa50ee6523365ff14c1f45f88737d'
# 63 bf a5 e e6 52 33 65 ff 14 c1 f4 5f 88 73 7d 
OP = unhexlify(OP)
key = b'0c0a34601d4f07677303652c0462535b'
# c a 34 60 1d 4f 7 67 73 3 65 2c 4 62 53 5b 
key = unhexlify(key)
sqn_xor_ak =  b'dfb47d96a93d'
sqn_xor_ak = unhexlify(sqn_xor_ak)
amf =  b'8000'
amf = unhexlify(amf)
mac =  b'36d1a7dd22a3636d'
mac = unhexlify(mac)
rand =  b'356e006def61e6d3095e6bb3e6863c3f'
rand = unhexlify(rand)
abba =  b'0000'
abba = unhexlify(abba)
AK =  b'1db5c87a0e3b'
AK = unhexlify(AK)
SQN =  b'c201b5eca706'
SQN = unhexlify(SQN)
supi = b'208930000000001'
# RES:  b'522236971106f317'
# CK:  b'3abacc0615ad58601b7c5736ee05cc18'
# IK:  b'855e74add04cb7d8a30c2c2a2f023b7c'
# Res:  b'a6dcb73641d32e7301805c51ae336255'
# K_AUSF:  b'dd27fc9ff0e12d46664856256c31b8ac09e9d225b8b6b99da292677bfd57f543'
# K_SEAF:  b'909ddfe98d24a41eb12808d0cbde71cb29a18e3b2e6efac0e46e933beffc3a08'
# K_AMF:  b'af074d0ef08a320e4e2149c56dcaff0dc77b1e02027220c845f5f141f3f8624e'
# K_NAS_ENC:  b'd9dbb55f1d72702b34dba24f90e8d857'
# K_NAS_INT:  b'c680824855437a9c6e50260350e7c815'


Mil = Milenage(OP)
# Mil.set_opc(make_OPc(key, OP))
Mil.set_opc(OP)
AK = Mil.f5star(key, rand)
print("AK: ", hexlify(AK))

Mil.f1(key, rand, SQN=SQN, AMF=amf)
RES, CK, IK, AK  = Mil.f2345(key, rand)
print("RES: ", hexlify(RES))
print("CK: ", hexlify(CK))
print("IK: ", hexlify(IK))
print("AK: ", hexlify(AK))

SQN = byte_xor(AK, sqn_xor_ak)
# SQN = b'000000000600'
# SQN = unhexlify(SQN)
print("SQN: ", hexlify(SQN))

sn_name = b"5G:mnc095.mcc208.3gppnetwork.org"
Res = conv_501_A4(CK, IK, sn_name, rand, RES)
print("Res: ", hexlify(Res))

IEs = {}
IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87 }
IEs['RES'] = { 'V': Res }
Msg = FGMMAuthenticationResponse(val=IEs)

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
print("K_NAS_INT: ", hexlify(k_nas_int))

