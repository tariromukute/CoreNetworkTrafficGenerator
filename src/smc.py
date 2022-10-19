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

AUTN=b'4db0dc59fa4480009971828e5aca723a'
OP = b'63bfa50ee6523365ff14c1f45f88737d'
# 63 bf a5 e e6 52 33 65 ff 14 c1 f4 5f 88 73 7d 
OP = unhexlify(OP)
key = b'0c0a34601d4f07677303652c0462535b'
# c a 34 60 1d 4f 7 67 73 3 65 2c 4 62 53 5b 
key = unhexlify(key)
sqn_xor_ak =  b'4db0dc59fa44'
sqn_xor_ak = unhexlify(sqn_xor_ak)
amf =  b'8000'
amf = unhexlify(amf)
mac =  b'9971828e5aca723a'
mac = unhexlify(mac)
rand =  b'a419154a2c51f9d49db365764093550b'
rand = unhexlify(rand)
abba =  b'0000'
abba = unhexlify(abba)
supi = b'208950000000031'
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
print("K_NAS_INT: ", hexlify(k_nas_int))

# Send Security Mode Complete
IEs = {}
IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
IEs['IMEISV'] = unhexlify('0035609204079514')
IEs['NASContainer'] = unhexlify('7e004179000d0102f8590000000000000000132e04f0f0f0f0')
# 25f5f12de488dbc1982aa419ceff540122079c7e4807420f5aca1c0e26ef69107b564924ceedcf99fb170e9e26a2f3ba8b874cf6c0b90c50
# 7337a893f4e04039a8c9cacdcacc8fa65d10381ac12dcc1d6dd9cbe908774f366b55bb20825e6d2b8ae32a6ea933661fda1126b2bc5c3873
Msg = FGMMSecurityModeComplete(val=IEs)
print(Msg)
print("=======================")
print(hexlify(Msg.to_bytes()))
print("=======================")
# Encrypt NAS message
IEs = {}
IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
SecMsg = FGMMSecProtNASMessage(val=IEs)
SecMsg['NASMessage'].set_val(Msg.to_bytes())
SecMsg.mac_compute(key=k_nas_int, dir=0, fgia=1, seqnoff=0, bearer=1)
SecMsg.encrypt(key=k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)
print("SecMsg._dec_msg", hexlify(SecMsg._dec_msg))
print("=======================")
print("SecMsg._enc_msg. Should equal uplink", hexlify(SecMsg._enc_msg))
print("=======================")
print('44c29abe225a469ae2b87119edc98c8919f4691be57fe12bdc2eb58937c77ba3423268e13765b2a70969ae770de854caddf6c7b3f41948c8')
print(hexlify(SecMsg['NASMessage'].get_val()))
print(SecMsg)

EncMsg, e = parse_NAS5G(unhexlify('7e04c11467500044c29abe225a469ae2b87119edc98c8919f4691be57fe12bdc2eb58937c77ba3423268e13765b2a70969ae770de854caddf6c7b3f41948c8'))
print(EncMsg)
print("=======================")
EncMsg.decrypt(key=k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)
print(hexlify(EncMsg._dec_msg))
print("=======================")
print(hexlify(EncMsg._enc_msg))
print("=======================")

DecMsg, e = parse_NAS5G(EncMsg._dec_msg)
print(DecMsg)
print("=======================")
