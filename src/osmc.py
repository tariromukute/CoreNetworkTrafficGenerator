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

AUTN=b'85bde878bd8f8000fa20c4b9b867ca98'
OP = b'E8ED289DEBA952E4283B54E88E6183CA'
# 63 bf a5 e e6 52 33 65 ff 14 c1 f4 5f 88 73 7d 
OP = unhexlify(OP)
key = b'465B5CE8B199B49FAA5F0A2EE238A6BC'
# c a 34 60 1d 4f 7 67 73 3 65 2c 4 62 53 5b 
key = unhexlify(key)
sqn_xor_ak =  b'85bde878bd8f'
sqn_xor_ak = unhexlify(sqn_xor_ak)
amf =  b'8000'
amf = unhexlify(amf)
mac =  b'fa20c4b9b867ca98'
mac = unhexlify(mac)
rand =  b'4be366391b0a65a22948f118c67a973e'
rand = unhexlify(rand)
abba =  b'0000'
abba = unhexlify(abba)
supi = b'999700000000001'

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
k_nas_enc = conv_501_A8(k_amf, alg_type=1, alg_id=2)
# Get least significate 16 bytes from K_NAS_ENC 32 bytes
k_nas_enc = k_nas_enc[16:]
print("K_NAS_ENC: ", hexlify(k_nas_enc))
# Get K_NAS_INT
k_nas_int = conv_501_A8(k_amf, alg_type=1, alg_id=2)
k_nas_int = k_nas_int[16:]
print("K_NAS_INT: ", hexlify(k_nas_int))

RegIEs = {}
RegIEs['5GSUpdateType'] = {'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0 }
RegIEs['5GMMCap'] = {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0, '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0 }
# TODO: Add NSSAI to RegIEs

# RegMsg = FGMMRegistrationRequest(val=RegIEs)
# RegMsg, _ = RegistrationProc().initiate(ue)
# Add the RegIEs to the RegMsg

# Send Security Mode Complete
IEs = {}
IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': 4, 'Digits': '370816125816151'}
Msg = FGMMSecurityModeComplete(val=IEs)

print(Msg.show())
# Encrypt NAS message
IEs = {}
IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
SecMsg = FGMMSecProtNASMessage(val=IEs)

print(SecMsg.show())

SecMsg['NASMessage'].set_val(Msg.to_bytes())
SecMsg.encrypt(key=k_nas_enc, dir=0, fgea=2, seqnoff=0, bearer=1)
SecMsg.mac_compute(key=k_nas_int, dir=0, fgia=2, seqnoff=0, bearer=1)

print(SecMsg.show())

print(hexlify(SecMsg.to_bytes()))