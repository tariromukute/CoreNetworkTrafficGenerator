from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import *
from CryptoMobile.ECIES import *
from pycrate_mobile.TS24501_IE import *

# NSSAI.CLASS
# NSSAI._GEN
def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

AUTN=b'3542f389174880007a003fecf436ab86'
OP = b'8e27b6af0e692e750f32667a3b14605d'
# 63 bf a5 e e6 52 33 65 ff 14 c1 f4 5f 88 73 7d 
OP = unhexlify(OP)
key = b'8baf473f2f8fd09487cccbd7097c6862'
# c a 34 60 1d 4f 7 67 73 3 65 2c 4 62 53 5b 
key = unhexlify(key)
sqn_xor_ak =  b'3542f3891748'
sqn_xor_ak = unhexlify(sqn_xor_ak)
amf =  b'8000'
amf = unhexlify(amf)
mac =  b'7a003fecf436ab86'
mac = unhexlify(mac)
rand =  b'5e9b6d3db90cec9f861efb30cc10009b'
rand = unhexlify(rand)
abba =  b'0000'
abba = unhexlify(abba)
supi = '208930000000003'

print("Creating Auth keys")
Mil = Milenage(OP)
# Mil.set_opc(OP)
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


sn_name = b"5G:mnc093.mcc208.3gppnetwork.org"
Res = conv_501_A4(CK, IK, sn_name, rand, RES)
print("Res: ", hexlify(Res))

# Get K_AUSF
k_ausf = conv_501_A2(CK, IK, sn_name, sqn_xor_ak)
print("K_AUSF: ", hexlify(k_ausf))
# Get K_SEAF
k_seaf = conv_501_A6(k_ausf, sn_name)
print("K_SEAF: ", hexlify(k_seaf))
# Get K_AMF
k_amf = conv_501_A7(k_seaf, supi.encode('ascii'), abba)
print("K_AMF: ", hexlify(k_amf))
# Get K_NAS_ENC
k_nas_enc = conv_501_A8(k_amf, alg_type=1, alg_id=1)
# Get least significate 16 bytes from K_NAS_ENC 32 bytes
k_nas_enc = k_nas_enc[16:]
print("K_NAS_ENC: ", hexlify(k_nas_enc))
# Get K_NAS_INT
k_nas_int = conv_501_A8(k_amf, alg_type=2, alg_id=1)
k_nas_int = k_nas_int[16:]
print("K_NAS_INT: ", hexlify(k_nas_int))

# ue.k_nas_enc  b'a2a08b79f7627a9761e53b6055cf8f269c48a94ce3eaddb2d786cd83ed5fdab3' b'9c48a94ce3eaddb2d786cd83ed5fdab3'
# ue.k_nas_enc  b'eea4d30e5cffe985e9149047d9f9708a28e779ff8632fafcef74595df3777051' b'28e779ff8632fafcef74595df3777051'
# Send Security Mode Complete
print("Creating SM Complete..................")
RegIEs = {}
RegIEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65 }
# RegIEs['NAS_KSI'] = NAS_KSI(val={ 'TSC': 0, 'Value': 7 })
RegIEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
RegIEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
RegIEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': '20895', 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': b'\x00\x00\x00\x00\x13'} }
RegIEs['UESecCap'] = { '5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0 }

RegIEs['5GSUpdateType'] = {'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0 }
RegIEs['5GMMCap'] = {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0, '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0 }
RegIEs['NSSAI'] = [{ 'SNSSAI': { 'SST': 222, 'SD': 0x00007b } }]

RegMsg = FGMMRegistrationRequest(val=RegIEs)

print(".......................Start Generated Reg Message...............................")
print(RegMsg.show())
print(".......................End Generated Reg Message...............................")

print("Creating Security Mode Control")
IEs = {}
IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': 0, 'Digits': '035609204079514'}
IEs['NASContainer'] = { }

Msg = FGMMSecurityModeComplete(val=IEs)
Msg['NASContainer']['V'].set_val(RegMsg.to_bytes())

print(".......................Start Sec Dec Message...............................")
print(Msg.show())
print(".......................End Sec Dec Message...............................")

# Encrypt NAS message
print("Encrypting Security Mode Control")
IEs = {}
IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
SecMsg = FGMMSecProtNASMessage(val=IEs)
SecMsg['NASMessage'].set_val(Msg.to_bytes())

print(".......................Start Sec Dec Message...............................")
print(SecMsg.show())
print(".......................End Sec Dec Message...............................")
SecMsg.mac_compute(key=k_nas_int, dir=0, fgia=1, seqnoff=0, bearer=1)
SecMsg.encrypt(key=k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)

print(".......................Start Sec Message...............................")
print(SecMsg.show())
print(".......................End Sec Message...............................")

print("..................Decoding EURANSIM generate msg...................")
EncMsg, e = parse_NAS5G(unhexlify('7e047f4b39830054da88996d544ac57ff9099878dd59e62149f6f297378fc95a371c02a934e12d509ad0550752b9a86196b8442295b79b58'))
print(".......................Enc Message...............................")
print(EncMsg.show())
print(".......................Enc Message...............................")

EncMsg.decrypt(key=k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)

DecMsg, e = parse_NAS5G(EncMsg._dec_msg)
print(e)
print(".......................Dec Message...............................")
print(DecMsg.show())
print(".......................Dec Message...............................")