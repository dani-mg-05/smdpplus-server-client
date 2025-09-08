import os, base64, random, binascii
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ, tag
from app.asn1_schemas import ServerSigned1, SmdpSigned2, StoreMetadataRequest, ControlRefTemplate, InitialiseSecureChannelRequest, BoundProfilePackage
from app.models import InitiateAuthenticationResponse, AuthenticateClientResponse, GetBoundProfilePackageResponse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import hashes, serialization

metadata = {}

def initiate_authentication_response(euicc_challenge: bytes, smdp_address: str) -> tuple[str, str]:
	transaction_id_bytes = os.urandom(16)
	transaction_id = transaction_id_bytes.hex().upper()
	server_challenge = os.urandom(16)

	ss1 = ServerSigned1()
	ss1.setComponentByName('transactionId', transaction_id_bytes)
	ss1.setComponentByName('euiccChallenge', euicc_challenge)
	ss1.setComponentByName('serverAddress', smdp_address)
	ss1.setComponentByName('serverChallenge', server_challenge)

	der_bytes = der_encoder.encode(ss1)
	server_signed_1 = base64.b64encode(der_bytes).decode()

	with open("certificates/smdp_auth_key.pem", "rb") as f:
		private_key = serialization.load_pem_private_key(f.read(), password=None)

	signature = private_key.sign(der_bytes, ec.ECDSA(hashes.SHA256()))
	server_signature_1 = base64.b64encode(signature).decode()

	with open("certificates/smdp_auth_cert.pem", "rb") as f:
		pem_data = f.read()

	cert = x509.load_pem_x509_certificate(pem_data, default_backend())
	der_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)

	server_certificate = base64.b64encode(der_bytes).decode()

	response = InitiateAuthenticationResponse(
		transactionId=transaction_id,
		serverSigned1=server_signed_1,
		serverSignature1=server_signature_1,
		serverCertificate=server_certificate,
	)

	return transaction_id, response

def authenticate_client_response(transaction_id: bytes, euicc_signature1: bytes) -> str:
	transaction_id_bytes = binascii.unhexlify(transaction_id)

	ss2 = SmdpSigned2()
	ss2.setComponentByName('transactionId', transaction_id_bytes)
	ss2.setComponentByName('ccRequiredFlag', False)

	der_bytes = der_encoder.encode(ss2)
	smdp_signed_2 = base64.b64encode(der_bytes).decode()

	to_sign = der_bytes + euicc_signature1

	with open("certificates/smdp_pb_key.pem", "rb") as f:
		private_key = serialization.load_pem_private_key(f.read(), password=None)

	signature = private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
	smdp_signature_2 = base64.b64encode(signature).decode()

	iccid_str = "8900101" + "".join([str(random.randint(0, 9)) for _ in range(13)])
	iccid_bytes = bytes.fromhex(iccid_str)

	storeMetadataRequest = StoreMetadataRequest()
	storeMetadataRequest.setComponentByName('iccid', iccid_bytes)
	storeMetadataRequest.setComponentByName('serviceProviderName', "OperadorTFM")
	storeMetadataRequest.setComponentByName('profileName', "PerfilTFM")
	storeMetadataRequest.setComponentByName('profileClass', 2)

	der_bytes = der_encoder.encode(storeMetadataRequest)
	profile_metadata = base64.b64encode(der_bytes).decode()

	metadata[transaction_id] = der_bytes

	with open("certificates/smdp_pb_cert.pem", "rb") as f:
		pem_data = f.read()

	cert = x509.load_pem_x509_certificate(pem_data, default_backend())
	der_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)

	smdp_certificate = base64.b64encode(der_bytes).decode()

	response = AuthenticateClientResponse(
		transactionId=transaction_id,
		profileMetadata=profile_metadata,
		smdpSigned2=smdp_signed_2,
		smdpSignature2=smdp_signature_2,
		smdpCertificate=smdp_certificate
	)

	return response

def get_bound_profile_package_response(transaction_id: bytes, euicc_otpk: bytes) -> str:
	transaction_id_bytes = binascii.unhexlify(transaction_id)

	crt = ControlRefTemplate().subtype(
		implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6)
	)
	crt.setComponentByName('keyType', b'\x88')
	crt.setComponentByName('keyLen', b'\x10')
	crt.setComponentByName('hostId', b"TFMHost".ljust(16, b"\x00"))

	smdp_otsk = ec.generate_private_key(ec.SECP256R1(), default_backend())
	smdp_otpk = smdp_otsk.public_key().public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	init_req = InitialiseSecureChannelRequest()
	init_req.setComponentByName('remoteOpId', 1)
	init_req.setComponentByName('transactionId', transaction_id_bytes)
	init_req.setComponentByName('controlRefTemplate', crt)
	init_req.setComponentByName('smdpOtpk', smdp_otpk)

	remoteOpId_der = der_encoder.encode(init_req.getComponentByName('remoteOpId'))
	transactionId_der = der_encoder.encode(init_req.getComponentByName('transactionId'))
	controlRefTemplate_der = der_encoder.encode(init_req.getComponentByName('controlRefTemplate'))
	smdpOtpk_der = der_encoder.encode(init_req.getComponentByName('smdpOtpk'))

	euicc_otpk_field = univ.OctetString(euicc_otpk).subtype(
		explicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 73)
	)

	toSign = remoteOpId_der + transactionId_der + controlRefTemplate_der + smdpOtpk_der + der_encoder.encode(euicc_otpk_field)

	with open("certificates/smdp_pb_key.pem", "rb") as f:
		private_key = serialization.load_pem_private_key(f.read(), password=None)

	smdp_sign = private_key.sign(toSign, ec.ECDSA(hashes.SHA256()))

	init_req.setComponentByName('smdpSign', smdp_sign)

	host_lv = bytes([len(b"TFMHost".ljust(16, b"\x00"))]) + b"TFMHost".ljust(16, b"\x00")
	eid_lv = bytes([len(b"")]) + b"" if b"" else bytes([0x00])
	euicc_pub = serialization.load_der_public_key(euicc_otpk, backend=default_backend())
	shared_secret = smdp_otsk.exchange(ec.ECDH(), euicc_pub)
	shared_info = b'\x88' + b'\x10' + host_lv + eid_lv

	L = 16
	total_len = 3 * L
	ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=total_len, otherinfo=shared_info, backend=default_backend())
	keydata = ckdf.derive(shared_secret)

	initial_mac = keydata[0:L]
	s_enc = keydata[L:2*L]
	s_mac = keydata[2*L:3*L]

	mac_chain = initial_mac
	icv_counter = 1

	payload87 = b"ConfigureISDP"
	tlv87, mac_chain, icv_counter = protect_encrypted_tlv(0x87, payload87, s_enc, s_mac, mac_chain, icv_counter)

	payload88 = metadata[transaction_id]
	tlv88, mac_chain, icv_counter = protect_maconly_tlv(0x88, payload88, s_mac, mac_chain, icv_counter)

	payload86 = b"ProtectedProfilePackage"
	tlv86, mac_chain, icv_counter = protect_encrypted_tlv(0x86, payload86, s_enc, s_mac, mac_chain, icv_counter)

	seq87 = make_sequence_of(7, [tlv87], 0)
	seq88 = make_sequence_of(8, [tlv88], 1)
	seq86 = make_sequence_of(6, [tlv86], 3)

	bpp = BoundProfilePackage()
	bpp.setComponentByName('initialiseSecureChannelRequest', init_req)
	bpp.setComponentByName('firstSequenceOf87', seq87)
	bpp.setComponentByName('sequenceOf88', seq88)
	bpp.setComponentByName('sequenceOf86', seq86)

	der_bytes = der_encoder.encode(bpp)
	bound_profile_package = base64.b64encode(der_bytes).decode()

	response = GetBoundProfilePackageResponse(
		transactionId=transaction_id,
		boundProfilePackage=bound_profile_package
	)

	return response

def make_sequence_of(tag_num, values, seq_tag):
	seq = univ.SequenceOf(
		componentType=univ.OctetString().subtype(
			explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_num)
		)
	).subtype(
		implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, seq_tag)
	)

	for v in values:
		seq.append(univ.OctetString(v).subtype(
			explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_num)
		))
	return seq

def encode_length(n: int) -> bytes:
	if n < 0x80:
		return bytes([n])
	elif n <= 0xFF:
		return bytes([0x81, n])
	elif n <= 0xFFFF:
		return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
	else:
		raise ValueError("length too large")
	
def compute_icv(s_enc: bytes, block_counter: int) -> bytes:
	counter_block = block_counter.to_bytes(16, 'big')
	cipher = Cipher(algorithms.AES(s_enc), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	return encryptor.update(counter_block) + encryptor.finalize()

def encrypt_with_icv(s_enc: bytes, block_counter: int, plaintext: bytes) -> bytes:
	iv = compute_icv(s_enc, block_counter)
	pad_len = (16 - ((len(plaintext) + 1) % 16)) % 16
	padded = plaintext + b'\x80' + (b'\x00' * pad_len)
	cipher = Cipher(algorithms.AES(s_enc), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	return encryptor.update(padded) + encryptor.finalize()

def compute_cmac_full_and_trunc(s_mac: bytes, mac_chaining_value: bytes, tag_byte: int, body: bytes):
	cmac = CMAC(algorithms.AES(s_mac), backend=default_backend())
	cmac_input = mac_chaining_value + bytes([tag_byte]) + encode_length(len(body)) + body
	cmac.update(cmac_input)
	full_mac = cmac.finalize()
	return full_mac, full_mac[:8]

def protect_encrypted_tlv(tag: int, payload: bytes, s_enc: bytes, s_mac: bytes, mac_chaining_value: bytes, icv_counter: int):
	ciphertext = encrypt_with_icv(s_enc, icv_counter, payload)
	full_mac, mac8 = compute_cmac_full_and_trunc(s_mac, mac_chaining_value, tag, ciphertext)
	tlv = bytes([tag]) + encode_length(len(ciphertext)) + ciphertext + mac8
	return tlv, full_mac, icv_counter + 1

def protect_maconly_tlv(tag: int, payload: bytes, s_mac: bytes, mac_chaining_value: bytes, icv_counter: int):
	full_mac, mac8 = compute_cmac_full_and_trunc(s_mac, mac_chaining_value, tag, payload)
	tlv = bytes([tag]) + encode_length(len(payload)) + payload + mac8
	return tlv, full_mac, icv_counter + 1
