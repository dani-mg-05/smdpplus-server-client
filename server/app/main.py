from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from app.models import *
from app.build_responses import initiate_authentication_response, authenticate_client_response, get_bound_profile_package_response
from typing import Optional
from io import BytesIO
from base64 import b64decode
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ
import qrcode, base64

app = FastAPI()

transactions = []

# Root path
@app.get("/", response_class=HTMLResponse)
async def root_route():
	with open("app/html/root.html", "r") as file:
		return HTMLResponse(content=file.read())

# InitiateAuthentication path
@app.post("/gsma/rsp2/es9plus/initiateAuthentication", response_model=InitiateAuthenticationResponse)
async def initiate_authentication(payload: InitiateAuthenticationRequest):
	print(payload)

	try:
		if not payload.euiccChallenge:
			return es9_error_response(10, "Missing euiccChallenge")
		
		try:
			euicc_challenge_bytes = base64.b64decode(payload.euiccChallenge)
		except Exception:
			return es9_error_response(11, "Invalid Base64 in euiccChallenge")

		if len(euicc_challenge_bytes) != 16:
			return es9_error_response(12, "euiccChallenge must be 16 bytes")

		if "." not in payload.smdpAddress:
			return es9_error_response(13, "Invalid smdpAddress format")

		transaction_id, response = initiate_authentication_response(euicc_challenge_bytes, payload.smdpAddress)

		transactions.append(transaction_id)

		return response

	except FileNotFoundError as e:
		return es9_error_response(20, "Server configuration error", str(e))

	except Exception as e:
		return es9_error_response(99, "Unexpected internal error", str(e))

# AuthenticateClient path
@app.post("/gsma/rsp2/es9plus/authenticateClient", response_model=AuthenticateClientResponse)
async def authenticate_client(payload: AuthenticateClientRequest):
	print(payload)

	try:
		if payload.transactionId in transactions:
			der_bytes = b64decode(payload.authenticateServerResponse)

			idx = der_bytes.find(b'\x5F\x37')

			length_byte = der_bytes[idx+2]
			if length_byte < 0x80:
				length = length_byte
				value_start = idx + 3
			else:
				num_bytes = length_byte & 0x7F
				length = int.from_bytes(der_bytes[idx+3: idx+3+num_bytes], "big")
				value_start = idx + 3 + num_bytes

			euicc_signature1 = der_bytes[value_start:value_start+length]

			return authenticate_client_response(payload.transactionId, euicc_signature1)

	except Exception as e:
		return es9_error_response(99, "Unexpected internal error", str(e))

# GetBoundProfilePackage path
@app.post("/gsma/rsp2/es9plus/getBoundProfilePackage", response_model=GetBoundProfilePackageResponse)
async def get_bound_profile_package(payload: GetBoundProfilePackageRequest):
	print(payload)

	try:
		if payload.transactionId in transactions:
			der_bytes = b64decode(payload.prepareDownloadResponse)

			idx = der_bytes.find(b'\x7F\x49')

			length_byte = der_bytes[idx+2]
			if length_byte < 0x80:
				length = length_byte
				value_start = idx + 3
			else:
				num_bytes = length_byte & 0x7F
				length = int.from_bytes(der_bytes[idx+3: idx+3+num_bytes], "big")
				value_start = idx + 3 + num_bytes

			value = der_bytes[value_start: value_start+length]

			octet_string, _ = der_decoder.decode(value, asn1Spec=univ.OctetString())
			euicc_otpk = bytes(octet_string)

			inner_len = value[1]
			euicc_otpk = value[2:2+inner_len]

			response = get_bound_profile_package_response(payload.transactionId, euicc_otpk)
			transactions.remove(payload.transactionId)
			return response

	except Exception as e:
		return es9_error_response(99, "Unexpected internal error", str(e))

# QR path
@app.get("/qr")
async def generate_qr():
	data = "LPA:1$esim.daniel-medina.engineer$ABCDE-12345"
	qr = qrcode.make(data)

	buf = BytesIO()
	qr.save(buf, format="PNG")
	buf.seek(0)
	return StreamingResponse(buf, media_type="image/png")

def es9_error_response(code: int, message: str, details: Optional[str] = None):
	error = Es9Error(
		resultCode=code,
		resultData=ResultData(message=message, details=details)
	)
	return JSONResponse(status_code=400, content=error.dict())
