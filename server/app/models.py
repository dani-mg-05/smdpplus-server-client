from pydantic import BaseModel
from typing import Optional

class InitiateAuthenticationRequest(BaseModel):
	euiccChallenge: str
	euiccInfo1: str
	smdpAddress: str

class InitiateAuthenticationResponse(BaseModel):
	transactionId: str
	serverSigned1: str
	serverSignature1: str
	serverCertificate: str

class AuthenticateClientRequest(BaseModel):
	transactionId: str
	authenticateServerResponse: str

class AuthenticateClientResponse(BaseModel):
	transactionId: str
	profileMetadata: str
	smdpSigned2: str
	smdpSignature2: str
	smdpCertificate: str

class GetBoundProfilePackageRequest(BaseModel):
	transactionId: str
	prepareDownloadResponse: str

class GetBoundProfilePackageResponse(BaseModel):
	transactionId: str
	boundProfilePackage: str

class ResultData(BaseModel):
	message: Optional[str] = None
	details: Optional[str] = None

class Es9Error(BaseModel):
	resultCode: int
	resultData: Optional[ResultData] = None
