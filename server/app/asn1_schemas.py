from pyasn1.type import univ, char, namedtype, tag, constraint

class Octet1(univ.OctetString):
	subtypeSpec = constraint.ValueSizeConstraint(1, 1)

class Octet16(univ.OctetString):
	subtypeSpec = constraint.ValueSizeConstraint(16, 16)

class OctetTo16(univ.OctetString):
	subtypeSpec = constraint.ValueSizeConstraint(1, 16)

class TransactionId(univ.OctetString):
	subtypeSpec = constraint.ValueSizeConstraint(1, 16)

class Iccid(univ.OctetString):
	tagSet = univ.OctetString.tagSet.tagExplicitly(
		tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 26)
	)
	subtypeSpec = constraint.ValueSizeConstraint(10, 10)

class ProfileClass(univ.Integer):
	namedValues = univ.Integer.namedValues.clone(
		test = 0,
		provisioning = 1,
		operational = 2
	)

class ServerSigned1(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType(
			'transactionId',
			TransactionId().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
			)
		),
		namedtype.NamedType(
			'euiccChallenge',
			Octet16().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
			)
		),
		namedtype.NamedType(
			'serverAddress',
			char.UTF8String().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
			)
		),
		namedtype.NamedType(
			'serverChallenge',
			Octet16().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
			)
		),
	)

class StoreMetadataRequest(univ.Sequence):
	tagSet = univ.Sequence.tagSet.tagExplicitly(
		tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 37)
	)
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('iccid', Iccid()),
		namedtype.NamedType(
			'serviceProviderName',
			char.UTF8String().subtype(
				subtypeSpec=constraint.ValueSizeConstraint(0, 32),
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)
			)
		),
		namedtype.NamedType(
			'profileName',
			char.UTF8String().subtype(
				subtypeSpec=constraint.ValueSizeConstraint(0, 64),
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 18)
			)
		),
		namedtype.DefaultedNamedType(
			'profileClass',
			ProfileClass(2).subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 21)
			)
		)
	)

class SmdpSigned2(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType(
			'transactionId',
			TransactionId().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
			)
		),
		namedtype.NamedType('ccRequiredFlag', univ.Boolean())
	)

class RemoteOpId(univ.Integer):
	tagSet = univ.Integer.tagSet.tagExplicitly(
		tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
	)
	namedValues = univ.Integer.namedValues.clone(
		installBoundProfilePackage=1
	)

class ControlRefTemplate(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType(
			'keyType',
			Octet1().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
			)
		),
		namedtype.NamedType(
			'keyLen',
			Octet1().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
			)
		),
		namedtype.NamedType(
			'hostId',
			OctetTo16().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
			)
		)
	)

class InitialiseSecureChannelRequest(univ.Sequence):
	tagSet = univ.Sequence.tagSet.tagExplicitly(
		tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 35)
	)
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('remoteOpId', RemoteOpId()),
		namedtype.NamedType(
			'transactionId',
			TransactionId().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
			)
		),
		namedtype.NamedType(
			'controlRefTemplate',
			ControlRefTemplate().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6)
			)
		),
		namedtype.NamedType(
			'smdpOtpk',
			univ.OctetString().subtype(
				explicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 73)
			)
		),
		namedtype.NamedType(
			'smdpSign',
			univ.OctetString().subtype(
				explicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 55)
			)
		)
	)

class BoundProfilePackage(univ.Sequence):
	tagSet = univ.Sequence.tagSet.tagExplicitly(
		tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 54)
	)
	componentType = namedtype.NamedTypes(
		namedtype.NamedType(
			'initialiseSecureChannelRequest',
			InitialiseSecureChannelRequest().subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 35)
			)
		),
		namedtype.NamedType(
			'firstSequenceOf87',
			univ.SequenceOf(componentType=univ.OctetString().subtype(
				explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
			)).subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
			)
		),
		namedtype.NamedType(
			'sequenceOf88',
			univ.SequenceOf(componentType=univ.OctetString().subtype(
				explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)
			)).subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
			)
		),
		namedtype.NamedType(
			'sequenceOf86',
			univ.SequenceOf(componentType=univ.OctetString().subtype(
				explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
			)).subtype(
				implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
			)
		)
	)
