package com.example.cliente_sm_dp_plus;

import java.io.IOException;
import java.security.SecureRandom;

import android.util.Base64;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class EUICC {
    public EUICC() {}

    public String GetEUICCChallenge() {
        byte[] challenge = new byte[16];
        new SecureRandom().nextBytes(challenge);
        return Base64.encodeToString(challenge, Base64.NO_WRAP);
    }

    public String GetEUICCInfo() {
        try {
            ASN1EncodableVector seq = new ASN1EncodableVector();

            byte[] lowestSvn = new byte[]{0x03, 0x01, 0x00};
            seq.add(new DERTaggedObject(true, 2, new DEROctetString(lowestSvn)));

            ASN1EncodableVector euiccCiPKIdListForVerification = new ASN1EncodableVector();
            euiccCiPKIdListForVerification.add(new DEROctetString(randomSubjectKeyIdentifier()));
            seq.add(new DERTaggedObject(true, 9, new DERSequence(euiccCiPKIdListForVerification)));

            ASN1EncodableVector euiccCiPKIdListForSigning = new ASN1EncodableVector();
            euiccCiPKIdListForSigning.add(new DEROctetString(randomSubjectKeyIdentifier()));
            seq.add(new DERTaggedObject(true, 10, new DERSequence(euiccCiPKIdListForSigning)));

            DERTaggedObject euiccInfo1 = new DERTaggedObject(true, 32, new DERSequence(seq));
            byte[] der = euiccInfo1.getEncoded(ASN1Encoding.DER);

            return Base64.encodeToString(der, Base64.NO_WRAP);
        } catch (IOException e) {
            throw new RuntimeException("Error encoding EuiccInfo1", e);
        }
    }

    private byte[] randomSubjectKeyIdentifier() {
        byte[] ski = new byte[20];
        new SecureRandom().nextBytes(ski);
        return ski;
    }
}
