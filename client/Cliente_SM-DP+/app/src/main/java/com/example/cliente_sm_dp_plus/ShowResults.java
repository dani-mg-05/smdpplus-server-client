package com.example.cliente_sm_dp_plus;

import android.content.Context;
import android.content.res.AssetManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;

import Peticiones.AuthenticateClient;
import Peticiones.GetBoundProfilePackage;
import Peticiones.InitiateAuthentication;

public class ShowResults extends AppCompatActivity {

    LinearLayout resultsLayout;
    String server;
    String activationCode;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_show_results);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        String qrCode = getIntent().getStringExtra("qrCode");
        String[] sections = qrCode.split("\\$");

        if (!sections[1].startsWith("https://") && !sections[1].startsWith("http://")) {
            sections[1] = "https://" + sections[1];
        }

        server = sections[1];
        activationCode = sections[2];

        resultsLayout = findViewById(R.id.resultsLayout);

        try {
            startCommunication(resultsLayout);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void startCommunication(LinearLayout layout) {
        EUICC euicc = new EUICC();

        InitiateAuthentication initiateAuthentication = new InitiateAuthentication(
            euicc.GetEUICCChallenge(),
            euicc.GetEUICCInfo(),
            server.split("://")[1]
        );

        initAuth(layout, server, initiateAuthentication.toJsonString());
    }

    private void initAuth(LinearLayout layout, String serverName, String requestJson) {
        sendMessage(layout, serverName + "/gsma/rsp2/es9plus/initiateAuthentication", requestJson, responseJson -> {
            String transactionId = getJsonElement(responseJson, "transactionId");
            String serverSigned1 = getJsonElement(responseJson, "serverSigned1");

            byte[] serverSigned1Der = java.util.Base64.getDecoder().decode(serverSigned1);
            ASN1Sequence serverSigned1Seq = (ASN1Sequence) ASN1Primitive.fromByteArray(serverSigned1Der);

            byte[] serverChallenge = null;

            Enumeration<?> e = serverSigned1Seq.getObjects();
            while (e.hasMoreElements()) {
                ASN1Encodable obj = (ASN1Encodable) e.nextElement();
                if (obj instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tagged = (ASN1TaggedObject) obj;
                    if (tagged.getTagNo() == 4) {
                        serverChallenge = DEROctetString.getInstance(tagged, false).getOctets();
                        break;
                    }
                }
            }

            if (serverChallenge == null) {
                throw new IllegalStateException("No se encontró serverChallenge en ServerSigned1");
            }

            ASN1EncodableVector euiccSigned1 = new ASN1EncodableVector();

            euiccSigned1.add(new DERTaggedObject(0, new DEROctetString(Base64.decode(transactionId, Base64.DEFAULT))));
            euiccSigned1.add(new DERTaggedObject(3, new DERUTF8String(serverName.split("://")[1])));
            euiccSigned1.add(new DERTaggedObject(4, new DEROctetString(serverChallenge)));

            ASN1EncodableVector euiccInfo2 = new ASN1EncodableVector();

            DEROctetString baseProfilePackageVersion = new DEROctetString(new byte[]{0x02,0x00,0x00});
            DEROctetString lowestSvn = new DEROctetString(new byte[]{0x03,0x01,0x00});
            DEROctetString euiccFirmwareVersion = new DEROctetString(new byte[]{0x01,0x00,0x00});
            DEROctetString extCardResource = new DEROctetString(new byte[]{0x00});
            DERBitString uiccCapability = new DERBitString(new byte[]{(byte)0x40}, 6);
            DERBitString euiccRspCapability = new DERBitString(new byte[]{(byte)0x80}, 7);
            byte[] ppVersion = new byte[]{0x01,0x00,0x00};
            String sasAcreditationNumber = "sasAcreditationNumber";

            euiccInfo2.add(new DERTaggedObject(1, baseProfilePackageVersion));
            euiccInfo2.add(new DERTaggedObject(2, lowestSvn));
            euiccInfo2.add(new DERTaggedObject(3, euiccFirmwareVersion));
            euiccInfo2.add(new DERTaggedObject(4, extCardResource));
            euiccInfo2.add(new DERTaggedObject(5, uiccCapability));
            euiccInfo2.add(new DERTaggedObject(8, euiccRspCapability));
            euiccInfo2.add(new DEROctetString(ppVersion));
            euiccInfo2.add(new DERUTF8String(sasAcreditationNumber));

            euiccSigned1.add(new DERTaggedObject(34, new DERSequence(euiccInfo2)));

            ASN1EncodableVector ctxParamsCommonAuth = new ASN1EncodableVector();

            ASN1EncodableVector deviceInfo = new ASN1EncodableVector();

            deviceInfo.add(new DEROctetString(new byte[]{0x01,0x02,0x03,0x04}));
            deviceInfo.add(new DERSequence());

            ctxParamsCommonAuth.add(new DERTaggedObject(1, new DERSequence(deviceInfo)));
            ctxParamsCommonAuth.add(new DERTaggedObject(2, new DERBitString(new byte[]{(byte)0x80}, 7)));

            euiccSigned1.add(new DERSequence(new DERTaggedObject(0, new DERSequence(ctxParamsCommonAuth))));

            DERSequence euiccSigned1Seq = new DERSequence(euiccSigned1);
            byte[] euiccSigned1Der = euiccSigned1Seq.getEncoded("DER");

            PrivateKey privateKey = loadPrivateKey(this, "euicc_key_pkcs8.pem");
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(euiccSigned1Der);
            byte[] euiccSignature1 = sig.sign();

            byte[] euiccCert = readAssetFile(this, "euicc_cert.pem");
            byte[] nextCert = readAssetFile(this, "eum_cert.pem");

            ASN1EncodableVector authRespOk = new ASN1EncodableVector();
            authRespOk.add(euiccSigned1Seq);
            authRespOk.add(new DEROctetString(euiccSignature1));
            authRespOk.add(new DEROctetString(euiccCertBytesFromPem(euiccCert)));
            authRespOk.add(new DEROctetString(euiccCertBytesFromPem(nextCert)));

            DERSequence authRespOkSeq = new DERSequence(authRespOk);

            DERTaggedObject authenticateServerResponse = new DERTaggedObject(false, 0, authRespOkSeq);

            byte[] finalDer = authenticateServerResponse.getEncoded("DER");

            AuthenticateClient authenticateClient = new AuthenticateClient(
                transactionId,
                java.util.Base64.getEncoder().encodeToString(finalDer)
            );

            authClient(layout, serverName, authenticateClient.toJsonString());
        });
    }

    private void authClient(LinearLayout layout, String serverName, String requestJson) {
        sendMessage(layout, serverName + "/gsma/rsp2/es9plus/authenticateClient", requestJson, responseJson -> {
            String transactionId = getJsonElement(responseJson, "transactionId");
            String smdpSignature2Base64 = getJsonElement(responseJson, "smdpSignature2");

            ASN1EncodableVector euiccSigned2 = new ASN1EncodableVector();
            euiccSigned2.add(new DERTaggedObject(0, new DEROctetString(Base64.decode(transactionId, Base64.DEFAULT))));

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            PublicKey euiccOtpk = kp.getPublic();

            byte[] euiccOtpkDer = euiccOtpk.getEncoded();
            ASN1TaggedObject euiccOtpkDO = new DERTaggedObject(true, BERTags.APPLICATION, 73, new DEROctetString(euiccOtpkDer));
            euiccSigned2.add(euiccOtpkDO);

            ASN1EncodableVector prepareDownloadResponseOk = new ASN1EncodableVector();

            prepareDownloadResponseOk.add(new DERSequence(euiccSigned2));

            DERSequence euiccSigned2Seq = new DERSequence(euiccSigned2);
            byte[] euiccSigned2Der = euiccSigned2Seq.getEncoded("DER");

            byte[] smdpSig2Raw = Base64.decode(smdpSignature2Base64, Base64.DEFAULT);
            ASN1TaggedObject smdpSig2DO = new DERTaggedObject(true, BERTags.APPLICATION, 55, new DEROctetString(smdpSig2Raw));
            byte[] smdpSig2Der = smdpSig2DO.getEncoded("DER");

            byte[] toSign = new byte[euiccSigned2Der.length + smdpSig2Der.length];
            System.arraycopy(euiccSigned2Der, 0, toSign, 0, euiccSigned2Der.length);
            System.arraycopy(smdpSig2Der, 0, toSign, euiccSigned2Der.length, smdpSig2Der.length);

            PrivateKey euiccPrivateKey = loadPrivateKey(this, "euicc_key_pkcs8.pem");
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(euiccPrivateKey);
            sig.update(toSign);
            byte[] euiccSignature2Raw = sig.sign();

            ASN1TaggedObject euiccSignature2DO = new DERTaggedObject(true, BERTags.APPLICATION, 55, new DEROctetString(euiccSignature2Raw));

            ASN1EncodableVector respOkVec = new ASN1EncodableVector();
            respOkVec.add(euiccSigned2Seq);
            respOkVec.add(euiccSignature2DO);
            DERSequence respOkSeq = new DERSequence(respOkVec);

            DERTaggedObject prepareDownloadResponse = new DERTaggedObject(false, 33, respOkSeq);

            byte[] finalDer = prepareDownloadResponse.getEncoded("DER");
            String prepareDownloadResponseB64 = Base64.encodeToString(finalDer, Base64.NO_WRAP);

            GetBoundProfilePackage getBoundProfilePackage = new GetBoundProfilePackage(
                transactionId,
                prepareDownloadResponseB64
            );

            getBoundProfilePack(layout, serverName, getBoundProfilePackage.toJsonString());
        });
    }

    private void getBoundProfilePack(LinearLayout layout, String serverName, String requestJson) {
        sendMessage(layout, serverName + "/gsma/rsp2/es9plus/getBoundProfilePackage", requestJson, responseJson -> {
        });
    }

    private static PrivateKey loadPrivateKey(Context context, String file) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        AssetManager am = context.getAssets();
        InputStream is = am.open(file);
        byte[] keyBytes = new byte[is.available()];
        is.read(keyBytes);
        is.close();

        String keyPem = new String(keyBytes, StandardCharsets.UTF_8);
        keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.decode(keyPem, Base64.DEFAULT);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("EC");

        return kf.generatePrivate(keySpec);
    }

    private byte[] readAssetFile(Context context, String filename) throws Exception {
        AssetManager am = context.getAssets();
        InputStream is = am.open(filename);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = is.read(tmp)) != -1) {
            buffer.write(tmp, 0, n);
        }
        is.close();

        return buffer.toByteArray();
    }

    private byte[] euiccCertBytesFromPem(byte[] pem) {
        String pemStr = new String(pem, StandardCharsets.UTF_8);
        pemStr = pemStr.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        return java.util.Base64.getDecoder().decode(pemStr);
    }

    private void sendMessage(LinearLayout layout, String destination, String requestJson, ResponseCallback callback) {
        createMessage(layout, "client", formatJson(requestJson));

        new Thread(() -> {
            try {
                URL url = new URL(destination);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(requestJson.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }

                int statusCode = conn.getResponseCode();
                InputStream inputStream;

                if (statusCode >= 200 && statusCode < 300) {
                    inputStream = conn.getInputStream();
                } else {
                    inputStream = conn.getErrorStream();
                }

                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                String responseJson = response.toString();

                runOnUiThread(() -> {
                    String finalMessage = "HTTP " + statusCode + ": " + formatJson(responseJson);
                    createMessage(resultsLayout, "server", finalMessage);

                    if (callback != null) {
                        try {
                            callback.onReceivedResponse(responseJson);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> createMessage(resultsLayout, "server", "Error: " + e.getMessage()));
            }
        }).start();
    }

    private void createMessage(LinearLayout layout, String sender, String message) {
        LinearLayout messageLayout = new LinearLayout(this);
        messageLayout.setOrientation(LinearLayout.VERTICAL);

        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(
                1100,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );

        TextView senderText = new TextView(this);
        TextView messageText = new TextView(this);

        if (Objects.equals(sender, "client")) {
            senderText.setText("CLIENTE");
            layoutParams.gravity = Gravity.END;
            messageLayout.setBackgroundColor(Color.parseColor("#90FFFA"));
        } else if (Objects.equals(sender, "server")) {
            senderText.setText("SERVIDOR SM-DP+");
            layoutParams.gravity = Gravity.START;
            messageLayout.setBackgroundColor(Color.parseColor("#FFB18A"));
        }
        else {
            return;
        }

        senderText.setTextSize(15);
        senderText.setTextColor(Color.BLACK);
        senderText.setTypeface(null, Typeface.BOLD);
        LinearLayout.LayoutParams layoutParamsSenderText = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        layoutParamsSenderText.setMargins(20, 20, 20, 10);
        senderText.setLayoutParams(layoutParamsSenderText);
        messageLayout.addView(senderText);

        messageText.setText(message);
        messageText.setTextSize(15);
        messageText.setTextColor(Color.BLACK);
        LinearLayout.LayoutParams layoutParamsMessageText = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        layoutParamsMessageText.setMargins(20, 10, 20, 20);
        messageText.setLayoutParams(layoutParamsMessageText);
        messageLayout.addView(messageText);

        layoutParams.setMargins(50, 50, 50, 50);

        messageLayout.setLayoutParams(layoutParams);
        layout.addView(messageLayout);
    }

    private String getJsonElement(String json, String element) {
        try {
            JSONObject jsonObject = new JSONObject(json);
            if (jsonObject.has(element)) {
                return jsonObject.get(element).toString();
            } else {
                return "Elemento no encontrado";
            }
        } catch (Exception e) {
            return "Error al leer el JSON: " + e.getMessage();
        }
    }

    private String formatJson(String json) {
        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            return json;
        }
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonElement jsonElement = JsonParser.parseString(json);
        return gson.toJson(jsonElement);
    }

    public interface ResponseCallback {
        void onReceivedResponse(String responseJson) throws Exception;
    }

    @Override
    public void finish() {
        super.finish();
        overridePendingTransition(R.anim.deslizar_izq_der_entrada, R.anim.deslizar_izq_der_salida);
    }

    public void atras(View v) {
        finish();
    }
}