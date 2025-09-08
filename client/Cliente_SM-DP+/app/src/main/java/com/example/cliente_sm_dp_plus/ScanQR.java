package com.example.cliente_sm_dp_plus;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import java.util.Objects;

public class ScanQR extends AppCompatActivity {

    Button scanButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_scan_qr);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        scanButton = findViewById(R.id.scanButton);

        scanButton.setOnClickListener(view -> {
            @SuppressWarnings("deprecation")
            IntentIntegrator integrator = new IntentIntegrator(ScanQR.this);
            integrator.setPrompt("Escanea el código QR de la eSIM");
            integrator.setOrientationLocked(true);
            integrator.initiateScan();
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        @SuppressWarnings("deprecation")
        IntentResult intentResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (intentResult != null) {
            if (intentResult.getContents() != null) {
                String qrCode = intentResult.getContents();

                if (isValidESimQR(qrCode)) {
                    Toast.makeText(this, "QR leído: " + qrCode, Toast.LENGTH_SHORT).show();

                    Intent intent = new Intent(ScanQR.this, ShowResults.class);
                    intent.putExtra("qrCode", qrCode);
                    startActivity(intent);
                    overridePendingTransition(R.anim.deslizar_der_izq_entrada, R.anim.deslizar_der_izq_salida);
                } else {
                    Toast.makeText(this, "El código QR no se corresponde con un perfil de eSIM o es incorrecto", Toast.LENGTH_LONG).show();
                }
            } else {
                Toast.makeText(this, "Escaneo cancelado", Toast.LENGTH_SHORT).show();
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    private boolean isValidESimQR(String codigoQR) {
        String[] sections = codigoQR.split("\\$");

        if (sections.length !=3) {
            return false;
        }

        String section1 = sections[0];
        String section2 = sections[1];
        String section3 = sections[2];

        if (!Objects.equals(section1, "LPA:1")) {
            return false;
        }

        if (!section2.startsWith("https://") && !section2.startsWith("http://")) {
            section2 = "https://" + section2;
        }

        try {
            new java.net.URL(section2);
        } catch (Exception e) {
            return false;
        }

        return (!section3.isEmpty());
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