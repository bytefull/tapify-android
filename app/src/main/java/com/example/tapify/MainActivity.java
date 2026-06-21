package com.example.tapify;

import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.i(TAG, "================ Started MainActivity ================");

        Toast.makeText(this, "HCE ready. Tap phone on reader.", Toast.LENGTH_LONG).show();

        // Check if NFC is enabled
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null || !adapter.isEnabled()) {
            Toast.makeText(this, "NFC is OFF", Toast.LENGTH_LONG).show();
        }
    }
}