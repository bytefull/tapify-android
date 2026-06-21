package com.example.tapify;

import android.content.Context;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.util.Log;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

public class MyHostApduService extends HostApduService {

    private static final String TAG = "MyHostApduService";
    private static final byte[] PRIVATE_KEY_DER = new byte[] {
            (byte)0x30, (byte)0x81, (byte)0x87, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30, (byte)0x13,
            (byte)0x06, (byte)0x07, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x02,
            (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d,
            (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x04, (byte)0x6d, (byte)0x30, (byte)0x6b, (byte)0x02,
            (byte)0x01, (byte)0x01, (byte)0x04, (byte)0x20, (byte)0x26, (byte)0xee, (byte)0xf2, (byte)0x8e,
            (byte)0x9a, (byte)0xff, (byte)0x16, (byte)0x0b, (byte)0x34, (byte)0xf3, (byte)0xf5, (byte)0x83,
            (byte)0x6d, (byte)0x2a, (byte)0x8f, (byte)0x9e, (byte)0xcd, (byte)0x9b, (byte)0x67, (byte)0xf4,
            (byte)0x2c, (byte)0x68, (byte)0xef, (byte)0x84, (byte)0x0e, (byte)0x9b, (byte)0x2e, (byte)0x34,
            (byte)0xd9, (byte)0x8f, (byte)0x52, (byte)0xd9, (byte)0xa1, (byte)0x44, (byte)0x03, (byte)0x42,
            (byte)0x00, (byte)0x04, (byte)0x89, (byte)0x04, (byte)0x9e, (byte)0xbd, (byte)0x0a, (byte)0x86,
            (byte)0xfd, (byte)0x4d, (byte)0xa3, (byte)0x64, (byte)0x82, (byte)0x11, (byte)0x20, (byte)0xa6,
            (byte)0x23, (byte)0x57, (byte)0x57, (byte)0x31, (byte)0x2a, (byte)0xeb, (byte)0x11, (byte)0xc1,
            (byte)0x85, (byte)0x71, (byte)0x68, (byte)0xc7, (byte)0x5d, (byte)0x6f, (byte)0x9a, (byte)0x92,
            (byte)0xb3, (byte)0x9d, (byte)0x67, (byte)0x44, (byte)0x3a, (byte)0x1e, (byte)0x7b, (byte)0xd2,
            (byte)0x72, (byte)0x4c, (byte)0x00, (byte)0x36, (byte)0x00, (byte)0x30, (byte)0xa0, (byte)0xf1,
            (byte)0x77, (byte)0x1e, (byte)0x13, (byte)0x88, (byte)0x65, (byte)0xc2, (byte)0xf7, (byte)0xbc,
            (byte)0x00, (byte)0xcd, (byte)0x1e, (byte)0x1b, (byte)0xcc, (byte)0x67, (byte)0x1e, (byte)0xd6,
            (byte)0x55, (byte)0xaf
    };
    private PrivateKey privateKey;

    @Override
    public void onCreate() {
        super.onCreate();

        Log.i(TAG, "================ Started MyHostApduService ================");

        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(PRIVATE_KEY_DER);

            KeyFactory kf = KeyFactory.getInstance("EC");

            privateKey = kf.generatePrivate(spec);

            Log.i(TAG, "Private key loaded successfully");

        } catch (Exception e) {
            Log.e(TAG, "Failed to load private key", e);
        }
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        // Vibrate for 500 milliseconds
        Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        v.vibrate(VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE));
        Log.i(TAG, "================ APDU RECEIVED ================");
        Log.d(TAG, "APDU received: " + bytesToHex(commandApdu));

        // 1. Check if command is SELECT AID
        if ((commandApdu[0] == (byte) 0x00) && (commandApdu[1] == (byte) 0xA4)) {
            Log.i(TAG, "================ SELECT AID ================");
            return new byte[]{(byte) 0x90, 0x00};
        }

        // 2. Check if command is challenge
        else if ((commandApdu[0] == (byte) 0x80) && (commandApdu[1] == (byte) 0x10)) {
            Log.i(TAG, "================ CHALLENGE ================");
            byte[] nonce = new byte[32];
            /* Skip APDU header (5 bytes) */
            System.arraycopy(commandApdu, 5, nonce, 0, 32);
            byte[] signedNonce = signNonce(nonce);
            Log.i(TAG, "================ CHALLENGE SUCCESS ================");
            byte[] response = new byte[signedNonce.length + 2];
            System.arraycopy(signedNonce, 0, response, 0, signedNonce.length);
            response[response.length - 2] = (byte) 0x90;
            response[response.length - 1] = (byte) 0x00;
            return response;
        } else {
            Log.i(TAG, "================ INVALID APDU ================");
            return new byte[]{(byte) 0x6F, 0x00};
        }
    }

    private byte[] signNonce(byte[] nonce) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");

            signature.initSign(privateKey);

            signature.update(nonce);

            byte[] derSignature = signature.sign();

            Log.d(TAG, "DER signature: " + bytesToHex(derSignature));

            return derToRawSignature(derSignature);

        } catch (Exception e) {
            Log.e(TAG, "Failed to sign nonce", e);

            return new byte[]{};
        }
    }

    private byte[] derToRawSignature(byte[] der) {
        int offset = 3;

        int rLength = der[offset++];
        byte[] r = new byte[32];

        if (rLength == 33) {
            System.arraycopy(der, offset + 1, r, 0, 32);
        } else {
            System.arraycopy(der, offset, r, 32 - rLength, rLength);
        }

        offset += rLength + 1;

        int sLength = der[offset++];
        byte[] s = new byte[32];

        if (sLength == 33) {
            System.arraycopy(der, offset + 1, s, 0, 32);
        } else {
            System.arraycopy(der, offset, s, 32 - sLength, sLength);
        }

        byte[] raw = new byte[64];

        System.arraycopy(r, 0, raw, 0, 32);
        System.arraycopy(s, 0, raw, 32, 32);

        Log.d(TAG, "RAW signature: " + bytesToHex(raw));

        return raw;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    @Override
    public void onDeactivated(int reason) {
        Log.d(TAG, "Deactivated: " + reason);
    }
}