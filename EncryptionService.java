package de.thorstenweiskopf;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 * Created by Thorsten Weiskopf
 * info@thorstenweiskopf.de
 * 06.02.2017
 Copyright 2017 Thorsten Weiskopf

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

public class EncryptionService {

    public static EncryptionService instance;

    static final String TAG = "EncryptionService.class";


    public EncryptionService() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

    }

    /**
     *
     * @return EncryptionService (null if Exception happend)
     */
    public static EncryptionService getInsSecureService() {
        try {
            if (instance == null) {
                instance = new EncryptionService();
            }
        }catch(Exception e){
            Log.e(TAG, Log.getStackTraceString(e));
         }
        return instance;
    }

    /**
     * Creates random public and private keys ansd stores them in android keystore
     * @param alias = name in keystore
     */
    public void createNewKeys(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // Create new key if needed
            if (!keyStore.containsAlias(alias)) {

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                keyPairGenerator.initialize(
                        new KeyGenParameterSpec.Builder(
                                alias,
                                KeyProperties.PURPOSE_DECRYPT)
                                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                                .build());
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            } else {
            }
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    /**
     *
     * @param alias = name in keystore
     * @param data = data to decrypt
     * @return encryptString String
     */
    public String encryptString(String alias, String data) {
        String encryptedData = "";
        try {

            //NEW
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

            Cipher input = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, input);
            cipherOutputStream.write(data.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte[] vals = outputStream.toByteArray();
            encryptedData = Base64.encodeToString(vals, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } finally {
            return encryptedData;
        }
    }


    /**
     *
     * @param alias  = name in keystore
     * @param encryptetData  = encryptetData to decrypt
     * @return decryptString String
     */
    public String decryptString(String alias, String encryptetData) {

        String decryptedData = "";

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

            Cipher output = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            output.init(Cipher.DECRYPT_MODE, privateKey);


            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encryptetData, Base64.DEFAULT)), output);


            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            decryptedData = new String(bytes, 0, bytes.length, "UTF-8");

        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } finally {
            return decryptedData;
        }
    }



}