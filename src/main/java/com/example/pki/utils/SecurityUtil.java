package com.example.pki.utils;

import com.example.pki.wrapper.RequestWrapper;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Base64;

@Slf4j
public class SecurityUtil {
    private static String serverPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF+ropsUEGSM9tP6ozpKb8hjHsaMeyOwRfqMjEn9Pi1+MkrjYMEuPMCi8cdbqRuJGXMU9RphK6tL87+xpNMsE2ralmpXKsy/+4xdrQCUzFRMiiaC9M4a/qYJEie3WdZ48T+gBxxuDlOJe09vOxsGjAO/HpHAq/PbKgQjnkbdlJ5wIDAQAB";
    private static String serverPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIX6uimxQQZIz20/qjOkpvyGMexox7I7BF+oyMSf0+LX4ySuNgwS48wKLxx1upG4kZcxT1GmErq0vzv7Gk0ywTatqWalcqzL/7jF2tAJTMVEyKJoL0zhr+pgkSJ7dZ1njxP6AHHG4OU4l7T287GwaMA78ekcCr89sqBCOeRt2UnnAgMBAAECgYBZOp3HbJyw0ccLrG3vTQZFgh43o6Tzx6hnCSMFCKj2F+/YGwo1ylLaLiIoIyQpLrIP7rAz4ZXxsLT3/okKxvW0NAuMm+Epj3DR/8waOuuTYZElhAmD6L7b4MV1V0t5k9qu3H4A3IhbtmQasvwEv1PFMwNQ8sBkXb+siIVazgeK0QJBAPJ8PAczoDvBpD+D6HQY4tPLIQZa5AT5ddVqF34wczSDm19R4h1GrRyfEZoHZ760fCDoYBkL8PvWSpUQl3xENqkCQQCNclZVydprAft9Ad1IiI8nd2bySlMcwbB7iwtoP0/ksgilxhonu6lMTsfEmr17Py5bzFTpECkFX0xC9cvG9SYPAkEAuqzDtbOb1oUTwkX1bXM/JFeLvA263s2BVmPPZDk+Z54tvesWzPz9Bjy7Wz36M0lVCix61q1nvyjQ0AMu697DyQJAGJ8eiDBq5NWjgU8hxc5/nM8cDHEDpq3QmrDJe4wJzDVxa+ngA6qW/cF45LBK63lECJa48RjvCxBbpgxDPI7P4QJAcW6RLuiu0o6969XOv541lI5+nW3IORhlL7gAdWdThPVJcB5tT+7e1Q3OcxJnCfrLtQWoCNnhRDGO2JtGS1xK0g==";

    private static String clientPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIX6uimxQQZIz20/qjOkpvyGMexox7I7BF+oyMSf0+LX4ySuNgwS48wKLxx1upG4kZcxT1GmErq0vzv7Gk0ywTatqWalcqzL/7jF2tAJTMVEyKJoL0zhr+pgkSJ7dZ1njxP6AHHG4OU4l7T287GwaMA78ekcCr89sqBCOeRt2UnnAgMBAAECgYBZOp3HbJyw0ccLrG3vTQZFgh43o6Tzx6hnCSMFCKj2F+/YGwo1ylLaLiIoIyQpLrIP7rAz4ZXxsLT3/okKxvW0NAuMm+Epj3DR/8waOuuTYZElhAmD6L7b4MV1V0t5k9qu3H4A3IhbtmQasvwEv1PFMwNQ8sBkXb+siIVazgeK0QJBAPJ8PAczoDvBpD+D6HQY4tPLIQZa5AT5ddVqF34wczSDm19R4h1GrRyfEZoHZ760fCDoYBkL8PvWSpUQl3xENqkCQQCNclZVydprAft9Ad1IiI8nd2bySlMcwbB7iwtoP0/ksgilxhonu6lMTsfEmr17Py5bzFTpECkFX0xC9cvG9SYPAkEAuqzDtbOb1oUTwkX1bXM/JFeLvA263s2BVmPPZDk+Z54tvesWzPz9Bjy7Wz36M0lVCix61q1nvyjQ0AMu697DyQJAGJ8eiDBq5NWjgU8hxc5/nM8cDHEDpq3QmrDJe4wJzDVxa+ngA6qW/cF45LBK63lECJa48RjvCxBbpgxDPI7P4QJAcW6RLuiu0o6969XOv541lI5+nW3IORhlL7gAdWdThPVJcB5tT+7e1Q3OcxJnCfrLtQWoCNnhRDGO2JtGS1xK0g==";
    private static String clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF+ropsUEGSM9tP6ozpKb8hjHsaMeyOwRfqMjEn9Pi1+MkrjYMEuPMCi8cdbqRuJGXMU9RphK6tL87+xpNMsE2ralmpXKsy/+4xdrQCUzFRMiiaC9M4a/qYJEie3WdZ48T+gBxxuDlOJe09vOxsGjAO/HpHAq/PbKgQjnkbdlJ5wIDAQAB";
    private static String client_id = "DARAZ";

    protected static JsonObject generateWrapperPayload(JsonObject jsonObject) {
        try {
            String payload = jsonObject.toString();

            SecretKey secretKey = AESEncryptionUtil.generateSecretKey();
            String base64EncodedSecretKey = AESEncryptionUtil.keyToString(secretKey);
            byte[] encryptedSecretKey = RSAEncryptionUtil.encrypt(base64EncodedSecretKey, serverPublicKey);
            String finalSecretKey = AESEncryptionUtil.base64Encode(encryptedSecretKey);

            String encryptedData = AESEncryptionUtil.encrypt(payload, secretKey);
            String signature = generateSignature(encryptedData);

            JsonObject wrapperJsonObject = Json.createObjectBuilder()
                    .add("signature", signature)
                    .add("secret_key", finalSecretKey)
                    .add("data", encryptedData)
                    .add("client_id", "daraz")
                    .build();

            log.info("wrapper payload " + wrapperJsonObject.toString());
            return wrapperJsonObject;
        } catch (Exception e) {
            log.error("Exeception : " + e);
            return null;
        }
    }

    protected static String generateSignature(String payload) {
        try {
            String encodedSignature = Base64.getEncoder().encodeToString(RSAEncryptionUtil.generateSignature(payload.getBytes(), clientPrivateKey));
            return encodedSignature;
        } catch (Exception e) {
            log.error("Exception : ", e);
            return null;
        }
    }

    protected static String responseValidator(String payload) throws Exception {
        try {
            RequestWrapper requestWrapper = JacksonUtil.get(payload, RequestWrapper.class);
            boolean verified = validateSignature(requestWrapper.getSignature(), requestWrapper.getData());

            byte[] decodedSecretKey = AESEncryptionUtil.base64Decode(requestWrapper.getSecret_key());
            log.info("Decoded secret key : " + new String(decodedSecretKey));
            String plainSecretKey = RSAEncryptionUtil.decrypt(decodedSecretKey, serverPrivateKey);
            SecretKey secretKey = AESEncryptionUtil.getSecretKey(plainSecretKey);

            String data = AESEncryptionUtil.decrypt(requestWrapper.getData(), secretKey);
            if (verified) {
                log.info("Decrypted data : " + data);
                return data;
            } else {
                throw new Exception("Invalid access");
            }
        } catch (Exception e) {
            throw new Exception("Invalid access");
        }
    }

    private static boolean validateSignature(String receivedSignature, String payload) {
        try {
            byte[] decodedSignature = Base64.getDecoder().decode(receivedSignature);
            return RSAEncryptionUtil.verifySignature(payload, clientPublicKey, decodedSignature);
        } catch (Exception e) {
            log.error(" Validate Signature Exception : " + e);
            return false;
        }
    }

    protected static String urlEncode(String url) {
        try {
            String encodeURL = URLEncoder.encode(url, "UTF-8");
            return encodeURL;
        } catch (UnsupportedEncodingException e) {
            return "Issue while encoding" + e.getMessage();
        }
    }
}
