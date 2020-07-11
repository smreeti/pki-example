package com.example.pki.utils;

import com.example.pki.dto.pki.PKIData;
import com.example.pki.exception.BadRequestException;
import com.example.pki.exception.NoContentFoundException;
import com.example.pki.exception.OperationUnsuccessfulException;
import com.example.pki.wrapper.RequestWrapper;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Base64;

import static com.example.pki.constants.ErrorMessageConstants.PKIMessages.INVALID_TOKEN_SIGNATURE;

@Slf4j
public class SecurityUtil {

    private static String serverPublicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl0wB6IGgyzoJ9xkcsS2U2wJqDTBl/FyoHpVNxBbfC8twLzBoQvvSHUfeHHpMv1XLchoswegXBssIvFVFtbGtECY5bc8RsFHkwd1dFNYaweGvjVQslJMFesr4mH4ytBvJBmNVF2Hs+G8BEszeLQTRdOKbw7FE2cuo2vIuhVCmQLq0osHkZthaYC059+IqZ6VcTNPdlGcipxVvF/ZjZtjX89cTdBlFfBjzVmIbLDSjbvxQY6Wk1F5aweRdnzGpoOuoflkOoShOttQZa0ffHEV+86vPZnpe8cWDxd/ioDsuRNTqXWxl+ElTu4Ma2QZLse4LLue3tj+1xWxRcsem8R4j0QIDAQAB";

    private static String serverPrivateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXTAHogaDLOgn3GRyxLZTbAmoNMGX8XKgelU3EFt8Ly3AvMGhC+9IdR94ceky/VctyGizB6BcGywi8VUW1sa0QJjltzxGwUeTB3V0U1hrB4a+NVCyUkwV6yviYfjK0G8kGY1UXYez4bwESzN4tBNF04pvDsUTZy6ja8i6FUKZAurSiweRm2FpgLTn34ipnpVxM092UZyKnFW8X9mNm2Nfz1xN0GUV8GPNWYhssNKNu/FBjpaTUXlrB5F2fMamg66h+WQ6hKE621BlrR98cRX7zq89mel7xxYPF3+KgOy5E1OpdbGX4SVO7gxrZBkux7gsu57e2P7XFbFFyx6bxHiPRAgMBAAECggEAcNJ+LcrUhBfwrHHugnUyJqtDODiaJLlXqQ6/YfWIOHxpWNcpOKIeijU4fVX5+0hYIOtB6wtOeINZLVANXrNzEbLfanJah3haNPME4W/TnjbUuXhGkjicgnfvL5AT8Vky6++Q2ZHtq0jjrQhWuY15QEdnzmNXq24CqdqlNEby4xrtjYnwruj3taClJMVpibjQ26syCWgpKGMqdWKEfry2Q+Xy6GdY2DRruh6YQthC1iIQOS23FqJeBrbo4+5gqDzjO5/yTBsGx3E9VS6eQM8sBYXcJFt9TEpreYMuuncpGeyi3veeoLNmaxZK3LG/IIDm6a0miS8I7CQ8xv6Jep90AQKBgQDpx8FrcrTpJgXBqYpUoSN56iE8E24EuXA43C5FfsTr12umqykamKo463tZPw7vvSTNl5ydlg7Jr7tAq9i3L+IPEV7/r3lZIEAOk0nBcTY5FIGs6refDTwx8l/0LTKqbKrdCD5jAvjGiXLF1yWVKN9Yny5Y5ePOK6C5zDE55FAdEQKBgQClrUzt43owsZRyxbBtsKlw1oltmDLYVGMlwEIIfxH2kus8GTaltR1AmTogxLMkdQP0s8A8Wj0qmBKEaE5uRBsdGQBAHDzOrQDWXqHmH92oJhIRCfCo4HpsVmPz2LwssdZPCzZv1DlrLkyKhuPncaMMdS/H1EY1CY7zAVAe23yawQKBgQDWcy1UuVaHASAKtNF2LJL0hPeTumcT4l+1aRTxHwbZKTVRIHWGNkEAEdOG3LeA58rY5Zj/XeWW0aM+AeW8tSnzlIXGmlsAjPr149qmnomU9uC1lGJ4fpWXY7TtsoBloWVjeOpxvQokZXVpUqDhISswimTjm47LU24OwebuKifrYQKBgBI+mFcmEsGj/JX7ASfDKZWcenvQI+FAwb5ZgqwO2jqOCUuP9z2eST9g4E7VemjMXggnd0buJQg4wOlF10U7SMUWiLmGooeb85inySpfXfhzYM/xiUf/mFuv08f5mRdO6ivAL1l3RG9yJMmoexZ0pCDuErntvWF/0PcfsOQFBZ7BAoGATSOgJJ3fN1wRMGLgMluR/wQHBbtVzBj5RG9tcAxrdPbKW7AA1wmUsmsxBPiXD1CZ+K5n2I2U62lg1bl5WdUaYPj35+m7mbnAC8j2lJ3qOjBfvEScvzus3WcXF5LgTITFkTrS4bguQf5+NQ8Vx0AuPqyiZchnBcVP7yJjCiHjmnI=";

    private static String clientPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIX6uimxQQZIz20/qjOkpvyGMexox7I7BF+oyMSf0+LX4ySuNgwS48wKLxx1upG4kZcxT1GmErq0vzv7Gk0ywTatqWalcqzL/7jF2tAJTMVEyKJoL0zhr+pgkSJ7dZ1njxP6AHHG4OU4l7T287GwaMA78ekcCr89sqBCOeRt2UnnAgMBAAECgYBZOp3HbJyw0ccLrG3vTQZFgh43o6Tzx6hnCSMFCKj2F+/YGwo1ylLaLiIoIyQpLrIP7rAz4ZXxsLT3/okKxvW0NAuMm+Epj3DR/8waOuuTYZElhAmD6L7b4MV1V0t5k9qu3H4A3IhbtmQasvwEv1PFMwNQ8sBkXb+siIVazgeK0QJBAPJ8PAczoDvBpD+D6HQY4tPLIQZa5AT5ddVqF34wczSDm19R4h1GrRyfEZoHZ760fCDoYBkL8PvWSpUQl3xENqkCQQCNclZVydprAft9Ad1IiI8nd2bySlMcwbB7iwtoP0/ksgilxhonu6lMTsfEmr17Py5bzFTpECkFX0xC9cvG9SYPAkEAuqzDtbOb1oUTwkX1bXM/JFeLvA263s2BVmPPZDk+Z54tvesWzPz9Bjy7Wz36M0lVCix61q1nvyjQ0AMu697DyQJAGJ8eiDBq5NWjgU8hxc5/nM8cDHEDpq3QmrDJe4wJzDVxa+ngA6qW/cF45LBK63lECJa48RjvCxBbpgxDPI7P4QJAcW6RLuiu0o6969XOv541lI5+nW3IORhlL7gAdWdThPVJcB5tT+7e1Q3OcxJnCfrLtQWoCNnhRDGO2JtGS1xK0g==";
    private static String clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF+ropsUEGSM9tP6ozpKb8hjHsaMeyOwRfqMjEn9Pi1+MkrjYMEuPMCi8cdbqRuJGXMU9RphK6tL87+xpNMsE2ralmpXKsy/+4xdrQCUzFRMiiaC9M4a/qYJEie3WdZ48T+gBxxuDlOJe09vOxsGjAO/HpHAq/PbKgQjnkbdlJ5wIDAQAB";

    private static String client_id = "test";

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
                    .add("client_id", "test")
                    .build();

            log.info("wrapper payload " + wrapperJsonObject.toString());
            return wrapperJsonObject;
        } catch (Exception e) {
            log.error("Exception : " + e);
            return null;
        }
    }

    private static String generateSignature(String payload) {
        try {
            String encodedSignature = Base64.getEncoder().encodeToString(
                    RSAEncryptionUtil.generateSignature(payload.getBytes(), clientPrivateKey));
            return encodedSignature;
        } catch (Exception e) {
            log.error("Exception : ", e);
            return null;
        }
    }

    public static String responseValidator(String payload) throws Exception {
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

    public static PKIData encryptPayloadAndGenerateSignature(String payload,
                                                             String clientPublicKey,
                                                             String serverPrivateKey) {
        try {
            SecretKey secretKey = AESEncryptionUtil.generateSecretKey();
            String base64EncodedSecretKey = AESEncryptionUtil.keyToString(secretKey);

            byte[] encryptedSecretKey = RSAEncryptionUtil.encrypt(base64EncodedSecretKey, clientPublicKey);
            String finalSecretKey = AESEncryptionUtil.base64Encode(encryptedSecretKey);
            String encryptedData = AESEncryptionUtil.encrypt(payload, secretKey);

            String signature = generateSignature(encryptedData, serverPrivateKey);
            PKIData pkiData = new PKIData();
            pkiData.setData(encryptedData);
            pkiData.setSecretKey(finalSecretKey);
            pkiData.setSignature(signature);
            return pkiData;
        } catch (Exception e) {
            log.error("Error occurred while encrypting data error:{} stack:{}", e.getMessage(), e);
            throw new BadRequestException(INVALID_TOKEN_SIGNATURE, e.getMessage());
        }
    }

    private static String generateSignature(String payload, String privateKey) {
        try {
            String encodedSignature = Base64.getEncoder()
                    .encodeToString(RSAEncryptionUtil.generateSignature(payload.getBytes(), privateKey));
            return encodedSignature;
        } catch (Exception e) {
            log.error("Exception : ", e);
            return null;
        }
    }

    public static String responseValidator(RequestWrapper requestWrapper,
                                           String clientPublicKey,
                                           String serverPrivateKey) {

        try {
            boolean verified = validateSignature(requestWrapper.getSignature(), requestWrapper.getData(), clientPublicKey);

            if (verified) {
                byte[] decodedSecretKey = AESEncryptionUtil.base64Decode(requestWrapper.getSecret_key());
                String plainSecretKey = RSAEncryptionUtil.decrypt(decodedSecretKey, serverPrivateKey);

                String data = AESEncryptionUtil.decrypt(requestWrapper.getData(),
                        AESEncryptionUtil.getSecretKey(plainSecretKey));
                log.info("DECRYPTED DATA :::::::::::::" + data);
                return data;
            } else {
                log.error("Error occurred while validating signature.");
                throw new NoContentFoundException(INVALID_TOKEN_SIGNATURE);
            }
        } catch (Exception e) {
            log.error("Error occurred while validating signature. :: {}", e.getMessage());
            throw new OperationUnsuccessfulException(INVALID_TOKEN_SIGNATURE);
        }
    }

    private static boolean validateSignature(String receivedSignature, String payload, String clientPublicKey) {
        try {
            return RSAEncryptionUtil.verifySignature(payload, clientPublicKey, Base64.getDecoder().decode(receivedSignature));
        } catch (Exception e) {
            log.error("Error occurred while validating signature. :: {}", e.getMessage());
            throw new BadRequestException(INVALID_TOKEN_SIGNATURE, e.getMessage());
        }
    }


}
