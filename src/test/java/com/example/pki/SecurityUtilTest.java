package com.example.pki;

import com.example.pki.utils.SecurityUtil;

import javax.json.Json;
import javax.json.JsonObject;

public class SecurityUtilTest extends SecurityUtil {

    public static void main(String[] args) throws Exception {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("url", "www.callback.com")
                .add("remarks", "Test refund")
                .build();
        JsonObject requestWrapper = generateWrapperPayload(jsonObject);
        responseValidator(requestWrapper.toString());
    }
}

