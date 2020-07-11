package com.example.pki;

import com.example.pki.utils.SecurityUtil;

import javax.json.Json;
import javax.json.JsonObject;

public class SecurityUtilTest extends SecurityUtil {

    public static void main(String[] args) throws Exception {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("Greeting", "Hello World")
                .add("Description", "This is PKI Example Project")
                .build();
        JsonObject requestWrapper = generateWrapperPayload(jsonObject);
        responseValidator(requestWrapper.toString());
    }
}

