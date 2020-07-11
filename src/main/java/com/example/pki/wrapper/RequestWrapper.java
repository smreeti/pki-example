package com.example.pki.wrapper;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class RequestWrapper implements Serializable{

    private String client_id;

    private String signature;

    private String data;

    private String secret_key;
}
