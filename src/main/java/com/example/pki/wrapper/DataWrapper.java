package com.example.pki.wrapper;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

import java.io.Serializable;

@Component
@RequestScope
@Slf4j
@Getter
@Setter
public class DataWrapper implements Serializable {

    private String data;
}
