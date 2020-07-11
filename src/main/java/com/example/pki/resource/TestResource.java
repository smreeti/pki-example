package com.example.pki.resource;


import com.example.pki.dto.pki.PKITestDTO;
import com.example.pki.utils.JacksonUtil;
import com.example.pki.wrapper.DataWrapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping(value = "/test")
public class TestResource {

    private final DataWrapper dataWrapper;

    public TestResource(DataWrapper dataWrapper) {
        this.dataWrapper = dataWrapper;
    }

    @GetMapping
    public String testClient() {
        return "Congratulations! e-Appointment esewa module is running successfully in Kubeshpere.. testing! ....";
    }

    @PostMapping("/pki")
    public Object testPKI() throws IOException, ClassNotFoundException {
        System.out.println("INSIDE CONTROLLER-------------->");
        Object data = dataWrapper.getData();
        System.out.println(dataWrapper.getData());
        PKITestDTO test = JacksonUtil.get(dataWrapper.getData(), PKITestDTO.class);
        return data;
    }

}
