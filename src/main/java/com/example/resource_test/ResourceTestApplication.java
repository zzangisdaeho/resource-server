package com.example.resource_test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceTestApplication.class, args);
    }

}
