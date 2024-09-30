package com.example.springkeycloak.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping("/customer")
    @PreAuthorize("hasRole('ROLE_client_customer')")
    public String customerInfo(){
        return "Hello.. i am keycloak customer";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_client_admin')")
    public String adminInfo(){
        return "Hello.. i am keycloak admin";
    }
}
