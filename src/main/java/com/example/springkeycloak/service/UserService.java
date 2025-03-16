package com.example.springkeycloak.service;

import com.example.springkeycloak.model.AppUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

public interface UserService {
    UserDetailsService userDetailsService();
    AppUser createNewUserIfNotExistsFromJwt(Jwt jwt);
}
