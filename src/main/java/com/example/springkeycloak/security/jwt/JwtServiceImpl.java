package com.example.springkeycloak.security.jwt;


import com.example.springkeycloak.model.AppUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class JwtServiceImpl implements JwtService {
//    @Value("${token.signing.key}")
//    private String jwtSigningKey;
//
//    @Value("${app.jwtExpirationMs}")
//    private long tokenExpirationTime;

    @Override
    public String extractUserName(Jwt jwt) {
        return jwt.getClaim("preferred_username");
    }

    @Override
    public String extractUserEmail(Jwt jwt) {
        return jwt.getClaim("email");
    }


    @Override
    public String extractUserId(Jwt jwt) {
        return jwt.getSubject();
    }

    @Override
    public AppUser extractUserInfoFromJwt(Jwt jwt) {
       return AppUser.builder()
                .keycloakUserId(jwt.getSubject())
                .username(jwt.getClaim("preferred_username"))
                .email(jwt.getClaim("email"))
                .firstName(jwt.getClaim("given_name"))
                .lastName(jwt.getClaim("family_name"))
                .build();
    }

    public boolean isTokenValid(Jwt jwt) {
        try {
            Instant expirationTime = jwt.getExpiresAt();
            return expirationTime != null && Instant.now().isBefore(expirationTime);
        } catch (Exception e) {
            return false; // Invalid or expired token
        }
    }










}
