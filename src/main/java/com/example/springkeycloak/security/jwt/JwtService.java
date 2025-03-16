package com.example.springkeycloak.security.jwt;


import com.example.springkeycloak.model.AppUser;
import org.springframework.security.oauth2.jwt.Jwt;

public interface JwtService {
    String extractUserName(Jwt jwt);

    String extractUserEmail(Jwt jwt);

    String extractUserId(Jwt jwt);

    AppUser extractUserInfoFromJwt(Jwt jwt);
//    String extractUserName(String token);
//    //String extractUserPhoneNumber(String token);
//
//    String extractUserEmail(String token);
//
//    //String extractUserIdentifier(String token);
//
//    String extractUserId(String token);
//
//    String generateToken(AppUser appUser);
//
//    boolean isTokenValid(String token, AppUser appUser);
}
