package com.example.springkeycloak.service.impl;

import com.example.springkeycloak.model.AppUser;
import com.example.springkeycloak.repository.UserRepository;
import com.example.springkeycloak.security.jwt.JwtService;
import com.example.springkeycloak.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    @Override
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + username));
    }

    @Override
    public AppUser createNewUserIfNotExistsFromJwt(Jwt jwt) {
       AppUser extractedUser = jwtService.extractUserInfoFromJwt(jwt);

       return userRepository.findByKeycloakUserId(extractedUser.getKeycloakUserId())
                        .orElseGet(() -> {
                            System.out.println("User not found in DB, creating new user");
                           return userRepository.save(extractedUser);
                        });
    }

}
