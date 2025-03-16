package com.example.springkeycloak.security;

import com.example.springkeycloak.model.AppUser;
import com.example.springkeycloak.service.UserService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@Component
@RequiredArgsConstructor
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    @Value("${jwt.auth.converter.principal-attribute-name}")
   private String principalAttributeName;

    @Value("${jwt.auth.converter.resource-id}")
   private String resourceId ;
   private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
   private final UserService userService;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = getAuthorities(jwt);

        // Load user from DB or create if not found
        AppUser appUser = userService.createNewUserIfNotExistsFromJwt(jwt);
        appUser.setRoles(authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return new UsernamePasswordAuthenticationToken(
                appUser, jwt, authorities
        );
    }

    private Collection<GrantedAuthority> getAuthorities(Jwt jwt) {
        return Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractRolesFromJwt(jwt).stream()
        ).collect(Collectors.toSet());
    }

    @Override
    public <U> Converter<Jwt, U> andThen(Converter<? super AbstractAuthenticationToken, ? extends U> after) {
        return Converter.super.andThen(after);
    }


    private Collection<? extends GrantedAuthority> extractRolesFromJwt(Jwt jwt) {
        // Step 1: Extract "resource_access" claim safely
        Map<?, ?> resourceAccess = Optional.ofNullable(jwt.getClaim("resource_access"))
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .orElse(Collections.emptyMap());

       // System.out.println("resourceAccess: " + resourceAccess);

        // Step 2: Retrieve client-specific resource map
        Map<String, ?> client = Optional.ofNullable((Map<String, ?>) resourceAccess.get(this.resourceId))
                .orElse(Collections.emptyMap());


        // Step 3: Extract the list of roles
        List<String> roles = Optional.ofNullable(client.get("roles"))
                .filter(List.class::isInstance)
                .map(roleList -> ((List<?>) roleList).stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .collect(Collectors.toList()))
                .orElse(Collections.emptyList());

       // System.out.println("roles: " + roles);

        // Step 4: Convert roles into authorities
        Set<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace('-', '_')))
                .collect(Collectors.toSet());

        return authorities;
    }

}
