package com.example.springkeycloak.security;

import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Value("${jwt.auth.converter.principal-attribute-name}")
   private String principalAttributeName;

    @Value("${jwt.auth.converter.resource-id}")
   private String resourceId ;

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractAuthorityRoles(jwt).stream()).collect(Collectors.toSet());

        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipalClaimName(jwt)
        );
    }

    @Override
    public <U> Converter<Jwt, U> andThen(Converter<? super AbstractAuthenticationToken, ? extends U> after) {
        return Converter.super.andThen(after);
    }

    private String getPrincipalClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if(this.principalAttributeName != null){
            claimName = this.principalAttributeName;
        }
        return jwt.getClaim(claimName);
    }

    private Collection<? extends GrantedAuthority> extractAuthorityRoles(Jwt jwt) {
        // Safely get the "resource_access" claim and cast it to a Map, handling possible nulls
        Map<?,?> resourceAccess = Optional.ofNullable(jwt.getClaim("resource_access"))
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .orElse(Collections.emptyMap());

        System.out.println("resourceAccess: " + resourceAccess);

        // Safely get the client map from resourceAccess
        Map<String, List<String>> client = Optional.ofNullable((Map<String, List<String>>) resourceAccess.get(this.resourceId))
                .orElse(Collections.emptyMap());

        // Safely get the "roles" list, ensuring it is not null
        List<String> roles = Optional.ofNullable(client.get("roles"))
                .orElse(Collections.emptyList());

        // Convert roles into authorities, handling empty roles properly
        var authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace('-', '_')))
                .collect(Collectors.toSet());

        //System.out.println("resourceId: " + this.resourceId);
        System.out.println("authorities: " + authorities);

        return authorities;
    }
}
