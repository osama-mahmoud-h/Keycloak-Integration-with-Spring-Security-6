# Keycloak Authorization with Spring Boot

## Table of Contents
- [Introduction to Keycloak](#introduction-to-keycloak)
- [Running Keycloak with Docker Compose](#running-keycloak-with-docker-compose)
- [Accessing Keycloak Admin Dashboard](#accessing-keycloak-admin-dashboard)
- [Creating Realm, Client, and Roles](#creating-realm-client-and-roles)
- [Exporting, Registering, and Logging in Users](#exporting-registering-and-logging-in-users)
- [Using Postman to Authenticate and Get Access Token](#using-postman-to-authenticate-and-get-access-token)
- [Spring Boot API Integration](#spring-boot-api-integration)
- [Tracking Registered Users in PostgreSQL](#tracking-registered-users-in-postgresql)
- [Running the Application via Docker Compose](#running-the-application-via-docker-compose)
- [Testing the Secured Endpoint](#testing-the-secured-endpoint)

## Introduction to Keycloak
Keycloak is an open-source identity and access management solution that provides authentication and authorization services for applications. It allows managing users, roles, and permissions through an admin dashboard.

## Running Keycloak with Docker Compose
To run Keycloak, run file a `keycloak-docker/docker-compose.yaml` file with the following configuration:

```yaml
version: '3.8'

services:
  keycloak:
    image: quay.io/keycloak/keycloak:25.0.0
    container_name: keycloak
    command:
      - start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: adminpassword
      #database
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloakpassword

      KC_HOSTNAME: localhost
    ports:
      - "8080:8080"
    depends_on:
      - postgres
    networks:
      - keycloak-network

  postgres:
    image: postgres:16
    container_name: postgres
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloakpassword
    ports:
      - "5438:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    networks:
      - keycloak-network

networks:
  keycloak-network:
    driver: bridge

volumes:
  pg_data:

```

Run the following command to start Keycloak:
```sh
docker-compose -f keycloak-docker/docker-compose.yaml up -d
```

## Accessing Keycloak Admin Dashboard
Once Keycloak is running, access the admin dashboard at:
```
http://localhost:8080
```
Log in using the credentials:
- **Username:** admin
- **Password:** adminpassword

## Creating Realm, Client, and Roles
1. **Create a new Realm:** Navigate to "Realm Settings" → "Add Realm" → Enter realm name.
2. **Create a Client:**
    - Go to "Clients" → "Create" → Enter a Client ID (e.g., `spring-app`).
    - Set "Access Type" to `public` or `confidential` (for backend apps requiring secret).
    - Save and update "Valid Redirect URIs" to match your frontend/backend.
3. **Create Roles:**
    - Go to "Roles" → "Add Role" → Define custom roles (e.g., `USER`, `ADMIN`).

## Exporting, Registering, and Logging in Users
1. **Create Users:**
    - Go to "Users" → "Add User" → Fill in details.
    - Set a password in "Credentials" → Enable "Temporary" if needed.
    - Assign roles under "Role Mappings."
2. **Export Users & Realm Configuration:**
    - Use Keycloak’s export feature to back up users and configurations.

## Using Postman to Authenticate and Get Access Token
To authenticate via Postman:
1. Send a `POST` request to Keycloak’s token endpoint:
   ```
   http://localhost:8080/realms/{your-realm}/protocol/openid-connect/token
   ```
2. Use `x-www-form-urlencoded` with:
    - `grant_type`: `password`
    - `client_id`: `{your-client-id}`
    - `username`: `testuser`
    - `password`: `password`
3. Copy the `access_token` from the response.

## Spring Boot API Integration
Secure your Spring Boot API by configuring `application.properties`

```.properties
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080/realms/{your-realm}
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8080/realms/{your-realm}/protocol/openid-connect/certs
```


Create a security filter to authorize requests.

## Tracking Registered Users in PostgreSQL
Upon first login, store user IDs in PostgreSQL:

in model/AppUser.java
```java
@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class AppUser implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(nullable = false, unique = true)
    private String keycloakUserId;

    private String username;
    private String password;
    private String email;
    private String firstName;
    private String lastName;
    private String phone;

    @Transient
    private List<String> roles;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```
browse project for more details

## Running the Application via Docker Compose
Ensure your `docker-compose.yml` includes your Spring Boot application alongside Keycloak:

```yaml
version: '3.8'
services:
  api:
    container_name: spring_auth_api
    build:
      context: .
    environment:
      - SPRING_APPLICATION_NAME:spring-keycloak
      - SERVER_PORT:8081
      - SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI:http://localhost:8080/realms/social-network-realm
      - JWT_AUTH_CONVERTER_RESOURCE_ID:social-network-backend
      - JWT_AUTH_CONVERTER_PRINCIPAL_ATTRIBUTE_NAME:preferred_username
      - SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/keycloak_spring_auth
      - SPRING_DATASOURCE_USERNAME=osama
      - SPRING_DATASOURCE_PASSWORD=password
      - SPRING_JPA_HIBERNATE_DDL_AUTO=update
      - SPRING_JPA_PROPERTIES_HIBERNATE_DIALECT=org.hibernate.dialect.PostgreSQLDialect
      - SPRING_JPA_SHOW_SQL=true
    ports:
      - "8081:8081"

    depends_on:
      - db
    networks:
      -  keycloak-network

  db:
    container_name: spring_auth_db
    image: postgres:16
    environment:
      POSTGRES_USER: osama
      POSTGRES_PASSWORD: password
      POSTGRES_DB: keycloak_spring_auth
    ports:
      - "5434:5432"

    volumes:
      - auth_pg_db_data:/var/lib/postgresql/data

    networks:
      - keycloak-network

networks:
  keycloak-network:
    driver: bridge
volumes:
  auth_pg_db_data:
    driver: local
```

Run the following command to start the entire setup:
```sh
docker-compose up -d
```

## Testing the Secured Endpoint
After running the setup, authenticate via Keycloak as explained earlier, and obtain an access token. Then, test your Spring Boot API:

1. Call the token endpoint:
   ```
   http://localhost:8080/realms/{your-realm}/protocol/openid-connect/token
   ```
2. Copy the `access_token` from the response.
3. Use the token to access the secured API:
   ```
   GET http://localhost:8081/api/v1/demo/me
   ```
    - Add `Authorization: Bearer {access_token}` in the request headers.

Your application is now secured with Keycloak and ready to handle user authentication and authorization! 🚀

