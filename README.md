# Keycloak-Integration-with-Spring-Boot
### this is a sample project to demonstrate how to integrate Keycloak with Spring Security 6.0.0-M1
### to authenticate users using Keycloak and secure a Spring Boot application with Spring Boot

### Keycloak is an open-source Identity and Access Management solution that provides authentication and authorization services.
### Spring Security is a powerful and customizable authentication and access control framework for Java applications.
### This project demonstrates how to integrate Keycloak with Spring Boot and secure a RESTful API using Spring Security.
### The project uses Keycloak as the authentication provider and Spring Security to secure the RESTful API endpoints.
### The project is built using Spring Boot 3.0.0-M1 and Spring Security 6.0.0-M1.
### The project uses Maven as the build tool and Java 17 as the programming language.
### The project is structured as a typical Spring Boot application with the following main components:
### 1. Keycloak Configuration: The Keycloak configuration is defined in the application.properties file. This includes the Keycloak server URL, realm name, client ID, and client secret.
### 2. Security Configuration: The security configuration is defined in the SecurityConfig class. This includes the Keycloak authentication provider, the security filter chain, and the authorization rules for the RESTful API endpoints.
### 3. RESTful API: The RESTful API is defined in the UserController class. This includes the endpoints for retrieving user information and creating new users.
### 4. Keycloak Client: The Keycloak client is defined in the KeycloakConfig class. This includes the Keycloak client configuration and the Keycloak authentication provider.
### 5. User Model: The user model is defined in the User class. This includes the user properties and the user repository.
### 6. User Repository: The user repository is defined in the UserRepository interface. This includes the methods for retrieving and creating users.
### 7. User Service: The user service is defined in the UserService class. This includes the methods for retrieving and creating users.
### 8. User DTO: The user DTO is defined in the UserDTO class. This includes the user properties and the user mapper.
### 9. User Mapper: The user mapper is defined in the UserMapper class. This includes the methods for mapping between the user model and the user DTO.

## How to run the project
### 1. Clone the project from GitHub
### 2. Open the project in your favorite IDE (e.g., IntelliJ IDEA, Eclipse)
### 3. Make sure you have Java 17 and Maven installed on your machine
### 4. Open the terminal and navigate to the project directory
### 5. Run the following command to build the project