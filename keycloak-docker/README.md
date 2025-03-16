
# Keycloak Production Deployment with Docker

This repository contains the necessary files to deploy Keycloak in production mode using Docker and Docker Compose. The setup includes a PostgreSQL database and configurations for secure HTTPS communication.

## What is Keycloak?

Keycloak is an open-source identity and access management solution aimed at modern applications and services. It provides features such as:

- Single Sign-On (SSO)
- Identity Brokering and Social Login
- User Federation
- Client Adapters
- Admin Console

Keycloak allows you to secure applications and services with minimal effort. It supports standard protocols like OpenID Connect, OAuth 2.0, and SAML 2.0.

## Usage

Keycloak is used to add authentication to applications and secure services. It provides centralized identity management, making it easier to manage users and their access rights across multiple applications. Keycloak can integrate with various identity providers and supports social logins, enabling users to log in using their social media accounts.

## Setup Instructions

### Prerequisites

- Docker installed on your system.
- Docker Compose installed on your system.
- SSL certificates (`keycloak.crt` and `keycloak.key`) located in the `certs` directory.

### Generating SSL Certificates

To generate self-signed SSL certificates for development purposes, you can use OpenSSL. Follow these steps:

1. Generate a private key:

   ```bash
   openssl genpkey -algorithm RSA -out keycloak.key -pkeyopt rsa_keygen_bits:2048
   ```

2. Generate a certificate signing request (CSR):

   ```bash
   openssl req -new -key keycloak.key -out keycloak.csr
   ```

3. Generate the certificate:

   ```bash
   openssl x509 -req -days 365 -in keycloak.csr -signkey keycloak.key -out keycloak.crt
   ```

Move the generated `keycloak.crt` and `keycloak.key` files to the `certs` directory.

### Getting Hostname or Machine IP

If you have a domain name, you can use it as the hostname for Keycloak. Otherwise, you can get your machine's IP address using the following command:

```bash
hostname -I | awk '{print $1}'
```

This command will return your machine's IP address, which you can use as the `KC_HOSTNAME` in the `docker-compose.yml` file.

### Directory Structure

Ensure your project directory has the following structure:

```
.
├── keycloak-entrypoint.sh
├── Dockerfile
├── docker-compose.yml
└── certs
    ├── keycloak.crt
    └── keycloak.key
```

### Instructions

1. **Build the Docker Image**

   Navigate to your project directory and build the Docker image using the provided Dockerfile:

   ```bash
   docker build -t your-dockerhub-username/my-keycloak:25.0.0 .
   ```

2. **Run the Docker Compose**

   Use Docker Compose to start the services defined in `docker-compose.yml`:

   ```bash
   docker-compose up -d
   ```

### Environment Variables

The following environment variables are set in the `docker-compose.yml` file:

- `KEYCLOAK_ADMIN`: The admin username for Keycloak.
- `KEYCLOAK_ADMIN_PASSWORD`: The admin password for Keycloak.
- `KC_DB`: Database type (PostgreSQL).
- `KC_DB_URL`: JDBC URL for the PostgreSQL database.
- `KC_DB_USERNAME`: Database username for Keycloak.
- `KC_DB_PASSWORD`: Database password for Keycloak.
- `KC_HOSTNAME`: The hostname for Keycloak.
- `KC_HTTPS_CERTIFICATE_FILE`: Path to the SSL certificate file.
- `KC_HTTPS_CERTIFICATE_KEY_FILE`: Path to the SSL certificate key file.
- `JAVA_OPTS`: Java options for tuning the JVM (e.g., memory settings).
- `JAVA_OPTS_APPEND`: Additional Java options that will be appended to `JAVA_OPTS`.

### Example JAVA_OPTS and JAVA_OPTS_APPEND

You can set `JAVA_OPTS` and `JAVA_OPTS_APPEND` to customize the Java Virtual Machine (JVM) settings. For example:

```yaml
environment:
  JAVA_OPTS: "-Xms512m -Xmx1024m"
  JAVA_OPTS_APPEND: "-Djava.security.egd=file:/dev/./urandom"
```

### Access Keycloak

Once the services are up and running, Keycloak will be accessible at `https://hostname:8443`. Use the admin credentials specified in the `docker-compose.yml` file to log in.

### License

This project is licensed under the MIT License.