FROM quay.io/keycloak/keycloak:25.0.0

#COPY keycloak-entrypoint.sh /opt/keycloak/keycloak-entrypoint.sh
#COPY certs /etc/x509/https/

# set -e
# /opt/keycloak/bin/kc.sh build
# exec /opt/keycloak/bin/kc.sh start  --optimized  --verbose
#dev mode

# Start Keycloak in development mode directly in the Dockerfile
CMD ["kc.sh", "start-dev"]
#ENTRYPOINT ["/opt/keycloak/keycloak-entrypoint.sh"]
