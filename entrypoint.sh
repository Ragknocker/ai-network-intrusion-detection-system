#!/bin/sh

# Set default credentials if not provided in docker-compose.yml
USERNAME=${SOC_USERNAME:-"admin"}
PASSWORD=${SOC_PASSWORD:-"secureSOC2026"}

echo "Configuring Nginx Basic Authentication for user: $USERNAME"

# Generate the .htpasswd file
htpasswd -bc /etc/nginx/.htpasswd "$USERNAME" "$PASSWORD"

# Start Nginx
exec "$@"
