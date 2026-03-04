# HTTPS/TLS Setup Guide

Secure your Agent Vault Proxy with TLS encryption.

## Quick Start (Let's Encrypt)

### 1. Install Certbot

```bash
# Ubuntu
sudo apt install -y certbot

# Or use Docker
```

### 2. Obtain Certificate

```bash
# Standalone mode (port 80 must be available)
sudo certbot certonly --standalone -d vault.yourdomain.com

# Or with webroot
sudo certbot certonly --webroot -w /var/www/html -d vault.yourdomain.com
```

### 3. Configure Vault

```bash
# Copy certs to vault directory
sudo cp /etc/letsencrypt/live/vault.yourdomain.com/fullchain.pem ./certs/cert.pem
sudo cp /etc/letsencrypt/live/vault.yourdomain.com/privkey.pem ./certs/key.pem
sudo chown $USER:$USER ./certs/*.pem
```

### 4. Update docker-compose.tls.yml

```yaml
version: '3.8'
services:
  vault:
    volumes:
      - ./certs:/certs:ro
    environment:
      - TLS_CERT_PATH=/certs/cert.pem
      - TLS_KEY_PATH=/certs/key.pem
    ports:
      - "443:8080"
```

### 5. Start with TLS

```bash
docker-compose -f docker-compose.yml -f docker-compose.tls.yml up -d
```

## Self-Signed Certificate (Development)

```bash
# Generate private key
openssl genrsa -out certs/key.pem 2048

# Generate certificate
openssl req -new -x509 -key certs/key.pem -out certs/cert.pem -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=vault.local"

# Trust certificate (Linux)
sudo cp certs/cert.pem /usr/local/share/ca-certificates/vault.crt
sudo update-ca-certificates
```

## Certificate Renewal

### Automatic (Cron)

```bash
# Edit crontab
sudo crontab -e

# Add line for daily renewal check
0 2 * * * certbot renew --quiet --deploy-hook "docker restart agent-vault-proxy"
```

### Manual

```bash
sudo certbot renew
sudo systemctl reload docker  # or restart container
```

## Verification

```bash
# Test HTTPS
curl -v https://vault.yourdomain.com/health

# Check certificate info
echo | openssl s_client -servername vault.yourdomain.com -connect vault.yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates -subject

# SSL Labs Test
# Visit: https://www.ssllabs.com/ssltest/
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Certificate expired | Run `certbot renew` |
| Permission denied | Check file ownership |
| Port 443 in use | Stop other services or change port |
| Chain incomplete | Use fullchain.pem not cert.pem |

## Security Best Practices

1. **Use strong keys**: 2048-bit RSA minimum (4096 recommended)
2. **Auto-renewal**: Set up cron job
3. **HSTS headers**: Enable in middleware
4. **Perfect Forward Secrecy**: Use ECDHE cipher suites
5. **Certificate pinning**: For high-security environments
