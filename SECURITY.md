# Security Considerations for Application Deployment

This document outlines essential security considerations for your Application deployment, which has access to company data and requires appropriate security measures.

> **Important**: See [DSGVO.md](./DSGVO.md) for GDPR compliance documentation.

## Key Security Measures Implemented

This deployment implements multiple layers of security:

| Security Layer | Implementation |
|----------------|----------------|
| Access Control | SSH key-only authentication, strong passwords |
| Network Security | Firewall (UFW), rate limiting, ModSecurity WAF |
| TLS Encryption | Auto-renewed certificates with HSTS enforcement |
| Container Security | Limited privileges, resource constraints, AppArmor profiles |
| Data Protection | Backups encrypted at rest, secure database connections |
| Monitoring | Netdata metrics, advanced logging, intrusion detection |
| GDPR Compliance | Data breach procedures, subject request handling |

## Security Recommendations

### Authentication

- **Enforce strong passwords** for all Application users (minimum 12 characters)
- **Use SSO integration** when possible for centralized authentication management
- **Regularly review user accounts** and remove unneeded access
- **Enable two-factor authentication** if supported by your Application edition

### Network Security

- **Access Application via VPN** for sensitive deployments
- **Segment your network** to isolate Application and data sources
- **Monitor unusual access patterns** using the provided logging tools
- **Restrict direct database access** to authorized IPs only

### Data Handling

- **Apply data minimization** principles in your application
- **Set appropriate view permissions** for different user groups
- **Review data collection consent** for GDPR compliance
- **Implement retention policies** for all data sources

### Incident Response

- Use the provided [DSGVO breach response toolkit](./DSGVO-TOOLS.md)
- **Test incident response procedures** quarterly
- **Maintain backup restore capability** for quick recovery
- **Document all security incidents** using the provided templates

## Application-Specific Hardening

The Application application itself has been configured with security-hardened settings:

- **Strong Password Policy**: Requires complex passwords (12+ chars)
- **Session Timeout**: Sessions expire after 8 hours of inactivity
- **Login Protection**: Accounts lock after 5 failed attempts
- **Public Sharing Disabled**: No public dashboards or questions
- **Embedding Disabled**: No embedding in external applications
- **Download Restrictions**: Prevents data exfiltration via CSV/Excel
- **Advanced Permissions**: Granular access control enabled
- **TLS Validation**: Strict certificate validation for data sources
- **JWT Token Security**: Enhanced token rotation and validation

### Database Encryption

For deployments using the embedded H2 database, encryption can be enabled for at-rest data protection. To enable this:

1. Generate a strong encryption key
2. Set the `MB_ENCRYPTION_SECRET_KEY` environment variable
3. Restart Application

```bash
# Generate a secure encryption key
openssl rand -base64 32

# Add to environment settings
MB_ENCRYPTION_SECRET_KEY=your_generated_key
```

### Content Security Policy

A robust Content Security Policy has been implemented through Nginx:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; 
  connect-src 'self' https://*.application.com; img-src 'self' data: blob:; 
  style-src 'self' 'unsafe-inline'; font-src 'self'; frame-src 'self'; base-uri 'self';
```

This policy:
- Restricts scripts to same origin (with exceptions needed for Application)
- Limits API connections to trusted sources
- Prevents loading of unauthorized resources
- Mitigates XSS and data injection attacks

## Web Application Firewall (ModSecurity)

ModSecurity provides an application-level firewall for Nginx, protecting against common web attacks.

### Features

- OWASP Core Rule Set integration
- Protection against:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Local/Remote File Inclusion
  - Command Injection
  - HTTP Protocol Violations
- Custom rules for Application API endpoints
- Logging of potential attacks

### Configuration

ModSecurity is enabled in the Nginx configuration with customized rules for Application:

```bash
# Check if ModSecurity is active
sudo nginx -t

# View ModSecurity logs
sudo cat /var/log/nginx/modsec_audit.log
```

## Container Security Scanning (Trivy)

Trivy scans Docker containers for vulnerabilities daily and reports any high or critical findings.

### Features

- Daily automated scanning
- Detection of known vulnerabilities in:
  - OS packages
  - Language-specific dependencies
  - Application libraries
- Focus on high and critical vulnerabilities
- Email alerts when issues are found

### Usage

```bash
# Run manual container scan
sudo /etc/cron.daily/trivy-scan

# View scan reports
ls -la /var/log/security/trivy/
```

## AppArmor Profiles

AppArmor provides mandatory access control profiles for Docker containers, restricting what they can access.

### Features

- Limited file system access
- Process isolation
- Network restrictions
- System call filtering

### Management

```bash
# Check if profile is loaded
sudo aa-status | grep application

# Temporarily disable profile for troubleshooting
sudo aa-complain docker-application

# Re-enable strict enforcement
sudo aa-enforce docker-application
```

## Network Intrusion Detection (Suricata)

Suricata monitors network traffic for suspicious activity, focusing on threats relevant to Application.

### Features

- Real-time traffic analysis
- Application-specific detection rules
- Protection against:
  - SQL injection attempts
  - Brute force attacks
  - Unauthorized API access
  - Data exfiltration
  - Scanning attempts

### Logs and Alerts

```bash
# View Suricata alerts
sudo cat /var/log/suricata/fast.log

# More detailed event information
sudo cat /var/log/suricata/eve.json | jq '.alert'
```

## Advanced Network Traffic Monitoring

In addition to the built-in monitoring tools, the system provides capabilities for advanced network traffic analysis using `tcpdump`. This can be extremely valuable during security incidents or for traffic analysis.

### Monitoring DNS Traffic

To monitor and log DNS queries for security analysis:

```bash
# Create log file with proper permissions
sudo touch /var/log/dns_queries.log
sudo chown root:root /var/log/dns_queries.log
sudo chmod 644 /var/log/dns_queries.log

# Start DNS monitoring in background (persists after logout)
nohup sudo bash -c 'tcpdump -i any port 53 -n -l -C 100 -W 5 >> /var/log/dns_queries.log 2>&1' &

# Check if monitoring is running
pgrep -a tcpdump
```

This configuration:
- Captures all DNS traffic (port 53)
- Creates a rotating log (5 files, 100MB each)
- Continues running even if you log out

### Full Packet Capture for Forensics

During security incidents, capturing full packet data can provide crucial forensic evidence:

```bash
# Capture all traffic on primary interface to a pcap file
sudo tcpdump -i eth0 -w /var/log/security/incident-$(date +%Y%m%d).pcap

# For long-term monitoring with file rotation (new file every 5 minutes)
nohup sudo tcpdump -i eth0 -w '/var/log/security/net_%Y%m%d_%H%M.pcap' -G 300 -W 12 > /dev/null 2>&1 &
```

For continuous long-term monitoring, set up a rotating capture with cleanup:

```bash
# Set up directory
sudo mkdir -p /var/log/security/netcapture
sudo chmod 700 /var/log/security/netcapture

# Start continuous capture with 5-minute rotation
nohup sudo tcpdump -i eth0 -w '/var/log/security/netcapture/net_%Y%m%d_%H%M.pcap' -G 300 > /dev/null 2>&1 &

# Add cron job to delete files older than 2 hours
sudo crontab -e
# Add this line:
0 * * * * find /var/log/security/netcapture -name "net_*.pcap" -mmin +120 -delete
```

### Managing Capture Processes

```bash
# Find running tcpdump processes
ps aux | grep tcpdump

# Stop all tcpdump processes
sudo pkill tcpdump

# Stop a specific process by PID
sudo kill 21678 

# Monitor capture file growth
ls -lh /var/log/security/netcapture/

# To leave shell while keeping capture running
jobs            # List jobs
disown %1       # Disown job #1
# or
disown -a       # Disown all jobs
```

### Targeted Traffic Monitoring

For targeted monitoring of specific services or suspicious activity:

```bash
# Monitor web traffic (HTTP/HTTPS)
sudo tcpdump -i eth0 'tcp port 80 or tcp port 443' -w /var/log/security/web_traffic.pcap

# Monitor traffic to a specific IP address
sudo tcpdump -i eth0 host 192.168.1.100 -w /var/log/security/host_traffic.pcap

# Monitor SSH traffic for intrusion attempts
sudo tcpdump -i eth0 'tcp port 22' -w /var/log/security/ssh_traffic.pcap

# Monitor database traffic (e.g., PostgreSQL)
sudo tcpdump -i eth0 'tcp port 5432' -w /var/log/security/db_traffic.pcap
```

### Analyzing Capture Files

Captured files can be analyzed with Wireshark or using command-line tools:

```bash
# Basic capture file statistics
tcpdump -r capture.pcap | wc -l        # Count packets
tcpdump -r capture.pcap -n | head -20  # View first 20 packets

# Extract HTTP request headers
tcpdump -r capture.pcap -A | grep -i "host:" | sort | uniq -c | sort -rn

# Find potential DNS exfiltration (unusually long DNS names)
tcpdump -r capture.pcap -n port 53 | grep -E '[A-Za-z0-9]{30,}'

# Extract IP conversations
tcpdump -r capture.pcap -nn -q | awk '{print $3 " " $5}' | tr -d : | sort | uniq -c | sort -nr | head
```

### Security Best Practices for Packet Capture

1. **Storage Management**: Network captures grow quickly. Always set up proper rotation and cleanup.
2. **Access Control**: Restrict access to packet capture files as they may contain sensitive information.
3. **Targeted Capture**: In production, use filters to capture only relevant traffic and avoid performance impact.
4. **Memory Usage**: Monitor system resources when running long captures as they can consume significant memory.
5. **Data Protection**: Consider the privacy implications of packet captures and handle according to your organization's data policies.

## Integration and Maintenance

These security features are integrated into the regular maintenance routines with:

- Automatically updated vulnerability databases
- Daily scans and reports
- Log rotation and retention policies
- Periodic rule updates
- Email notifications for security events

For the most comprehensive security posture, follow the maintenance schedule in the main README.md document.

## Additional Resources

- [Container Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Application Security Documentation](https://www.application.com/learn/administration/securing-application)
- [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)
- [GDPR Official Documentation](https://gdpr.eu/)
