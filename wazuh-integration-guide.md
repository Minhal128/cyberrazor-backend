# Wazuh Integration Guide for CyberRazor Threat Detection Agent

This guide explains how to integrate the CyberRazor threat detection agent with Wazuh SIEM for centralized security monitoring and alerting.

## Prerequisites

- Wazuh Manager installed and running (version 4.5+)
- CyberRazor threat detection agent installed
- Network connectivity between agent and Wazuh manager

## 1. Wazuh Manager Configuration

### 1.1 Create Custom Decoder

Create a custom decoder for CyberRazor alerts in `/var/ossec/etc/decoders/cyberrazor_decoders.xml`:

```xml
<decoder name="cyberrazor">
  <prematch>CyberRazor Threat</prematch>
</decoder>

<decoder name="cyberrazor-threat">
  <parent>cyberrazor</parent>
  <regex>device_id: (\S+)</regex>
  <order>device_id</order>
</decoder>

<decoder name="cyberrazor-threat-type">
  <parent>cyberrazor-threat</parent>
  <regex>threat_type: (\S+)</regex>
  <order>threat_type</order>
</decoder>

<decoder name="cyberrazor-severity">
  <parent>cyberrazor-threat-type</parent>
  <regex>severity: (\S+)</regex>
  <order>severity</order>
</decoder>
```

### 1.2 Create Custom Rules

Create custom rules in `/var/ossec/etc/rules/cyberrazor_rules.xml`:

```xml
<group name="cyberrazor,threat_detection,">
  <rule id="100001" level="5">
    <if_sid>0</if_sid>
    <match>CyberRazor Threat</match>
    <description>CyberRazor: Threat detected</description>
    <options>alert_by_email</options>
  </rule>

  <rule id="100002" level="10">
    <if_sid>100001</if_sid>
    <field name="severity">Critical</field>
    <description>CyberRazor: Critical threat detected</description>
    <options>alert_by_email</options>
  </rule>

  <rule id="100003" level="8">
    <if_sid>100001</if_sid>
    <field name="severity">High</field>
    <description>CyberRazor: High severity threat detected</description>
    <options>alert_by_email</options>
  </rule>

  <rule id="100004" level="6">
    <if_sid>100001</if_sid>
    <field name="threat_type">Known Malware</field>
    <description>CyberRazor: Known malware detected</description>
    <options>alert_by_email</options>
  </rule>

  <rule id="100005" level="7">
    <if_sid>100001</if_sid>
    <field name="threat_type">Suspicious Process</field>
    <description>CyberRazor: Suspicious process detected</description>
    <options>alert_by_email</options>
  </rule>
</group>
```

### 1.3 Configure API Access

1. Create an API user for CyberRazor:

```bash
# Access Wazuh API
curl -u admin:admin -k -X POST "https://localhost:55000/security/users" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "cyberrazor",
    "password": "CyberRazor2024!",
    "roles": ["administrator"]
  }'
```

2. Get API token:

```bash
curl -u cyberrazor:CyberRazor2024! -k -X POST "https://localhost:55000/security/user/authenticate"
```

## 2. Agent Configuration

### 2.1 Update Agent Configuration

Edit `agent_config.yaml`:

```yaml
# Wazuh SIEM Integration
wazuh_url: "https://your-wazuh-manager:55000"
wazuh_credentials:
  username: "cyberrazor"
  password: "CyberRazor2024!"
  # Or use API token
  # token: "your-api-token-here"

# SSL Configuration
ssl_verify: true  # Set to false for self-signed certificates
```

### 2.2 Test Wazuh Connection

Run the agent in test mode:

```bash
python3 threat_agent.py --test-wazuh
```

## 3. Wazuh Dashboard Integration

### 3.1 Create Custom Dashboard

1. Access Wazuh Dashboard (Kibana)
2. Go to Management > Stack Management > Index Patterns
3. Create index pattern: `wazuh-alerts-*`
4. Go to Dashboard > Create Dashboard
5. Add visualization for CyberRazor threats

### 3.2 Sample Dashboard Queries

**Threat Count by Severity:**
```
_source.threat_type: "CyberRazor*" AND _source.rule.groups: "cyberrazor"
```

**Recent Threats:**
```
_source.timestamp: [now-24h TO now] AND _source.rule.groups: "cyberrazor"
```

**Critical Threats:**
```
_source.severity: "Critical" AND _source.rule.groups: "cyberrazor"
```

## 4. Alert Integration

### 4.1 Email Alerts

Configure email alerts in Wazuh:

```bash
# Edit /var/ossec/etc/ossec.conf
<email_alerts>
  <email_to>security@yourcompany.com</email_to>
  <level>6</level>
</email_alerts>
```

### 4.2 Slack Integration

Create Slack webhook and configure in Wazuh:

```bash
# Add to /var/ossec/etc/ossec.conf
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
  <api_url>https://slack.com/api/chat.postMessage</api_url>
  <alert_format>json</alert_format>
</integration>
```

### 4.3 Custom Webhook

Configure webhook to send alerts back to CyberRazor backend:

```bash
# Add to /var/ossec/etc/ossec.conf
<integration>
  <name>cyberrazor_webhook</name>
  <hook_url>http://your-cyberrazor-backend:8000/api/wazuh-webhook</hook_url>
  <api_url>http://your-cyberrazor-backend:8000/api/wazuh-webhook</api_url>
  <alert_format>json</alert_format>
</integration>
```

## 5. Monitoring and Maintenance

### 5.1 Check Wazuh Manager Status

```bash
# Check Wazuh manager status
systemctl status wazuh-manager

# Check Wazuh API status
curl -u admin:admin -k "https://localhost:55000/"

# View Wazuh logs
tail -f /var/ossec/logs/ossec.log
```

### 5.2 Monitor Agent Connections

```bash
# Check agent status
curl -u admin:admin -k "https://localhost:55000/agents"

# Check specific agent
curl -u admin:admin -k "https://localhost:55000/agents/AGENT_ID"
```

### 5.3 Backup Configuration

```bash
# Backup Wazuh configuration
tar -czf wazuh-config-backup-$(date +%Y%m%d).tar.gz /var/ossec/etc/

# Backup CyberRazor agent configuration
cp agent_config.yaml agent_config.yaml.backup
```

## 6. Troubleshooting

### 6.1 Common Issues

**Connection Refused:**
- Check firewall settings
- Verify Wazuh manager is running
- Check port 55000 is open

**Authentication Failed:**
- Verify API credentials
- Check user permissions in Wazuh
- Ensure SSL certificates are valid

**No Alerts Received:**
- Check decoder configuration
- Verify rule syntax
- Check log files for errors

### 6.2 Debug Mode

Enable debug logging in the agent:

```yaml
# In agent_config.yaml
log_level: "DEBUG"
```

### 6.3 Wazuh Log Analysis

```bash
# View Wazuh manager logs
tail -f /var/ossec/logs/ossec.log | grep cyberrazor

# View API logs
tail -f /var/ossec/logs/api.log

# Check for errors
grep -i error /var/ossec/logs/ossec.log
```

## 7. Security Considerations

### 7.1 API Security

- Use strong passwords for API users
- Rotate API tokens regularly
- Use HTTPS for all communications
- Implement IP whitelisting

### 7.2 Network Security

- Use VPN for remote connections
- Implement network segmentation
- Monitor network traffic
- Use firewalls to restrict access

### 7.3 Data Protection

- Encrypt sensitive data
- Implement access controls
- Regular security audits
- Backup configurations securely

## 8. Performance Optimization

### 8.1 Wazuh Performance

```bash
# Optimize Wazuh manager
# Edit /var/ossec/etc/ossec.conf
<ossec_config>
  <global>
    <memory_size>8G</memory_size>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>10m</agents_disconnection_alert_time>
  </global>
</ossec_config>
```

### 8.2 Agent Performance

```yaml
# In agent_config.yaml
scan_interval: 60  # Increase for better performance
max_processes_per_scan: 500  # Reduce for better performance
```

## 9. Scaling Considerations

### 9.1 Multiple Agents

- Use Wazuh cluster for high availability
- Implement load balancing
- Monitor resource usage
- Plan for growth

### 9.2 High Volume Environments

- Use Wazuh indexer for better performance
- Implement log rotation
- Monitor disk space
- Use dedicated hardware

## 10. Compliance and Reporting

### 10.1 Compliance Reports

Wazuh provides built-in compliance reporting:
- PCI DSS
- GDPR
- SOX
- HIPAA

### 10.2 Custom Reports

Create custom reports for CyberRazor threats:
- Threat trends
- Response times
- False positive rates
- System performance

This integration provides a comprehensive security monitoring solution combining real-time threat detection with centralized SIEM capabilities. 