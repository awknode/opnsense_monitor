---

# 🦇 OPNsense Sentinel Supreme - Network Monitoring & Automation

A comprehensive Python-based network monitoring solution for OPNsense with Slack integration, featuring real-time alerts, bandwidth tracking, security monitoring, and intelligent pattern detection.

## 🌟 Features

### 📊 **Network Monitoring**
- Real-time WAN and VPN bandwidth tracking
- WireGuard VPN session monitoring with geographic anomaly detection
- DHCP lease tracking (supports both Kea and ISC DHCP)
- Internet speed testing with historical trends
- Network health scoring (0-100)
- Top bandwidth users ("top talkers")

### 🛡️ **Security & Threat Detection**
- Suricata IDS integration
- Zenarmor threat detection
- AdGuard Home + Pi-hole DNS protection (3 servers)
- Automatic port scan detection
- Real-time security event tracking
- IP geolocation with threat assessment

### 📺 **Plex Media Server Monitoring**
- Live streaming detection (local + remote)
- VPN bandwidth correlation
- DNS telemetry tracking across all DNS servers
- Privacy monitoring

### 🐳 **Infrastructure Monitoring**
- Docker container health checks
- Service uptime tracking
- Automatic restart detection
- System performance monitoring

### 📱 **Slack Integration**
- Interactive slash commands (`/opnsense`)
- Real-time notifications
- Daily/Weekly/Monthly reports
- Actionable buttons for common tasks

### 🤖 **AI-Powered Analysis**
- Ollama integration for threat analysis
- Intelligent pattern detection
- Behavioral anomaly detection
- Smart insights generation

---

## 📋 Prerequisites

- **OPNsense**: 24.x or later
- **Python**: 3.9+
- **Docker** (optional but recommended)
- **Slack Workspace** with bot permissions
- **Ollama** (optional, for AI features)

### OPNsense API Requirements
- API key/secret with appropriate permissions
- Plugins: Zenarmor (optional), Suricata IDS (optional)

---

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/opnsense-sentinel.git
cd opnsense-sentinel
```

### 2. Configure Environment

Create a `.env` file:

```bash
# OPNsense Configuration
OPNSENSE_URL=http://10.1.1.1
OPN_API_KEY=your_api_key_here
OPN_API_SECRET=your_api_secret_here

# Slack Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token

# Network Monitoring
POLL_INTERVAL=60
SPEEDTEST_API_URL=http://10.1.1.8:8765/api/speedtest/latest

# DNS Protection (AdGuard + Pi-hole)
ADGUARD_URL=http://10.1.1.1:8080
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your_password

# Pi-hole Configuration (v6 API)
PIHOLE_PASSWORD=your_pihole_password

# Plex Configuration (optional)
PLEX_URL=http://10.1.1.98:32400
PLEX_TOKEN=your_plex_token_here

# Alert Thresholds
SPEED_DROP_THRESHOLD=0.5
WG_SESSION_ALERT_GB=5.0
DAILY_BANDWIDTH_ALERT_GB=100.0
DHCP_BURST_THRESHOLD=5
DHCP_BURST_WINDOW=5
DISCONNECT_CYCLE_THRESHOLD=3
DISCONNECT_CYCLE_WINDOW=10
```

### 3. Install Dependencies

```bash
pip install requests python-dotenv slack-sdk psutil ollama
```

### 4. Run the Monitor

```bash
python monitor.py
```

Or use Docker:

```bash
docker build -t opnsense-monitor .
docker run -d --name dhcp_watcher --env-file .env opnsense-monitor
```

---

## 🎮 Slack Commands

### 📊 **Status & Monitoring**
```
/opnsense status              - Full status report
/opnsense speedtest           - Run speed test
/opnsense speed-history       - Internet speed trends (7 days)
/opnsense network-health      - Overall health score (0-100)
```

### 📡 **Network Analysis**
```
/opnsense top-talkers         - Show bandwidth users
/opnsense show-leases         - List all active DHCP leases
/opnsense device <ip>         - Detailed device profile
/opnsense apps                - Application usage breakdown
/opnsense hogs                - Find bandwidth hogs
```

### 🛡️ **Security & DNS**
```
/opnsense dns-stats           - DNS protection report (AdGuard + Pi-hole)
/opnsense dns-top-domains     - Most queried domains
/opnsense dns-blocked         - Most blocked domains
/opnsense firewall-stats      - Firewall analytics
/opnsense insights            - AI pattern analysis
```

### 🔐 **VPN & Plex**
```
/opnsense vpn-dashboard       - WireGuard VPN status
/opnsense plex-status         - Real-time streaming detection
/opnsense plex-live           - Live Plex sessions (requires token)
/opnsense plex-privacy        - Check Plex telemetry
/opnsense plex-dns            - Plex in DNS logs
```

### 🐳 **Infrastructure**
```
/opnsense containers          - Docker container health
```

### 🔧 **Management**
```
/opnsense watch <ip> <name>   - Add a Hero Device
/opnsense block <ip>          - Block an IP address
/opnsense unblock <ip>        - Unblock an IP
/opnsense blocklist           - Show all blocked IPs
```

---

## 📅 Automated Reports

### **Daily Report** (7:00 AM)
- 24-hour WAN/VPN bandwidth summary
- Usage heatmap by hour
- Historical comparison (yesterday, 7-day avg)
- Top bandwidth users
- Application breakdown
- Network health score
- Smart insights

### **Weekly Report** (Monday 7:00 AM)
- 7-day WAN/VPN totals
- Service health (uptime percentages)
- Security event summary
- Performance SLA check
- Unique devices/VPN clients

### **Monthly Report** (1st of month, 7:00 AM)
- Executive summary
- 30-day totals
- Security overview
- System health metrics

---

## 🔔 Real-Time Alerts

### **Connection Events**
- New device connections (with hostname)
- VPN connections (with geolocation)
- Geographic anomalies (VPN from new country)
- Device disconnections

### **Security Alerts**
- Port scan detection (10+ ports in 5 min)
- Suricata IDS alerts
- Zenarmor threat detection
- High-severity security events

### **Performance Alerts**
- Internet outages (with duration tracking)
- Service restarts (Suricata, Zenarmor)
- Speed degradation (>50% below baseline)
- Bandwidth hogs (>30% of total usage)

### **Anomaly Detection**
- DHCP burst (5+ devices in 5 min)
- Disconnect cycles (3+ in 10 min)
- Connection spikes (300%+ above normal)
- Unusual time activity (1-5 AM)

---

## 🏆 Hero Device Watchlist

Track critical devices with special alerts:

```python
HERO_WATCHLIST = {
    "10.1.1.42": {"name": "The Bat WiFi", "emoji": "🏎️", "rank": "Legendary"},
    "10.1.1.6": {"name": "Beast Server", "emoji": "🏰", "rank": "Critical"},
    "10.1.1.8": {"name": "The Beast-Box", "emoji": "👹", "rank": "Core System"}
}
```

Add devices dynamically:
```
/opnsense watch 10.1.1.50 Robin
```

---

## 🗺️ Network Topology

```
Internet ─── OPNsense (10.1.1.1)
              ├── WAN Interface
              ├── LAN (10.1.1.0/24)
              ├── AdGuard Home (10.1.1.1:8080)
              ├── Pi-hole 1 (10.1.1.69)
              ├── Pi-hole 2 (10.1.1.70)
              ├── Beast-Box (10.1.1.8) [Monitor Host]
              ├── Beast Server (10.1.1.6)
              ├── Plex Server (10.1.1.98)
              └── WireGuard VPN (wg0)
```

---

## 🔧 Configuration Guide

### **OPNsense Setup**

1. **Create API User**
   - System > Access > Users
   - Add user with API privileges
   - Generate API key/secret

2. **Enable Services**
   - Services > Intrusion Detection (Suricata)
   - Services > Zenarmor (optional)
   - Services > DHCPv4 (Kea or ISC)

3. **Configure WireGuard**
   - VPN > WireGuard > Settings
   - Create server instance
   - Add peers

### **Slack App Setup**

1. **Create Slack App**
   - Go to api.slack.com/apps
   - Create "New App" > From Scratch
   - Name: "OPNsense Bot"

2. **Configure OAuth & Permissions**
   - Add scopes: `chat:write`, `commands`
   - Install to workspace
   - Copy Bot User OAuth Token

3. **Enable Socket Mode**
   - Settings > Socket Mode > Enable
   - Generate App-Level Token
   - Add scope: `connections:write`

4. **Create Slash Command**
   - Features > Slash Commands
   - Create `/opnsense` command
   - Request URL not needed (Socket Mode)

5. **Create Webhook**
   - Incoming Webhooks > Add New Webhook
   - Select channel
   - Copy Webhook URL

### **Pi-hole v6 API Setup**

1. **Get Password**
   ```bash
   # On Pi-hole server
   sudo pihole -a -p
   ```

2. **Test Authentication**
   ```bash
   curl -X POST "http://10.1.1.69/api/auth" \
     -H "Content-Type: application/json" \
     -d '{"password": "YOUR_PASSWORD"}'
   ```

3. **Add to .env**
   ```bash
   PIHOLE_PASSWORD=your_password_here
   ```

### **Plex Token (Optional)**

1. **Get Token from URL**
   - Open Plex Web (http://10.1.1.98:32400/web)
   - Play any video
   - Click ⋮ > Get Info > View XML
   - Look for `X-Plex-Token=` in URL

2. **Or via Settings**
   - Settings > Account > Authorized Devices
   - Right-click device > Inspect
   - Find token in network requests

---

## 📊 Data Tracking

### **Bandwidth Tracking**
- **WAN Traffic**: Total internet usage (all devices)
- **VPN Traffic**: WireGuard peer usage
- **Per-Device**: Top talkers by IP
- **Historical**: 30 days of daily stats

### **DHCP Leases**
- Active/inactive tracking
- Hostname resolution via reservations
- Connection/disconnection events
- Subnet organization

### **Security Events**
- Last 1000 Suricata alerts
- Last 1000 Zenarmor blocks
- Last 100 port scans
- 7-day rolling summary

### **Performance Baselines**
- 7-day speed averages
- Latency trends
- Connection patterns
- Service uptime

---

## 🐛 Troubleshooting

### **Common Issues**

**1. No Slack Notifications**
```bash
# Check webhook
curl -X POST YOUR_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"text":"Test message"}'

# Check bot token
echo $SLACK_BOT_TOKEN

# Verify Socket Mode connection
docker logs dhcp_watcher | grep "Socket Mode"
```

**2. API Connection Failed**
```bash
# Test OPNsense API
curl -k -u "KEY:SECRET" https://10.1.1.1/api/diagnostics/interface/getInterfaceStatistics

# Check network from container
docker exec dhcp_watcher ping 10.1.1.1
```

**3. Pi-hole API Unauthorized**
```bash
# Verify password
curl -X POST "http://10.1.1.69/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"password": "YOUR_PASSWORD"}' | jq

# Check response for session ID
```

**4. DHCP Leases Not Tracking**
```bash
# Check Kea API
curl -k -u "KEY:SECRET" https://10.1.1.1/api/kea/leases4/search | jq

# Check ISC DHCP (fallback)
curl -k -u "KEY:SECRET" https://10.1.1.1/api/dhcpv4/leases/searchLease | jq
```

### **Debug Mode**

Enable verbose logging:
```python
# In monitor.py, add to top:
import logging
logging.basicConfig(level=logging.DEBUG)
```

View logs:
```bash
docker logs -f dhcp_watcher --tail 100
```

---

## 🎨 Customization

### **Alert Thresholds**

Edit `.env`:
```bash
# Speed must be >50% of baseline to avoid alert
SPEED_DROP_THRESHOLD=0.5

# Alert if VPN session uses >5 GB
WG_SESSION_ALERT_GB=5.0

# Alert if daily usage exceeds 100 GB
DAILY_BANDWIDTH_ALERT_GB=100.0

# Alert if 5+ devices connect within 5 minutes
DHCP_BURST_THRESHOLD=5
DHCP_BURST_WINDOW=5
```

### **Report Schedule**

Edit `monitor.py`:
```python
# Daily report time (default: 7 AM)
if now.hour == 7 and now.minute < 5:
    send_daily_report()

# Weekly report (default: Monday 7 AM)
if now.weekday() == 0 and now.hour == 7:
    send_weekly_report()

# Monthly report (default: 1st at 7 AM)
if now.day == 1 and now.hour == 7:
    send_monthly_report()
```

### **Hero Devices**

Add to `HERO_WATCHLIST` in `monitor.py`:
```python
HERO_WATCHLIST = {
    "10.1.1.100": {
        "name": "Gaming PC",
        "emoji": "🎮",
        "rank": "High Priority"
    }
}
```

---

## 📈 Performance

- **CPU Usage**: ~5-10% on Intel N100
- **RAM**: ~150-200 MB
- **Network**: Minimal (<1 MB/min)
- **Poll Interval**: 10s (configurable)

---

## 🔒 Security

- API credentials stored in `.env` (never committed)
- HTTPS support for OPNsense API
- Pi-hole session tokens cached (30s before expiry)
- IP geolocation for VPN connections
- Automatic threat assessment

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

---

## 💡 Tips

1. **Use Docker** for easier deployment and isolation
2. **Enable all DNS servers** (AdGuard + 2 Pi-holes) for comprehensive tracking
3. **Set Plex token** for accurate local streaming detection
4. **Monitor logs** during first 24h to tune thresholds
5. **Use Hero Watchlist** for critical devices
6. **Check weekly reports** to identify patterns

---

## 🏙️ Location

Network monitored from: **Denver, Colorado, US**

Timezone: `America/Denver` (MST/MDT)

---

## 📞 Support

- GitHub Issues: [Report bugs](https://github.com/yourusername/opnsense-sentinel/issues)
- Documentation: [Wiki](https://github.com/yourusername/opnsense-sentinel/wiki)
- Slack: #opnsense-monitor

---

**Made with 🦇 in Denver, Colorado**
