# 🦇 OPNsense Sentinel Supreme - Network Monitoring System

> **Enterprise-grade network monitoring and automation for OPNsense firewalls with Slack integration**

A comprehensive Python-based monitoring solution that tracks WireGuard VPN connections, DHCP leases, network performance, security threats, bandwidth usage, and system health with real-time Slack notifications and interactive controls.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Monitoring Capabilities](#-monitoring-capabilities)
- [Slack Commands](#-slack-commands)
- [Alerts & Notifications](#-alerts--notifications)
- [Reports](#-reports)
- [Data Tracking](#-data-tracking)
- [API Endpoints Used](#-api-endpoints-used)
- [Troubleshooting](#-troubleshooting)
- [Advanced Features](#-advanced-features)

---

## ✨ Features

### 🔐 **VPN Monitoring (WireGuard)**
- Real-time connection/disconnection alerts
- Session bandwidth tracking (download/upload per session)
- IP geolocation with city, country, ISP, timezone
- Geographic anomaly detection (location changes)
- Threat level assessment (VPN/datacenter/proxy detection)
- Per-peer bandwidth statistics
- Mobile network detection
- Automatic baseline tracking

### 📡 **DHCP Lease Monitoring**
- Supports both ISC DHCP and Kea DHCP
- New device detection
- Device connect/disconnect notifications
- DHCP reservation integration for hostname mapping
- Anomaly detection:
  - Connection burst detection (5+ devices in 5 minutes)
  - Disconnect cycle detection (unstable devices)
- Hero device watchlist with custom alerts

### 🛡️ **Security Monitoring**
- **Suricata IDS**: Service status, alerts, restart detection
- **Zenarmor (Sensei)**: 
  - Threat detection and blocking
  - Application category tracking
  - Bandwidth usage by app
  - Top local hosts monitoring
  - Network health scoring
  - Connection spike detection
  - Port activity monitoring
- Security event aggregation (24-hour summaries)
- Threat cooldown system (prevents alert spam)

### 📊 **Network Performance**
- Speedtest integration with caching detection
- Baseline speed tracking
- Speed degradation alerts (<50% of baseline)
- 7-day rolling performance baselines
- Latency tracking
- SLA monitoring (uptime percentages)
- WAN traffic tracking (total internet usage)
- Interface statistics monitoring

### 🌐 **Gateway & Internet Monitoring**
- Gateway status tracking
- Internet outage detection (tests: 8.8.8.8, 1.1.1.1, 9.9.9.9)
- Outage duration tracking
- Automatic restoration alerts

### 📈 **Bandwidth Analytics**
- Daily bandwidth tracking (WAN + WireGuard separate)
- Weekly summaries
- Historical comparisons (yesterday, 7-day average, 30-day trends)
- Top talkers identification (VPN + WAN)
- Bandwidth hog detection (>30% usage alerts)
- Per-peer session tracking
- Hourly usage heatmaps
- Application category breakdown

### 🤖 **AI-Powered Analysis**
- Ollama integration for event analysis
- Pattern detection (bandwidth spikes, late-night activity)
- Threat level assessment
- Smart insights generation

### 📅 **Automated Reporting**
- **Daily Report** (7:00 AM):
  - 24-hour WAN traffic summary
  - WireGuard session stats
  - Historical comparisons
  - Smart pattern insights
  - Usage heatmap
  - Top talkers
  - Network health score
  - App category breakdown
  - Bandwidth hog alerts
  - Current speed/latency
- **Weekly Report** (Monday 7:00 AM):
  - 7-day traffic totals
  - Service health percentages
  - Security event summary
  - Performance SLA metrics
  - Unique device count
  - Service incident log

### 💬 **Interactive Slack Controls**
- Socket Mode real-time communication
- Slash command interface (`/opnsense`)
- Action buttons on notifications
- Manual speedtest triggers
- Service restart buttons
- Device blocking/unblocking
- Real-time status queries

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Container                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            Python Monitoring Script                    │  │
│  │                                                         │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │  │
│  │  │ OPNsense API │  │  Slack API   │  │  Ollama AI  │ │  │
│  │  │   Client     │  │   Client     │  │   Client    │ │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │  │
│  │         │                  │                  │        │  │
│  │  ┌──────▼──────────────────▼──────────────────▼──────┐ │  │
│  │  │         Main Monitoring Loop (60s interval)       │ │  │
│  │  │  - DHCP tracking    - Service health             │ │  │
│  │  │  - WireGuard peers  - Performance baselines      │ │  │
│  │  │  - Gateway status   - Security events            │ │  │
│  │  │  - Internet check   - Bandwidth tracking         │ │  │
│  │  └───────────────────────────────────────────────────┘ │  │
│  │                                                         │  │
│  │  ┌───────────────────────────────────────────────────┐ │  │
│  │  │        State Management & Data Storage            │ │  │
│  │  │  - DHCP leases      - Security events             │ │  │
│  │  │  - WireGuard peers  - Performance data            │ │  │
│  │  │  - Bandwidth stats  - Historical trends           │ │  │
│  │  │  - Service health   - Anomaly detection           │ │  │
│  │  └───────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                      │                      │
         ▼                      ▼                      ▼
   OPNsense API          Slack Webhook          Speedtest API
   10.13.20.1           (Notifications)         10.13.20.8:8765
```

### Data Flow

1. **Polling Loop** (every 60 seconds):
   - Fetches data from OPNsense APIs
   - Compares against known state
   - Detects changes and anomalies
   - Triggers alerts if thresholds exceeded

2. **Event Processing**:
   - New events → Immediate Slack notification
   - State changes → Update in-memory tracking
   - Anomalies → AI analysis + alert
   - Metrics → Historical data storage

3. **Scheduled Tasks**:
   - Daily reports: 7:00 AM
   - Weekly reports: Monday 7:00 AM
   - Hourly: Performance baseline updates
   - Every 10 min: Bandwidth hog checks

---

## 🚀 Installation

### Prerequisites

- Docker and Docker Compose
- OPNsense firewall with API access
- Slack workspace with bot configured
- (Optional) Speedtest container
- (Optional) Ollama AI server

### Environment Variables

Create a `.env` file:

```bash
# OPNsense Configuration
OPNSENSE_URL=http://10.13.20.1
OPN_API_KEY=your_api_key_here
OPN_API_SECRET=your_api_secret_here

# Slack Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token
SLACK_CHANNEL_ID=C01234567  # Optional for hero alerts

# Speedtest Configuration
SPEEDTEST_API_URL=http://10.13.20.8:8765/api/speedtest/latest

# Monitoring Thresholds
POLL_INTERVAL=60
SPEED_DROP_THRESHOLD=0.5
WG_SESSION_ALERT_GB=5.0
DAILY_BANDWIDTH_ALERT_GB=100.0
DHCP_BURST_THRESHOLD=5
DHCP_BURST_WINDOW=5
DISCONNECT_CYCLE_THRESHOLD=3
DISCONNECT_CYCLE_WINDOW=10
```

### Docker Deployment

```bash
# Build and start
docker-compose up -d

# View logs
docker logs -f dhcp_watcher

# Restart
docker restart dhcp_watcher
```

### Slack Bot Setup

1. Create a new Slack app at api.slack.com/apps
2. Enable **Socket Mode**
3. Add Bot Token Scopes:
   - `chat:write`
   - `commands`
   - `im:history`
4. Install app to workspace
5. Create slash command: `/opnsense`
6. Subscribe to bot events
7. Copy tokens to `.env`

---

## ⚙️ Configuration

### DHCP Reservation Endpoints

The system tries multiple Kea DHCP endpoints:
- `kea/dhcpv4/searchReservation`
- `kea/dhcpv4/reservation/search`
- `dhcpv4/reservation/search`

Fallback to ISC DHCP if Kea unavailable.

### Hero Watchlist

Add VIP devices for custom Batman-themed alerts:

```python
HERO_WATCHLIST = {
    "10.13.20.42": {
        "name": "The Bat WiFi", 
        "emoji": "🏎️", 
        "rank": "Legendary"
    },
    "10.13.20.6": {
        "name": "Beast Server", 
        "emoji": "🏰", 
        "rank": "Critical"
    }
}
```

### Threshold Tuning

```python
# Speed degradation (0.5 = 50% of baseline)
SPEED_DROP_THRESHOLD = 0.5

# WireGuard session alert (GB)
WG_SESSION_ALERT_GB = 5.0

# Daily bandwidth alert (GB)
DAILY_BANDWIDTH_ALERT_GB = 100.0

# DHCP burst: X devices in Y minutes
DHCP_BURST_THRESHOLD = 5
DHCP_BURST_WINDOW = 5

# Disconnect cycles
DISCONNECT_CYCLE_THRESHOLD = 3
DISCONNECT_CYCLE_WINDOW = 10
```

---

## 📊 Monitoring Capabilities

### WireGuard VPN

**Tracked Data:**
- Peer name
- Public key
- Endpoint IP and port
- Latest handshake age
- Transfer RX/TX (bytes)
- Session download/upload
- Connection duration

**Events Detected:**
- New connection
- Disconnection
- Location change (different IP)
- Excessive bandwidth usage (>5 GB session)

**Geolocation Data:**
- City, region, country
- ISP/organization
- Timezone
- Country flag emoji
- Connection type (VPN/mobile/datacenter)
- Threat level

**Example Alert:**
```
🔐 WireGuard Connected: laptop-vpn

📍 Location: Phoenix, United States
🏢 ISP: Cox Communications
🌐 IP Address: 45.23.156.89
🛡️ Threat Level: Low ✅

🕐 Timezone: America/Phoenix  |  Status: 📱 Mobile
```

### DHCP Leases

**Tracked Data:**
- MAC address
- IP address
- Hostname (from leases + reservations)
- Lease state (active/inactive)
- Connection history

**Events Detected:**
- New device (first-time connection)
- Device reconnection
- Device disconnection
- Connection bursts (anomaly)
- Unstable connections (disconnect cycling)

**Example Alert:**
```
🟢 New Device: iPhone-15

🖥️ Hostname: iPhone-15
🌐 IP Address: 10.13.20.123
🔖 MAC Address: aa:bb:cc:dd:ee:ff
📊 Status: CONNECTED 🟢

First time seen on network
```

### Security Events

**Suricata IDS:**
- Service status (up/down)
- Alert severity levels
- Attack signatures
- Source/destination IPs
- Restart tracking

**Zenarmor:**
- Threat detection count
- Blocked threat count
- Top threat categories
- Application monitoring
- Bandwidth per app
- Network health score

**Cooldown System:**
- Threat alerts: 24-hour cooldown
- Prevents notification spam
- Debug logging for cooldown status

### Network Performance

**Speedtest Tracking:**
- Download speed (Mbps)
- Upload speed (Mbps)
- Latency (ms)
- Test timestamp
- Cache detection (>6.5 hours old)

**Baseline System:**
- 7-day rolling average
- Speed degradation detection
- SLA compliance tracking
- Performance trend analysis

**Example Alert:**
```
📊 Performance SLA

✅ Download Speed: 95% of baseline
✅ Avg Latency: 12.3ms (excellent)

7-Day Baseline:
• Download: 850.2 Mbps
• Upload: 42.1 Mbps
• Latency: 12.3ms

Based on 156 measurements
```

### Bandwidth Analytics

**WAN Traffic (Total):**
- Daily download/upload
- Weekly totals
- Interface statistics
- Historical comparisons

**WireGuard Traffic (VPN only):**
- Per-session tracking
- Per-peer totals
- Top VPN users
- Session count

**Top Talkers:**
- Live WireGuard users (current session)
- WAN top hosts (Zenarmor data)
- Hostname resolution via DHCP
- Bandwidth ranking

**Example:**
```
🏆 Top WireGuard Users (Current Session)
1. `laptop-vpn`: 2.34 GB (↓2.10 ↑0.24)
2. `phone-remote`: 1.89 GB (↓1.50 ↑0.39)

🌐 Top WAN Talkers (Current)
1. `The Bat WiFi`: 15.67 GB
2. `Beast Server`: 8.21 GB
3. `Plex-Server`: 6.89 GB
```

---

## 💬 Slack Commands

### Available Commands

```
/opnsense status              - Full system status report
/opnsense speedtest           - Trigger manual speed test
/opnsense top-talkers         - Show bandwidth leaders
/opnsense insights            - AI pattern analysis
/opnsense network-health      - Overall health score (0-100)
/opnsense apps                - Application usage breakdown
/opnsense hogs                - Find bandwidth hogs (>30% usage)
/opnsense watch <ip> <name>   - Add device to Hero Watchlist
/opnsense block <ip>          - Block IP via firewall alias
/opnsense unblock <ip>        - Unblock IP
/opnsense blocklist           - Show all blocked IPs
/opnsense plex-privacy        - Check Plex telemetry activity
```

### Interactive Buttons

Notifications include action buttons:
- 📊 **Status Report** - Instant system overview
- ⚡ **Run Speedtest** - Manual test trigger
- 🔄 **Restart Suricata** - IDS service restart
- 🔄 **Restart Zenarmor** - L7 firewall restart

---

## 🔔 Alerts & Notifications

### Real-Time Alerts

| Event | Trigger | Cooldown |
|-------|---------|----------|
| VPN Connection | New WireGuard handshake | None |
| VPN Disconnection | Handshake timeout (180s) | None |
| VPN Location Change | Different endpoint IP | None |
| New DHCP Device | First-time MAC address | None |
| Device Reconnect/Disconnect | State change | None |
| Internet Outage | DNS unreachable (3 servers) | 30s |
| Speed Degradation | <50% of baseline | Per-test |
| Gateway Change | Status flip | Per-gateway |
| Service Down | Suricata/Zenarmor offline | Per-service |
| Security Threats | Zenarmor detections | 24 hours |
| Bandwidth Spike | >200% of 7-day average | None |
| Connection Spike | >300% above baseline | 1 hour |
| Bandwidth Hog | >30% total usage | 10 minutes |

### Notification Format

**Grid Layout:**
```
┌─────────────────────────────────────────┐
│         🔐 Event Title                  │
├─────────────────┬───────────────────────┤
│ 📥 Download     │ ⏱️ Ping               │
│ `Value 1`       │ `Value 2`             │
├─────────────────┼───────────────────────┤
│ 📤 Upload       │ 🌐 Gateway Status     │
│ `Value 3`       │ `Value 4`             │
├─────────────────┴───────────────────────┤
│ 🛡️ Security Services                    │
│ Suricata: ACTIVE ✅                     │
│ Zenarmor: ACTIVE ✅                     │
├─────────────────────────────────────────┤
│ ⏱️ System Uptime                        │
│ `1 day, 21:16:56`                       │
├─────────────────────────────────────────┤
│ Extra context/details                   │
└─────────────────────────────────────────┘
```

---

## 📅 Reports

### Daily Report (7:00 AM)

**Sections:**
1. **24-Hour Summary**
   - WAN traffic totals
   - WireGuard session count
   - Combined bandwidth

2. **Historical Comparison**
   - vs. Yesterday (percentage change)
   - vs. 7-day average
   - Trend arrows (↗️ ↘️ ➡️)

3. **Smart Insights**
   - Bandwidth spikes
   - Heavy VPN users
   - Late-night activity (1-5 AM)
   - Multiple disconnects
   - Service instability
   - Plex telemetry detection

4. **Usage Heatmap**
   - 24-hour WireGuard usage
   - Bar chart visualization
   - Peak hour identification

5. **Top Talkers**
   - WireGuard session leaders
   - WAN bandwidth consumers

6. **Network Health Score**
   - 0-100 rating
   - Issue breakdown
   - Status: Excellent/Good/Fair/Poor

7. **App Category Breakdown**
   - Traffic by application type
   - Bandwidth per category
   - Percentage distribution

8. **Current Metrics**
   - Speed test results
   - Latency
   - Active device count

9. **Bandwidth Hog Alert** (if detected)
   - Devices using >30% total
   - Traffic breakdown

### Weekly Report (Monday 7:00 AM)

**Sections:**
1. **Weekly Summary**
   - Date range
   - Total WAN traffic
   - Total VPN sessions
   - Unique devices

2. **Top Talkers**
   - Week's bandwidth leaders

3. **Service Health**
   - Uptime percentages
   - Restart counts
   - Downtime durations

4. **Security Events**
   - Suricata alerts (24h)
   - Zenarmor blocks
   - Top threat types

5. **Performance SLA**
   - Speed vs. baseline
   - Latency metrics
   - 7-day averages

---

## 🗄️ Data Tracking

### In-Memory State

```python
# DHCP Leases
known_dhcp_leases = {
    'aa:bb:cc:dd:ee:ff': {
        'hostname': 'laptop',
        'ip': '10.13.20.50',
        'state': 'active',
        'active': True
    }
}

# WireGuard Peers
wg_active_peers = {'wg0:abc123def456'}
wg_baselines = {
    'wg0:abc123def456': {'rx': 1234567890, 'tx': 987654321}
}

# Bandwidth Stats
daily_bandwidth = {
    '2026-02-14': {
        'wg_download': 5.2,
        'wg_upload': 1.3,
        'wg_sessions': 8,
        'wan_download': 45.7,
        'wan_upload': 12.3
    }
}

# Service Health
service_health = {
    'suricata': {
        'uptime_start': datetime(...),
        'restart_count': 0,
        'downtime_total': 0
    }
}
```

### Historical Data

```python
# Daily Stats (last 30 days)
historical_daily_stats = deque([
    {'date': '2026-02-13', 'wan_total': 58.0, 'wg_total': 6.5},
    {'date': '2026-02-14', 'wan_total': 62.3, 'wg_total': 7.8}
], maxlen=30)

# Performance Baselines (168 hours = 7 days)
performance_baselines = {
    'latency': deque([12.3, 11.8, ...], maxlen=168),
    'download_speed': deque([850.2, 847.9, ...], maxlen=168),
    'upload_speed': deque([42.1, 41.8, ...], maxlen=168)
}

# Security Events (last 1000)
security_events = {
    'suricata_alerts': deque([...], maxlen=1000),
    'zenarmor_blocks': deque([...], maxlen=1000)
}
```

### Anomaly Detection

```python
# Connection events (last 100)
dhcp_connection_events = deque([
    {'time': datetime(...), 'mac': 'aa:bb:cc:dd:ee:ff'}
], maxlen=100)

# Device disconnect history (last 20 per device)
device_disconnect_history = {
    'aa:bb:cc:dd:ee:ff': deque([datetime(...), ...], maxlen=20)
}

# WireGuard endpoint history (last 10 per peer)
wg_endpoint_history = {
    'wg0:abc123': ['45.23.156.89:51820', ...]
}
```

---

## 🔌 API Endpoints Used

### OPNsense APIs

**Working Endpoints:**
```python
# Core Services
"core/service/search"              # Service status
"core/service/status"              # Service details

# WireGuard
"wireguard/service/show"           # Peer information

# DHCP (Kea)
"kea/leases4/search"               # Active leases
"kea/dhcpv4/searchReservation"     # Reservations

# DHCP (ISC - fallback)
"dhcpv4/leases/searchLease"        # ISC leases

# Network
"routes/gateway/status"            # Gateway status
"diagnostics/interface/get_interface_config"  # Interfaces
"diagnostics/interface/getInterfaceStatistics" # Traffic stats

# Security
"ids/service/status"               # Suricata status
"ids/service/getAlertLogs"         # IDS alerts
"zenarmor/status"                  # Zenarmor dashboard data

# Firewall
"firewall/alias/getItem/<alias>"   # Alias contents
"firewall/alias/addItem"           # Add to alias (POST)
"firewall/alias/delItem"           # Remove from alias (POST)
"firewall/filter/apply"            # Apply changes (POST)

# Updates
"core/firmware/status"             # Firmware updates (POST)
"core/firmware/upgradestatus"      # Package updates
```

**Zenarmor Status Data:**
```python
zen_status = fetch_opn("zenarmor/status")
# Returns:
{
    'threat_detected': 4,
    'threat_detected_blocked': 0,
    'active_device': 24,
    'top_apps_categories': {
        'labels': ['Web Browsing', 'Streaming', ...],
        'datasets': [{'data': [bytes, ...]}]
    },
    'top_local_hosts': {
        'labels': ['10.13.20.42', '10.13.20.8', ...],
        'datasets': [{'data': [bytes, ...]}]
    },
    'top_detect_threats': {
        'labels': ['Phishing', 'Malware', ...]
    }
}
```

### External APIs

**IP Geolocation:**
```python
# Primary
GET https://ifconfig.co/json?ip={ip_address}

# Returns:
{
    'city': 'Phoenix',
    'region_name': 'Arizona',
    'country': 'United States',
    'country_iso': 'US',
    'time_zone': 'America/Phoenix',
    'asn_org': 'Cox Communications'
}
```

**Speedtest:**
```python
GET http://10.13.20.8:8765/api/speedtest/latest
GET http://10.13.20.8:8765/api/speedtest/run  # Trigger
```

**AI Analysis (Ollama):**
```python
POST http://10.13.20.8:11434/api/chat
# Model: llama3
```

---

## 🔧 Troubleshooting

### Common Issues

**1. Zenarmor 404 Errors**
```
⚠️ API FAILURE: zenarmor/reporting/categories returned 404
```
**Fix:** Use only `zenarmor/status` endpoint (all reporting endpoints deprecated)

**2. DHCP Leases Not Detected**
```
📊 DHCP API Scan Complete: 0 active, 0 inactive
```
**Fix:** Check Kea/ISC DHCP service is running, verify API endpoint accessibility

**3. Speedtest Always Cached**
```
📥 Download: 850.2 Mbps (cached)
```
**Fix:** Speedtest container may be down or not running tests automatically

**4. Slack Notifications Not Sending**
```
❌ Failed to send Slack notification: timeout
```
**Fix:** Verify `SLACK_WEBHOOK_URL` is correct, check network connectivity

**5. Socket Mode Connection Failed**
```
❌ CRITICAL CONNECTION ERROR: invalid_auth
```
**Fix:** Regenerate `SLACK_APP_TOKEN`, ensure Socket Mode enabled

**6. Threat Alerts Every 2 Minutes**
```python
# Old (broken):
if "⚠️" in threat_intel:  # Crashes on None

# Fixed:
if threat_intel:  # Checks for None properly
```

### Debug Mode

Enable detailed logging:
```python
# In fetch_opn():
if r.status_code != 200:
    print(f"⚠️ API FAILURE: {path} returned {r.status_code}")
    print(f"⚠️ RESPONSE BODY: {r.text[:200]}")
```

### Log Monitoring

```bash
# Real-time logs
docker logs -f dhcp_watcher

# Filter for errors
docker logs dhcp_watcher 2>&1 | grep "❌\|⚠️"

# Check specific feature
docker logs dhcp_watcher 2>&1 | grep "WireGuard\|DHCP\|Zenarmor"
```

---

## 🎯 Advanced Features

### Network Health Score

**Algorithm:**
```python
score = 100
- 20 per active threat (max -60)
- 10 if >50 devices
- 30 if Suricata offline
- 30 if Zenarmor offline

Result:
90-100 = 🟢 Excellent
75-89  = 🟡 Good
50-74  = 🟠 Fair
0-49   = 🔴 Poor
```

### Bandwidth Hog Detection

**Criteria:**
- Uses >30% of total network bandwidth
- Measured against all active hosts
- Checks every 10 minutes
- Sends alert with device name and percentage

### Connection Spike Detection

**Baseline:** 7-day rolling average of connections
**Trigger:** >300% above baseline
**Cooldown:** 1 hour between alerts

### Geographic Anomaly Detection

**Tracking:**
- Stores last 10 endpoint IPs per VPN peer
- Compares new connection IP against history
- Alerts if connecting from new location

**Threat Levels:**
- **Safe ✅**: Home ISP, normal connection
- **Low ✅**: Residential ISP
- **Low-Medium 🟡**: VPN/datacenter/hosting
- **Medium ⚠️**: Proxy detected

### Smart Pattern Detection

**Patterns Identified:**
1. Bandwidth spike (>200% of average)
2. Heavy VPN user (>10 GB session)
3. Late-night activity (1-5 AM, >5 devices)
4. Multiple disconnects (<5 min, 3+ devices)
5. Service instability (>2 restarts)
6. Plex telemetry active
7. Security alerts (threats detected)

### Application Category Monitoring

**Categories Tracked:**
- Web Browsing 🌐
- Streaming 📺
- Social Media 💬
- Gaming 🎮
- Software Updates 🔄
- Cloud Storage ☁️
- VPN 🔒
- Email 📧
- File Transfer 📁
- Music 🎵
- Shopping 🛒
- News 📰

---

## 📚 Data Retention

| Data Type | Retention | Storage |
|-----------|-----------|---------|
| DHCP Leases | Current state only | In-memory |
| WireGuard Peers | Current + 10 historical endpoints | In-memory |
| Daily Bandwidth | 30 days | Deque |
| Weekly Stats | 12 weeks | Deque |
| Performance Baselines | 7 days (168 hours) | Deque |
| Security Events | 1000 most recent | Deque |
| Connection Events | 100 most recent | Deque |
| Disconnect History | 20 per device | Dict of deques |

**Note:** All data is stored in-memory and resets on container restart.

---

## 🎨 Customization

### Add New Hero Device

```python
HERO_WATCHLIST["10.13.20.99"] = {
    "name": "New Hero",
    "emoji": "🦸",
    "rank": "Guardian"
}
```

### Adjust Alert Thresholds

```python
# More sensitive speed alerts (30% degradation)
SPEED_DROP_THRESHOLD = 0.7

# Lower VPN session alert (2 GB)
WG_SESSION_ALERT_GB = 2.0

# Stricter bandwidth hog (20% instead of 30%)
# In detect_bandwidth_hogs():
if percentage > 20:  # Changed from 30
```

### Add Custom Insights

```python
# In detect_smart_patterns():
if your_condition:
    insights.append(f"🔥 Your custom alert: {details}")
```

---

## 📄 License

MIT License - Feel free to modify and distribute

---

## 🙏 Credits

- **OPNsense** - Network security platform
- **Slack** - Communication platform
- **Zenarmor (Sensei)** - Layer 7 application firewall
- **Suricata** - Intrusion detection system
- **Ollama** - Local AI inference
- **ifconfig.co** - IP geolocation API

---

## 📞 Support

For issues or questions:
1. Check logs: `docker logs dhcp_watcher`
2. Verify API connectivity: Test endpoints manually
3. Review configuration: Check `.env` file
4. Enable debug mode: Add print statements

---

**Version:** 2.0 (Enhanced)
**Last Updated:** February 2026
**Status:** Production Ready ✅
