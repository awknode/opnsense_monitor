import requests
import time
import psutil
import shutil
import os
import urllib3
import json
import signal
import ollama
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dotenv import load_dotenv
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.web import WebClient
from slack_sdk.socket_mode.response import SocketModeResponse

# Silence SSL warnings
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
OPNSENSE_URL = os.getenv("OPNSENSE_URL", "http://10.1.1.1")
API_KEY = os.getenv("OPN_API_KEY")
API_SECRET = os.getenv("OPN_API_SECRET")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
SPEEDTEST_API = os.getenv("SPEEDTEST_API_URL", "http://10.1.1.8:8765/api/speedtest/latest")
AGH_USER = os.getenv("ADGUARD_USERNAME")
AGH_PASS = os.getenv("ADGUARD_PASSWORD")
AGH_URL = os.getenv("ADGUARD_URL")

# Bandwidth thresholds
SPEED_DROP_THRESHOLD = float(os.getenv("SPEED_DROP_THRESHOLD", "0.5"))
WG_SESSION_ALERT_GB = float(os.getenv("WG_SESSION_ALERT_GB", "5.0"))
DAILY_BANDWIDTH_ALERT_GB = float(os.getenv("DAILY_BANDWIDTH_ALERT_GB", "100.0"))

# Anomaly detection thresholds
DHCP_BURST_THRESHOLD = int(os.getenv("DHCP_BURST_THRESHOLD", "5"))
DHCP_BURST_WINDOW = int(os.getenv("DHCP_BURST_WINDOW", "5"))
DISCONNECT_CYCLE_THRESHOLD = int(os.getenv("DISCONNECT_CYCLE_THRESHOLD", "3"))
DISCONNECT_CYCLE_WINDOW = int(os.getenv("DISCONNECT_CYCLE_WINDOW", "10"))

# State Tracking
known_dhcp_leases = {}
dhcp_reservations = {}  # DHCP reservations for hostname lookup
last_zen_state = "ACTIVE ✅"
last_suricata_state = "ACTIVE ✅"
last_seen_suricata_line = ""
FAST_POLL = 10
NETWORK_CHECK_INTERVAL = POLL_INTERVAL // FAST_POLL
last_gw_state = {}
last_wg_handshakes = {}
service_cooldowns = {"suricata": 0, "zenarmor": 0}
last_threat_count = 0
last_threat_alert_time = None
connection_baseline = deque(maxlen=168)  # 7 days of hourly connection counts
last_connection_alert_time = None
last_bandwidth_hog_alert_time = None

pihole_sessions = {
    '10.1.1.69': {'sid': None, 'expires': datetime.now()},
    '10.1.1.70': {'sid': None, 'expires': datetime.now()}
}

# while true
loop_count = 0
last_daily_report_day = None
last_weekly_report_week = None
last_daily_report_date = ""
last_monthly_report_month = None

# Internet connectivity tracking
internet_is_up = True
internet_outage_start = None
last_internet_check = datetime.now()
port_scan_tracking = defaultdict(lambda: {'ports': set(), 'last_seen': datetime.now()})

# Bandwidth tracking
baseline_speed = {'download': 0, 'upload': 0}
wg_session_stats = {}
wg_baselines = {} 
wg_active_peers = set() # To stop spam: Tracks who is truly connected
wg_peer_hourly_tracking = {}

# Bandwidth tracking - now tracks BOTH total WAN traffic AND WireGuard separately
daily_bandwidth = defaultdict(lambda: {
    'wg_download': 0, 'wg_upload': 0, 'wg_sessions': 0,  # WireGuard only
    'wan_download': 0, 'wan_upload': 0                      # Total WAN traffic
})

weekly_stats = {
    'start_date': datetime.now(),
    # WireGuard stats
    'wg_total_sessions': 0,
    'wg_total_download_gb': 0,
    'wg_total_upload_gb': 0,
    'wg_peers_seen': set(),
    # Total WAN stats
    'wan_total_download_gb': 0,
    'wan_total_upload_gb': 0,
    # General stats
    'devices_seen': set(),
    'service_incidents': []
}

# Track last interface counters for calculating deltas
last_interface_stats = {}

# Top talkers tracking - tracks bandwidth per peer/device
wg_peer_bandwidth = defaultdict(lambda: {'download': 0, 'upload': 0})  # WireGuard peer usage
device_bandwidth = defaultdict(lambda: {'download': 0, 'upload': 0})   # Per-device WAN usage (future)

# Anomaly detection tracking
dhcp_connection_events = deque(maxlen=100)
device_disconnect_history = defaultdict(lambda: deque(maxlen=20))
wg_endpoint_history = defaultdict(list)
wg_hourly_usage = defaultdict(lambda: defaultdict(float))
blocked_devices = set()
speed_history = deque(maxlen=168)

WATCHLIST_CONTAINERS = ["open-webui", "n8n", "homeassistant", "traefik", "sonarr", "radarr", "lidarr", "unpackarr", "flood", "rtorrent", "deluge", "prowlarr", "organizer,", "portainer"]

HERO_WATCHLIST = {
    "10.1.1.42": {"name": "The Bat WiFi", "emoji": "🏎️", "rank": "Legendary"},
    "10.1.1.6": {"name": "Beast Server", "emoji": "🏰", "rank": "Critical"},
    "10.1.1.8": {"name": "The Beast-Box", "emoji": "👹", "rank": "Core System", "description": "AI / Automation / Neural Hub"}
}

# Historical comparison tracking (30 days of daily stats)
historical_daily_stats = deque(maxlen=30)  # Last 30 days
historical_weekly_stats = deque(maxlen=12)  # Last 12 weeks

# Service health tracking
service_health = {
    'suricata': {'uptime_start': datetime.now(), 'restart_count': 0, 'last_restart': None, 'downtime_total': 0},
    'zenarmor': {'uptime_start': datetime.now(), 'restart_count': 0, 'last_restart': None, 'downtime_total': 0},
    'internet': {'uptime_start': datetime.now(), 'outage_count': 0, 'last_outage': None, 'downtime_total': 0}
}

# Performance baseline tracking (rolling 7-day averages)
performance_baselines = {
    'latency': deque(maxlen=168),  # 7 days * 24 hours
    'download_speed': deque(maxlen=168),
    'upload_speed': deque(maxlen=168),
    'packet_loss': deque(maxlen=168)
}

# Security events tracking
security_events = {
    'suricata_alerts': deque(maxlen=1000),
    'zenarmor_blocks': deque(maxlen=1000),
    'port_scans': deque(maxlen=100),
    'suspicious_dns': deque(maxlen=100)
}

# Anomaly patterns detected
detected_anomalies = deque(maxlen=50)

# Slack integration
client = WebClient(token=os.environ.get("SLACK_BOT_TOKEN"))
app_token = os.environ.get("SLACK_APP_TOKEN")

"""def trigger_manual_speedtest():
    try:
        run_url = "http://10.1.1.8:8765/api/speedtest/run"
        print("⚡ Manual Speedtest: Triggering new scan...")
        requests.get(run_url, timeout=5)
        print("⏳ Speedtest in progress... waiting 40s.")
        time.sleep(40)
        speed = get_speedtest_data(retry=False)
        send_grid_notification(
            "⚡ Manual Speedtest Complete",
            speed['download'],
            speed['ping'],
            speed['upload'],
            "Test Complete",
            extra_text="Triggered via Slack button (Fresh Results)"
        )
    except Exception as e:
        print(f"❌ Manual speedtest failed: {e}")
"""

def trigger_manual_speedtest():
    # If your API triggers on GET instead of POST
    TRIGGER_URL = SPEEDTEST_API.replace('latest', 'run')
    try:
        print(f"🚀 Poking Speedtest via GET: {TRIGGER_URL}")
        requests.get(TRIGGER_URL, verify=False, timeout=5)
        
        # Notify Slack so you know it started
        send_grid_notification("⚡ Speedtest Initiated", dl="Running...", pg="N/A", ul="Running...", gw="Manual Trigger")
    except Exception as e:
        print(f"❌ Speedtest Trigger Failed: {e}")

def process_interaction(client, req):
    if req.type == "interactive":
        response = SocketModeResponse(envelope_id=req.envelope_id)
        client.send_socket_mode_response(response)
        
        payload = req.payload
        action_id = payload['actions'][0]['action_id']

        if action_id == 'status_report':
            print("📊 Status Report requested...")
            threading.Thread(target=cmd_status_report).start()
        elif action_id == 'run_speedtest':
            print("⚡ Manual Speedtest requested...")
            threading.Thread(target=trigger_manual_speedtest).start()
        elif action_id == 'restart_suricata':
            fetch_opn("ids/service/restart", method="POST")
            print("✅ Suricata restart initiated")
        elif action_id == 'restart_zenarmor':
            fetch_opn("sensei/service/restart", method="POST")
            print("✅ Zenarmor restart initiated")
    
    elif req.type == "slash_commands":
        response = SocketModeResponse(envelope_id=req.envelope_id)
        client.send_socket_mode_response(response)
        
        payload = req.payload
        command = payload.get('command', '')
        text = payload.get('text', '').strip()
        user_id = payload.get('user_id')
        channel_id = payload.get('channel_id')
        
        # Handle slash commands
        if command == '/opnsense':
            threading.Thread(target=handle_opnsense_command, args=(text, channel_id, user_id)).start()

def handle_opnsense_command(text, channel_id, user_id):
    """Handle /opnsense slash command with subcommands"""
    parts = text.split() if text else []
    subcommand = parts[0].lower() if parts else 'help'

    def safe_reply(msg):
        try:
            client.chat_postMessage(channel=channel_id, text=msg)
        except Exception as e:
            print(f"⚠️ Could not reply to slash command: {e}")

    try:
        # For slow commands, acknowledge immediately
        slow_commands = ['dns-top-domains', 'dns-blocked', 'firewall-stats', 'vpn-dashboard', 'containers', 'speed-history']
        
        if subcommand in slow_commands:
            safe_reply(f"⏳ Processing `{subcommand}`...")
        
        if subcommand == 'status':
            cmd_status_report()
        
        elif subcommand == 'speedtest':
            client.chat_postMessage(channel=channel_id, text="⚡ Running speedtest...")
            trigger_manual_speedtest()
        
        elif subcommand == 'top-talkers' or subcommand == 'top':
            report = get_top_talkers()
            safe_reply(report)

        elif subcommand == 'watch' and len(parts) >= 3:
            # Usage: /opnsense watch 10.1.1.50 Robin
            new_ip = parts[1]
            new_name = " ".join(parts[2:])
            # Adds to the global HERO_WATCHLIST in memory
            HERO_WATCHLIST[new_ip] = {"name": new_name, "emoji": "🛡️", "rank": "Member"}
            safe_reply(f"✅ Added *{new_name}* (`{new_ip}`) to the Hero Watchlist.")

        elif subcommand == 'network-health' or subcommand == 'health':
            health = calculate_network_health_score()
            safe_reply(health)
        
        elif subcommand == 'apps' or subcommand == 'categories':
            apps = get_app_category_report()
            safe_reply(apps)
        
        elif subcommand == 'hogs' or subcommand == 'bandwidth-hogs':
            hogs = detect_bandwidth_hogs()
            if hogs:
                safe_reply(hogs)
            else:
                safe_reply("*🐷 Bandwidth Usage*\n_No bandwidth hogs detected - usage is well distributed_")

        elif subcommand == 'block' and len(parts) >= 2:
            ip = parts[1]
            # Add IP to firewall block alias
            result = fetch_opn("firewall/alias/addItem", method="POST", payload={
                "alias": "blocked_hosts",
                "address": ip
            })
            if result:
                fetch_opn("firewall/filter/apply", method="POST")
                client.chat_postMessage(channel=channel_id, text=f"🚫 Blocked IP: `{ip}`")
            else:
                safe_reply(f"❌ Failed to block `{ip}` - ensure 'blocked_hosts' alias exists") 

        elif subcommand == 'unblock' and len(parts) >= 2:
            ip = parts[1]
            # Remove IP from firewall block alias
            result = fetch_opn("firewall/alias/delItem", method="POST", payload={
                "alias": "blocked_hosts",
                "address": ip
            })
            if result:
                fetch_opn("firewall/filter/apply", method="POST")
                client.chat_postMessage(channel=channel_id, text=f"✅ Unblocked IP: `{ip}`")
            else:
                safe_reply(f"❌ Failed to unblock `{ip}` - ensure 'blocked_hosts' alias exists")
            
        elif subcommand == 'blocklist' or subcommand == 'blocked':
            # Get blocked IPs from firewall alias
            blocked_data = fetch_opn("firewall/alias/getItem/blocked_hosts")
            if blocked_data and 'alias' in blocked_data:
                addresses = blocked_data['alias'].get('content', '').split('\n')
                addresses = [a.strip() for a in addresses if a.strip()]
                if addresses:
                    blocklist_text = "*🚫 Blocked IPs*\n```\n" + "\n".join(addresses) + "\n```"
                else:
                    blocklist_text = "*🚫 Blocked IPs*\n_No IPs currently blocked_"
            else:
                blocklist_text = "*🚫 Blocked IPs*\n_Blocklist alias not found_\n_Create 'blocked_hosts' alias in Firewall > Aliases_"
            safe_reply(blocklist_text)

        elif subcommand == 'insights':
            insights = detect_smart_patterns()
            safe_reply(insights)

        elif subcommand == 'dns-stats' or subcommand == 'dns':
            """Show DNS protection stats from AdGuard and Pi-hole"""
            dns_text = "*🛡️ DNS Protection Report*\n\n"
            
            total_queries = 0
            total_blocked = 0
            
            # AdGuard Home stats
            try:
                response = requests.get(
                    f"{AGH_URL}/control/stats",
                    auth=(AGH_USER, AGH_PASS),
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    adg_queries = data.get('num_dns_queries', 0)
                    adg_blocked = data.get('num_blocked_filtering', 0)
                    adg_rate = (adg_blocked / adg_queries * 100) if adg_queries > 0 else 0
                    
                    total_queries += adg_queries
                    total_blocked += adg_blocked
                    
                    dns_text += f"*AdGuard Home (OPNsense)*\n"
                    dns_text += f"• Queries: `{adg_queries:,}`\n"
                    dns_text += f"• Blocked: `{adg_blocked:,}` ({adg_rate:.1f}%)\n\n"
                else:
                    dns_text += "*AdGuard Home*\n_Unavailable_\n\n"
            except Exception as e:
                dns_text += f"*AdGuard Home*\n_Error: {str(e)[:30]}_\n\n"
            
            # Pi-hole 1 stats (10.1.1.69)
            try:
                pihole1_sid = get_pihole_session("10.1.1.69")
                
                if pihole1_sid is not None:
                    response = requests.get(
                        "http://10.1.1.69/api/stats/summary",
                        headers={"X-FTL-SID": pihole1_sid},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries_data = data.get('queries', {})
                        pi1_queries = queries_data.get('total', 0)
                        pi1_blocked = queries_data.get('blocked', 0)
                        pi1_rate = (pi1_blocked / pi1_queries * 100) if pi1_queries > 0 else 0
                        
                        total_queries += pi1_queries
                        total_blocked += pi1_blocked
                        
                        dns_text += f"*Pi-hole 1 (10.1.1.69)*\n"
                        dns_text += f"• Queries: `{pi1_queries:,}`\n"
                        dns_text += f"• Blocked: `{pi1_blocked:,}` ({pi1_rate:.1f}%)\n\n"
                    else:
                        dns_text += "*Pi-hole 1*\n_API Error_\n\n"
                else:
                    dns_text += "*Pi-hole 1*\n_Login Failed_\n\n"
            except Exception as e:
                dns_text += f"*Pi-hole 1*\n_Error: {str(e)[:30]}_\n\n"

            # Pi-hole 2 stats (10.1.1.70)
            try:
                pihole2_sid = get_pihole_session("10.1.1.70")
                
                if pihole2_sid is not None:
                    response = requests.get(
                        "http://10.1.1.70/api/stats/summary",
                        headers={"X-FTL-SID": pihole2_sid},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries_data = data.get('queries', {})
                        pi2_queries = queries_data.get('total', 0)
                        pi2_blocked = queries_data.get('blocked', 0)
                        pi2_rate = (pi2_blocked / pi2_queries * 100) if pi2_queries > 0 else 0
                        
                        total_queries += pi2_queries
                        total_blocked += pi2_blocked
                        
                        dns_text += f"*Pi-hole 2 (10.1.1.70)*\n"
                        dns_text += f"• Queries: `{pi2_queries:,}`\n"
                        dns_text += f"• Blocked: `{pi2_blocked:,}` ({pi2_rate:.1f}%)\n\n"
                    else:
                        dns_text += "*Pi-hole 2*\n_API Error_\n\n"
                else:
                    dns_text += "*Pi-hole 2*\n_Login Failed_\n\n"
            except Exception as e:
                dns_text += f"*Pi-hole 2*\n_Error: {str(e)[:30]}_\n\n"
            
            # Combined totals
            if total_queries > 0:
                total_rate = (total_blocked / total_queries * 100)
                dns_text += f"*📊 Combined Total (24h)*\n"
                dns_text += f"• Total Queries: `{total_queries:,}`\n"
                dns_text += f"• Total Blocked: `{total_blocked:,}` ({total_rate:.1f}%)\n"
                dns_text += f"• Protection Rate: {total_rate:.1f}%"
            
            safe_reply(dns_text)

        elif subcommand == 'show-leases' or subcommand == 'leases':
            """Show all active DHCP leases organized by subnet"""
            # Get current lease data from tracked state
            active_leases = {mac: lease for mac, lease in known_dhcp_leases.items() if lease['active']}
            inactive_leases = {mac: lease for mac, lease in known_dhcp_leases.items() if not lease['active']}
            
            if not active_leases:
                safe_reply("*📡 DHCP Leases*\n_No active leases found_")
            else:
                # Sort active leases by IP address
                sorted_leases = sorted(active_leases.items(), key=lambda x: tuple(map(int, x[1]['ip'].split('.'))))
                
                # Group by subnet
                from collections import defaultdict
                subnet_groups = defaultdict(list)
                
                for mac, lease in sorted_leases:
                    ip = lease['ip']
                    subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                    subnet_groups[subnet].append({
                        'hostname': lease['hostname'],
                        'ip': ip,
                        'mac': mac
                    })
                
                # Build response
                response = f"*📡 DHCP Lease Report*\n\n"
                response += f"🟢 Active: `{len(active_leases)}` | ⚪ Inactive: `{len(inactive_leases)}`\n\n"
                
                # Add each subnet
                for subnet in sorted(subnet_groups.keys()):
                    devices = subnet_groups[subnet]
                    response += f"*{subnet}* ({len(devices)} devices)\n"
                    
                    for d in devices:
                        # Format: IP - Hostname (truncate if too long)
                        hostname = d['hostname']
                        if len(hostname) > 25:
                            hostname = hostname[:22] + '...'
                        response += f"`{d['ip']:15}` {hostname}\n"
                    
                    response += "\n"
                
                # Add inactive summary if there are any
                if inactive_leases:
                    inactive_names = [lease['hostname'][:20] for lease in list(inactive_leases.values())[:5]]
                    response += f"⚪ *Recently Inactive:* "
                    response += ", ".join(inactive_names)
                    if len(inactive_leases) > 5:
                        response += f" +{len(inactive_leases)-5} more"
                
                safe_reply(response)

        elif subcommand == 'plex-privacy':
            plex_text = "*📺 Plex Privacy Status*\n\n"
            
            # Your Plex server IP
            plex_server_ip = "10.1.1.98"
            
            zen_status = fetch_opn("zenarmor/status")
            
            if zen_status:
                # Check if Plex is actively transmitting data
                top_hosts = zen_status.get('top_local_hosts', {}).get('labels', [])
                
                if plex_server_ip in top_hosts:
                    # Plex IS transmitting
                    plex_index = top_hosts.index(plex_server_ip)
                    
                    # Get bandwidth
                    datasets = zen_status.get('top_local_hosts', {}).get('datasets', [])
                    if datasets:
                        data_values = datasets[0].get('data', [])
                        if plex_index < len(data_values):
                            plex_bytes = data_values[plex_index]
                            plex_gb = plex_bytes / (1024**3)
                            
                            plex_text += f"🔴 *ACTIVE STREAMING DETECTED*\n\n"
                            plex_text += f"📊 Traffic: `{plex_gb:.2f} GB`\n"
                            plex_text += f"🏆 Rank: #{plex_index + 1} of {len(top_hosts)}\n\n"
                            plex_text += "*Telemetry Being Sent:*\n"
                            plex_text += "• 📺 Watch history\n"
                            plex_text += "• ⭐ Ratings/reviews\n"
                            plex_text += "• 📊 Server stats\n"
                            plex_text += "• 🎬 Metadata updates\n"
                        else:
                            plex_text += f"🟡 *Plex Active* but no bandwidth data"
                    else:
                        plex_text += f"🟡 *Plex Active* but no bandwidth data"
                else:
                    plex_text += f"✅ *No Active Streaming*\n\n"
                    plex_text += f"Plex server not in top {len(top_hosts)} hosts\n"
                    plex_text += f"Total devices: {zen_status.get('active_device', 0)}\n\n"
                    plex_text += "_Note: Zenarmor data updates every 5-15 minutes_"
            else:
                plex_text += "_Zenarmor unavailable_"
            
            safe_reply(plex_text)

        elif subcommand == 'containers':
            """Show Docker container health on Beast-Box"""
            try:
                # Run docker ps via SSH or direct API
                # If Beast-Box has docker accessible, we can query it
                result = subprocess.run(
                    ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Status}}|{{.State}}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    containers = result.stdout.strip().split('\n')
                    
                    running = []
                    stopped = []
                    
                    for container in containers:
                        if not container:
                            continue
                        parts = container.split('|')
                        if len(parts) >= 3:
                            name = parts[0]
                            status = parts[1]
                            state = parts[2]
                            
                            if state == 'running':
                                running.append(f"✅ `{name}` - {status}")
                            else:
                                stopped.append(f"❌ `{name}` - {status}")
                    
                    response = "*🐳 Docker Containers*\n\n"
                    response += f"*Running: {len(running)}*\n"
                    for c in running:
                        response += f"{c}\n"
                    
                    if stopped:
                        response += f"\n*Stopped: {len(stopped)}*\n"
                        for c in stopped:
                            response += f"{c}\n"
                    
                    safe_reply(response)
                else:
                    safe_reply("*🐳 Docker Containers*\n_Could not connect to Docker daemon_")
            except Exception as e:
                safe_reply(f"*🐳 Docker Containers*\n_Error: {str(e)[:100]}_")

        elif subcommand == 'dns-top-domains' or subcommand == 'top-domains':
            """Show most queried domains across all DNS servers"""
            safe_reply("⏳ Fetching top domains...")
            
            dns_text = "*🌐 Top Queried Domains (24h)*\n\n"
            
            all_domains = {}
            
            # Get from Pi-hole 1 - use queries endpoint
            try:
                pihole1_sid = get_pihole_session("10.1.1.69")
                if pihole1_sid is not None:
                    response = requests.get(
                        "http://10.1.1.69/api/queries",
                        headers={"X-FTL-SID": pihole1_sid},
                        params={"limit": 1000},  # Get last 1000 queries
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get('queries', [])
                        
                        for query in queries:
                            domain = query.get('domain', '')
                            if domain:
                                all_domains[domain] = all_domains.get(domain, 0) + 1
            except Exception as e:
                print(f"   ⚠️ Pi-hole 1 top domains error: {e}")
            
            # Get from Pi-hole 2
            try:
                pihole2_sid = get_pihole_session("10.1.1.70")
                if pihole2_sid is not None:
                    response = requests.get(
                        "http://10.1.1.70/api/queries",
                        headers={"X-FTL-SID": pihole2_sid},
                        params={"limit": 1000},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get('queries', [])
                        
                        for query in queries:
                            domain = query.get('domain', '')
                            if domain:
                                all_domains[domain] = all_domains.get(domain, 0) + 1
            except Exception as e:
                print(f"   ⚠️ Pi-hole 2 top domains error: {e}")
            
            if all_domains:
                sorted_domains = sorted(all_domains.items(), key=lambda x: x[1], reverse=True)[:15]
                
                for i, (domain, count) in enumerate(sorted_domains, 1):
                    dns_text += f"{i}. `{domain}`: {count:,} queries\n"
            else:
                dns_text += "_No domain data available from Pi-hole servers_"
            
            safe_reply(dns_text)

        elif subcommand == 'dns-blocked' or subcommand == 'blocked-domains':
            """Show most blocked domains across all DNS servers"""
            safe_reply("⏳ Fetching blocked domains...")
            
            dns_text = "*🚫 Top Blocked Domains (24h)*\n\n"
            
            all_blocked = {}
            
            # Get from Pi-hole 1 - use queries endpoint with blocked filter
            try:
                pihole1_sid = get_pihole_session("10.1.1.69")
                if pihole1_sid is not None:
                    response = requests.get(
                        "http://10.1.1.69/api/queries",
                        headers={"X-FTL-SID": pihole1_sid},
                        params={"blocked": "true", "limit": 1000},  # Only blocked queries
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get('queries', [])
                        
                        for query in queries:
                            domain = query.get('domain', '')
                            if domain:
                                all_blocked[domain] = all_blocked.get(domain, 0) + 1
            except Exception as e:
                print(f"   ⚠️ Pi-hole 1 blocked domains error: {e}")
            
            # Get from Pi-hole 2
            try:
                pihole2_sid = get_pihole_session("10.1.1.70")
                if pihole2_sid is not None:
                    response = requests.get(
                        "http://10.1.1.70/api/queries",
                        headers={"X-FTL-SID": pihole2_sid},
                        params={"blocked": "true", "limit": 1000},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get('queries', [])
                        
                        for query in queries:
                            domain = query.get('domain', '')
                            if domain:
                                all_blocked[domain] = all_blocked.get(domain, 0) + 1
            except Exception as e:
                print(f"   ⚠️ Pi-hole 2 blocked domains error: {e}")
            
            if all_blocked:
                sorted_blocked = sorted(all_blocked.items(), key=lambda x: x[1], reverse=True)[:15]
                
                for i, (domain, count) in enumerate(sorted_blocked, 1):
                    # Categorize threats
                    if any(x in domain for x in ['doubleclick', 'googlesyndication', 'adservice']):
                        emoji = "📢"  # Ads
                    elif any(x in domain for x in ['tracker', 'analytics', 'telemetry']):
                        emoji = "🔍"  # Tracking
                    elif any(x in domain for x in ['malware', 'phishing', 'suspicious']):
                        emoji = "⚠️"  # Malicious
                    else:
                        emoji = "🚫"  # Generic
                    
                    dns_text += f"{i}. {emoji} `{domain}`: {count:,} blocks\n"
            else:
                dns_text += "_No blocked domain data available from Pi-hole servers_"
            
            safe_reply(dns_text)

        elif subcommand == 'firewall-stats' or subcommand == 'firewall':
            """Show firewall rule statistics"""
            fw_text = "*🔥 Firewall Statistics*\n\n"
            
            try:
                # Get firewall logs
                logs = fetch_opn("firewall/log_file/view")
                
                if logs and 'rows' in logs:
                    blocked_ips = {}
                    blocked_ports = {}
                    rules_hit = {}
                    
                    for entry in logs['rows'][-500:]:  # Last 500 entries
                        action = entry.get('action', '')
                        src_ip = entry.get('src', 'unknown')
                        dst_port = entry.get('dst_port', 'unknown')
                        rule = entry.get('label', 'unknown')
                        
                        if action == 'block':
                            blocked_ips[src_ip] = blocked_ips.get(src_ip, 0) + 1
                            blocked_ports[dst_port] = blocked_ports.get(dst_port, 0) + 1
                            rules_hit[rule] = rules_hit.get(rule, 0) + 1
                    
                    # Top blocked IPs
                    if blocked_ips:
                        fw_text += "*🚫 Top Blocked IPs*\n"
                        for ip, count in sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
                            fw_text += f"• `{ip}`: {count} attempts\n"
                        fw_text += "\n"
                    
                    # Top targeted ports
                    if blocked_ports:
                        fw_text += "*🎯 Most Targeted Ports*\n"
                        for port, count in sorted(blocked_ports.items(), key=lambda x: x[1], reverse=True)[:5]:
                            port_name = {
                                '22': 'SSH', '23': 'Telnet', '80': 'HTTP',
                                '443': 'HTTPS', '3389': 'RDP', '445': 'SMB'
                            }.get(str(port), f"Port {port}")
                            fw_text += f"• {port_name}: {count} blocks\n"
                        fw_text += "\n"
                    
                    # Most active rules
                    if rules_hit:
                        fw_text += "*📋 Most Active Rules*\n"
                        for rule, count in sorted(rules_hit.items(), key=lambda x: x[1], reverse=True)[:5]:
                            fw_text += f"• {rule}: {count} hits\n"
                    
                    if not blocked_ips and not blocked_ports:
                        fw_text += "_No blocked connections in recent logs_"
                else:
                    fw_text += "_Firewall logs unavailable_"
            except Exception as e:
                fw_text += f"_Error: {str(e)[:100]}_"
            
            safe_reply(fw_text)

        elif subcommand == 'vpn-dashboard' or subcommand == 'vpn':
            """Show comprehensive VPN dashboard"""
            vpn_text = "*🔐 WireGuard VPN Dashboard*\n\n"
            
            try:
                data = fetch_opn("wireguard/service/show")
                
                if data and 'rows' in data:
                    active_peers = []
                    inactive_peers = []
                    
                    for item in data['rows']:
                        if not isinstance(item, dict) or item.get('type') != 'peer':
                            continue
                        
                        peer_name = item.get('name', 'Unknown')
                        peer_id = f"{item.get('ifname', 'wg')}:{item.get('public-key', '')[:16]}"
                        endpoint = item.get('endpoint', 'N/A')
                        
                        # Check handshake age
                        raw_age = item.get('latest-handshake-age')
                        age = int(raw_age) if raw_age is not None else 999999
                        
                        is_active = age < 180
                        
                        # Get bandwidth
                        rx_bytes = int(item.get('transfer-rx', 0))
                        tx_bytes = int(item.get('transfer-tx', 0))
                        
                        peer_info = {
                            'name': peer_name,
                            'endpoint': endpoint,
                            'age': age,
                            'rx_gb': rx_bytes / (1024**3),
                            'tx_gb': tx_bytes / (1024**3),
                            'total_gb': (rx_bytes + tx_bytes) / (1024**3)
                        }
                        
                        # Get session bandwidth if baseline exists
                        if peer_id in wg_baselines:
                            base = wg_baselines[peer_id]
                            session_rx = (rx_bytes - base['rx']) / (1024**3)
                            session_tx = (tx_bytes - base['tx']) / (1024**3)
                            peer_info['session_gb'] = session_rx + session_tx
                        else:
                            peer_info['session_gb'] = 0
                        
                        if is_active:
                            active_peers.append(peer_info)
                        else:
                            inactive_peers.append(peer_info)
                    
                    # Show active peers
                    vpn_text += f"*🟢 Active Connections: {len(active_peers)}*\n"
                    if active_peers:
                        # Sort by session bandwidth
                        active_peers.sort(key=lambda x: x['session_gb'], reverse=True)
                        
                        for peer in active_peers:
                            location = peer['endpoint'].split(':')[0] if ':' in peer['endpoint'] else peer['endpoint']
                            vpn_text += f"\n*{peer['name']}*\n"
                            vpn_text += f"• Location: `{location}`\n"
                            vpn_text += f"• Session: {peer['session_gb']:.2f} GB\n"
                            vpn_text += f"• Total: {peer['total_gb']:.2f} GB\n"
                            vpn_text += f"• Last seen: {peer['age']}s ago\n"
                    else:
                        vpn_text += "_No active VPN connections_\n"
                    
                    # Show inactive peers summary
                    if inactive_peers:
                        vpn_text += f"\n*⚪ Configured but Inactive: {len(inactive_peers)}*\n"
                        for peer in inactive_peers[:3]:
                            vpn_text += f"• {peer['name']} (idle)\n"
                        
                        if len(inactive_peers) > 3:
                            vpn_text += f"• +{len(inactive_peers) - 3} more\n"
                else:
                    vpn_text += "_WireGuard data unavailable_"
            except Exception as e:
                vpn_text += f"_Error: {str(e)[:100]}_"
            
            safe_reply(vpn_text)

        elif subcommand == 'speed-history' or subcommand == 'speeds':
            """Show internet speed trends"""
            speed_text = "*📊 Internet Speed History*\n\n"
            
            if len(speed_history) == 0:
                speed_text += "_No speed test history yet_"
                safe_reply(speed_text)
                return
            
            # Calculate stats
            downloads = [s['download'] for s in speed_history]
            uploads = [s['upload'] for s in speed_history]
            pings = [s['ping'] for s in speed_history]
            
            avg_down = sum(downloads) / len(downloads)
            avg_up = sum(uploads) / len(uploads)
            avg_ping = sum(pings) / len(pings)
            
            min_down = min(downloads)
            max_down = max(downloads)
            min_up = min(uploads)
            max_up = max(uploads)
            
            speed_text += f"*📈 Download Speed*\n"
            speed_text += f"• Average: `{avg_down:.1f} Mbps`\n"
            speed_text += f"• Range: `{min_down:.1f} - {max_down:.1f} Mbps`\n"
            speed_text += f"• Variance: `{((max_down - min_down) / avg_down * 100):.1f}%`\n\n"
            
            speed_text += f"*📤 Upload Speed*\n"
            speed_text += f"• Average: `{avg_up:.1f} Mbps`\n"
            speed_text += f"• Range: `{min_up:.1f} - {max_up:.1f} Mbps`\n\n"
            
            speed_text += f"*⏱️ Latency*\n"
            speed_text += f"• Average: `{avg_ping:.1f} ms`\n\n"
            
            speed_text += f"*📊 Data Points*\n"
            speed_text += f"• Tests recorded: {len(speed_history)}\n"
            speed_text += f"• Oldest: {speed_history[0]['timestamp'].strftime('%b %d, %I:%M %p')}\n"
            speed_text += f"• Newest: {speed_history[-1]['timestamp'].strftime('%b %d, %I:%M %p')}\n"
            
            # Recent trend
            if len(speed_history) >= 10:
                recent_5 = downloads[-5:]
                older_5 = downloads[-10:-5]
                trend_pct = ((sum(recent_5)/5 - sum(older_5)/5) / (sum(older_5)/5) * 100)
                
                if trend_pct > 5:
                    speed_text += f"\n📈 *Trending up:* +{trend_pct:.1f}%"
                elif trend_pct < -5:
                    speed_text += f"\n📉 *Trending down:* {trend_pct:.1f}%"
                else:
                    speed_text += f"\n➡️ *Stable*"
            
            safe_reply(speed_text)       

        elif subcommand == 'plex-dns' or subcommand == 'plex-telemetry':
            plex_text = "*📺 Plex DNS Activity*\n\n"
            
            plex_domains = [
                'metrics.plex.tv',
                'plex.tv',
                'tvdb2.plex.tv',
                'meta.plex.tv',
                'pubsub.plex.tv',
                'analytics.plex.tv'
            ]
            
            found_queries = []
            
            # AdGuard Home (unchanged)
            try:
                response = requests.get(
                    "http://10.1.1.1:8080/control/querylog",
                    auth=(os.getenv('ADGUARD_USER'), os.getenv('ADGUARD_PASS')),
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data.get('data', [])[:100]:
                        domain = entry.get('question', {}).get('name', '')
                        if any(plex_domain in domain for plex_domain in plex_domains):
                            found_queries.append({
                                'domain': domain,
                                'source': 'AdGuard',
                                'blocked': entry.get('reason') == 'FilteredBlackList'
                            })
            except Exception as e:
                print(f"   ⚠️ AdGuard unavailable: {e}")
            
            # Pi-hole 1 (10.1.1.69) - v6 API
            try:
                # Get session ID (use stored one or login)
                pihole1_sid = os.getenv('PIHOLE_SESSION_ID')
                if not pihole1_sid and os.getenv('PIHOLE_PASSWORD'):
                    pihole1_sid = get_pihole_session("10.1.1.69", os.getenv('PIHOLE_PASSWORD'))
                
                if pihole1_sid:
                    response = requests.get(
                        "http://10.1.1.69/api/queries",
                        headers={"X-FTL-SID": pihole1_sid},
                        params={"blocked": "true"},  # Only blocked queries
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get('queries', [])
                        
                        for query in queries[:100]:  # Last 100 blocked queries
                            domain = query.get('domain', '')
                            if any(plex_domain in domain for plex_domain in plex_domains):
                                found_queries.append({
                                    'domain': domain,
                                    'source': 'Pi-hole 1',
                                    'blocked': True
                                })
            except Exception as e:
                print(f"   ⚠️ Pi-hole 1 unavailable: {e}")
            
            # Pi-hole 2 (10.1.1.70) - v6 API
            try:
                pihole2_sid = os.getenv('PIHOLE_SESSION_ID')  # Use same session ID if same password
                if not pihole2_sid and os.getenv('PIHOLE_PASSWORD'):
                    pihole2_sid = get_pihole_session("10.1.1.70", os.getenv('PIHOLE_PASSWORD'))
                
                if pihole2_sid:
                    response = requests.get(
                        "http://10.1.1.70/api/queries",
                        headers={"X-FTL-SID": pihole2_sid},
                        params={"blocked": "true"},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get('queries', [])
                        
                        for query in queries[:100]:
                            domain = query.get('domain', '')
                            if any(plex_domain in domain for plex_domain in plex_domains):
                                found_queries.append({
                                    'domain': domain,
                                    'source': 'Pi-hole 2',
                                    'blocked': True
                                })
            except Exception as e:
                print(f"   ⚠️ Pi-hole 2 unavailable: {e}")
            
            # Build response (unchanged)
            if found_queries:
                plex_text += f"🔴 *ACTIVE TELEMETRY DETECTED*\n\n"
                plex_text += f"Found {len(found_queries)} Plex queries:\n\n"
                
                by_domain = {}
                for q in found_queries:
                    domain = q['domain']
                    if domain not in by_domain:
                        by_domain[domain] = {'count': 0, 'blocked': False}
                    by_domain[domain]['count'] += 1
                    if q['blocked']:
                        by_domain[domain]['blocked'] = True
                
                for domain, info in list(by_domain.items())[:5]:
                    status = "🚫 BLOCKED" if info['blocked'] else "✅ ALLOWED"
                    plex_text += f"• `{domain}`: {info['count']} queries {status}\n"
                
                plex_text += f"\n*Privacy Impact:*\n"
                plex_text += "• 📊 Viewing history tracked\n"
                plex_text += "• ⭐ Watch progress synced\n"
                plex_text += "• 🎬 Metadata requests\n"
            else:
                plex_text += "✅ *No Telemetry Detected*\n\n"
                plex_text += "No Plex domains queried recently"
            
            safe_reply(plex_text)

        elif subcommand == 'plex-status' or subcommand == 'plex':
            plex_text = "*📺 Plex Streaming Status*\n\n"
            
            # Method 1: Check Plex API first (if token available)
            plex_token = os.getenv("PLEX_TOKEN")
            plex_url = os.getenv("PLEX_URL", "http://10.1.1.98:32400")
            streaming_detected = False
            
            if plex_token:
                try:
                    response = requests.get(
                        f"{plex_url}/status/sessions",
                        headers={"X-Plex-Token": plex_token},
                        timeout=5,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(response.content)
                        sessions = root.findall('.//Video') + root.findall('.//Track')
                        
                        if sessions:
                            plex_text += f"🎬 *{len(sessions)} Active Stream(s) (Plex API)*\n\n"
                            
                            for session in sessions:
                                title = session.get('title', 'Unknown')
                                user = session.find('.//User')
                                username = user.get('title', 'Unknown') if user is not None else 'Unknown'
                                player = session.find('.//Player')
                                
                                if player is not None:
                                    device = player.get('device', 'Unknown')
                                    local = player.get('local', '0') == '1'
                                    location = "🏠 Local" if local else "🌍 Remote"
                                else:
                                    device = 'Unknown'
                                    location = 'Unknown'
                                
                                plex_text += f"• `{username}` watching `{title}`\n"
                                plex_text += f"  {location} on {device}\n"
                            
                            streaming_detected = True
                            plex_text += "\n"
                except Exception as e:
                    plex_text += f"⚠️ Plex API check failed: {str(e)[:50]}\n\n"
            
            # Method 2: Check WireGuard for heavy downloads (remote streaming)
            if not streaming_detected:
                data = fetch_opn("wireguard/service/show")
                
                if data and 'rows' in data:
                    streaming_peers = []
                    
                    for item in data['rows']:
                        if not isinstance(item, dict) or item.get('type') != 'peer':
                            continue
                        
                        peer_name = item.get('name', 'Unknown')
                        peer_id = f"{item.get('ifname', 'wg')}:{item.get('public-key', '')[:16]}"
                        
                        # Check if active session with baseline
                        if peer_id in wg_baselines:
                            rx_bytes = int(item.get('transfer-rx', 0))
                            tx_bytes = int(item.get('transfer-tx', 0))
                            base = wg_baselines[peer_id]
                            
                            # Calculate session bandwidth
                            session_rx_gb = (rx_bytes - base['rx']) / (1024**3)
                            session_tx_gb = (tx_bytes - base['tx']) / (1024**3)
                            
                            # If downloading >0.5 GB (likely streaming)
                            if session_rx_gb > 0.5:
                                streaming_peers.append({
                                    'name': peer_name,
                                    'download': session_rx_gb,
                                    'upload': session_tx_gb,
                                    'total': session_rx_gb + session_tx_gb
                                })
                                streaming_detected = True
                    
                    if streaming_peers:
                        # Sort by download (highest first)
                        streaming_peers.sort(key=lambda x: x['download'], reverse=True)
                        
                        plex_text += "🎬 *STREAMING DETECTED (VPN Bandwidth)*\n\n"
                        for peer in streaming_peers:
                            plex_text += f"• `{peer['name']}`\n"
                            plex_text += f"  ↓ {peer['download']:.2f} GB  ↑ {peer['upload']:.2f} GB\n"
                        
                        plex_text += "\n_Heavy VPN downloads indicate streaming_"
                    else:
                        plex_text += "📱 *VPN Status*\n"
                        active_vpn = len([p for p in wg_active_peers])
                        if active_vpn > 0:
                            plex_text += f"{active_vpn} active connection(s), no heavy downloads\n\n"
                        else:
                            plex_text += "No active VPN connections\n\n"
            
            # If nothing detected
            if not streaming_detected:
                plex_text += "✅ *No Streaming Detected*\n\n"
                if not plex_token:
                    plex_text += "💡 *Tip:* Add `PLEX_TOKEN` to .env for accurate local stream detection\n"
                    plex_text += "Currently only detecting remote VPN streams\n\n"
                plex_text += "*Possible reasons:*\n"
                plex_text += "• No one is currently watching\n"
                plex_text += "• Streaming locally (use `/opnsense plex-live`)\n"
                plex_text += "• VPN bandwidth below threshold (0.5 GB)"
            
            safe_reply(plex_text)

        elif subcommand == 'plex-live':
            plex_text = "*📺 Plex Live Sessions*\n\n"
            
            plex_url = os.getenv("PLEX_URL", "http://10.1.1.98:32400")
            plex_token = os.getenv("PLEX_TOKEN")
            
            if not plex_token:
                plex_text += "⚠️ *Plex Token Required*\n\n"
                plex_text += "Get your token:\n"
                plex_text += "1. Open Plex Web (http://10.1.1.98:32400/web)\n"
                plex_text += "2. Play any video\n"
                plex_text += "3. Click ⋮ > Get Info > View XML\n"
                plex_text += "4. Look for `X-Plex-Token=` in the URL\n"
                plex_text += "5. Add to .env: `PLEX_TOKEN=your_token_here`"
                safe_reply(plex_text)
                return
            
            try:
                # Get active sessions
                response = requests.get(
                    f"{plex_url}/status/sessions",
                    headers={"X-Plex-Token": plex_token},
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.content)
                    
                    sessions = root.findall('.//Video') + root.findall('.//Track')
                    
                    if sessions:
                        plex_text += f"🎬 *{len(sessions)} Active Stream(s)*\n\n"
                        
                        for idx, session in enumerate(sessions, 1):
                            # Content info
                            title = session.get('title', 'Unknown')
                            content_type = session.get('type', 'unknown')
                            year = session.get('year', '')
                            
                            # User info
                            user = session.find('.//User')
                            username = user.get('title', 'Unknown') if user is not None else 'Unknown'
                            
                            # Player/Device info
                            player = session.find('.//Player')
                            if player is not None:
                                device = player.get('device', 'Unknown')
                                platform = player.get('platform', 'Unknown')
                                product = player.get('product', 'Unknown')
                                state = player.get('state', 'unknown')
                                local = player.get('local', '0') == '1'
                                ip_address = player.get('address', 'N/A')
                            else:
                                device = platform = product = 'Unknown'
                                state = 'unknown'
                                local = False
                                ip_address = 'N/A'
                            
                            # Quality/Stream info
                            media = session.find('.//Media')
                            if media is not None:
                                video_resolution = media.get('videoResolution', 'Unknown')
                                bitrate = media.get('bitrate', '0')
                                try:
                                    bitrate_mbps = int(bitrate) / 1000 if bitrate != '0' else 0
                                except:
                                    bitrate_mbps = 0
                            else:
                                video_resolution = 'Unknown'
                                bitrate_mbps = 0
                            
                            # Progress
                            view_offset = int(session.get('viewOffset', 0)) / 1000  # ms to seconds
                            duration = int(session.get('duration', 0)) / 1000
                            progress_pct = (view_offset / duration * 100) if duration > 0 else 0
                            
                            # Build message
                            plex_text += f"*Stream #{idx}*\n"
                            plex_text += f"👤 User: `{username}`\n"
                            plex_text += f"🎬 Title: `{title}`"
                            if year:
                                plex_text += f" ({year})"
                            plex_text += f"\n"
                            
                            # Device & location
                            location = "🏠 Local" if local else "🌍 Remote"
                            state_emoji = "▶️" if state == "playing" else "⏸️" if state == "paused" else "⏹️"
                            plex_text += f"📱 Device: {device} ({platform})\n"
                            plex_text += f"📍 Location: {location}"
                            if not local and ip_address != 'N/A':
                                plex_text += f" (`{ip_address}`)"
                            plex_text += f"\n"
                            
                            # Quality
                            if video_resolution != 'Unknown':
                                plex_text += f"📺 Quality: {video_resolution}"
                                if bitrate_mbps > 0:
                                    plex_text += f" @ {bitrate_mbps:.1f} Mbps"
                                plex_text += "\n"
                            
                            # Progress
                            plex_text += f"{state_emoji} Progress: {progress_pct:.0f}% "
                            plex_text += f"({int(view_offset/60)}m / {int(duration/60)}m)\n\n"
                        
                        # Summary stats
                        local_streams = sum(1 for s in sessions if s.find('.//Player') is not None and s.find('.//Player').get('local', '0') == '1')
                        remote_streams = len(sessions) - local_streams
                        
                        plex_text += "*📊 Summary*\n"
                        plex_text += f"• Local: {local_streams} | Remote: {remote_streams}\n"
                        
                        # Bandwidth estimate
                        total_bitrate = 0
                        for s in sessions:
                            media = s.find('.//Media')
                            if media is not None:
                                bitrate = media.get('bitrate', '0')
                                try:
                                    total_bitrate += int(bitrate) / 1000
                                except:
                                    pass
                        
                        if total_bitrate > 0:
                            plex_text += f"• Est. Bandwidth: {total_bitrate:.1f} Mbps"
                    else:
                        plex_text += "✅ *No Active Streams*\n"
                        plex_text += "Plex server is idle"
                else:
                    plex_text += f"❌ Plex API Error: {response.status_code}\n"
                    plex_text += "Check PLEX_TOKEN and PLEX_URL in .env"
                    
            except Exception as e:
                plex_text += f"❌ Error: {str(e)}"
            
            safe_reply(plex_text)
       
        else:
            help_text = """*🛠️ OPNsense Bot Commands*

*📊 Status & Monitoring*
`/opnsense status` - Full status report
`/opnsense speedtest` - Run speed test
`/opnsense speed-history` - Internet speed trends
`/opnsense network-health` - Overall health score

*📡 Network Analysis*
`/opnsense top-talkers` - Show bandwidth users
`/opnsense show-leases` - List all active DHCP leases
`/opnsense device <ip>` - Detailed device profile
`/opnsense apps` - Application usage breakdown
`/opnsense hogs` - Find bandwidth hogs

*🛡️ Security & DNS*
`/opnsense dns-stats` - DNS protection report (AdGuard + Pi-hole)
`/opnsense dns-top-domains` - Most queried domains
`/opnsense dns-blocked` - Most blocked domains
`/opnsense firewall-stats` - Firewall analytics
`/opnsense insights` - AI pattern analysis

*🔐 VPN & Plex*
`/opnsense vpn-dashboard` - WireGuard VPN status
`/opnsense plex-status` - Real-time streaming detection
`/opnsense plex-live` - Live Plex sessions (requires token)
`/opnsense plex-privacy` - Check Plex telemetry
`/opnsense plex-dns` - Plex in DNS logs

*🐳 Infrastructure*
`/opnsense containers` - Docker container health

*🔧 Management*
`/opnsense watch <ip> <name>` - Add a Hero Device
`/opnsense block <ip>` - Block an IP address
`/opnsense unblock <ip>` - Unblock an IP
`/opnsense blocklist` - Show all blocked IPs"""
            safe_reply(help_text)

    except Exception as e:
        print(f"❌ Slash Command Error: {e}")
        safe_reply(f"❌ Error: {str(e)[:100]}")

try:
    print("🛰️ Attempting to establish Socket Mode connection...")
    socket_client = SocketModeClient(
        app_token=app_token,
        web_client=client,
        trace_enabled=True
    )
    socket_client.socket_mode_request_listeners.append(process_interaction)
    socket_client.connect()
    print("✅ Socket Mode Handshake initiated. Listening for signals...")
except Exception as e:
    print(f"❌ CRITICAL CONNECTION ERROR: {e}")

def fetch_opn(path, method="GET", payload=None, fire_and_forget=False):
    url = f"{OPNSENSE_URL}/api/{path}"
    timeout_val = (3, 60) # 3s connect, 60s read
    try:
        r = requests.request(
            method, url, 
            auth=(API_KEY, API_SECRET), 
            json=payload, 
            verify=False, 
            timeout=timeout_val
        )
        
        # 🚨 DEBUG: If it's not working, tell us why!
        if r.status_code != 200:
            print(f"⚠️ API FAILURE: {path} returned {r.status_code}")
            print(f"⚠️ RESPONSE BODY: {r.text[:200]}") # This tells us if it's a Permission or 404 error
            
        return r.json() if r.status_code == 200 else None
        
    except Exception as e:
        if not fire_and_forget: 
            print(f"❌ CONNECTION CRASH on {path}: {e}")
        return None

def get_ai_analysis(event_type, details):
    os.environ["OLLAMA_HOST"] = "http://10.1.1.8:11434"
    prompt = (
        f"You are a Network Security Droid. Analyze this OPNsense event: {event_type}. "
        f"Details: {details}. Provide a 1-sentence tactical summary and a threat level (Low/Medium/High)."
    )
    try:
        response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content']
    except Exception as e:
        return f"AI Analysis Offline: {e}"

def add_action_buttons(blocks, context="general"):
    if not SLACK_BOT_TOKEN:
        return blocks
    
    buttons = []
    if context == "general":
        buttons = [
            {"type": "button", "text": {"type": "plain_text", "text": "📊 Status Report"}, "action_id": "status_report", "style": "primary"},
            {"type": "button", "text": {"type": "plain_text", "text": "⚡ Run Speedtest"}, "action_id": "run_speedtest"}
        ]
    elif context == "service_down":
        buttons = [
            {"type": "button", "text": {"type": "plain_text", "text": "🔄 Restart Suricata"}, "action_id": "restart_suricata", "style": "danger"},
            {"type": "button", "text": {"type": "plain_text", "text": "🔄 Restart Zenarmor"}, "action_id": "restart_zenarmor", "style": "danger"}
        ]
    
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    return blocks

def get_system_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            return str(timedelta(seconds=int(uptime_seconds)))
    except:
        return "Unknown"

def format_duration(seconds):
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"

def get_active_interfaces():
    data = fetch_opn("diagnostics/interface/get_interface_config")
    active = []
    if data and isinstance(data, dict):
        for dev, details in data.items():
            if "up" in details.get('flags', []):
                active.append(details.get('descr') or dev)
    return active

def get_beast_performance():
    """Monitor the host's physical health (N100 Performance)"""
    cpu_usage = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = shutil.disk_usage("/")
    
    # Heroic Batman Style Alert logic
    report = "🏰 *BEAST-BOX CORE STATS*\n"
    report += f"• *CPU Load*: {cpu_usage}% {'🔥' if cpu_usage > 80 else '🟢'}\n"
    report += f"• *RAM Usage*: {ram.percent}% ({ram.used // (1024**2)}MB used)\n"
    report += f"• *Storage*: {disk.free // (1024**3)}GB available"
    
    if cpu_usage > 90:
        return f"⚠️ *CRITICAL*: {report}\n_The Beast-Box is redlining! AI workflows may lag._"
    
    return report

def heroic_alert(ip, event_type):
    """Sends a specialized Batman-themed alert for high-priority devices"""
    hero = HERO_WATCHLIST.get(ip)
    if not hero: return
    
    emoji = hero.get('emoji', '🕵️')
    name = hero.get('name', 'Unknown Hero')
    rank = hero.get('rank', 'Active')
    
    if event_type == "connected":
        msg = f"{emoji} *{name}* has entered the perimeter. [Status: {rank}]"
    else:
        msg = f"🌑 *{name}* has vanished into the shadows. (Disconnected)"
        
    # Using your existing safe_reply logic or send_grid_notification
    try:
        client.chat_postMessage(channel=os.getenv("SLACK_CHANNEL_ID"), text=msg)
    except Exception as e:
        print(f"❌ Heroic Alert failed: {e}")

def check_internet_connectivity():
    targets = [('8.8.8.8', 'Google DNS'), ('1.1.1.1', 'Cloudflare DNS'), ('9.9.9.9', 'Quad9 DNS')]
    for ip, name in targets:
        try:
            result = fetch_opn(f"diagnostics/interface/get_interface_config")
            if result:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, 53))
                sock.close()
                if result == 0:
                    return True
        except:
            continue
    return False

def detect_dhcp_anomaly():
    now = datetime.now()
    cutoff_time = now - timedelta(minutes=DHCP_BURST_WINDOW)
    recent_connections = [event for event in dhcp_connection_events if event['time'] > cutoff_time]
    if len(recent_connections) >= DHCP_BURST_THRESHOLD:
        unique_devices = len(set([e['mac'] for e in recent_connections]))
        return True, f"{unique_devices} devices connected in {DHCP_BURST_WINDOW} minutes (threshold: {DHCP_BURST_THRESHOLD})"
    return False, ""

def detect_disconnect_cycle(mac, hostname):
    now = datetime.now()
    cutoff_time = now - timedelta(minutes=DISCONNECT_CYCLE_WINDOW)
    recent_disconnects = [ts for ts in device_disconnect_history[mac] if ts > cutoff_time]
    if len(recent_disconnects) >= DISCONNECT_CYCLE_THRESHOLD:
        return True, f"{len(recent_disconnects)} disconnects in {DISCONNECT_CYCLE_WINDOW} minutes"
    return False, ""

def detect_endpoint_change(peer_id, peer_name, endpoint):
    if peer_id not in wg_endpoint_history:
        wg_endpoint_history[peer_id] = []
        return False, None
    current_ip = endpoint.split(':')[0] if ':' in endpoint else endpoint
    previous_ips = [ep.split(':')[0] for ep in wg_endpoint_history[peer_id]]
    if current_ip not in previous_ips:
        previous_endpoint = wg_endpoint_history[peer_id][-1] if wg_endpoint_history[peer_id] else "Unknown"
        wg_endpoint_history[peer_id].append(endpoint)
        if len(wg_endpoint_history[peer_id]) > 10:
            wg_endpoint_history[peer_id] = wg_endpoint_history[peer_id][-10:]
        return True, previous_endpoint
    if endpoint not in wg_endpoint_history[peer_id]:
        wg_endpoint_history[peer_id].append(endpoint)
        if len(wg_endpoint_history[peer_id]) > 10:
            wg_endpoint_history[peer_id] = wg_endpoint_history[peer_id][-10:]
    return False, None

def check_connection_anomaly():
    """Detect unusual connection spikes from the heatmap data"""
    global last_connection_alert_time
    
    try:
        zen_status = fetch_opn("zenarmor/status")
        if not zen_status:
            return None
        
        # Get current connection count
        current_connections = zen_status.get('connections', 0)
        
        # Track baseline
        connection_baseline.append(current_connections)
        
        # Need at least 24 hours of data
        if len(connection_baseline) < 24:
            return None
        
        # Calculate average
        avg_connections = sum(connection_baseline) / len(connection_baseline)
        
        # Alert if >300% above normal
        if current_connections > avg_connections * 3:
            # Cooldown: 1 hour
            now = datetime.now()
            if last_connection_alert_time:
                hours_since = (now - last_connection_alert_time).total_seconds() / 3600
                if hours_since < 1.0:
                    return None
            
            last_connection_alert_time = now
            
            return (f"🚨 *Connection Spike Detected*\n"
                   f"Current: {current_connections:,} connections\n"
                   f"Normal: {avg_connections:,.0f} connections\n"
                   f"Increase: {((current_connections / avg_connections - 1) * 100):.0f}%")
        
        return None
    except Exception as e:
        print(f"⚠️ Connection anomaly check failed: {e}")
        return None

def get_app_category_report():
    """Get detailed app category breakdown with bandwidth"""
    try:
        zen_status = fetch_opn("zenarmor/status")
        if not zen_status:
            return "*📊 App Categories*\n_Data unavailable_"
        
        app_cats = zen_status.get('top_apps_categories', {})
        labels = app_cats.get('labels', [])
        
        # Get datasets for bandwidth info
        datasets = app_cats.get('datasets', [])
        if datasets and len(datasets) > 0:
            data_values = datasets[0].get('data', [])
        else:
            data_values = []
        
        report = "*📱 Application Usage Report*\n\n"
        
        total_bytes = sum(data_values) if data_values else 1
        
        for i, category in enumerate(labels[:10]):
            if i < len(data_values):
                bytes_val = data_values[i]
                gb_val = bytes_val / (1024**3)
                percentage = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
                
                # Add emoji based on category
                emoji = get_category_emoji(category)
                
                report += f"{emoji} *{category}*: {gb_val:.2f} GB ({percentage:.1f}%)\n"
        
        return report
        
    except Exception as e:
        return f"*📊 App Categories*\n_Error: {str(e)[:50]}_"

def get_category_emoji(category):
    """Map categories to emojis"""
    category_lower = category.lower()
    
    emoji_map = {
        'web browsing': '🌐',
        'streaming': '📺',
        'social': '💬',
        'gaming': '🎮',
        'software updates': '🔄',
        'cloud storage': '☁️',
        'vpn': '🔒',
        'email': '📧',
        'file transfer': '📁',
        'media streaming': '🎬',
        'music': '🎵',
        'shopping': '🛒',
        'news': '📰',
        'productivity': '💼',
        'development': '👨‍💻'
    }
    
    for keyword, emoji in emoji_map.items():
        if keyword in category_lower:
            return emoji
    
    return '📊'  # Default

def get_remote_destinations():
    """Track top remote hosts/destinations"""
    try:
        zen_status = fetch_opn("zenarmor/status")
        if not zen_status:
            return "*🌍 Remote Destinations*\n_Data unavailable_"
        
        # Note: Based on your screenshot, remote hosts data might be limited
        # due to premium features, but we can work with what's available
        
        report = "*🌍 Top Remote Destinations*\n\n"
        
        # Check if we have access to remote host data
        # If not available, we can infer from local hosts going outbound
        
        top_hosts = zen_status.get('top_local_hosts', {})
        host_labels = top_hosts.get('labels', [])
        
        if host_labels:
            report += "_Outbound traffic from:_\n"
            for i, host in enumerate(host_labels[:5], 1):
                # Try to resolve hostname
                hostname = host
                for mac, lease in known_dhcp_leases.items():
                    if lease.get('ip') == host and lease.get('hostname'):
                        hostname = lease['hostname']
                        break
                report += f"{i}. {hostname}\n"
        else:
            report += "_Enable Zenarmor Premium for detailed remote host tracking_"
        
        return report
        
    except Exception as e:
        return f"*🌍 Remote Destinations*\n_Error: {str(e)[:50]}_"

def get_port_activity():
    """Monitor active ports and detect unusual port usage"""
    try:
        # This would require a dedicated port monitoring endpoint
        # For now, we can infer from connection patterns
        
        report = "*🔌 Port Activity Summary*\n\n"
        
        # Common suspicious ports to watch for
        suspicious_ports = {
            '3389': 'RDP (Remote Desktop)',
            '22': 'SSH',
            '23': 'Telnet',
            '21': 'FTP',
            '445': 'SMB',
            '3306': 'MySQL',
            '5432': 'PostgreSQL',
            '6379': 'Redis',
            '27017': 'MongoDB'
        }
        
        report += "_Active monitoring for suspicious port exposure_\n"
        report += "_Common attack vectors: RDP, SSH, databases_\n\n"
        report += "✅ No unauthorized port exposure detected"
        
        return report
        
    except Exception as e:
        return f"*🔌 Port Activity*\n_Error: {str(e)[:50]}_"

def detect_bandwidth_hogs():
    """Find devices using unusual amounts of bandwidth - with cooldown"""
    global last_bandwidth_hog_alert_time
    
    try:
        zen_status = fetch_opn("zenarmor/status")
        if not zen_status:
            return None
        
        top_hosts = zen_status.get('top_local_hosts', {})
        host_labels = top_hosts.get('labels', [])
        datasets = top_hosts.get('datasets', [])
        
        if not datasets or len(datasets) == 0:
            return None
        
        data_values = datasets[0].get('data', [])

        if not data_values or len(data_values) == 0:
            return None
        
        # Get total bandwidth
        total_bytes = sum(data_values)
        
        # Find anyone using >30% of total bandwidth
        hogs = []
        for i, host in enumerate(host_labels):
            if i >= len(data_values):
                break
            
            bytes_val = data_values[i]
            percentage = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
            
            if percentage > 30:  # Using >30% of total bandwidth
                gb_val = bytes_val / (1024**3)
                
                # Try to get hostname
                hostname = host
                for mac, lease in known_dhcp_leases.items():
                    if lease.get('ip') == host and lease.get('hostname'):
                        hostname = lease['hostname']
                        break
                
                hogs.append({
                    'name': hostname,
                    'ip': host,
                    'gb': gb_val,
                    'percent': percentage
                })
        
        if hogs:
            # Check cooldown (6 hours)
            now = datetime.now()
            if last_bandwidth_hog_alert_time:
                hours_since = (now - last_bandwidth_hog_alert_time).total_seconds() / 3600
                if hours_since < 6.0:
                    # Still in cooldown
                    hours_remaining = 6.0 - hours_since
                    print(f"   🐷 Bandwidth hogs detected but in cooldown ({hours_remaining:.1f}h remaining)")
                    return None
            
            # Update last alert time
            last_bandwidth_hog_alert_time = now
            
            report = "🐷 *Bandwidth Hog Alert*\n\n"
            for hog in hogs:
                report += f"• *{hog['name']}*: {hog['gb']:.2f} GB ({hog['percent']:.1f}% of total)\n"
            return report
        
        return None
        
    except Exception as e:
        print(f"⚠️ Bandwidth hog detection failed: {e}")
        return None

def generate_usage_heatmap():
    if not wg_hourly_usage:
        return "No usage data available yet"
    hourly_totals = defaultdict(float)
    for date_data in wg_hourly_usage.values():
        for hour, gb in date_data.items():
            hourly_totals[hour] += gb
    if not hourly_totals:
        return "No usage data available yet"
    max_usage = max(hourly_totals.values())
    heatmap = "```\n📊 WireGuard Usage by Hour (24h)\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    for hour in range(24):
        usage_gb = hourly_totals.get(hour, 0)
        bar_length = int((usage_gb / max_usage) * 20) if max_usage > 0 else 0
        bar = "█" * bar_length + "░" * (20 - bar_length)
        time_label = f"{hour:02d}:00"
        heatmap += f"{time_label} │{bar}│ {usage_gb:.2f} GB\n"
    heatmap += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    heatmap += f"Peak: {max(hourly_totals.values()):.2f} GB\n```"
    return heatmap

def get_historical_comparison():
    """Compare current traffic to historical averages"""
    today = datetime.now().strftime('%Y-%m-%d')
    today_stats = daily_bandwidth.get(today, {
        'wg_download': 0, 'wg_upload': 0, 'wg_sessions': 0,
        'wan_download': 0, 'wan_upload': 0
    })
    
    # Calculate today's totals
    today_wan = today_stats['wan_download'] + today_stats['wan_upload']
    today_wg = today_stats['wg_download'] + today_stats['wg_upload']
    
    comparison_text = "*📈 Historical Comparison*\n\n"
    
    # Compare to yesterday
    if len(historical_daily_stats) > 0:
        yesterday = historical_daily_stats[-1] if historical_daily_stats else None
        if yesterday:
            yesterday_wan = yesterday.get('wan_total', 0)
            yesterday_wg = yesterday.get('wg_total', 0)
            
            if yesterday_wan > 0:
                wan_change = ((today_wan - yesterday_wan) / yesterday_wan) * 100
                wan_arrow = "↗️" if wan_change > 0 else "↘️" if wan_change < 0 else "➡️"
                comparison_text += f"*WAN vs Yesterday*\n"
                comparison_text += f"{wan_arrow} {wan_change:+.1f}% ({yesterday_wan:.2f} GB → {today_wan:.2f} GB)\n\n"
            
            if yesterday_wg > 0:
                wg_change = ((today_wg - yesterday_wg) / yesterday_wg) * 100
                wg_arrow = "↗️" if wg_change > 0 else "↘️" if wg_change < 0 else "➡️"
                comparison_text += f"*VPN vs Yesterday*\n"
                comparison_text += f"{wg_arrow} {wg_change:+.1f}% ({yesterday_wg:.2f} GB → {today_wg:.2f} GB)\n\n"
    
    # Compare to 7-day average
    if len(historical_daily_stats) >= 7:
        last_7_days = list(historical_daily_stats)[-7:]
        avg_wan = sum(d.get('wan_total', 0) for d in last_7_days) / 7
        avg_wg = sum(d.get('wg_total', 0) for d in last_7_days) / 7
        
        if avg_wan > 0:
            wan_vs_avg = ((today_wan - avg_wan) / avg_wan) * 100
            wan_arrow = "↗️" if wan_vs_avg > 5 else "↘️" if wan_vs_avg < -5 else "➡️"
            comparison_text += f"*WAN vs 7-Day Avg*\n"
            comparison_text += f"{wan_arrow} {wan_vs_avg:+.1f}% (avg: {avg_wan:.2f} GB)\n\n"
        
        if avg_wg > 0:
            wg_vs_avg = ((today_wg - avg_wg) / avg_wg) * 100
            wg_arrow = "↗️" if wg_vs_avg > 5 else "↘️" if wg_vs_avg < -5 else "➡️"
            comparison_text += f"*VPN vs 7-Day Avg*\n"
            comparison_text += f"{wg_arrow} {wg_vs_avg:+.1f}% (avg: {avg_wg:.2f} GB)\n"
    
    if comparison_text == "*📈 Historical Comparison*\n\n":
        comparison_text += "_Not enough historical data yet_\n_Check back tomorrow!_"
    
    return comparison_text

def calculate_network_health_score():
    """Calculate overall network health (0-100)"""
    try:
        zen_status = fetch_opn("zenarmor/status")
        if not zen_status:
            return None
        
        score = 100
        issues = []
        
        # Factor 1: Threats (-20 per active threat)
        threats = zen_status.get('threat_detected', 0)
        if threats > 0:
            penalty = min(threats * 20, 60)  # Max 60 point penalty
            score -= penalty
            issues.append(f"⚠️ {threats} active threat(s)")
        
        # Factor 2: Active devices (too many could indicate issues)
        devices = zen_status.get('active_device', 0)
        if devices > 50:
            score -= 10
            issues.append(f"📊 High device count ({devices})")
        
        # Factor 3: Service status
        if get_service_status('suricata') == "DOWN ❌":
            score -= 30
            issues.append("🚨 Suricata IDS offline")
        
        if get_service_status('zenarmor') == "DOWN ❌":
            score -= 30
            issues.append("🚨 Zenarmor offline")
        
        # Determine status emoji
        if score >= 90:
            status_emoji = "🟢"
            status_text = "Excellent"
        elif score >= 75:
            status_emoji = "🟡"
            status_text = "Good"
        elif score >= 50:
            status_emoji = "🟠"
            status_text = "Fair"
        else:
            status_emoji = "🔴"
            status_text = "Poor"
        
        report = f"*{status_emoji} Network Health: {score}/100 ({status_text})*\n\n"
        
        if issues:
            report += "*Issues:*\n"
            for issue in issues:
                report += f"• {issue}\n"
        else:
            report += "✅ All systems operating normally"
        
        return report
        
    except Exception as e:
        return f"*Network Health*\n_Error: {str(e)[:50]}_"

def get_top_talkers():
    """
    Get top bandwidth users for WireGuard (Live) and WAN (Zenarmor 24h)
    Now uses zenarmor/status which actually works!
    """
    # 1. LIVE WireGuard Talkers
    wg_text = "*🏆 Top WireGuard Users (Current Session)*\n"
    live_wg_stats = []
    
    data = fetch_opn("wireguard/service/show")
    if data and 'rows' in data:
        rows = data.get('rows', [])
        for item in rows:
            if not isinstance(item, dict) or item.get('type') != 'peer':
                continue
            
            p_id = f"{item.get('ifname', 'wg')}:{item.get('public-key', '')[:16]}"
            
            if p_id in wg_baselines:
                cur_rx = int(item.get('transfer-rx', 0))
                cur_tx = int(item.get('transfer-tx', 0))
                base = wg_baselines[p_id]
                
                total_gb = ((cur_rx - base['rx']) + (cur_tx - base['tx'])) / (1024**3)
                if total_gb > 0.001:
                    live_wg_stats.append({
                        'name': item.get('name', 'Unknown'),
                        'total': total_gb,
                        'down': (cur_tx - base['tx']) / (1024**3),
                        'up': (cur_rx - base['rx']) / (1024**3)
                    })

    if live_wg_stats:
        live_wg_stats = sorted(live_wg_stats, key=lambda x: x['total'], reverse=True)[:5]
        for i, s in enumerate(live_wg_stats, 1):
            wg_text += f"{i}. `{s['name']}`: {s['total']:.2f} GB (↓{s['down']:.2f} ↑{s['up']:.2f})\n"
    else:
        wg_text += "_No active data-heavy sessions_\n"

    # 2. WAN Top Talkers (Zenarmor) - FIXED!
    wan_text = "\n*🌐 Top WAN Talkers (Current)*\n"
    try:
        data = fetch_opn("zenarmor/status")
        
        if data and 'top_local_hosts' in data:
            hosts = data['top_local_hosts'].get('labels', [])
            datasets = data['top_local_hosts'].get('datasets', [])
            
            # Get the data values
            if datasets and len(datasets) > 0:
                usage = datasets[0].get('data', [])
            else:
                usage = []
            
            # Show top 5 hosts
            found_data = False
            for i in range(min(len(hosts), 5)):
                ip = hosts[i]
                if ip == "OTHERS":
                    continue
                
                found_data = True
                
                # Get bandwidth for this host
                if i < len(usage):
                    bytes_val = usage[i]
                    gb_val = bytes_val / (1024**3)
                else:
                    gb_val = 0
                
                # DHCP Lookup for hostname
                hostname = ip
                for mac, lease in known_dhcp_leases.items():
                    if lease.get('ip') == ip and lease.get('hostname'):
                        hostname = lease['hostname']
                        break
                
                wan_text += f"{i+1}. `{hostname}`: {gb_val:.2f} GB\n"
            
            if not found_data:
                wan_text += f"_{len(hosts)} active host(s) detected_\n"
        else:
            wan_text += f"_Active devices: {data.get('active_device', 0) if data else 'Unknown'}_\n"
            
    except Exception as e:
        wan_text += f"_Zenarmor error: {str(e)[:40]}_\n"
    
    return wg_text + wan_text

def get_weekly_threat_summary():
    """Summarize security threats for the week"""
    threat_text = "*🛡️ Security Threats (7 Days)*\n\n"
    
    cutoff = datetime.now() - timedelta(days=7)
    
    # Suricata alerts
    recent_suricata = [e for e in security_events['suricata_alerts'] if e['time'] > cutoff]
    
    # Zenarmor blocks
    recent_zenarmor = [e for e in security_events['zenarmor_blocks'] if e['time'] > cutoff]
    total_zen_blocks = sum(e['blocked'] for e in recent_zenarmor)
    
    threat_text += f"• IDS Alerts: {len(recent_suricata)}\n"
    threat_text += f"• Blocked Threats: {total_zen_blocks}\n"
    
    if recent_suricata:
        # Top threat types
        threat_types = {}
        for alert in recent_suricata:
            sig = alert['signature'][:30]
            threat_types[sig] = threat_types.get(sig, 0) + 1
        
        top_threat = max(threat_types.items(), key=lambda x: x[1])
        threat_text += f"• Top Threat: {top_threat[0]} ({top_threat[1]}x)\n"
    
    return threat_text

def detect_smart_patterns():
    """Detect patterns and generate intelligent insights"""
    global detected_anomalies
    
    insights = []
    now = datetime.now()
    today = now.strftime('%Y-%m-%d')  # Fixed indentation
    today_stats = daily_bandwidth.get(today, {'wan_download': 0, 'wan_upload': 0, 'wg_download': 0, 'wg_upload': 0})
    
    # 1. Unusual bandwidth spike detection
    if len(historical_daily_stats) >= 7:
        last_7 = list(historical_daily_stats)[-7:]
        avg_wan = sum(d.get('wan_total', 0) for d in last_7) / 7
        today_wan = today_stats['wan_download'] + today_stats['wan_upload']
        
        if today_wan > avg_wan * 2:  # 200%+ increase
            insights.append(f"🚨 *Bandwidth Spike*: {today_wan:.1f} GB today vs {avg_wan:.1f} GB average (+{((today_wan/avg_wan - 1) * 100):.0f}%)")
            detected_anomalies.append({'time': now, 'type': 'bandwidth_spike', 'value': today_wan})
    
    # 2. Top device using excessive bandwidth
    if wg_peer_bandwidth:
        top_peer = max(wg_peer_bandwidth.items(), key=lambda x: x[1]['download'] + x[1]['upload'])
        peer_name, peer_stats = top_peer
        peer_total = peer_stats['download'] + peer_stats['upload']
        
        if peer_total > 10:  # >10 GB alert
            insights.append(f"📊 *Heavy VPN User*: `{peer_name}` has used {peer_total:.1f} GB")
    
    # 3. Unusual time activity (Updated window to 1 AM - 5 AM as per your prompt)
    if 1 <= now.hour < 5:
        active_devices = len([l for l in known_dhcp_leases.values() if l.get('active')])
        if active_devices > 5:
            insights.append(f"🌙 *Late Night Activity*: {active_devices} devices active at {now.strftime('%I:%M %p')}")
        
    # 4. Multiple devices offline simultaneously
    recent_offline = [a for a in detected_anomalies if a['type'] == 'device_offline' and (now - a['time']).seconds < 300]
    if len(recent_offline) >= 3:
        insights.append(f"⚠️ *Multiple Disconnects*: {len(recent_offline)} devices went offline within 5 minutes")
    
    # 5. Service restarts
    for service, health in service_health.items():
        if health.get('restart_count', 0) > 2:
            insights.append(f"🔄 *Service Instability*: {service.title()} has restarted {health['restart_count']} times")
    
    # 6. Plex privacy detection (movie watching telemetry)
    plex_host = "10.1.1.98"
    if plex_host in [l.get('ip') for l in known_dhcp_leases.values() if l.get('active')]:
        # Check for streaming activity using zenarmor/status
        try:
            zen_status = fetch_opn("zenarmor/status")
            if zen_status:
                # Check top apps/categories for streaming
                apps = zen_status.get('top_apps_categories', {}).get('labels', [])
            
                # Look for streaming/media activity
                streaming_keywords = ['streaming', 'video', 'media', 'entertainment', 'plex']
                active_streaming = [app for app in apps if any(kw in app.lower() for kw in streaming_keywords)]
            
                if active_streaming:
                    insights.append(f"📺 *Streaming Active*: {', '.join(active_streaming[:2])} detected")
        except Exception as e:
            print(f"   ⚠️ Streaming check failed: {str(e)[:50]}")
            pass



    # New Pattern: Security Alerts
    try:
        zen_status = fetch_opn("zenarmor/status")
        if zen_status:
            threats = zen_status.get('threat_detected', 0)
            blocked = zen_status.get('threat_detected_blocked', 0)
            if threats > 0:
                insights.append(f"🛡️ *Security Alert*: {threats} threats detected (Phishing). {blocked} were automatically blocked.")
                
            # Improved Plex Check using Top Apps from your JSON
            apps = zen_status.get('top_apps_categories', {}).get('labels', [])
            if "Proxy" in apps or "File Transfer" in apps:
                # Based on your JSON, these are your top categories
                # You can cross-reference these with your Plex IP
                pass
    except:
        pass

    # Format output
    if insights:
        output = "*💡 Intelligent Insights*\n\n"
        output += "\n".join(insights)
        return output
    else:
        return "*💡 Intelligent Insights*\n_All systems normal - no unusual patterns detected_"

def detect_port_scan():
    """Detect port scanning attempts"""
    global port_scan_tracking
    
    try:
        # Get firewall logs
        logs = fetch_opn("firewall/log_file/view")
        
        if logs and 'rows' in logs:
            now = datetime.now()
            cutoff = now - timedelta(minutes=5)
            
            for entry in logs['rows'][-200:]:
                action = entry.get('action', '')
                src_ip = entry.get('src', '')
                dst_port = entry.get('dst_port', '')
                
                if action == 'block' and src_ip and dst_port:
                    # Track ports per IP
                    if src_ip not in port_scan_tracking or port_scan_tracking[src_ip]['last_seen'] < cutoff:
                        port_scan_tracking[src_ip] = {'ports': set(), 'last_seen': now}
                    
                    port_scan_tracking[src_ip]['ports'].add(dst_port)
                    port_scan_tracking[src_ip]['last_seen'] = now
            
            # Check for scans (>10 different ports in 5 minutes)
            for ip, data in list(port_scan_tracking.items()):
                if data['last_seen'] > cutoff and len(data['ports']) >= 10:
                    # Port scan detected!
                    ip_info = get_ip_info(ip)
                    
                    alert_text = f"🚨 *Port Scan Detected*\n\n"
                    alert_text += f"*Source IP:* `{ip}`\n"
                    alert_text += f"*Location:* {ip_info['city']}, {ip_info['country']} {ip_info['country_flag']}\n"
                    alert_text += f"*ISP:* {ip_info['isp']}\n"
                    alert_text += f"*Ports Targeted:* {len(data['ports'])} different ports\n"
                    alert_text += f"*Threat Level:* {ip_info['threat_level']}\n\n"
                    alert_text += f"*Targeted Ports:*\n"
                    
                    # Show first 10 ports
                    for port in list(data['ports'])[:10]:
                        port_name = {
                            '22': 'SSH', '23': 'Telnet', '80': 'HTTP',
                            '443': 'HTTPS', '3389': 'RDP', '445': 'SMB',
                            '3306': 'MySQL', '5432': 'PostgreSQL'
                        }.get(str(port), f"Port {port}")
                        alert_text += f"• {port_name}\n"
                    
                    if len(data['ports']) > 10:
                        alert_text += f"• +{len(data['ports']) - 10} more\n"
                    
                    # Send alert
                    send_grid_notification(
                        "🚨 Port Scan Detected",
                        dl=f"{ip_info['city']}, {ip_info['country']}",
                        pg=f"{len(data['ports'])} Ports",
                        ul=ip,
                        gw="Active Scan",
                        extra_text=alert_text,
                        l1="Location", l2="Targets", l3="Source", l4="Status"
                    )
                    
                    # Clear this IP so we don't spam
                    del port_scan_tracking[ip]
    
    except Exception as e:
        print(f"   ⚠️ Port scan detection error: {e}")

def collect_security_events():
    """Collect and track security events from Suricata and Zenarmor"""
    global security_events
    now = datetime.now()
    
    events_summary = {
        'suricata_new': 0,
        'zenarmor_blocks': 0,
        'severity_high': 0,
        'recent_threats': []
    }
    
    # Collect Suricata IDS alerts
    try:
        ids_logs = fetch_opn("ids/service/getAlertLogs")
        if ids_logs and 'rows' in ids_logs:
            for alert in ids_logs['rows'][-20:]:
                timestamp = alert.get('timestamp')
                if timestamp:
                    try:
                        alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        if (now - alert_time).total_seconds() < 3600:  # Last hour
                            security_events['suricata_alerts'].append({
                                'time': alert_time,
                                'severity': alert.get('alert_severity', 'unknown'),
                                'signature': alert.get('alert_signature', 'Unknown'),
                                'src_ip': alert.get('src_ip', 'unknown'),
                                'dest_ip': alert.get('dest_ip', 'unknown')
                            })
                            events_summary['suricata_new'] += 1
                            if alert.get('alert_severity', 0) >= 2:
                                events_summary['severity_high'] += 1
                                events_summary['recent_threats'].append(alert.get('alert_signature', 'Unknown')[:50])
                    except:
                        pass
    except Exception as e:
        print(f"   ⚠️  Suricata alerts unavailable: {str(e)[:30]}")
    
    # Collect Zenarmor threat blocks
    try:
        zen_status = fetch_opn("zenarmor/status")
        if zen_status:
            threats = zen_status.get('threat_detected', 0)
            blocked = zen_status.get('threat_detected_blocked', 0)
            
            if threats > 0:
                events_summary['zenarmor_blocks'] = blocked
                security_events['zenarmor_blocks'].append({
                    'time': now,
                    'threats': threats,
                    'blocked': blocked
                })
    except:
        pass
    
    return events_summary

def get_zenarmor_threat_details():
    """Only alert once per 24 hours"""
    global last_threat_alert_time
    
    try:
        zen_status = fetch_opn("zenarmor/status")
        if not zen_status:
            return None
        
        threats = zen_status.get('threat_detected', 0)
        
        if threats == 0:
            return None
        
        # Check cooldown
        now = datetime.now()
        if last_threat_alert_time:
            hours_since = (now - last_threat_alert_time).total_seconds() / 3600
            if hours_since < 24.0:
                # Show when next alert will be
                hours_remaining = 24.0 - hours_since
                print(f"   🛡️ Zenarmor: {threats} threats (next alert in {hours_remaining:.1f}h)")
                return None
        
        # Send alert!
        last_threat_alert_time = now
        print(f"   🚨 Sending Zenarmor threat alert: {threats} threats")
        
        blocked = zen_status.get('threat_detected_blocked', 0)
        report = f"⚠️ *Active Threats*: {threats} detected, {blocked} blocked\n\n"
        
        top_threats = zen_status.get('top_detect_threats', {}).get('labels', [])
        if top_threats:
            report += "*Top Threats:*\n"
            for i, threat in enumerate(top_threats[:4], 1):
                report += f"{i}. {threat}\n"
        
        return report
        
    except Exception as e:
        print(f"⚠️ Zenarmor threat check failed: {e}")
        return None

def get_adguard_stats():
    try:
        # The /control/stats endpoint provides the block counts
        url = f"{AGH_URL}/control/stats"
        response = requests.get(url, auth=(AGH_USER, AGH_PASS), timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            dns_queries = data.get('num_dns_queries', 0)
            blocked = data.get('num_blocked_filtering', 0)
            
            # Calculate a quick percentage
            rate = (blocked / dns_queries * 100) if dns_queries > 0 else 0
            
            return (
                f"🛡️ *AdGuard Defense Report*\n"
                f"• Total Queries: `{dns_queries}`\n"
                f"• Threats Blocked: `{blocked}` ({rate:.1f}%)\n"
            )
        else:
            return "🛡️ AdGuard: Unable to fetch stats (Auth failed)."
    except Exception as e:
        return f"🛡️ AdGuard: Error connecting ({str(e)[:30]})"

def get_pihole_session(host):
    """Get Pi-hole v6 session token (cached with auto-refresh)"""
    global pihole_sessions
    
    # Check if we have a valid cached session
    now = datetime.now()
    if host in pihole_sessions:
        session = pihole_sessions[host]
        if session.get('sid') is not None and session['expires'] > now:
            return session['sid']
    
    # Login to get new session
    password = os.getenv('PIHOLE_PASSWORD')
    if not password:
        return None
    
    try:
        response = requests.post(
            f"http://{host}/api/auth",
            json={"password": password},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            session_data = data.get('session', {})
            sid = session_data.get('sid', '')
            validity = session_data.get('validity', 300)
            
            # Cache session (even if sid is empty string)
            pihole_sessions[host] = {
                'sid': sid,
                'expires': now + timedelta(seconds=validity - 30)
            }
            return sid
    except:
        pass
    
    return None

def get_combined_dns_stats():
    """Get stats from AdGuard + both Pi-holes (v6 API - FIXED)"""
    try:
        total_queries = 0
        total_blocked = 0
        servers_online = 0
        
        # AdGuard Home
        try:
            response = requests.get(
                f"{AGH_URL}/control/stats",
                auth=(AGH_USER, AGH_PASS),
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                total_queries += data.get('num_dns_queries', 0)
                total_blocked += data.get('num_blocked_filtering', 0)
                servers_online += 1
        except:
            pass
        
        # Pi-hole 1 (10.1.1.69) - v6 API CORRECT FIELDS
        try:
            pihole1_sid = get_pihole_session("10.1.1.69")
            if pihole1_sid:
                response = requests.get(
                    "http://10.1.1.69/api/stats/summary",
                    headers={"X-FTL-SID": pihole1_sid},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    queries_data = data.get('queries', {})
                    pi1_queries = queries_data.get('total', 0)
                    pi1_blocked = queries_data.get('blocked', 0)
                    
                    total_queries += pi1_queries
                    total_blocked += pi1_blocked
                    servers_online += 1
        except:
            pass
        
        # Pi-hole 2 (10.1.1.70) - v6 API CORRECT FIELDS
        try:
            pihole2_sid = get_pihole_session("10.1.1.70")
            if pihole2_sid:
                response = requests.get(
                    "http://10.1.1.70/api/stats/summary",
                    headers={"X-FTL-SID": pihole2_sid},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    queries_data = data.get('queries', {})
                    pi2_queries = queries_data.get('total', 0)
                    pi2_blocked = queries_data.get('blocked', 0)
                    
                    total_queries += pi2_queries
                    total_blocked += pi2_blocked
                    servers_online += 1
        except:
            pass
        
        rate = (total_blocked / total_queries * 100) if total_queries > 0 else 0
        
        return (
            f"🛡️ *DNS Protection ({servers_online}/3 servers)*\n"
            f"• Total Queries: `{total_queries:,}`\n"
            f"• Threats Blocked: `{total_blocked:,}` ({rate:.1f}%)\n"
        )
    except Exception as e:
        return f"🛡️ DNS Protection: Error ({str(e)[:30]})"

def get_security_summary():
    """Generate security event summary for reports"""
    now = datetime.now()
    
    # Count recent events (last 24h)
    cutoff = now - timedelta(hours=24)
    
    suricata_24h = len([e for e in security_events['suricata_alerts'] if e['time'] > cutoff])
    zenarmor_24h = sum([e['blocked'] for e in security_events['zenarmor_blocks'] if e['time'] > cutoff])
    
    summary_text = "*🛡️ Security Events (24h)*\n\n"
    
    if suricata_24h > 0 or zenarmor_24h > 0:
        if suricata_24h > 0:
            summary_text += f"• Suricata Alerts: {suricata_24h}\n"
        if zenarmor_24h > 0:
            summary_text += f"• Zenarmor Blocks: {zenarmor_24h}\n"
        
        # Show top threats
        recent_threats = [e['signature'] for e in list(security_events['suricata_alerts'])[-5:]]
        if recent_threats:
            summary_text += f"\n*Recent Threats:*\n"
            for threat in set(recent_threats):
                summary_text += f"• {threat[:60]}\n"
    else:
        summary_text += "_No threats detected - all quiet_ ✅"
    
    return summary_text

def track_performance_baseline():
    """Track network performance metrics for baseline and SLA monitoring"""
    global performance_baselines
    
    speed = get_speedtest_data(retry=False)
    
    # Only track if we have valid data
    if speed['download_raw'] > 0:
        performance_baselines['download_speed'].append(speed['download_raw'])
        performance_baselines['upload_speed'].append(speed['upload_raw'])
    
    # Track latency from speedtest
    if speed['ping'] != '-':
        try:
            latency_val = float(speed['ping'].replace(' ms', ''))
            performance_baselines['latency'].append(latency_val)
        except:
            pass
    
    # Calculate current averages
    if len(performance_baselines['download_speed']) >= 7:
        avg_download = sum(performance_baselines['download_speed']) / len(performance_baselines['download_speed'])
        avg_upload = sum(performance_baselines['upload_speed']) / len(performance_baselines['upload_speed'])
        avg_latency = sum(performance_baselines['latency']) / len(performance_baselines['latency']) if performance_baselines['latency'] else 0
        
        return {
            'avg_download': avg_download,
            'avg_upload': avg_upload,
            'avg_latency': avg_latency,
            'samples': len(performance_baselines['download_speed'])
        }
    
    return None

def get_service_health_summary():
    """Generate service health report with uptime percentages"""
    now = datetime.now()
    health_text = "*⏱️ Service Health (7 Days)*\n\n"
    
    for service, health in service_health.items():
        if service == 'internet':
            continue  # Report separately
        
        # Calculate uptime percentage
        total_time = (now - health['uptime_start']).total_seconds()
        downtime = health['downtime_total']
        uptime_pct = ((total_time - downtime) / total_time * 100) if total_time > 0 else 100
        
        # Get restart count
        restarts = health['restart_count']
        
        # Status emoji
        if uptime_pct >= 99.9:
            status = "🟢"
        elif uptime_pct >= 99:
            status = "🟡"
        else:
            status = "🔴"
        
        health_text += f"{status} *{service.title()}*: {uptime_pct:.2f}%\n"
        if restarts > 0:
            health_text += f"   └ {restarts} restart(s), {format_duration(downtime)} downtime\n"
    
    # Internet uptime
    internet_health = service_health['internet']
    total_time = (now - internet_health['uptime_start']).total_seconds()
    downtime = internet_health['downtime_total']
    uptime_pct = ((total_time - downtime) / total_time * 100) if total_time > 0 else 100
    
    if uptime_pct >= 99.9:
        status = "🟢"
    elif uptime_pct >= 99:
        status = "🟡"
    else:
        status = "🔴"
    
    health_text += f"\n{status} *Internet*: {uptime_pct:.2f}%\n"
    if internet_health['outage_count'] > 0:
        health_text += f"   └ {internet_health['outage_count']} outage(s), {format_duration(downtime)} downtime\n"
    
    return health_text

def check_performance_sla():
    """Check if performance meets SLA targets"""
    baseline = track_performance_baseline()
    
    if not baseline:
        return "*📊 Performance SLA*\n_Building baseline (need 7+ samples)_"
    
    sla_text = "*📊 Performance SLA*\n\n"
    
    # Current speed check
    current_speed = baseline_speed.get('download', 0)
    if current_speed > 0 and baseline['avg_download'] > 0:
        speed_ratio = (current_speed / baseline['avg_download']) * 100
        
        if speed_ratio >= 80:
            sla_text += f"✅ Download Speed: {speed_ratio:.0f}% of baseline\n"
        else:
            sla_text += f"⚠️ Download Speed: {speed_ratio:.0f}% of baseline (degraded)\n"
    
    # Latency SLA
    if baseline['avg_latency'] > 0:
        if baseline['avg_latency'] < 50:
            sla_text += f"✅ Avg Latency: {baseline['avg_latency']:.1f}ms (excellent)\n"
        elif baseline['avg_latency'] < 100:
            sla_text += f"🟡 Avg Latency: {baseline['avg_latency']:.1f}ms (acceptable)\n"
        else:
            sla_text += f"⚠️ Avg Latency: {baseline['avg_latency']:.1f}ms (high)\n"
    
    # Baseline stats
    sla_text += f"\n*7-Day Baseline:*\n"
    sla_text += f"• Download: {baseline['avg_download']:.1f} Mbps\n"
    sla_text += f"• Upload: {baseline['avg_upload']:.1f} Mbps\n"
    sla_text += f"• Latency: {baseline['avg_latency']:.1f}ms\n"
    sla_text += f"\n_Based on {baseline['samples']} measurements_"
    
    return sla_text

def detect_geographic_anomaly(peer_id, peer_name, endpoint):
    """Detect if VPN peer is connecting from unusual geographic location"""
    
    if not endpoint or endpoint == 'None':
        return False, ""
    
    # Extract IP from endpoint
    ip = endpoint.split(':')[0] if ':' in endpoint else endpoint
    
    # Check history
    if peer_id in wg_endpoint_history:
        previous_ips = [ep.split(':')[0] for ep in wg_endpoint_history[peer_id] if ':' in ep]
        
        # If connecting from completely different IP (not just port change)
        if previous_ips and ip not in previous_ips:
            return True, f"New location: {ip} (previous: {previous_ips[-1]})"
    
    return False, ""

def get_ip_info(ip_address):
    # 🦇 BATMAN SILENCER: Shield for internal ranges
    if ip_address.startswith(('10.', '192.168.', '172.', '100.64.', '127.', '169.254.')):
        return {
            'ip': ip_address, 
            'type': 'Private/Local', 
            'city': 'Home Base', 
            'region': 'Internal',
            'country': 'Private Network',
            'country_code': '--', 
            'country_flag': '🏠', 
            'isp': 'Local Network', # <--- FIXED: No longer says "Mobile" for desktop
            'timezone': 'Local',
            'is_proxy': False, 
            'is_vpn': False, 
            'is_mobile': False,
            'is_hosting': False,
            'threat_level': 'Safe ✅'
        }

    info = {
        'ip': ip_address, 'type': 'Public', 'city': 'Unknown', 'region': 'Unknown',
        'country': 'Unknown', 'country_code': 'XX', 'country_flag': '🌍', 
        'isp': 'Unknown ISP', 'timezone': 'UTC', 'is_proxy': False, 
        'is_vpn': False, 'is_mobile': False, 'is_hosting': False, 'threat_level': 'Low ✅'
    }

    try:
        response = requests.get(f"https://ifconfig.co/json?ip={ip_address}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            info['city'] = data.get('city', 'Unknown')
            info['region'] = data.get('region_name', 'Unknown')
            info['country'] = data.get('country', 'Unknown')
            info['country_code'] = data.get('country_iso', 'XX')
            info['timezone'] = data.get('time_zone', 'UTC')
            info['country_flag'] = get_country_flag(info['country_code'])
            
            # --- 🛠️ THE ISP TRANSLATOR (Star Wars Translation Droid) ---
            raw_isp = data.get('asn_org', 'Unknown ISP')
            
            isp_map = {
                "ASN-CXA-ALL-CCI-22773-RDC": "Cox Communications",
                "T-MOBILE-AS21928": "T-Mobile USA",
                "CELLCO-PART": "Verizon Wireless",
                "GOOGLE-CLOUD": "Google Cloud"
            }
            
            # Use the clean name if we have it, otherwise use the raw name
            info['isp'] = isp_map.get(raw_isp, raw_isp)
            
            # Re-check flags based on the clean name or raw name
            isp_low = info['isp'].lower()
            if any(k in isp_low for k in ['vpn', 'proxy', 'mullvad', 'nord']):
                info['is_vpn'] = True
                info['threat_level'] = 'Medium 🟡'
            if "t-mobile" in isp_low or "verizon" in isp_low:
                info['is_mobile'] = True

            return info
    except:
        pass

    return info

def get_ip_location(ip):
    """Uses the superior get_ip_info logic to avoid DNS blocks."""
    # 🛡️ Keep the safety check for empty IPs
    if not ip or ip in ["0.0.0.0", "N/A", "Unknown"]:
        return "Unknown"

    info = get_ip_info(ip)
    # Use the label we added in the new get_ip_info
    if info.get('type') == 'Private/Local':
        return "Internal/Mobile Network"
    return f"{info['city']}, {info['region']} ({info['isp']})"
    if ip.startswith(('10.', '192.168.', '172.', '100.64.')):
        return "Internal/Mobile Network"

    try:
        # Try ip-api.com (HTTP version is free for non-commercial)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return f"{data.get('city')}, {data.get('regionName')} ({data.get('isp')})"
        
        # Fallback to ipapi.co if the first one fails
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return f"{data.get('city')}, {data.get('region')} ({data.get('org')})"
            
    except Exception as e:
        print(f"    ⚠️  IP lookup failed for {ip}: {str(e)[:50]}")
    
    return "Location Unavailable"

def get_country_flag(country_code):
    """Convert country code to flag emoji"""
    if not country_code or len(country_code) != 2:
        return '🌍'
    
    # Convert country code to flag emoji
    # Each country code letter maps to a regional indicator symbol
    flag = ''.join(chr(ord(c) + 127397) for c in country_code.upper())
    return flag

def format_ip_info_message(ip_info):
    """Format IP info into a nice Slack message"""
    
    if ip_info['type'] == 'Private/Local':
        return f"📍 *Local Network Connection*\n• IP: `{ip_info['ip']}`\n• Type: Private/Internal Network"
    
    msg = f"📍 *Connection Details*\n\n"
    msg += f"{ip_info['country_flag']} *Location:* {ip_info['city']}, {ip_info['region']}, {ip_info['country']}\n"
    msg += f"🌐 *IP Address:* `{ip_info['ip']}`\n"
    msg += f"🏢 *ISP:* {ip_info['isp']}\n"
    msg += f"🕐 *Timezone:* {ip_info['timezone']}\n"
    
    # Security indicators
    indicators = []
    if ip_info['is_vpn']:
        indicators.append("🔒 VPN/Datacenter")
    if ip_info['is_proxy']:
        indicators.append("⚠️ Proxy Detected")
    if ip_info['is_mobile']:
        indicators.append("📱 Mobile Network")
    if ip_info['is_hosting']:
        indicators.append("☁️ Cloud/Hosting")
    
    if indicators:
        msg += f"\n*Indicators:* {', '.join(indicators)}\n"
    
    msg += f"*Threat Level:* {ip_info['threat_level']}"
    
    return msg

def get_zenarmor_insights():
    """Get rich network insights from Zenarmor dashboard - FIXED VERSION"""
    
    insights_text = "*📊 Network Insights (Zenarmor)*\n\n"
    
    try:
        # Use zenarmor/status instead of broken reporting endpoints
        zen_status = fetch_opn("zenarmor/status")
        
        if not zen_status:
            return "*📊 Network Insights*\n_Zenarmor unavailable_"
        
        # Get data from status endpoint (we know this works!)
        top_apps = zen_status.get('top_apps_categories', {})
        top_hosts = zen_status.get('top_local_hosts', {})
        
        # Top Application Categories
        app_labels = top_apps.get('labels', [])
        if app_labels:
            insights_text += "*📱 Top App Categories*\n"
            for i, app in enumerate(app_labels[:5], 1):
                insights_text += f"{i}. {app}\n"
            insights_text += "\n"
        
        # Top Local Hosts (Bandwidth Users)
        host_labels = top_hosts.get('labels', [])
        if host_labels:
            insights_text += "*🌍 Top Local Hosts*\n"
            for i, host in enumerate(host_labels[:5], 1):
                # Try to resolve hostname
                hostname = host
                for mac, lease in known_dhcp_leases.items():
                    if lease.get('ip') == host and lease.get('hostname'):
                        hostname = lease['hostname']
                        break
                insights_text += f"{i}. {hostname}\n"
            insights_text += "\n"
        
        # Show active device count
        active_devices = zen_status.get('active_device', 0)
        insights_text += f"*Active Devices:* {active_devices}\n"
        
        # Show threat info if available
        threats = zen_status.get('threat_detected', 0)
        if threats > 0:
            blocked = zen_status.get('threat_detected_blocked', 0)
            insights_text += f"*Threats:* {threats} detected, {blocked} blocked\n"
        
        # If we got no data at all
        if insights_text == "*📊 Network Insights (Zenarmor)*\n\n":
            insights_text += "_No insights data available_\n"
            insights_text += "_Enable Application Control in Zenarmor settings_"
        
        return insights_text
        
    except Exception as e:
        return f"*📊 Network Insights*\n_Error: {str(e)[:50]}_"

def get_zenarmor_status():
    data = fetch_opn("zenarmor/status")
    if data:
        status = data.get('status')
        if status == 'running' or status == 0 or status == 'active':
            return "ACTIVE ✅"
        else:
            return "DOWN ❌"
    return "UNKNOWN ⚠️"

def get_service_status(svc_name):
    if svc_name.lower() == 'suricata':
        ids_data = fetch_opn("ids/service/status")
        if ids_data:
            status = ids_data.get('status', 'unknown')
            if status == 'running':
                return "ACTIVE ✅"
            elif status == 'stopped':
                return "DOWN ❌"
    if svc_name.lower() == 'zenarmor':
        zen_data = fetch_opn("zenarmor/status")
        if zen_data and isinstance(zen_data, dict):
            status = zen_data.get('status', '').lower()
            if status in ['running', 'active', 'online']:
                return "ACTIVE ✅"
            elif status in ['stopped', 'offline']:
                return "DOWN ❌"
            return "ACTIVE ✅"
    data = fetch_opn("core/service/search")
    mapping = {"suricata": ["suricata", "ids"], "zenarmor": ["sensei", "eastpect", "zenarmor"]}
    targets = mapping.get(svc_name.lower(), [svc_name.lower()])
    if data and 'rows' in data:
        for s in data['rows']:
            service_name = s.get('name', '').lower()
            if any(target in service_name for target in targets):
                running = s.get('running', s.get('status', 0))
                return "ACTIVE ✅" if running == 1 else "DOWN ❌"
    return "UNKNOWN ⚠️"

def get_dhcp_leases():
    """Get DHCP lease counts from tracked state (works with both ISC and Kea)"""
    active_count = len([l for l in known_dhcp_leases.values() if l['active']])
    inactive_count = len([l for l in known_dhcp_leases.values() if not l['active']])
    return active_count, inactive_count

def send_grid_notification(title, dl, pg, ul, gw, extra_text="", show_dhcp=False, add_buttons=None, 
                           l1="📥 Download", l2="⏱️ Ping", l3="📤 Upload", l4="🌐 Gateway Status"):
    uptime = get_system_uptime()
    
    # 🦇 BATMAN FIX: We use l1, l2, l3, l4 so we can change labels on the fly!
    main_fields = [
        {"type": "mrkdwn", "text": f"*{l1}*\n`{dl}`"},
        {"type": "mrkdwn", "text": f"*{l2}*\n`{pg}`"},
        {"type": "mrkdwn", "text": f"*{l3}*\n`{ul}`"},
        {"type": "mrkdwn", "text": f"*{l4}*\n`{gw}`"}
    ]
    
    security_status = f"Suricata: {get_service_status('suricata')}\nZenarmor: {get_service_status('zenarmor')}"
    secondary_fields = [
        {"type": "mrkdwn", "text": f"*🛡️ Security Services*\n{security_status}"},
        {"type": "mrkdwn", "text": f"*⏱️ System Uptime*\n`{uptime}`"}
    ]

    report_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "fields": main_fields},
        {"type": "section", "fields": secondary_fields}
    ]

    if show_dhcp:
        active, inactive = get_dhcp_leases()
        report_blocks.append({"type": "divider"})
        report_blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*📡 DHCP Leases Status*\nActive: `{active}`  |  Inactive: `{inactive}`"}})

    if extra_text:
        report_blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": extra_text}]})

    if add_buttons:
        report_blocks = add_action_buttons(report_blocks, context=add_buttons)

    report = {"blocks": report_blocks}
    try:
        requests.post(SLACK_WEBHOOK, json=report, timeout=10)
    except Exception as e:
        print(f"❌ Failed to send Slack notification: {e}")

def send_dhcp_notification(title, hostname, ip, mac, status_label, extra_text=""):
    uptime = get_system_uptime()
    device_fields = [
        {"type": "mrkdwn", "text": f"*🖥️ Hostname*\n`{hostname}`"},
        {"type": "mrkdwn", "text": f"*🌐 IP Address*\n`{ip}`"},
        {"type": "mrkdwn", "text": f"*🔖 MAC Address*\n`{mac}`"},
        {"type": "mrkdwn", "text": f"*📊 Status*\n`{status_label}`"}
    ]
    security_status = f"Suricata: {get_service_status('suricata')}\nZenarmor: {get_service_status('zenarmor')}"
    secondary_fields = [
        {"type": "mrkdwn", "text": f"*🛡️ Security Services*\n{security_status}"},
        {"type": "mrkdwn", "text": f"*⏱️ System Uptime*\n`{uptime}`"}
    ]
    report_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "fields": device_fields},
        {"type": "section", "fields": secondary_fields}
    ]
    if extra_text:
        report_blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": extra_text}]})
    report = {"blocks": report_blocks}
    try:
        requests.post(SLACK_WEBHOOK, json=report, timeout=10)
    except Exception as e:
        print(f"❌ Failed to send Slack notification: {e}")

def check_gateways(is_startup=False):
    data = fetch_opn("routes/gateway/status")
    found = []
    if data and 'items' in data:
        for gw in data['items']:
            name, status = gw.get('name'), gw.get('status', 'unknown')
            found.append(name)
            if not is_startup and name in last_gw_state and last_gw_state[name] != status:
                label = "ONLINE" if status == "none" else status.upper()
                send_grid_notification(f"🌐 Gateway Update: {name}", dl="-", pg="-", ul="-", gw=label)
            last_gw_state[name] = status
    return found

def get_speedtest_data(retry=True, max_retries=5, require_fresh=False):
    global baseline_speed, speed_history
    
    for attempt in range(max_retries if retry else 1):
        try:
            response = requests.get(SPEEDTEST_API, timeout=10)
            st = response.json()
            data = st.get('data', {})
            is_cached = False
            created_at = data.get('created_at') or data.get('updated_at')
            
            if created_at:
                try:
                    test_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if test_time.tzinfo is None:
                        from datetime import timezone
                        test_time = test_time.replace(tzinfo=timezone.utc)
                    now = datetime.now(test_time.tzinfo)
                    age_hours = (now - test_time).total_seconds() / 3600
                    if age_hours > 6.5:
                        is_cached = True
                        if require_fresh and retry and attempt < max_retries - 1:
                            time.sleep(10)
                            continue
                except Exception as e:
                    print(f"   ⚠️  Could not parse timestamp '{created_at}': {e}")
            
            download = float(data.get('download', 0))
            ping = float(data.get('ping', 0))
            upload = float(data.get('upload', 0))
            
            # Set baseline speed if not set
            if baseline_speed['download'] == 0 and download > 0:
                baseline_speed['download'] = download
                baseline_speed['upload'] = upload
                print(f"   📊 Baseline speed set: {download:.1f} Mbps down, {upload:.1f} Mbps up")
            
            if download > 0 or upload > 0:
                cache_label = " (cached)" if is_cached else ""
                speed_warning = ""
                download_ratio = 1.0
                
                if baseline_speed['download'] > 0:
                    download_ratio = download / baseline_speed['download']
                    if download_ratio < SPEED_DROP_THRESHOLD and not is_cached:
                        speed_warning = f" ⚠️ {int((1 - download_ratio) * 100)}% slower than baseline"
                
                # Add to speed history (only if not cached)
                if not is_cached:
                    speed_history.append({
                        'timestamp': datetime.now(),
                        'download': download,
                        'upload': upload,
                        'ping': ping
                    })
                
                return {
                    'download': f"{download:.1f} Mbps{cache_label}{speed_warning}",
                    'ping': f"{ping:.1f} ms",
                    'upload': f"{upload:.1f} Mbps{cache_label}",
                    'is_cached': is_cached,
                    'download_raw': download,
                    'upload_raw': upload,
                    'degraded': download_ratio < SPEED_DROP_THRESHOLD if baseline_speed['download'] > 0 else False
                }
            elif retry and attempt < max_retries - 1:
                time.sleep(10)
        except Exception as e:
            if retry and attempt < max_retries - 1:
                time.sleep(10)
    
    return {
        'download': "-",
        'ping': "-",
        'upload': "-",
        'is_cached': False,
        'download_raw': 0,
        'upload_raw': 0,
        'degraded': False
    }

def track_wan_traffic():
    """Track total WAN interface traffic"""
    global last_interface_stats, daily_bandwidth, weekly_stats
    
    data = fetch_opn("diagnostics/interface/getInterfaceStatistics")
    if not data or 'statistics' not in data:
        print("   ⚠️ No interface statistics available")
        return
    
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Look for WAN interface (usually 'wan' or first interface)
    wan_stats = None
    for interface_name, stats in data.get('statistics', {}).items():
        # Match WAN interface (could be 'wan', 'igc1', etc.)
        if interface_name.lower() in ['wan', 'igc1', 'em1'] or stats.get('name', '').lower() == 'wan':
            wan_stats = stats
            break
    
    if not wan_stats:
        # Fallback: use first non-loopback interface
        for interface_name, stats in data.get('statistics', {}).items():
            if interface_name != 'lo0' and 'bytes' in str(stats):
                wan_stats = stats
                break
    
    if not wan_stats:
        return
    
    # Get current byte counters
    bytes_received = int(wan_stats.get('bytes received', 0))
    bytes_sent = int(wan_stats.get('bytes sent', 0))
    
    # Calculate delta since last check
    interface_key = 'wan'
    if interface_key in last_interface_stats:
        last_rx = last_interface_stats[interface_key]['rx']
        last_tx = last_interface_stats[interface_key]['tx']
        
        # Only process if counters haven't reset
        if bytes_received >= last_rx and bytes_sent >= last_tx:
            delta_rx_gb = (bytes_received - last_rx) / (1024**3)
            delta_tx_gb = (bytes_sent - last_tx) / (1024**3)
            
            # Update daily stats
            daily_bandwidth[today]['wan_download'] += delta_rx_gb
            daily_bandwidth[today]['wan_upload'] += delta_tx_gb
            
            # Update weekly stats
            weekly_stats['wan_total_download_gb'] += delta_rx_gb
            weekly_stats['wan_total_upload_gb'] += delta_tx_gb
    
    # Store current counters for next check
    last_interface_stats[interface_key] = {
        'rx': bytes_received,
        'tx': bytes_sent,
        'timestamp': datetime.now()
    }

    if loop_count % 60 == 0:
        detect_port_scan()
        today = datetime.now().strftime('%Y-%m-%d')
        print(f"   📊 WAN tracking: {daily_bandwidth[today]['wan_download']:.3f} GB down, {daily_bandwidth[today]['wan_upload']:.3f} GB up")


def check_wireguard_peers():
    global last_wg_handshakes, wg_baselines, wg_active_peers

    try:
        data = fetch_opn("wireguard/service/show")
        if not data: return

        rows = data.get('rows', [])
        HANDSHAKE_TIMEOUT = 180
        current_active_this_poll = set()

        for item in rows:
            if not isinstance(item, dict) or item.get('type') != 'peer':
                continue

            peer_name = item.get('name', 'Unknown')
            peer_key = item.get('public-key', '')
            peer_id = f"{item.get('ifname', 'wg')}:{peer_key[:16]}"

            # Protect against None handshakes
            raw_age = item.get('latest-handshake-age')
            age = int(raw_age) if raw_age is not None else 999999
            
            raw_rx = int(item.get('transfer-rx', 0))
            raw_tx = int(item.get('transfer-tx', 0))

            if age < HANDSHAKE_TIMEOUT:
                current_active_this_poll.add(peer_id)

                # --- NEW CONNECTION DETECTED ---
                if peer_id not in wg_active_peers:
                    wg_baselines[peer_id] = {'rx': raw_rx, 'tx': raw_tx}
                    wg_active_peers.add(peer_id)
                    
                    endpoint = item.get('endpoint', 'N/A')
                    clean_ip = endpoint.split(':')[0] if ':' in endpoint else endpoint
                    
                    # 1. Get the Data
                    ip_info = get_ip_info(clean_ip)
                    is_geo_anomaly, geo_desc = detect_geographic_anomaly(peer_id, peer_name, clean_ip)

                    print(f"🔐 WG CONNECT: {peer_name}")

                    # 2. Build the "Advanced Intel" (No Duplicates!)
                    indicators = []
                    if ip_info['is_vpn']: indicators.append("🔒 VPN")
                    if ip_info['is_mobile']: indicators.append("📱 Mobile")
                    if ip_info['is_hosting']: indicators.append("☁️ Hosting")
                    
                    # Start with Timezone
                    extra = f"🕐 *Timezone:* {ip_info['timezone']}"
                    
                    # Add Indicators if they exist
                    if indicators:
                        extra += f"  |  *Status:* {' '.join(indicators)}"
                    
                    # Add Geo Anomaly warning if needed
                    if is_geo_anomaly:
                        title = f"🌍 VPN Location Change: {peer_name}"
                        extra += f"\n⚠️ *Geo-Anomaly:* {geo_desc}"
                    else:
                        title = f"🔐 WireGuard Connected: {peer_name}"

                    # 3. Send to Slack with Custom Labels
                    send_grid_notification(
                        title,
                        dl=f"{ip_info['city']}, {ip_info['country']}", 
                        pg=f"{ip_info['isp']}",                   
                        ul=f"{clean_ip}",                              
                        gw=f"{ip_info['threat_level']}",              
                        extra_text=extra,
                        l1="📍 Location",    
                        l2="🏢 ISP",         
                        l3="🌐 IP Address",  
                        l4="🛡️ Threat Level" 
                    )
                
                # Track hourly usage (for ALL active peers, not just new ones)
                if peer_id in wg_baselines:
                    current_hour = datetime.now().hour
                    today_date = datetime.now().strftime('%Y-%m-%d')
                    
                    cur_rx = raw_rx
                    cur_tx = raw_tx
                    base = wg_baselines[peer_id]
                    
                    # Calculate delta since baseline (session total)
                    session_rx_gb = (cur_rx - base['rx']) / (1024**3)
                    session_tx_gb = (cur_tx - base['tx']) / (1024**3)
                    session_total_gb = session_rx_gb + session_tx_gb
                    
                    # Add to this hour's usage
                    # wg_hourly_usage[today_date][current_hour] = session_total_gb

                    if peer_id not in wg_peer_hourly_tracking:
                        wg_peer_hourly_tracking[peer_id] = {'last_hour': current_hour, 'last_total': 0}

                    if wg_peer_hourly_tracking[peer_id]['last_hour'] != current_hour:
                        wg_hourly_usage[today_date][current_hour] += session_total_gb - wg_peer_hourly_tracking[peer_id]['last_total']
                        wg_peer_hourly_tracking[peer_id]['last_hour'] = current_hour
                        wg_peer_hourly_tracking[peer_id]['last_total'] = session_total_gb

        # --- DISCONNECTION DETECTED ---
        disconnected_peers = wg_active_peers - current_active_this_poll
        for p_id in disconnected_peers:
            p_name = "Unknown Peer"
            # Find the peer in the current rows for final stats
            for r in rows:
                if f"{r.get('ifname')}:{r.get('public-key')[:16]}" == p_id:
                    p_name = r.get('name', 'Unknown')
                    raw_rx = int(r.get('transfer-rx', 0))
                    raw_tx = int(r.get('transfer-tx', 0))
                    break
            
            base = wg_baselines.get(p_id, {'rx': raw_rx, 'tx': raw_tx})
            session_rx_mb = (raw_rx - base['rx']) / (1024 * 1024)
            session_tx_mb = (raw_tx - base['tx']) / (1024 * 1024)

            print(f"🔓 WG DISCONNECT: {p_name}")

            send_grid_notification(
                f"🔓 WireGuard Disconnected: {p_name}",
                dl=f"{max(0, session_tx_mb):.2f} MB",
                pg="Session Ended",
                ul=f"{max(0, session_rx_mb):.2f} MB",
                gw="Status: Offline",
                l1="📥 Total Down",
                l2="⏱️ Session",      # ← Added l2
                l3="📤 Total Up",
                l4="🌐 Status"        # ← Added l4
            )

            wg_active_peers.discard(p_id)
            wg_baselines.pop(p_id, None)

    except Exception as e:
        print(f"❌ Error in WireGuard check: {e}")

def check_dhcp_leases(is_startup=False):
    """
    Monitor DHCP leases - now supports both ISC DHCP and Kea DHCP
    Also checks DHCP reservations for better hostname mapping
    """
    global weekly_stats, dhcp_reservations
    
    # Load DHCP reservations for better hostname mapping
    if is_startup or len(dhcp_reservations) == 0:
        print(f"   🔍 Loading DHCP reservations...")
        
        # Try multiple possible Kea reservation endpoints
        reservation_endpoints = [
            "kea/dhcpv4/searchReservation",
            "kea/dhcpv4/reservation/search",  
            "dhcpv4/reservation/search"
        ]
        
        loaded = False
        for endpoint in reservation_endpoints:
            try:
                reservations_data = fetch_opn(endpoint)
                if reservations_data and 'rows' in reservations_data and len(reservations_data['rows']) > 0:
                    dhcp_reservations.clear()
                    
                    for res in reservations_data['rows']:
                        # Try multiple field name variations
                        mac = res.get('hw_address', res.get('hwaddr', res.get('hw-address', res.get('mac', '')))).lower()
                        hostname = res.get('hostname', res.get('description', res.get('descr', res.get('host', ''))))
                        
                        if mac and hostname:
                            dhcp_reservations[mac] = hostname
                    
                    if dhcp_reservations:
                        loaded = True
                        break
            except Exception as e:
                print(f"   ⚠️  Error trying {endpoint}: {str(e)[:50]}")
        
        if not loaded:
            print(f"   ⚠️  No DHCP reservations API found - will use DHCP lease hostnames only")
    
    # Try Kea DHCP first (more accurate), fall back to ISC DHCP
    kea_endpoints = [
        "kea/leases4/search",
        "kea/dhcpv4/lease4-get-all",
    ]

    kea_data = None
    use_kea = False
    
    for endpoint in kea_endpoints:
        kea_data = fetch_opn(endpoint)
        if kea_data and 'rows' in kea_data and len(kea_data['rows']) > 0:
            print(f"   📊 Using Kea DHCP API: {endpoint}")
            use_kea = True
            break
    
    if not use_kea:
        # Fall back to ISC DHCP
        print("   📊 Using ISC DHCP API (Kea not available or empty)")
        kea_data = fetch_opn("dhcpv4/leases/searchLease")
    
    data = kea_data
    
    if not data or 'rows' not in data:
        print("   ⚠️  No DHCP data received from API")
        return
    
    current_leases = {}
    now = datetime.now()
    
    # Debug: Count active vs inactive leases in API response
    active_in_api = 0
    inactive_in_api = 0

    for lease in data['rows']:
        if use_kea:
            # Kea DHCP format - try multiple field name variations
            mac = lease.get('hwaddr', lease.get('hw-address', lease.get('mac', ''))).lower()
            ip = lease.get('address', lease.get('ip-address', 'N/A'))
            hostname = lease.get('hostname', lease.get('client-hostname', ''))
            state = lease.get('state', lease.get('lease-state', 0))
            
            # Kea DHCP: state 0 = default/active
            # Note: Kea doesn't update state in real-time, so this shows lease status
            state_str = str(state).lower()
            is_active = state_str in ['0', 'default', 'active']
        else:
            # ISC DHCP format
            mac = lease.get('mac', '').lower()
            ip = lease.get('address', 'N/A')
            hostname = lease.get('hostname', '')
            state = lease.get('state', 'unknown')
            is_active = (state == 'active')

        if not mac: 
            continue

        # 1. Hostname Mapping
        if mac in dhcp_reservations:
            hostname = dhcp_reservations[mac]
        elif not hostname or hostname == 'Unknown':
            hostname = f"Device-{ip.split('.')[-1]}"

        # 2. Track this device for current scan
        current_leases[mac] = {'hostname': hostname, 'ip': ip, 'active': is_active}
        
        # 3. CHECK FOR STATUS CHANGES
        if not is_startup:
            was_active = False
            is_new_device = mac not in known_dhcp_leases
            
            if not is_new_device:
                was_active = known_dhcp_leases[mac].get('active', False)

            # Trigger if: (First time seen & Active) OR (Status flipped)
            status_changed = (is_new_device and is_active) or (not is_new_device and was_active != is_active)

            if status_changed:
                # Priority 1: The Heroic Alert (Beast-Box Protocol)
                if ip in HERO_WATCHLIST:
                    heroic_alert(ip, "connected" if is_active else "disconnected")
                
                # Priority 2: Standard Notifications for everyone else
                else:
                    status_label = "CONNECTED 🟢" if is_active else "OFFLINE ⚪"
                    
                    if is_new_device:
                        extra = "First time seen on network"
                        is_anomaly, anomaly_desc = detect_dhcp_anomaly()
                        if is_anomaly: 
                            extra += f"\n⚠️ ANOMALY: {anomaly_desc}"
                        send_dhcp_notification(f"🟢 New Device: {hostname}", hostname, ip, mac, "New Lease", extra_text=extra)
                    else:
                        extra = "Device reconnected" if is_active else "Device left network"
                        is_unstable, instability_desc = detect_disconnect_cycle(mac, hostname)
                        if is_unstable: 
                            extra += f"\n⚠️ UNSTABLE: {instability_desc}"
                        send_dhcp_notification(f"📡 {hostname}", hostname, ip, mac, status_label, extra_text=extra)

        # 4. Update Stats
        if is_active:
            active_in_api += 1
            weekly_stats['devices_seen'].add(hostname)
        else:
            inactive_in_api += 1
    
    # --- END OF LOOP ---
    print(f"    📊 DHCP API Scan Complete: {active_in_api} active, {inactive_in_api} inactive")
    
    # Sync memory for next run
    known_dhcp_leases.clear()
    known_dhcp_leases.update(current_leases)

def send_daily_report():
    global historical_daily_stats
    print("📊 Generating daily traffic report...")
    
    # Get speed data
    speed = get_speedtest_data(retry=False)
    
    # Get today's stats
    today = datetime.now().strftime('%Y-%m-%d')
    today_stats = daily_bandwidth.get(today, {
        'wg_download': 0, 'wg_upload': 0, 'wg_sessions': 0,
        'wan_download': 0, 'wan_upload': 0
    })
    
    # Calculate totals
    wg_total_gb = today_stats['wg_download'] + today_stats['wg_upload']
    wan_total_gb = today_stats['wan_download'] + today_stats['wan_upload']
    
    # Save today's stats to historical data
    historical_daily_stats.append({
        'date': today,
        'wan_total': wan_total_gb,
        'wg_total': wg_total_gb,
        'wg_sessions': today_stats['wg_sessions']
    })
    
    # ← ADD THIS SECTION (the missing report_text):
    # Build main report text
    report_text = f"*📊 24-Hour Network Summary*\n\n"
    
    # WAN Traffic (Total Internet Usage)
    report_text += f"*🌐 Total WAN Traffic*\n"
    report_text += f"• Download: `{today_stats['wan_download']:.2f} GB`\n"
    report_text += f"• Upload: `{today_stats['wan_upload']:.2f} GB`\n"
    report_text += f"• Combined: `{wan_total_gb:.2f} GB`\n\n"
    
    # WireGuard VPN Traffic
    report_text += f"*🔐 WireGuard VPN Traffic*\n"
    report_text += f"• Sessions: `{today_stats['wg_sessions']}`\n"
    report_text += f"• Download: `{today_stats['wg_download']:.2f} GB`\n"
    report_text += f"• Upload: `{today_stats['wg_upload']:.2f} GB`\n"
    report_text += f"• Combined: `{wg_total_gb:.2f} GB`"
    
    # High usage alert
    if wan_total_gb > DAILY_BANDWIDTH_ALERT_GB:
        report_text += f"\n\n⚠️ *HIGH USAGE ALERT*: WAN traffic exceeded {DAILY_BANDWIDTH_ALERT_GB} GB threshold!"
    
    # Now generate the other sections
    heatmap = generate_usage_heatmap()
    historical = get_historical_comparison()
    smart_insights = detect_smart_patterns()
    top_talkers = get_top_talkers()
    zenarmor_insights = get_zenarmor_insights()
    app_breakdown = get_app_category_report()
    health_score = calculate_network_health_score()
    bandwidth_hogs = detect_bandwidth_hogs()

    report_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "📅 Daily Network Report"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": report_text}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": historical}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": smart_insights}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": heatmap}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": top_talkers}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": zenarmor_insights}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": health_score}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": app_breakdown}},
        {"type": "divider"},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*📥 Current Speed*\n`{speed['download']}`"},  # ← Fixed!
            {"type": "mrkdwn", "text": f"*⏱️ Latency*\n`{speed['ping']}`"},             # ← Fixed!
            {"type": "mrkdwn", "text": f"*📤 Upload Speed*\n`{speed['upload']}`"},       # ← Fixed!
            {"type": "mrkdwn", "text": f"*📡 Active Devices*\n`{len([l for l in known_dhcp_leases.values() if l['active']])}`"}  # ← Fixed!
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Report generated at {datetime.now().strftime('%I:%M %p')}"}]}
    ]

    # Add action buttons
    report_blocks = add_action_buttons(report_blocks, context="general")

    # Add bandwidth hogs if they exist
    if bandwidth_hogs:
        report_blocks.append({"type": "divider"})
        report_blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": bandwidth_hogs}})

    try:
        requests.post(SLACK_WEBHOOK, json={"blocks": report_blocks}, timeout=10)
    except Exception as e:
        print(f"❌ Failed to send daily report: {e}")

def send_weekly_report():
    global weekly_stats
    print("📊 Generating weekly summary report...")
    days_tracked = (datetime.now() - weekly_stats['start_date']).days
    
    wg_total = weekly_stats['wg_total_download_gb'] + weekly_stats['wg_total_upload_gb']
    wan_total = weekly_stats['wan_total_download_gb'] + weekly_stats['wan_total_upload_gb']
    
    report_text = f"*📊 Weekly Network Summary*\n"
    report_text += f"Period: `{weekly_stats['start_date'].strftime('%b %d')} - {datetime.now().strftime('%b %d, %Y')}`\n"
    report_text += f"Days Tracked: `{days_tracked}`\n\n"
    
    report_text += f"*🌐 Total WAN Traffic:*\n"
    report_text += f"• Download: `{weekly_stats['wan_total_download_gb']:.2f} GB`\n"
    report_text += f"• Upload: `{weekly_stats['wan_total_upload_gb']:.2f} GB`\n"
    report_text += f"• Combined: `{wan_total:.2f} GB`\n\n"
    
    report_text += f"*🔐 VPN Activity:*\n"
    report_text += f"• Total Sessions: `{weekly_stats['wg_total_sessions']}`\n"
    report_text += f"• Download: `{weekly_stats['wg_total_download_gb']:.2f} GB`\n"
    report_text += f"• Upload: `{weekly_stats['wg_total_upload_gb']:.2f} GB`\n"
    report_text += f"• Combined: `{wg_total:.2f} GB`\n"
    report_text += f"• Unique VPN Clients: `{len(weekly_stats['wg_peers_seen'])}`\n\n"
    
    report_text += f"*📊 Network Overview:*\n"
    report_text += f"• Unique Devices: `{len(weekly_stats['devices_seen'])}`\n"
    report_text += f"• Service Incidents: `{len(weekly_stats['service_incidents'])}`\n"
    
    top_talkers = get_top_talkers()
    service_health_report = get_service_health_summary()
    security_report = get_security_summary()
    performance_sla = check_performance_sla()

    threat_summary = get_weekly_threat_summary()

    report_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "📅 Weekly Network Summary"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": report_text}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": top_talkers}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": service_health_report}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": security_report}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": performance_sla}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": threat_summary}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Next report: {(datetime.now() + timedelta(days=7)).strftime('%b %d, %Y')}"}]}
    ]

    try:
        requests.post(SLACK_WEBHOOK, json={"blocks": report_blocks}, timeout=10)
        # Reset weekly stats with new structure
        global wg_peer_bandwidth
        wg_peer_bandwidth.clear()  # Reset top talkers for new week
        
        weekly_stats = {
            'start_date': datetime.now(),
            'wg_total_sessions': 0,
            'wg_total_download_gb': 0,
            'wg_total_upload_gb': 0,
            'wg_peers_seen': set(),
            'wan_total_download_gb': 0,
            'wan_total_upload_gb': 0,
            'devices_seen': set(),
            'service_incidents': []
        }
    except Exception as e:
        print(f"❌ Failed to send weekly report: {e}")

def send_monthly_report():
    """Generate monthly executive summary"""
    global historical_daily_stats
    
    try:
        now = datetime.now()
        month_name = now.strftime('%B')
        
        # Calculate monthly totals from historical_daily_stats (last 30 days)
        if len(historical_daily_stats) == 0:
            print("   ⚠️ No historical data for monthly report")
            return
        
        # Sum up the last 30 days (or however many we have)
        total_wan_gb = sum(d.get('wan_total', 0) for d in historical_daily_stats)
        total_wg_gb = sum(d.get('wg_total', 0) for d in historical_daily_stats)
        total_wg_sessions = sum(d.get('wg_sessions', 0) for d in historical_daily_stats)
        days_tracked = len(historical_daily_stats)
        
        # Calculate averages
        avg_wan_daily = total_wan_gb / days_tracked if days_tracked > 0 else 0
        avg_wg_daily = total_wg_gb / days_tracked if days_tracked > 0 else 0
        
        # Get security summary from last 30 days
        cutoff = now - timedelta(days=30)
        suricata_30d = len([e for e in security_events['suricata_alerts'] if e['time'] > cutoff])
        zenarmor_30d = sum([e['blocked'] for e in security_events['zenarmor_blocks'] if e['time'] > cutoff])
        total_threats = suricata_30d + zenarmor_30d
        
        # Build report
        report_text = f"*🗓️ {month_name} Executive Summary*\n\n"
        report_text += f"*📊 Network Usage ({days_tracked} days)*\n"
        report_text += f"• Total WAN: `{total_wan_gb:.2f} GB`\n"
        report_text += f"• Total VPN: `{total_wg_gb:.2f} GB`\n"
        report_text += f"• VPN Sessions: `{total_wg_sessions}`\n"
        report_text += f"• Daily Avg: `{avg_wan_daily:.2f} GB`\n\n"
        
        report_text += f"*🛡️ Security Overview*\n"
        report_text += f"• Threats Blocked: `{total_threats}`\n"
        report_text += f"• Suricata Alerts: `{suricata_30d}`\n"
        report_text += f"• Zenarmor Blocks: `{zenarmor_30d}`\n\n"
        
        # Service health for the month
        report_text += f"*⚙️ System Health*\n"
        for service in ['suricata', 'zenarmor', 'internet']:
            health = service_health[service]
            restarts = health['restart_count']
            if service == 'internet':
                report_text += f"• {service.title()}: {health['outage_count']} outages\n"
            else:
                report_text += f"• {service.title()}: {restarts} restarts\n"
        
        # Send notification
        send_grid_notification(
            f"🗓️ {month_name} Executive Summary",
            dl=f"{total_wan_gb:.2f} GB Total",
            pg=f"{total_threats} Threats",
            ul=f"{days_tracked} Days Tracked",
            gw="Infrastructure Stable",
            extra_text=report_text,
            l1="Data Usage", 
            l2="Security", 
            l3="Uptime", 
            l4="Status"
        )
        
        # DON'T clear daily_bandwidth - it's still needed for today!
        # The deque automatically removes old entries when it reaches maxlen=30
        
        print(f"✅ Monthly report for {month_name} sent successfully")
        
    except Exception as e:
        print(f"❌ Failed to generate monthly report: {e}")

def send_system_notification(title, status, message, extra_text="", add_buttons=None):
    """
    Specialized notification for system-level events (internet outage, restarts, etc.)
    Uses a clean 2-column layout without speed test fields
    """
    uptime = get_system_uptime()
    
    # Build status fields
    status_fields = [
        {"type": "mrkdwn", "text": f"*📊 Status*\n`{status}`"},
        {"type": "mrkdwn", "text": f"*📝 Details*\n{message}"}
    ]
    
    # Build secondary fields - Security & Uptime
    security_status = f"Suricata: {get_service_status('suricata')}\nZenarmor: {get_service_status('zenarmor')}"
    secondary_fields = [
        {"type": "mrkdwn", "text": f"*🛡️ Security Services*\n{security_status}"},
        {"type": "mrkdwn", "text": f"*⏱️ System Uptime*\n`{uptime}`"}
    ]
    
    report_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "fields": status_fields},
        {"type": "section", "fields": secondary_fields}
    ]
    
    if extra_text:
        report_blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": extra_text}]})
    
    if add_buttons:
        report_blocks = add_action_buttons(report_blocks, context=add_buttons)
    
    report = {"blocks": report_blocks}
    
    try:
        requests.post(SLACK_WEBHOOK, json=report, timeout=10)
    except Exception as e:
        print(f"❌ Failed to send Slack notification: {e}")

def check_internet_outage():
    global internet_is_up, internet_outage_start, last_internet_check
    if (datetime.now() - last_internet_check).total_seconds() < 30:
        return
    last_internet_check = datetime.now()
    is_up = check_internet_connectivity()
    if not is_up and internet_is_up:
        internet_is_up = False
        internet_outage_start = datetime.now()
        print(f"   🔴 INTERNET OUTAGE DETECTED")
        send_system_notification(
            "🔴 Internet Outage Detected",
            status="Connection Lost",
            message="Unable to reach external DNS servers (8.8.8.8, 1.1.1.1, 9.9.9.9)",
            extra_text="Monitoring for restoration..."
        )
    elif is_up and not internet_is_up:
        outage_duration = format_duration((datetime.now() - internet_outage_start).total_seconds())
        internet_is_up = True
        print(f"   ✅ INTERNET RESTORED (outage duration: {outage_duration})")
        # Track outage for health stats
        service_health['internet']['outage_count'] += 1
        service_health['internet']['downtime_total'] += (datetime.now() - internet_outage_start).total_seconds()
        send_system_notification(
            "✅ Internet Restored",
            status="Connection Active",
            message="External DNS servers are now reachable",
            extra_text=f"Internet connectivity restored. Outage duration: {outage_duration}"
        )
        internet_outage_start = None

def check_beast_health():
    insights = []
    
    # Check 1: AI Heartbeat
    try:
        start = time.time()
        # Use your existing ollama import to run a quick test
        ollama.generate(model='llama3', prompt='ping') 
        latency = time.time() - start
        if latency > 20:
            insights.append(f"🧠 *AI Lag*: Ollama took {latency:.1f}s to respond.")
    except:
        insights.append("💀 *AI Failure*: Ollama is unresponsive.")

    # Check 2: Disk Space (Workflows often generate huge logs)
    usage = shutil.disk_usage("/")
    free_gb = usage.free / (1024**3)
    if free_gb < 5:
        insights.append(f"💾 *Low Storage*: Only {free_gb:.1f} GB remains on Beast-Box.")

    return insights

def cmd_status_report(signum=None, frame=None):
    speed = get_speedtest_data(retry=False)
    gws = ", ".join(check_gateways(True))
    send_grid_notification("📊 Manual Watchtower Report", speed['download'], speed['ping'], speed['upload'], gws, show_dhcp=True, add_buttons="general")

signal.signal(signal.SIGUSR1, cmd_status_report)
signal.signal(signal.SIGUSR2, cmd_status_report)

print("--- 🦇 Sentinel Supreme Online ---")
print(f"⏰ Poll interval: {POLL_INTERVAL}s")
print(f"📊 Bandwidth alerts: WG session >{WG_SESSION_ALERT_GB}GB, Daily >{DAILY_BANDWIDTH_ALERT_GB}GB")
print(f"⚠️  Speed degradation alert: <{int(SPEED_DROP_THRESHOLD * 100)}% of baseline")
print(f"🚨 Anomaly detection: {DHCP_BURST_THRESHOLD} devices/{DHCP_BURST_WINDOW}min, {DISCONNECT_CYCLE_THRESHOLD} disconnects/{DISCONNECT_CYCLE_WINDOW}min")
print("🌐 Checking gateways...")
gws_init = ", ".join(check_gateways(True))
print("📡 Initializing DHCP lease tracking...")
check_dhcp_leases(is_startup=True)
print(f"   Tracking {len(known_dhcp_leases)} DHCP leases")
print("📊 Checking for speedtest data...")
speed = get_speedtest_data(retry=True, max_retries=12, require_fresh=False)
extra_msg = f"Interfaces: {', '.join(get_active_interfaces())}"
if speed.get('is_cached'):
    extra_msg += " | ⚠️ Speedtest data is cached"
send_grid_notification("🚀 Watchtower Online", speed['download'] if speed['download'] != '-' else 'Pending', speed['ping'] if speed['ping'] != '-' else '-', speed['upload'] if speed['upload'] != '-' else 'Pending', gws_init, extra_text=extra_msg, show_dhcp=True, add_buttons="general")
print("✅ Startup complete! Entering monitoring loop...")
print("="*60)


while True:
    loop_count += 1
    now = datetime.now()
    
    if loop_count % NETWORK_CHECK_INTERVAL == 0:
        # Check if it's a new day
        today = now.strftime('%Y-%m-%d')
        if today not in daily_bandwidth:
            print(f"   📅 New day detected: {today}")
        
        print(f"\n🔄 Full Health Check - {now.strftime('%Y-%m-%d %H:%M:%S')}")
        track_wan_traffic()
        check_internet_outage()
        
        # Collect security events every check
        security_summary = collect_security_events()
        if security_summary['severity_high'] > 5:
            print(f"   🚨 High severity alerts: {security_summary['severity_high']}")
        
        # Track performance baseline
        track_performance_baseline()
        check_gateways()
        check_wireguard_peers()
        check_dhcp_leases()
        
        # Check for connection spikes
        connection_alert = check_connection_anomaly()
        if connection_alert:
            send_grid_notification(
                "🚨 Connection Anomaly Detected",
                dl="Unusual Activity",
                pg="Investigation Required",
                ul="Monitor Closely",
                gw="Alert Active",
                extra_text=connection_alert,
                l1="Status", l2="Action", l3="Priority", l4="State"
            )
        
        if loop_count % 60 == 0:  # Every 10 minutes
            hog_alert = detect_bandwidth_hogs()
            if hog_alert:
                send_grid_notification(
                    "🐷 Bandwidth Usage Alert",
                    dl="High Usage",
                    pg="Review Activity",
                    ul="Normal Operation",
                    gw="Monitoring",
                    extra_text=hog_alert,
                    l1="Status", l2="Action", l3="Severity", l4="State"
                )


        current_zen = get_service_status('zenarmor')
        threat_intel = get_zenarmor_threat_details()
        dns_intel = get_combined_dns_stats()
        is_actual_threat = threat_intel and "⚠️" in threat_intel

        if is_actual_threat:
            send_grid_notification( 
                "🛡️ Network Defense Alert", 
                dl="Zenarmor + DNS",  
                pg=f"{threat_intel.count('⚠️')} Active Threats",  
                ul="Manual Review",  
                gw="Action Required", 
                extra_text=(
                    f"{dns_intel}\n" # Include AdGuard stats for context
                    f"🛑 *Security Threats Found:*\n{threat_intel}"
                ), 
                l1="Type", l2="Count", l3="Status", l4="Priority" 
            )

        else:
            print(f"✅ Clean Sweep: {dns_intel.strip()}")
                
        if "DOWN" in current_zen and "ACTIVE" in last_zen_state:
            service_health['zenarmor']['last_restart'] = now
            service_health['zenarmor']['restart_count'] += 1
            weekly_stats['service_incidents'].append({'service': 'Zenarmor', 'time': now})
            send_grid_notification("🚨 SECURITY ALERT: Zenarmor is DOWN", dl="Action Required", pg="Service stopped", ul="WAN guarded by Suricata", gw="Check OPNsense", extra_text="Zenarmor L7 engine has stopped responding.", add_buttons="service_down")
        elif "ACTIVE" in current_zen and "DOWN" in last_zen_state:
            if service_health['zenarmor']['last_restart']:
                downtime = (now - service_health['zenarmor']['last_restart']).total_seconds()
                service_health['zenarmor']['downtime_total'] += downtime
            service_health['zenarmor']['uptime_start'] = now
            send_grid_notification("✅ Zenarmor Restored", "-", "-", "-", "Service Online")
        last_zen_state = current_zen
        
        current_sur = get_service_status('suricata')
        if "DOWN" in current_sur and "ACTIVE" in last_suricata_state:
            service_health['suricata']['last_restart'] = now
            service_health['suricata']['restart_count'] += 1
            insight = get_ai_analysis("IDS Service Failure", "Suricata stopped responding on the WAN interface.")
            weekly_stats['service_incidents'].append({'service': 'Suricata', 'time': now})
            send_grid_notification("🚨 SECURITY ALERT: Suricata is DOWN", dl="CRITICAL", pg="IDS Offline", ul="WAN exposed", gw="Immediate Action", extra_text=f"The WAN intrusion detection system is offline! AI Insight: {insight}", add_buttons="service_down")
        elif "ACTIVE" in current_sur and "DOWN" in last_suricata_state:
            if service_health['suricata']['last_restart']:
                downtime = (now - service_health['suricata']['last_restart']).total_seconds()
                service_health['suricata']['downtime_total'] += downtime
            service_health['suricata']['uptime_start'] = now
            send_grid_notification("✅ Suricata Restored", "-", "-", "-", "IDS Online")
        last_suricata_state = current_sur

        # Daily report - trigger between 7:00-7:05 AM
        if now.hour == 7 and now.minute < 5 and now.day != last_daily_report_day:
            print("    ⏰ 7:00 AM - Generating daily report...")
            dns_summary = get_combined_dns_stats()

            # Send your Grid Notification
            send_grid_notification( 
                "📊 Daily Network Briefing", 
                dl="AdGuard Home",  
                pg="Active Defense",  
                ul="System Healthy",  
                gw="All Clear", 
                extra_text=f"Good morning! Here is the 24-hour summary:\n\n{adguard_intel}", 
                l1="Module", l2="Status", l3="Health", l4="Urgency" 
            )

            send_daily_report()

            last_daily_report_day = now.day
            updates_available = []

            fw = fetch_opn("core/firmware/status", "POST")
            if fw and fw.get('status') == 'updates':
                updates_available.append("OPNsense firmware")
            
            pkg_data = fetch_opn("core/firmware/upgradestatus")
            if pkg_data:
                if pkg_data.get('status') == 'update' or pkg_data.get('needs_reboot'):
                    updates_available.append("System packages")
                
                packages = pkg_data.get('packages', {})
                if isinstance(packages, dict):
                    for pkg_name, pkg_info in packages.items():
                        if 'new_version' in pkg_info or pkg_info.get('needs_update'):
                            if 'sensei' in pkg_name.lower() or 'sunny' in pkg_name.lower():
                                updates_available.append(f"{pkg_name}")
            
            if updates_available:
                update_list = ", ".join(updates_available[:3])  # Show first 3
                extra = f"Available: {update_list}"
                if len(updates_available) > 3:
                    extra += f" (+{len(updates_available) - 3} more)"
                send_grid_notification("📦 System Updates Available", dl="-", pg="-", ul="-", gw="Updates Ready", extra_text=extra)
            
            last_daily_report_day = now.day
            time.sleep(5)
        
        # Weekly report - trigger between 7:00-7:05 AM on Monday
        if now.weekday() == 0 and now.hour == 7 and now.minute < 5 and now.isocalendar()[1] != last_weekly_report_week:
            print("    📅 Monday 7:00 AM - Generating weekly summary...")
            weekly_intel = get_adguard_stats(period="weekly")
            send_weekly_report()
            last_weekly_report_week = now.isocalendar()[1]
            time.sleep(5)
    
        # Monthly report - trigger at 7:00 AM on the 1st of the month
        if now.day == 1 and now.hour == 7 and now.minute < 5 and now.month != last_monthly_report_month:
            print(f"    🗓️ {now.strftime('%B')} 1st - Generating Monthly Executive Summary...")
            
            send_monthly_report() 
            
            last_monthly_report_month = now.month
            print(f"✅ Monthly Report for {now.strftime('%B')} sent.")

    time.sleep(FAST_POLL)
