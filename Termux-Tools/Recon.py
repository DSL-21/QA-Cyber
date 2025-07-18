import os
import sys
import socket
import threading
import ipaddress
import concurrent.futures
import time
import signal
import re
import argparse
import subprocess
import struct

# --- ASCII ART LOGO ---
ASCII_LOGO = """
  ____  ____  __    _  _  _  _  ____ 
 (    \\(  __)(  )  / )( \\( \\/ )(  __)
  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) 
 (____/(____)\\____/\\____/(_/\\_)(____)
***************************************
* Copyright 2025, ★DSL★               *
* https://github.com/DSL-21           *
***************************************
"""

# ANSI escape codes for colors and styles in the terminal
COLOR_RESET = "\x1b[0m"
COLOR_BOLD = "\x1b[1m"
COLOR_GREEN = "\x1b[32m"   # Otevřený port / Aktivní host
COLOR_RED = "\x1b[31m"     # Chyba / Neaktivní host
COLOR_YELLOW = "\x1b[33m"  # Upozornění / Vstup
COLOR_CYAN = "\x1b[36m"    # Informace
COLOR_BLUE = "\x1b[34m"    # Průběh
COLOR_MAGENTA = "\x1b[35m" # Detekovaná služba
COLOR_ORANGE = "\x1b[38;5;208m" # Barva pro zranitelnosti
COLOR_PURPLE = "\x1b[35m" # Barva pro webové technologie

# Global variable for shutdown signaling
SHUTDOWN_FLAG = threading.Event()

# Predefined list of common ports
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 135, 139, 143, 161, 162, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5060, 5061, 5432, 5900, 5985, 5986, 6000, 6379, 8000, 8080, 8443, 9000, 9200, 9300, 11211, 17001, 25565, 27017
]
COMMON_PORTS = sorted(list(set(COMMON_PORTS))) # Ensure unique and sorted

# Hardcoded database of known vulnerabilities (very limited for demonstration)
# Format: { "service_name": { "version_regex": "CVE-ID (Popis)" } }
# Using regex for version matching for more flexibility
KNOWN_VULNERABILITIES = {
    "SSH": {
        r"OpenSSH_7\.2p2": "CVE-2016-6210 (User Enumeration)",
        r"OpenSSH_7\.7": "CVE-2018-15473 (User Enumeration)",
        r"OpenSSH_8\.0": "CVE-2019-6111 (SCP client vulnerability)",
        r"Dropbear_2011\.54": "Dropbear 2011.54 (Starší verze, doporučena bezpečnostní kontrola)", 
        r".*": "Obecné SSH zranitelnosti (ověřte konkrétní verzi a konfiguraci)"
    },
    "FTP": {
        r"vsFTPd 2\.3\.4": "Backdoor (CVE-2011-2523)",
        r"ProFTPd 1\.3\.5": "CVE-2015-3306 (Mod_copy RCE)",
        r"MikroTik 6\.49\.2": "MikroTik RouterOS 6.49.2 (Zkontrolujte nedávné zranitelnosti RouterOS)",
        r".*": "Obecné FTP zranitelnosti (ověřte konkrétní verzi a konfiguraci)"
    },
    "HTTP": { 
        r"Apache/2\.4\.49": "CVE-2021-41773 (Path Traversal)",
        r"Apache/2\.4\.50": "CVE-2021-42013 (Path Traversal)",
        r"nginx/1\.13\.9": "CVE-2017-7529 (Integer Overflow)",
        r"Microsoft IIS/7\.5": "CVE-2017-7269 (WebDAV ScStoragePathFromUrl Buffer Overflow)",
        r".*": "Obecné HTTP zranitelnosti (ověřte konkrétní server a verzi)"
    },
    "MySQL": {
        r"5\.6(\.\d+)?": "CVE-2012-2122 (Authentication Bypass)",
        r"5\.7(\.\d+)?": "CVE-2016-6662 (Privilege Escalation)"
    },
    "PostgreSQL": {
        r"9\.3(\.\d+)?": "CVE-2014-0062 (Privilege Escalation)"
    },
    "Redis": {
        r"2\.8(\.\d+)?": "CVE-2015-4335 (Remote Code Execution)",
        r"3\.2(\.\d+)?": "CVE-2016-8339 (Lua Sandbox Escape)"
    },
    "Telnet": {
        r".*": "Slabý protokol (přenos hesel v plaintextu)"
    },
    "SMB": {
        r".*": "Často zranitelné na EternalBlue (MS17-010) pokud neaktualizováno"
    },
    "RDP": {
        r".*": "Často zranitelné na BlueKeep (CVE-2019-0708) pokud neaktualizováno"
    },
    "DNS": {
        r".*": "DNS server (ověřte zranitelnosti cache poisoning, zónových transferů)"
    },
    "WordPress": {
        r".*": "WordPress (Časté zranitelnosti v pluginech/tématech, doporučena aktualizace)"
    },
    "Joomla": {
        r".*": "Joomla (Časté zranitelnosti, doporučena aktualizace)"
    },
    "Drupal": {
        r".*": "Drupal (Časté zranitelnosti, doporučena aktualizace)"
    }
}


# Funkce pro vymazání obrazovky terminálu
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Funkce pro získání vstupu od uživatele
def ask_question(query):
    if SHUTDOWN_FLAG.is_set():
        return "konec"
    print(query, end="")
    try:
        return input().strip()
    except KeyboardInterrupt:
        print(f"\n{COLOR_CYAN}Zachycen Ctrl+C. Ukončuji program...{COLOR_RESET}")
        SHUTDOWN_FLAG.set()
        return "konec"

# Funkce pro získání lokální IP adresy a masky sítě
def get_local_ip_and_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        local_ip = s.getsockname()[0]
        s.close()
        
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        network_address = str(network.network_address)
        prefixlen = str(network.prefixlen)
        return local_ip, network_address, prefixlen
    except Exception as e:
        print(f"{COLOR_YELLOW}[*] Nepodařilo se automaticky zjistit lokální IP. Zadejte prosím síťový rozsah ručně.{COLOR_RESET}")
        return None, None, None

# Funkce pro pingování hostitele a získání TTL
def ping_host(ip_address, timeout_seconds=1):
    if SHUTDOWN_FLAG.is_set():
        return False, None
    
    ttl = None
    try:
        ping_cmd = []
        if os.name == 'nt': # Windows
            ping_cmd = ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), ip_address]
        else: # Linux / Termux
            ping_cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), ip_address]

        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=timeout_seconds + 1, check=False)
        
        if result.returncode == 0: 
            if os.name == 'nt': 
                match = re.search(r'TTL=(\d+)', result.stdout)
            else: 
                match = re.search(r'ttl=(\d+)', result.stdout)
            
            if match:
                ttl = int(match.group(1))
            return True, ttl
        else: 
            return False, None
    except subprocess.TimeoutExpired:
        return False, None
    except Exception as e:
        return False, None

# Funkce pro odhad OS na základě TTL
def get_os_from_ttl(ttl):
    if ttl is None:
        return "N/A"
    
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Router/Starší OS" 
    return "Neznámý"

# Funkce pro skenování aktivních hostitelů v síti pomocí pingu
def scan_active_hosts(ip_range_str, max_workers):
    print(f"{COLOR_CYAN}[*] Provádím skenování aktivních hostitelů (ping) pro {ip_range_str}...{COLOR_RESET}")
    active_hosts = []
    
    try:
        network = ipaddress.ip_network(ip_range_str, strict=False)
    except ValueError as e:
        print(f"{COLOR_RED}[-] Neplatný síťový rozsah: {e}{COLOR_RESET}")
        return []

    hosts_to_scan = [str(ip) for ip in network.hosts()] 
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts_to_scan}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_ip)):
            if SHUTDOWN_FLAG.is_set(): 
                break
            ip = future_to_ip[future]
            try:
                is_alive, ttl = future.result()
                if is_alive:
                    os_guess = get_os_from_ttl(ttl)
                    active_hosts.append({'ip': ip, 'mac': 'N/A (Ping)', 'ttl': ttl, 'os_guess': os_guess}) 
                    print(f"  {COLOR_GREEN}[+] Host nalezen: {ip} (TTL: {ttl}, OS: {os_guess}){COLOR_RESET}")
            except Exception as e:
                pass 
            
            if (i + 1) % 50 == 0 or (i + 1) == len(hosts_to_scan):
                print(f"{COLOR_BLUE}[Průběh Ping Skenu] Zkontrolováno: {i + 1}/{len(hosts_to_scan)} hostitelů{COLOR_RESET}")

    print(f"{COLOR_CYAN}[*] Skenování aktivních hostitelů dokončeno. Nalezeno {len(active_hosts)} aktivních hostitelů.{COLOR_RESET}")
    return active_hosts

# Funkce pro detekci webových technologií
def detect_web_technologies(headers, body):
    technologies = []
    body_lower = body.lower()

    # Headers-based detection
    server_header = headers.get('server', '').lower()
    x_powered_by = headers.get('x-powered-by', '').lower()
    set_cookie = headers.get('set-cookie', '').lower()
    link_header = headers.get('link', '').lower() # For WordPress, etc.

    if "nginx" in server_header:
        technologies.append("Nginx")
    if "apache" in server_header:
        technologies.append("Apache HTTPD")
    if "iis" in server_header:
        technologies.append("Microsoft IIS")
    if "php" in x_powered_by:
        technologies.append("PHP")
    if "asp.net" in x_powered_by:
        technologies.append("ASP.NET")
    if "express" in x_powered_by:
        technologies.append("Express.js")
    if "cloudflare" in server_header or "cloudflare" in headers.get('via', '').lower():
        technologies.append("Cloudflare (CDN/WAF)")
    if "x-generator" in headers: # Common for CMS
        if "wordpress" in headers['x-generator'].lower():
            technologies.append("WordPress")
        elif "joomla" in headers['x-generator'].lower():
            technologies.append("Joomla")
        elif "drupal" in headers['x-generator'].lower():
            technologies.append("Drupal")
    if "x-frame-options" in headers and "deny" in headers['x-frame-options'].lower():
        technologies.append("X-Frame-Options: DENY") # Security header

    # Body-based detection (more robust)
    if "wp-content" in body_lower or "wp-includes" in body_lower or "wordpress" in body_lower or re.search(r'href=["\'][^"\']*wp-content', body_lower):
        if "WordPress" not in technologies: technologies.append("WordPress")
    if "joomla.css" in body_lower or "/media/com_joomla/" in body_lower or "joomla" in body_lower:
        if "Joomla" not in technologies: technologies.append("Joomla")
    if "/sites/default/files/" in body_lower or "drupal.js" in body_lower or "drupal" in body_lower:
        if "Drupal" not in technologies: technologies.append("Drupal")
    if "generator" in body_lower and "wordpress" in body_lower:
        if "WordPress" not in technologies: technologies.append("WordPress")
    if "generator" in body_lower and "joomla" in body_lower:
        if "Joomla" not in technologies: technologies.append("Joomla")
    if "generator" in body_lower and "drupal" in body_lower:
        if "Drupal" not in technologies: technologies.append("Drupal")
    
    # Common JS libraries
    if "jquery.js" in body_lower or "jquery.min.js" in body_lower:
        technologies.append("jQuery")
    if "react.production.min.js" in body_lower or "react-dom.production.min.js" in body_lower:
        technologies.append("React")
    if "vue.js" in body_lower or "vue.min.js" in body_lower:
        technologies.append("Vue.js")
    if "angular.js" in body_lower or "angular.min.js" in body_lower:
        technologies.append("AngularJS") # Older Angular
    if "bootstrap.min.css" in body_lower or "bootstrap.min.js" in body_lower:
        technologies.append("Bootstrap")

    return sorted(list(set(technologies))) # Return unique and sorted technologies

# Funkce pro detekci služby a získání banneru
def get_service_info(sock, port, timeout_ms, host_ip): 
    service_name = "Neznámá"
    service_version = "N/A"
    full_banner = ""
    http_title = None
    web_technologies = []
    
    try:
        sock.settimeout(timeout_ms / 1000.0) 
        
        # --- Specific probes and parsing for common services ---
        if port == 21: # FTP
            sock.send(b"HELP\r\n")
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("220"):
                service_name = "FTP"
                match_vsftpd = re.search(r'\(vsFTPd\s+([\d.]+)\)', full_banner)
                match_proftpd = re.search(r'ProFTPD\s+([\d.]+)', full_banner)
                match_pureftpd = re.search(r'Pure-FTPd\s+([\d.]+)', full_banner)
                match_mikrotik = re.search(r'MikroTik\s+([\d.]+)', full_banner)
                if match_vsftpd:
                    service_version = f"vsFTPd {match_vsftpd.group(1)}"
                elif match_proftpd:
                    service_version = f"ProFTPd {match_proftpd.group(1)}"
                elif match_pureftpd:
                    service_version = f"Pure-FTPd {match_pureftpd.group(1)}"
                elif match_mikrotik:
                    service_version = f"MikroTik {match_mikrotik.group(1)}"
                else:
                    match = re.search(r'220\s+([^\s]+)\s+([\d.]+)', full_banner)
                    if match:
                        service_version = f"{match.group(1).strip()} {match.group(2).strip()}"
        elif port == 22: # SSH
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("SSH-2.0-"):
                service_name = "SSH"
                match_openssh = re.search(r'SSH-2.0-OpenSSH_([\d\.p]+)', full_banner)
                match_dropbear = re.search(r'SSH-2.0-dropbear_([\d\.]+)', full_banner)
                if match_openssh:
                    service_version = f"OpenSSH_{match_openssh.group(1)}"
                elif match_dropbear:
                    service_version = f"Dropbear_{match_dropbear.group(1)}"
                else:
                    parts = full_banner.split(' ')
                    if len(parts) > 0:
                        service_version = parts[0].replace("SSH-2.0-", "")
        elif port == 23: # Telnet
            sock.send(b"\r\n") 
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if "login:" in full_banner or "Telnet" in full_banner or "Welcome" in full_banner:
                service_name = "Telnet"
        elif port == 25: # SMTP
            sock.send(b"HELO example.com\r\n")
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("220"):
                service_name = "SMTP"
                match_postfix = re.search(r'ESMTP\s+Postfix', full_banner)
                match_exim = re.search(r'ESMTP\s+Exim\s+([\d.]+)', full_banner)
                match_sendmail = re.search(r'Sendmail\s+([\d.]+)', full_banner)
                if match_postfix:
                    service_version = "Postfix"
                elif match_exim:
                    service_version = f"Exim {match_exim.group(1)}"
                elif match_sendmail:
                    service_version = f"Sendmail {match_sendmail.group(1)}"
                else:
                    match = re.search(r'ESMTP\s+([^\s]+)', full_banner)
                    if match:
                        service_version = f"{match.group(1).strip()} {match.group(2).strip()}"
        elif port == 53: # DNS (TCP)
            service_name = "DNS"
            full_banner = "N/A (DNS - TCP)"
        elif port == 80 or port == 8080 or port == 8443: # HTTP (non-HTTPS)
            # Use actual host_ip in Host header
            request_line = b"GET / HTTP/1.1\r\nHost: " + host_ip.encode() + b"\r\nUser-Agent: PythonScanner\r\nConnection: close\r\n\r\n"
            sock.send(request_line)
            
            full_response_bytes = b""
            MAX_HTTP_RESPONSE_SIZE = 1024 * 1024 # 1 MB limit for HTTP response
            
            # Add a small delay to allow the server to respond
            time.sleep(0.05) 

            # Read response until no more data or max size reached
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk: # Connection closed by peer or no more data
                        break
                    full_response_bytes += chunk
                    if len(full_response_bytes) > MAX_HTTP_RESPONSE_SIZE:
                        break # Prevent excessive memory usage
            except socket.timeout:
                pass # Timeout, stop reading
            except Exception as e:
                full_banner = f"Chyba čtení HTTP odpovědi: {e}"
                return service_name, service_version, full_banner, http_title, web_technologies

            decoded_http_response = full_response_bytes.decode('utf-8', errors='ignore')
            
            # Parse headers and body from the single, full response
            http_headers = {}
            http_body = ""
            header_end_match = re.search(r'\r\n\r\n', decoded_http_response)
            if header_end_match:
                headers_raw = decoded_http_response[:header_end_match.end()].strip()
                http_body = decoded_http_response[header_end_match.end():].strip()
                
                for line in headers_raw.split('\r\n')[1:]: # Skip status line
                    if ':' in line:
                        key, value = line.split(':', 1)
                        http_headers[key.strip().lower()] = value.strip()
            else:
                http_body = decoded_http_response # If no clear headers, treat all as body

            full_banner = decoded_http_response.split('\n')[0] # First line of response

            if full_banner.startswith("HTTP/"):
                service_name = "HTTP"
                server_header = http_headers.get('server', '')
                if server_header:
                    if "Apache" in server_header:
                        match_version = re.search(r'Apache/([\d.]+)', server_header)
                        service_version = f"Apache/{match_version.group(1)}" if match_version else "Apache"
                    elif "nginx" in server_header:
                        match_version = re.search(r'nginx/([\d.]+)', server_header)
                        service_version = f"Nginx/{match_version.group(1)}" if match_version else "Nginx"
                    elif "IIS" in server_header:
                        match_version = re.search(r'IIS/([\d.]+)', server_header)
                        service_version = f"Microsoft IIS/{match_version.group(1)}" if match_version else "Microsoft IIS"
                    else:
                        service_version = server_header 
                else: 
                    match_http_version = re.search(r'HTTP/([\d.]+)', full_banner)
                    if match_http_version:
                        service_version = f"HTTP/{match_http_version.group(1)}"
            
            # Extract HTTP Title from the parsed body
            title_match = re.search(r'<title>(.*?)</title>', http_body, re.IGNORECASE | re.DOTALL)
            if title_match:
                http_title = title_match.group(1).strip()
                if len(http_title) > 50: 
                    http_title = http_title[:50] + "..."
            
            # Detect web technologies from parsed headers and body
            web_technologies = detect_web_technologies(http_headers, http_body)

        elif port == 443: # HTTPS (limited fingerprinting without SSL/TLS)
            service_name = "HTTPS"
            # We cannot perform a full SSL/TLS handshake without external libraries (like 'ssl' module)
            # or root privileges. Therefore, full web fingerprinting is not possible here.
            # We'll try to read a small initial banner, but expect connection resets.
            try:
                # Attempt to read a small amount of data, but don't expect a full HTTP response
                data = sock.recv(1024) 
                full_banner = data.decode('utf-8', errors='ignore').strip()
                if full_banner:
                    full_banner = full_banner.split('\n')[0]
                    if len(full_banner) > 100:
                        full_banner = full_banner[:100] + "..."
                else:
                    full_banner = "Žádná odpověď (očekává se SSL/TLS)"
            except socket.timeout:
                full_banner = "Timeout (očekává se SSL/TLS)"
            except Exception as e:
                full_banner = f"Chyba banneru: {e} (očekává se SSL/TLS)"
            
            # Set a clear message for web technologies and title for HTTPS
            http_title = "N/A (Vyžaduje SSL/TLS)"
            web_technologies = ["HTTPS (Vyžaduje SSL/TLS pro plný fingerprinting)"]

        elif port == 110: # POP3
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("+OK"):
                service_name = "POP3"
                match = re.search(r'\+OK\s+([^\s]+)\s+([\d.]+)', full_banner)
                if match:
                    service_version = f"{match.group(1).strip()} {match.group(2).strip()}"
        elif port == 143: # IMAP
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("* OK"):
                service_name = "IMAP"
                match = re.search(r'\* OK\s+([^\s]+)\s+([\d.]+)', full_banner)
                if match:
                    service_version = f"{match.group(1).strip()} {match.group(2).strip()}"
        elif port == 135: # MS RPC / EPMAP
            service_name = "MS RPC/EPMAP"
            full_banner = "N/A (MS RPC)"
        elif port == 139: # NetBIOS Session Service
            service_name = "NetBIOS-SSN"
            full_banner = "N/A (NetBIOS)"
        elif port == 445: # SMB
            service_name = "SMB"
            full_banner = "N/A (SMB)"
        elif port == 3306: # MySQL
            data = sock.recv(4096)
            if data and len(data) >= 5 and data[4] == 0x0a: 
                service_name = "MySQL"
                null_byte_index = data.find(b'\x00', 5)
                if null_byte_index != -1:
                    server_version = data[5:null_byte_index].decode('utf-8', errors='ignore')
                    service_version = server_version
        elif port == 5432: # PostgreSQL
            data = sock.recv(4096)
            if data:
                service_name = "PostgreSQL"
        elif port == 3389: # RDP
            service_name = "RDP"
            full_banner = "N/A (RDP)"
        elif port == 5900: # VNC
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("RFB 0"):
                service_name = "VNC"
                match = re.search(r'RFB\s+(\d+\.\d+)', full_banner)
                if match:
                    service_version = match.group(1)
        elif port == 6379: # Redis
            sock.send(b"INFO\r\n")
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner.startswith("$"): # RESP protokol
                service_name = "Redis"
                match = re.search(r'redis_version:([\d.]+)', full_banner)
                if match:
                    service_version = match.group(1)
        elif port == 27017: # MongoDB
            data = sock.recv(4096)
            if data:
                service_name = "MongoDB"
        elif port == 389 or port == 636: # LDAP
            service_name = "LDAP"
            full_banner = "N/A (LDAP)"
        elif port == 161 or port == 162: # SNMP (TCP)
            service_name = "SNMP"
            full_banner = "N/A (SNMP - TCP)"
        elif port == 1433: # MSSQL
            data = sock.recv(4096)
            if data:
                service_name = "MSSQL"
        elif port == 1521: # Oracle
            data = sock.recv(4096)
            if data:
                service_name = "Oracle DB"
        elif port == 25565: # Minecraft
            data = sock.recv(4096)
            if data:
                service_name = "Minecraft Server"
        # --- End of specific probes ---
        else: # Generic banner grabbing for other TCP ports
            data = sock.recv(4096)
            full_banner = data.decode('utf-8', errors='ignore').strip()
            if full_banner:
                service_name = "Generický TCP"
    except socket.timeout:
        full_banner = "Timeout při čtení banneru"
    except Exception as e:
        full_banner = f"Chyba banneru: {e}"
    
    display_banner = full_banner.split('\n')[0]
    if len(full_banner.split('\n')) > 1:
        display_banner += "..."
    if len(display_banner) > 100:
        display_banner = display_banner[:100] + "..."

    return service_name, service_version, display_banner, http_title, web_technologies

# Funkce pro kontrolu známých zranitelností
def check_vulnerabilities(service_name, service_version, web_technologies):
    vulnerabilities = []

    # Check for service-specific vulnerabilities
    if service_name in KNOWN_VULNERABILITIES:
        specific_vuln_found_for_service = False
        for version_regex, vuln_info in KNOWN_VULNERABILITIES[service_name].items():
            if version_regex == r".*":
                continue # Handle generic case later
            
            # If a specific version is detected and matches regex
            if service_version != "N/A" and re.match(version_regex, service_version):
                if vuln_info not in vulnerabilities:
                    vulnerabilities.append(vuln_info)
                    specific_vuln_found_for_service = True

        # After checking all specific versions, add generic if no specific one was found for this service
        if not specific_vuln_found_for_service and r".*" in KNOWN_VULNERABILITIES[service_name]:
            generic_vuln_info = KNOWN_VULNERABILITIES[service_name][r".*"]
            if generic_vuln_info not in vulnerabilities:
                vulnerabilities.append(generic_vuln_info)

    # Check for web technology vulnerabilities (these are typically generic for the tech itself)
    for tech in web_technologies:
        if tech in KNOWN_VULNERABILITIES:
            for version_regex, vuln_info in KNOWN_VULNERABILITIES[tech].items():
                # Web tech vulnerabilities are usually generic (regex ".*")
                if version_regex == r".*": 
                    if vuln_info not in vulnerabilities: # Avoid duplicates
                        vulnerabilities.append(vuln_info)
    
    return vulnerabilities if vulnerabilities else None

# Funkce pro skenování jednoho portu
def scan_port(host, port, timeout_ms):
    if SHUTDOWN_FLAG.is_set(): 
        return {'port': port, 'status': 'Aborted', 'service': 'N/A', 'version': 'N/A', 'banner': 'Sken přerušen', 'vulnerability': None, 'http_title': None, 'web_tech': []}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_ms / 1000.0) 
        result = sock.connect_ex((host, port)) 

        if result == 0:
            # get_service_info now returns http_title and web_technologies directly
            service_name, service_version, display_banner, http_title, web_technologies = get_service_info(sock, port, timeout_ms, host) # Předáváme host_ip
            vulnerability_info = check_vulnerabilities(service_name, service_version, web_technologies)
            
            return {'port': port, 'status': 'Open', 'service': service_name, 'version': service_version, 'banner': display_banner, 'vulnerability': vulnerability_info, 'http_title': http_title, 'web_tech': web_technologies}
        elif result == 111: 
            return {'port': port, 'status': 'Closed', 'service': 'N/A', 'version': 'N/A', 'banner': 'N/A', 'vulnerability': None, 'http_title': None, 'web_tech': []}
        elif result == 110: 
            return {'port': port, 'status': 'Filtered (Timeout)', 'service': 'N/A', 'version': 'N/A', 'banner': 'N/A', 'vulnerability': None, 'http_title': None, 'web_tech': []}
        else:
            return {'port': port, 'status': f'Unknown Error ({result})', 'service': 'N/A', 'version': 'N/A', 'banner': 'N/A', 'vulnerability': None, 'http_title': None, 'web_tech': []}
    except Exception as e:
        return {'port': port, 'status': f'Scan Error ({e})', 'service': 'N/A', 'version': 'N/A', 'banner': 'N/A', 'vulnerability': None, 'http_title': None, 'web_tech': []}
    finally:
        if 'sock' in locals() and sock:
            sock.close()

# Funkce pro získání platného celého čísla od uživatele
def get_valid_int_input(prompt, min_val=1, max_val=65535):
    while True:
        user_input = ask_question(prompt)
        if SHUTDOWN_FLAG.is_set(): 
            return -1 
        try:
            value = int(user_input)
            if min_val <= value <= max_val:
                return value
            else:
                print(f"{COLOR_RED}[-] Neplatná hodnota. Zadejte číslo mezi {min_val} a {max_val}.{COLOR_RESET}")
        except ValueError:
            print(f"{COLOR_RED}[-] Neplatný vstup. Zadejte prosím číslo.{COLOR_RESET}")

# Nová funkce pro formátování seznamu portů pro zobrazení
def format_port_list_display(ports_list, is_common_ports_flag):
    if is_common_ports_flag:
        return "Předdefinovaný seznam běžných portů"
    
    if not ports_list:
        return "Žádné porty"

    # Zkontrolovat, zda se jedná o souvislý rozsah
    if len(ports_list) > 1 and all(ports_list[i] == ports_list[i-1] + 1 for i in range(1, len(ports_list))):
        return f"{ports_list[0]}-{ports_list[-1]}"
    
    # Pokud je seznam malý (<= 10 portů), zobrazit všechny
    if len(ports_list) <= 10: 
        return ', '.join(map(str, ports_list))
    
    # Jinak zobrazit pouze počet portů
    return f"Vlastní seznam portů ({len(ports_list)} portů)"

# Hlavní funkce programu
def main():
    # Nastavení handleru pro Ctrl+C
    def signal_handler(sig, frame):
        print(f"\n{COLOR_CYAN}Zachycen Ctrl+C. Ukončuji program...{COLOR_RESET}")
        SHUTDOWN_FLAG.set() 

    signal.signal(signal.SIGINT, signal_handler)

    # Argument parser setup
    parser = argparse.ArgumentParser(description=f"{COLOR_BOLD}Pokročilý Síťový Průzkumník (Python){COLOR_RESET}",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--range', type=str, help='Síťový rozsah pro ping sken (např. 192.168.1.0/24)')
    parser.add_argument('--ports', type=str, 
                        help='Rozsah portů pro skenování (např. "1-1024"),\n'
                             'jednotlivý port (např. "80"),\n'
                             'nebo čárkou oddělený seznam (např. "21,22,80,443").')
    parser.add_argument('--common-ports', action='store_true', 
                        help='Skenovat předdefinovaný seznam běžných portů.')
    parser.add_argument('--timeout', type=int, help='Časový limit na port v milisekundách (např. 500)')
    parser.add_argument('--workers', type=int, help='Počet souběžných skenů/vláken (např. 100)')
    
    args = parser.parse_args()

    clear_screen()
    print(ASCII_LOGO)
    print(f"\n{COLOR_BOLD}--- Pokročilý Síťový Průzkumník (Python) ---{COLOR_RESET}")
    print("Tento nástroj provádí ping skenování pro objevení hostitelů a následné skenování portů.")
    print(f"{COLOR_YELLOW}[*] Nevyžaduje root oprávnění.{COLOR_RESET}")
    print("Pro ukončení zadejte 'konec' nebo stiskněte Ctrl+C.")
    
    # Try to get parameters from arguments, otherwise ask interactively
    ip_range = args.range
    ports_to_scan = []
    timeout_ms = args.timeout
    max_workers = args.workers
    is_common_ports_selected = args.common_ports # Nová proměnná pro sledování, zda byly vybrány běžné porty

    if is_common_ports_selected:
        ports_to_scan = sorted(COMMON_PORTS)
        print(f"\n{COLOR_CYAN}[*] Používám předdefinovaný seznam běžných portů.{COLOR_RESET}") # Zkrácený výpis
    elif args.ports:
        try:
            if '-' in args.ports: # Range like "1-1024"
                port_parts = args.ports.split('-')
                if len(port_parts) == 2:
                    start_p = int(port_parts[0])
                    end_p = int(port_parts[1])
                    if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
                        raise ValueError("Neplatný rozsah portů.")
                    ports_to_scan = list(range(start_p, end_p + 1))
                else:
                    raise ValueError("Neplatný formát rozsahu portů. Použijte např. '1-1024'.")
            elif ',' in args.ports: # Comma-separated list like "21,22,80"
                ports_str_list = args.ports.split(',')
                for p_str in ports_str_list:
                    p = int(p_str.strip())
                    if not (1 <= p <= 65535):
                        raise ValueError(f"Neplatné číslo portu: {p}")
                    ports_to_scan.append(p)
                ports_to_scan = sorted(list(set(ports_to_scan))) # Remove duplicates and sort
            else: # Single port like "80"
                p = int(args.ports.strip())
                if not (1 <= p <= 65535):
                    raise ValueError(f"Neplatné číslo portu: {p}")
                ports_to_scan = [p]
            
            if not ports_to_scan: # If parsing resulted in an empty list
                raise ValueError("Nebyly zadány žádné platné porty.")

        except ValueError as e:
            print(f"{COLOR_RED}[-] Chyba v argumentu --ports: {e}. Zadejte prosím platný formát.{COLOR_RESET}")
            ports_to_scan = [] # Reset, aby se zeptal interaktivně
    
    # Main loop for interactive input or running with args
    while not SHUTDOWN_FLAG.is_set():
        # Interactive input if arguments not provided
        if not ip_range:
            local_ip, network_address, prefix_len = get_local_ip_and_subnet()
            default_ip_range = f"{network_address}/{prefix_len}" if local_ip else ""
            ip_range = ask_question(f"\n{COLOR_YELLOW}Zadejte síťový rozsah pro ping sken (např. 192.168.1.0/24, výchozí: {default_ip_range}): {COLOR_RESET}")
            if SHUTDOWN_FLAG.is_set(): break
            if ip_range == "":
                ip_range = default_ip_range
            
            if ip_range.lower() == 'konec':
                print(f"{COLOR_CYAN}Ukončuji nástroj. Na shledanou!{COLOR_RESET}")
                break

            if not ip_range:
                print(f"{COLOR_RED}[-] Síťový rozsah nemůže být prázdný. Zkuste to znovu.{COLOR_RESET}")
                ask_question(f"\n{COLOR_YELLOW}Stiskněte Enter pro pokračování...{COLOR_RESET}")
                if SHUTDOWN_FLAG.is_set(): break
                continue

        if not ports_to_scan: # If ports were not provided via args or parsing failed
            port_choice = ask_question(f"{COLOR_YELLOW}Zadejte rozsah portů (např. 1-1024), jednotlivý port (např. 80),\n"
                                       f"nebo čárkou oddělený seznam (např. 21,22,80,443), nebo 'common' pro běžné porty: {COLOR_RESET}")
            if SHUTDOWN_FLAG.is_set(): break
            if port_choice.lower() == 'konec':
                print(f"{COLOR_CYAN}Ukončuji nástroj. Na shledanou!{COLOR_RESET}")
                break
            
            if port_choice.lower() == 'common':
                ports_to_scan = sorted(COMMON_PORTS)
                is_common_ports_selected = True # Set flag for interactive choice
            elif '-' in port_choice:
                try:
                    port_parts = port_choice.split('-')
                    if len(port_parts) == 2:
                        start_p = int(port_parts[0])
                        end_p = int(port_parts[1])
                        if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
                            raise ValueError("Neplatný rozsah portů.")
                        ports_to_scan = list(range(start_p, end_p + 1))
                    else:
                        raise ValueError("Neplatný formát rozsahu portů. Použijte např. '1-1024'.")
                except ValueError as e:
                    print(f"{COLOR_RED}[-] Chyba v zadání portů: {e}. Zkuste to znovu.{COLOR_RESET}")
                    ports_to_scan = [] # Reset for re-prompt
                    continue
            elif ',' in port_choice:
                try:
                    ports_str_list = port_choice.split(',')
                    for p_str in ports_str_list:
                        p = int(p_str.strip())
                        if not (1 <= p <= 65535):
                            raise ValueError(f"Neplatné číslo portu: {p}")
                        ports_to_scan.append(p)
                    ports_to_scan = sorted(list(set(ports_to_scan)))
                except ValueError as e:
                    print(f"{COLOR_RED}[-] Chyba v zadání portů: {e}. Zkuste to znovu.{COLOR_RESET}")
                    ports_to_scan = [] # Reset for re-prompt
                    continue
            else: # Single port
                try:
                    p = int(port_choice.strip())
                    if not (1 <= p <= 65535):
                        raise ValueError(f"Neplatné číslo portu: {p}")
                    ports_to_scan = [p]
                except ValueError as e:
                    print(f"{COLOR_RED}[-] Neplatné zadání portu. Zadejte číslo, rozsah, seznam nebo 'common'.{COLOR_RESET}")
                    ports_to_scan = [] # Reset for re-prompt
                    continue
            
            if not ports_to_scan: # If interactive parsing resulted in empty list
                print(f"{COLOR_RED}[-] Nebyly zadány žádné platné porty. Zkuste to znovu.{COLOR_RESET}")
                continue # Loop again

        if timeout_ms is None:
            timeout_ms = get_valid_int_input(f"{COLOR_YELLOW}Zadejte časový limit na port (v milisekundách, např. 500): {COLOR_RESET}", 1)
            if SHUTDOWN_FLAG.is_set(): break
        if max_workers is None:
            max_workers = get_valid_int_input(f"{COLOR_YELLOW}Zadejte počet souběžných skenů (vláken, např. 100): {COLOR_RESET}", 1)
            if SHUTDOWN_FLAG.is_set(): break

        formatted_ports_display = format_port_list_display(ports_to_scan, is_common_ports_selected)

        print(f"\n{COLOR_CYAN}[*] Spouštím průzkum sítě pro: {ip_range}{COLOR_RESET}")
        print(f"{COLOR_CYAN}[*] Rozsah portů: {formatted_ports_display}{COLOR_RESET}")
        print(f"{COLOR_CYAN}[*] Souběžná vlákna: {max_workers}{COLOR_RESET}")
        print(f"{COLOR_CYAN}[*] Časový limit na port: {timeout_ms} ms{COLOR_RESET}")
        print(f"{COLOR_YELLOW}[*] Pro ukončení stiskněte Ctrl+C.{COLOR_RESET}")

        # Phase 1: Scan active hosts (ping)
        active_hosts = scan_active_hosts(ip_range, max_workers)
        if SHUTDOWN_FLAG.is_set(): break

        if not active_hosts:
            print(f"{COLOR_YELLOW}[*] V daném rozsahu nebyly nalezeny žádné aktivní hostitelé (nereagují na ping). Zkuste jiný rozsah nebo zkontrolujte, zda hostitelé blokují ping.{COLOR_RESET}")
            ask_question(f"\n{COLOR_YELLOW}Stiskněte Enter pro nové skenování, nebo 'konec'...{COLOR_RESET}")
            if SHUTDOWN_FLAG.is_set(): break
            # Reset arguments for next loop if interactive
            ip_range = None
            ports_to_scan = []
            timeout_ms = None
            max_workers = None
            is_common_ports_selected = False
            continue

        # Phase 2: Port scanning on active hosts
        print(f"\n{COLOR_BOLD}--- Skenování portů na nalezených hostitelích ---{COLOR_RESET}")
        
        all_open_ports = {}
        total_ports_to_scan = len(active_hosts) * len(ports_to_scan) 
        completed_ports_count = 0
        
        # Progress bar
        def update_progress():
            nonlocal completed_ports_count
            while completed_ports_count < total_ports_to_scan and not SHUTDOWN_FLAG.is_set():
                time.sleep(2) 
                if completed_ports_count > 0:
                    print(f"{COLOR_BLUE}[Průběh Port Skenu] Skenováno: {completed_ports_count}/{total_ports_to_scan} portů{COLOR_RESET}")
        
        progress_thread = threading.Thread(target=update_progress)
        progress_thread.daemon = True 
        progress_thread.start()

        for host_info in active_hosts:
            if SHUTDOWN_FLAG.is_set(): break 
            host_ip = host_info['ip']
            host_os_guess = host_info['os_guess']
            host_ttl = host_info['ttl']
            print(f"\n{COLOR_CYAN}[*] Skenuji porty na hostiteli: {host_ip} (OS: {host_os_guess}, TTL: {host_ttl}){COLOR_RESET}")
            
            host_open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {executor.submit(scan_port, host_ip, port, timeout_ms): port for port in ports_to_scan} 
                for future in concurrent.futures.as_completed(future_to_port):
                    if SHUTDOWN_FLAG.is_set(): 
                        executor.shutdown(wait=False, cancel_futures=True) 
                        break
                    port_result = future.result()
                    completed_ports_count += 1
                    if port_result['status'] == 'Open':
                        host_open_ports.append(port_result)
                        status_line = f"  {COLOR_GREEN}[+] Port {port_result['port']} je otevřený!{COLOR_RESET}"
                        if port_result.get('service') and port_result['service'] != "Neznámá":
                            status_line += f" {COLOR_MAGENTA}Služba: {port_result['service']}"
                            if port_result.get('version') and port_result['version'] != "N/A":
                                status_line += f" ({port_result['version']}){COLOR_RESET}"
                            else:
                                status_line += f"{COLOR_RESET}"
                        if port_result.get('vulnerability'): # Zranitelnost
                            # Handle multiple vulnerabilities if present
                            for vuln in port_result['vulnerability']:
                                status_line += f" {COLOR_ORANGE}[!] Možná zranitelnost: {vuln}{COLOR_RESET}"
                        if port_result.get('http_title'): # HTTP Titul
                            status_line += f" {COLOR_CYAN}[Titul]: '{port_result['http_title']}'{COLOR_RESET}"
                        if port_result.get('web_tech'): # Web Technologies
                            status_line += f" {COLOR_PURPLE}[Web Tech]: {', '.join(port_result['web_tech'])}{COLOR_RESET}"
                        if port_result.get('banner') and port_result['banner'] != "N/A":
                            status_line += f" {COLOR_MAGENTA}Banner: '{port_result['banner']}'{COLOR_RESET}"
                        print(status_line)

            if not host_open_ports:
                print(f"  {COLOR_YELLOW}[*] Na hostiteli {host_ip} nebyly nalezeny žádné otevřené porty v rozsahu {formatted_ports_display}.{COLOR_RESET}")
            else:
                all_open_ports[host_ip] = host_open_ports
        
        # Stop progress bar thread
        completed_ports_count = total_ports_to_scan 
        if progress_thread.is_alive(): 
            progress_thread.join(timeout=3) 

        if SHUTDOWN_FLAG.is_set(): break 

        print(f"\n{COLOR_BOLD}--- Shrnutí skenování ---{COLOR_RESET}")
        if not all_open_ports:
            print(f"{COLOR_YELLOW}[*] Žádné otevřené porty nebyly nalezeny na žádném aktivním hostiteli.{COLOR_RESET}")
        else:
            for host_ip, ports in all_open_ports.items():
                host_info_summary = next((h for h in active_hosts if h['ip'] == host_ip), None)
                os_summary = f" (OS: {host_info_summary['os_guess']}, TTL: {host_info_summary['ttl']})" if host_info_summary and host_info_summary['ttl'] else ""
                print(f"\n{COLOR_GREEN}[+] Otevřené porty na hostiteli {host_ip}{os_summary}:{COLOR_RESET}")
                for p in sorted(ports, key=lambda x: x['port']):
                    status_line = f"  - Port {p['port']} ({p['status']})"
                    if p.get('service') and p['service'] != "Neznámá":
                        status_line += f" {COLOR_MAGENTA}Služba: {p['service']}"
                        if p.get('version') and p['version'] != "N/A":
                            status_line += f" ({p['version']}){COLOR_RESET}"
                        else:
                            status_line += f"{COLOR_RESET}"
                    if p.get('vulnerability'): # Zranitelnost
                        # Handle multiple vulnerabilities if present
                        for vuln in p['vulnerability']:
                            status_line += f" {COLOR_ORANGE}[!] Možná zranitelnost: {vuln}{COLOR_RESET}"
                    if p.get('http_title'): # HTTP Titul
                        status_line += f" {COLOR_CYAN}[Titul]: '{p['http_title']}'{COLOR_RESET}"
                    if p.get('web_tech'): # Web Technologies
                        status_line += f" {COLOR_PURPLE}[Web Tech]: {', '.join(p['web_tech'])}{COLOR_RESET}"
                    if p.get('banner') and p['banner'] != "N/A":
                        status_line += f" {COLOR_MAGENTA}Banner: '{p['banner']}'{COLOR_RESET}"
                    print(status_line)
        
        print(f"{COLOR_RESET}\n{'=' * (os.get_terminal_size().columns if sys.stdout.isatty() else 80)}")

        final_input = ask_question(f"\n{COLOR_YELLOW}Stiskněte Enter pro nové skenování, nebo 'konec'...{COLOR_RESET}")
        if SHUTDOWN_FLAG.is_set() or final_input.lower() == 'konec':
            print(f"{COLOR_CYAN}Ukončuji nástroj. Na shledanou!{COLOR_RESET}")
            break

# Spuštění hlavní funkce
if __name__ == "__main__":
    main()
