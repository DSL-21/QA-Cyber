import requests
from bs4 import BeautifulSoup, Comment # Import Comment pro detekci HTML komentářů
import re
import os
import sys
import time
from urllib.parse import urljoin, urlparse
from collections import deque # Pro správu fronty URL pro skenování
import socket # Pro získání IP adresy
import json # Pro zpracování JSON z Wayback Machine API

# --- VAŠE ASCII ART LOGO ---
ascii_logo = (
    "  ____  ____  __    _  _  _  _  ____ \n"
    " (    \\(  __)(  )  / )( \\( \\/ )(  __)\n"
    "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n"
    " (____/(____)\\____/\\____/(_/\\_)(____)\n"
    "***************************************\n"
    "* Copyright 2025, ★DSL★               *\n"
    "* https://github.com/DSL-21           *\n"
    "***************************************"
)

# ANSI escape kódy pro barvy a styly v terminálu
# \033[1m - Bold (tučné)
# \033[0m - Reset (resetuje styl na výchozí)
# \033[32m - Zelená barva (úspěch/nalezeno)
# \033[33m - Žlutá barva (upozornění)
# \033[31m - Červená barva (chyba)
# \033[36m - Azurová barva (hlavičky)
# \033[35m - Purpurová barva (meta tagy)
# \033[34m - Modrá barva (hloubka/komentáře/API/chyby)
# \033[38;5;208m - Oranžová barva (technologie)
# \033[38;5;198m - Růžová barva (externí OSINT)

# Globální seznam pro sledování navštívených URL, aby se zabránilo nekonečným smyčkám
visited_urls = set()
# Globální proměnná pro crawl-delay
global_crawl_delay = 3 # Výchozí hodnota

def clear_screen():
    """Vymaže obrazovku terminálu."""
    os.system('clear' if os.name == 'posix' else 'cls')

def get_crawl_delay_from_robots(robots_text):
    """
    Analyzuje text robots.txt a pokusí se najít crawl-delay.
    """
    crawl_delay_match = re.search(r'Crawl-delay:\s*(\d+)', robots_text, re.IGNORECASE)
    if crawl_delay_match:
        return int(crawl_delay_match.group(1))
    return 0 # Není explicitně specifikováno

def check_robots_txt(base_url):
    """
    Zkontroluje soubor robots.txt pro danou URL a vypíše jeho obsah.
    """
    global global_crawl_delay
    robots_url = base_url.rstrip('/') + '/robots.txt'
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            print(f"\n{os.linesep}\033[1m--- Obsah robots.txt ---\033[0m")
            print(response.text)
            print("------------------------")
            
            delay = get_crawl_delay_from_robots(response.text)
            if delay > 0:
                global_crawl_delay = delay
                print(f"\n\033[33m[*] robots.txt doporučuje Crawl-delay: {global_crawl_delay} sekund.\033[0m")
            else:
                print("\n[*] robots.txt nedoporučuje specifický Crawl-delay. Používám výchozí 3 sekundy.")
                global_crawl_delay = 3
            return True
        else:
            print(f"\n[*] robots.txt nenalezen nebo nedostupný (Status: {response.status_code})")
            global_crawl_delay = 3
            return False
    except requests.exceptions.RequestException as e:
        print(f"\n[*] Nepodařilo se získat robots.txt: {e}")
        global_crawl_delay = 3
        return False

def identify_technologies(url, response_headers, soup, response_text, all_found_data):
    """
    Identifikuje webové technologie na základě hlaviček, HTML obsahu a URL.
    """
    
    # Z HTTP hlaviček
    server_header = response_headers.get('Server')
    if server_header:
        all_found_data['technologies']['Web Server'] = server_header
    
    x_powered_by_header = response_headers.get('X-Powered-By')
    if x_powered_by_header:
        all_found_data['technologies']['Powered By'] = x_powered_by_header

    # Z meta tagů (již sbíráme)
    if 'generator' in all_found_data['meta_tags']:
        all_found_data['technologies']['CMS/Generator'] = all_found_data['meta_tags']['generator']

    # Z HTML obsahu a URL (pro CMS a JS Frameworky)
    
    # WordPress detekce a verze
    wp_version_match = re.search(r'wp-includes/js/dist/vendor/wp-polyfill-fetch\.min\.js\?ver=([0-9.]+)', response_text)
    if wp_version_match:
        all_found_data['technologies']['CMS'] = f'WordPress {wp_version_match.group(1)}'
    elif soup.find('link', rel='stylesheet', href=re.compile(r'/wp-(content|includes)/')) or \
         soup.find('script', src=re.compile(r'/wp-(includes|content)/')):
        all_found_data['technologies']['CMS'] = 'WordPress (verze nezjištěna)'
    
    # Joomla detekce a verze
    joomla_meta = soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Joomla! (\d+\.\d+\.\d+)', re.IGNORECASE)})
    if joomla_meta:
        all_found_data['technologies']['CMS'] = f"Joomla! {joomla_meta['content']}"
    elif soup.find('script', src=re.compile(r'/media/system/js/joomla.js')):
        all_found_data['technologies']['CMS'] = 'Joomla! (verze nezjištěna)'

    # Drupal detekce a verze
    drupal_meta = soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Drupal (\d+\.\d+)', re.IGNORECASE)})
    if drupal_meta:
        all_found_data['technologies']['CMS'] = f"Drupal {drupal_meta['content']}"
    elif soup.find('link', href=re.compile(r'/sites/default/files/')):
        all_found_data['technologies']['CMS'] = 'Drupal (verze nezjištěna)'

    # Cloudflare CDN
    if 'cloudflare' in response_headers.get('Server', '').lower() or \
       '__cf_bm' in response_headers.get('Set-Cookie', ''):
        all_found_data['technologies']['CDN'] = 'Cloudflare'

    # Google Analytics
    if re.search(r'ga\.js|analytics\.js|gtag\.js|googletagmanager\.com/gtag/js', response_text):
        all_found_data['technologies']['Analytics'] = 'Google Analytics'

    # Google Fonts
    if soup.find('link', href=re.compile(r'fonts\.googleapis\.com|fonts\.gstatic\.com')):
        all_found_data['technologies']['Fonts'] = 'Google Fonts'

    # Font Awesome
    if soup.find('link', href=re.compile(r'fontawesome\.com')) or \
       soup.find('i', class_=re.compile(r'fa[srlb]? fa-')): # Hledá ikony Font Awesome
        all_found_data['technologies']['Icons'] = 'Font Awesome'

    # jQuery
    if re.search(r'jQuery|jquery\.js', response_text, re.IGNORECASE):
        # Pokus o detekci verze jQuery z kódu
        jquery_version_match = re.search(r'jQuery JavaScript Library v([0-9.]+)', response_text)
        if jquery_version_match:
            all_found_data['technologies']['JavaScript Library'] = f'jQuery {jquery_version_match.group(1)}'
        else:
            all_found_data['technologies']['JavaScript Library'] = 'jQuery'

    # React (základní detekce)
    if re.search(r'ReactDOM|react-dom\.production\.min\.js|data-reactroot', response_text):
        all_found_data['technologies']['JavaScript Framework'] = 'React'

    # Vue.js (základní detekce)
    if re.search(r'Vue\.js|vue\.min\.js|id="app"|data-v-', response_text):
        all_found_data['technologies']['JavaScript Framework'] = 'Vue.js'

    # Angular (základní detekce)
    if re.search(r'ng-app|angular\.js|data-ng-app', response_text):
        all_found_data['technologies']['JavaScript Framework'] = 'Angular'


def extract_info_from_page(url, response_headers, soup, response_text, all_found_data, scan_choices):
    """
    Extrahuje různé typy informací z BeautifulSoup objektu a textu odpovědi.
    """
    
    # --- Extrakce e-mailových adres ---
    if scan_choices['emails']:
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        found_emails = set(re.findall(email_pattern, response_text))
        for email in found_emails:
            all_found_data['emails'].add(email)

    # --- Extrakce telefonních čísel ---
    if scan_choices['phones']:
        # Vylepšený regex pro telefonní čísla: zahrnuje více mezinárodních předpon a formátů
        # Přidáno více variant oddělovačů, volitelné předvolby země
        phone_pattern = r'(?:\+\d{1,4}[ -]?)?(?:\(\d{1,4}\)[ -]?)?\d{1,4}[ -]?\d{1,4}[ -]?\d{1,4}(?:[ -]?\d{1,4})?'
        found_phones = set(re.findall(phone_pattern, soup.get_text()))
        
        cleaned_phones = set()
        for phone in found_phones:
            digits = re.sub(r'\D', '', phone) # Odstraní vše kromě číslic
            # Filtrovat čísla, která jsou příliš krátká nebo příliš dlouhá
            if 7 <= len(digits) <= 15: # Typická délka telefonních čísel
                cleaned_phones.add(phone.strip())
                
        for phone in cleaned_phones:
            all_found_data['phones'].add(phone)

    # --- Extrakce odkazů na sociální média ---
    if scan_choices['social_links']:
        social_media_domains = {
            'facebook.com', 'fb.com', 'twitter.com', 'x.com', 'linkedin.com',
            'instagram.com', 'youtube.com', 'tiktok.com', 'pinterest.com'
        }
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if any(domain in href for domain in social_media_domains):
                all_found_data['social_links'].add(href)

    # --- Extrakce HTML Meta Tagů ---
    if scan_choices['meta_tags']:
        generator_meta = soup.find('meta', attrs={'name': 'generator'})
        if generator_meta and 'content' in generator_meta.attrs:
            all_found_data['meta_tags']['generator'] = generator_meta['content']
            
        description_meta = soup.find('meta', attrs={'name': 'description'})
        if description_meta and 'content' in description_meta.attrs:
            all_found_data['meta_tags']['description'] = description_meta['content']

        keywords_meta = soup.find('meta', attrs={'name': 'keywords'})
        if keywords_meta and 'content' in keywords_meta.attrs:
            all_found_data['meta_tags']['keywords'] = keywords_meta['content']
                
        og_title = soup.find('meta', property='og:title')
        if og_title and 'content' in og_title.attrs:
            all_found_data['meta_tags']['og_title'] = og_title['content']
        og_description = soup.find('meta', property='og:description')
        if og_description and 'content' in og_description.attrs:
            all_found_data['meta_tags']['og_description'] = og_description['content']

    # --- Extrakce HTML/JS Komentářů ---
    if scan_choices['comments']:
        html_comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in html_comments:
            all_found_data['comments'].add(comment.strip())
        
        for script_tag in soup.find_all('script', string=True):
            script_content = script_tag.string
            js_comment_pattern = r'//.*|/\*[\s\S]*?\*/'
            found_js_comments = re.findall(js_comment_pattern, script_content)
            for comment in found_js_comments:
                all_found_data['comments'].add(comment.strip())

    # --- Extrakce potenciálních API klíčů/tokenů ---
    if scan_choices['api_keys']:
        api_key_patterns = [
            r'(?:api_key|apikey|token|secret|client_id|client_secret)=([a-zA-Z0-9_-]{16,64})',
            r'sk-[a-zA-Z0-9]{32,}',
            r'AIza[0-9A-Za-z-_]{35}',
            r'pk_live_[a-zA-Z0-9]{24}',
        ]
        for pattern in api_key_patterns:
            found_keys = re.findall(pattern, response_text)
            for key in found_keys:
                all_found_data['api_keys'].add(key)

    # --- Extrakce běžných chybových zpráv ---
    if scan_choices['error_messages']:
        error_keywords = [
            'SQL Error', 'Fatal Error', 'Warning:', 'Deprecated:', 
            'Stack trace', 'Parse error', 'syntax error', 'uncaught exception',
            'database error', 'connection refused', 'permission denied'
        ]
        page_text = soup.get_text()
        for keyword in error_keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', page_text, re.IGNORECASE):
                match = re.search(r'(.{0,100}' + re.escape(keyword) + r'.{0,100})', page_text, re.IGNORECASE | re.DOTALL)
                if match:
                    all_found_data['error_messages'].add(match.group(1).strip().replace('\n', ' '))
                else:
                    all_found_data['error_messages'].add(keyword)


def get_page_content_and_info(url, all_found_data, scan_choices, current_depth, max_depth):
    """
    Stáhne obsah webové stránky, extrahuje informace a najde interní odkazy.
    """
    global visited_urls
    global global_crawl_delay

    if url in visited_urls:
        return [] # Již navštíveno, přeskočit

    visited_urls.add(url) # Přidat do navštívených

    prefix_indent = "  " * (current_depth + 1)
    # Změněno pro stručnější výstup během skenování
    print(f"{prefix_indent}\033[34m[*] Zpracovávám: {url} (Hloubka {current_depth})\033[0m")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # --- Extrakce HTTP Hlaviček (vždy, pokud je volba zapnutá) ---
        if scan_choices['http_headers']:
            for header_name in ['Server', 'X-Powered-By', 'Content-Type', 'Date', 
                                'Strict-Transport-Security', 'X-Frame-Options', 
                                'Content-Security-Policy', 'X-XSS-Protection', 'X-Content-Type-Options']:
                if header_name in response.headers:
                    all_found_data['http_headers'][header_name] = response.headers[header_name]

        # Extrahujeme další informace na základě voleb uživatele
        identify_technologies(url, response.headers, soup, response.text, all_found_data)
        extract_info_from_page(url, response.headers, soup, response.text, all_found_data, scan_choices)

        # Hledáme interní odkazy pro hlubší skenování, pokud jsme nedosáhli max_depth
        internal_links = set()
        if current_depth < max_depth:
            base_domain = urlparse(url).netloc
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                parsed_full_url = urlparse(full_url)

                # Kontrola, zda je odkaz interní a není soubor (rozšířeno o .css, .js, .xml, .txt, .json)
                if parsed_full_url.netloc == base_domain and \
                   not re.search(r'\.(pdf|jpg|jpeg|png|gif|zip|rar|doc|docx|xls|xlsx|ppt|pptx|css|js|xml|txt|json)$', parsed_full_url.path, re.IGNORECASE):
                    if full_url not in visited_urls:
                        internal_links.add(full_url)
                            
        return list(internal_links)
        
    except requests.exceptions.MissingSchema:
        print(f"{prefix_indent}\033[31m❌ Chyba: Neplatná URL. Ujistěte se, že URL začíná 'http://' nebo 'https://'.\033[0m")
    except requests.exceptions.ConnectionError:
        print(f"{prefix_indent}\033[31m❌ Chyba připojení: Nelze se připojit k webové stránce. Zkontrolujte URL a připojení k internetu.\033[0m")
    except requests.exceptions.Timeout:
        print(f"{prefix_indent}\033[31m❌ Chyba časového limitu: Požadavek na webovou stránku vypršel.\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"{prefix_indent}\033[31m❌ Chyba HTTP požadavku: {e}\033[0m")
    except Exception as e:
        print(f"{prefix_indent}\033[31m❌ Vyskytla se neočekávaná chyba: {e}\033[0m")
    
    return []

def get_subdomains_from_crtsh(domain):
    """
    Získá subdomény z crt.sh (Certificate Transparency logs).
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        data = json.loads(response.text)
        
        for entry in data:
            if 'common_name' in entry:
                cn = entry['common_name']
                if cn.endswith(f".{domain}") or cn == domain:
                    # Odstranit wildcard subdomény jako *.example.com
                    if not cn.startswith('*.'):
                        subdomains.add(cn)
            if 'name_value' in entry:
                names = entry['name_value'].split('\n')
                for name in names:
                    if (name.endswith(f".{domain}") or name == domain) and not name.startswith('*.'):
                        subdomains.add(name)
        return sorted(list(subdomains))
    except json.JSONDecodeError:
        print(f"\033[31m[-] Chyba dekódování JSON z crt.sh pro {domain}. Možná žádné výsledky nebo změna formátu.\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"\033[31m[-] Chyba při získávání subdomén z crt.sh pro {domain}: {e}\033[0m")
    return []

def get_reverse_ip_from_hackertarget(domain, all_found_data):
    """
    Získá domény hostované na stejné IP adrese z HackerTarget.com API.
    """
    reverse_ip_domains = set()
    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain)
        all_found_data['target_ip'] = ip_address # Uložit IP adresu
        print(f"\033[34m[*] IP adresa pro {domain}: {ip_address}\033[0m")
    except socket.gaierror:
        print(f"\033[31m[-] Nelze získat IP adresu pro {domain}.\033[0m")
        return []

    if not ip_address:
        return []

    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() # Vyvolá výjimku pro HTTP chyby (4xx nebo 5xx)
        
        # HackerTarget API vrací prostý text, jedna doména na řádek
        domains_text = response.text.strip()
        if domains_text and "error" not in domains_text.lower() and "no records found" not in domains_text.lower():
            for line in domains_text.splitlines():
                domain_name = line.strip()
                if domain_name:
                    reverse_ip_domains.add(domain_name)
        
        return sorted(list(reverse_ip_domains))
    except requests.exceptions.RequestException as e:
        print(f"\033[31m[-] Chyba při získávání reverzních IP domén z HackerTarget.com pro {ip_address}: {e}\033[0m")
    return []

def get_wayback_machine_archives(url_to_archive):
    """
    Získá archivované URL z Wayback Machine (CDX API).
    """
    archives = []
    # CDX API pro získání všech snímků pro danou URL
    # filter=statuscode:200 - pouze úspěšné snímky
    # limit=100 - omezíme počet výsledků pro přehlednost
    cdx_url = f"http://web.archive.org/cdx/search/cdx?url={url_to_archive}/*&output=json&filter=statuscode:200&limit=100"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    try:
        response = requests.get(cdx_url, headers=headers, timeout=15)
        response.raise_for_status()
        data = json.loads(response.text)
        
        # První řádek je hlavička, zbytek jsou data
        if data and len(data) > 1:
            headers = data[0]
            for entry in data[1:]:
                record = dict(zip(headers, entry))
                if record.get('timestamp') and record.get('original'):
                    archive_url = f"https://web.archive.org/web/{record['timestamp']}/{record['original']}"
                    archives.append({
                        'timestamp': record['timestamp'],
                        'original_url': record['original'],
                        'archive_url': archive_url
                    })
        return archives
    except json.JSONDecodeError:
        print(f"\033[31m[-] Chyba dekódování JSON z Wayback Machine pro {url_to_archive}. Možná žádné výsledky nebo změna formátu.\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"\033[31m[-] Chyba při získávání archivů z Wayback Machine pro {url_to_archive}: {e}\033[0m")
    return []


def display_results(all_found_data, scan_choices, display_limits):
    """
    Zobrazí všechny shromážděné informace na základě voleb uživatele a limitů zobrazení.
    """
    print(f"\n{os.linesep}\033[1m--- SHRNUTÍ NALEZENÝCH INFORMACÍ ---\033[0m")

    if scan_choices['emails']:
        print(f"\n{os.linesep}\033[1m📧 Nalezené e-mailové adresy ({len(all_found_data['emails'])}) ---\033[0m")
        if all_found_data['emails']:
            for email in sorted(list(all_found_data['emails'])):
                print(f"  \033[32m- {email}\033[0m")
        else:
            print("  Žádné e-mailové adresy nenalezeny.")

    if scan_choices['phones']:
        print(f"\n{os.linesep}\033[1m📞 Nalezená telefonní čísla ({len(all_found_data['phones'])}) ---\033[0m")
        if all_found_data['phones']:
            for phone in sorted(list(all_found_data['phones'])):
                print(f"  \033[32m- {phone}\033[0m")
        else:
            print("  Žádná telefonní čísla nenalezena.")

    if scan_choices['social_links']:
        print(f"\n{os.linesep}\033[1m🔗 Nalezené odkazy na sociální média ({len(all_found_data['social_links'])}) ---\033[0m")
        if all_found_data['social_links']:
            for link in sorted(list(all_found_data['social_links'])):
                print(f"  \033[32m- {link}\033[0m")
        else:
            print("  Žádné odkazy na sociální média nenalezeny.")

    if scan_choices['http_headers']:
        print(f"\n{os.linesep}\033[1m--- Unikátní HTTP Hlavičky ---\033[0m")
        if all_found_data['http_headers']:
            for header_name, header_value in sorted(all_found_data['http_headers'].items()):
                print(f"  \033[36m{header_name}:\033[0m {header_value}")
        else:
            print("  Žádné specifické HTTP hlavičky nenalezeny.")

    if scan_choices['meta_tags']:
        print(f"\n{os.linesep}\033[1m--- Unikátní HTML Meta Tagy ---\033[0m")
        if all_found_data['meta_tags']:
            for meta_name, meta_value in sorted(all_found_data['meta_tags'].items()):
                print(f"  \033[35m{meta_name}:\033[0m {meta_value}")
        else:
            print("  Žádné specifické meta tagy nenalezeny.")
            
    if scan_choices['comments']:
        print(f"\n{os.linesep}\033[1m--- Nalezené HTML/JS Komentáře ({len(all_found_data['comments'])}) ---\033[0m")
        if all_found_data['comments']:
            for i, comment in enumerate(sorted(list(all_found_data['comments']))):
                if display_limits['comments'] != 0 and i >= display_limits['comments']:
                    print(f"  \033[34m- ... a dalších {len(all_found_data['comments']) - i} komentářů.\033[0m")
                    break
                print(f"  \033[34m- {comment}\033[0m")
        else:
            print("  Žádné komentáře nenalezeny.")

    if scan_choices['api_keys']:
        print(f"\n{os.linesep}\033[1m--- Potenciální API klíče/tokeny ({len(all_found_data['api_keys'])}) ---\033[0m")
        if all_found_data['api_keys']:
            print("\033[33m  Upozornění: Toto jsou vzory. Nemusí jít o aktivní klíče. Pro vzdělávací účely.\033[0m")
            for i, key in enumerate(sorted(list(all_found_data['api_keys']))):
                if display_limits['api_keys'] != 0 and i >= display_limits['api_keys']:
                    print(f"  \033[34m- ... a dalších {len(all_found_data['api_keys']) - i} klíčů.\033[0m")
                    break
                print(f"  \033[34m- {key}\033[0m")
        else:
            print("  Žádné potenciální API klíče/tokeny nenalezeny.")

    if scan_choices['error_messages']:
        print(f"\n{os.linesep}\033[1m--- Nalezené chybové zprávy ({len(all_found_data['error_messages'])}) ---\033[0m")
        if all_found_data['error_messages']:
            print("\033[33m  Upozornění: Nalezené chybové zprávy mohou naznačovat problémy, ale nejsou vždy zranitelností.\033[0m")
            for i, msg in enumerate(sorted(list(all_found_data['error_messages']))):
                if display_limits['error_messages'] != 0 and i >= display_limits['error_messages']:
                    print(f"  \033[34m- ... a dalších {len(all_found_data['error_messages']) - i} zpráv.\033[0m")
                    break
                print(f"  \033[34m- {msg}\033[0m")
        else:
            print("  Žádné chybové zprávy nenalezeny.")
            
    # Identifikované technologie
    print(f"\n{os.linesep}\033[1m--- Identifikované Technologie ---\033[0m")
    if all_found_data['technologies']:
        for tech_name, tech_value in sorted(all_found_data['technologies'].items()):
            print(f"  \033[38;5;208m{tech_name}:\033[0m {tech_value}") # Oranžová barva
    else:
        print("  Žádné klíčové technologie nebyly identifikovány.")
        print("  \033[33mTip: Zkuste prohledat zdrojový kód stránky pro další stopy (např. 'generator', 'version').\033[0m")
        
    # Nové sekce pro pokročilé OSINT
    if scan_choices['subdomains']:
        print(f"\n{os.linesep}\033[1m--- Nalezené Subdomény ({len(all_found_data['subdomains'])}) ---\033[0m")
        if all_found_data['subdomains']:
            for i, subdomain in enumerate(sorted(list(all_found_data['subdomains']))):
                if display_limits['subdomains'] != 0 and i >= display_limits['subdomains']:
                    print(f"  \033[38;5;198m- ... a dalších {len(all_found_data['subdomains']) - i} subdomén.\033[0m")
                    break
                print(f"  \033[38;5;198m- {subdomain}\033[0m")
        else:
            print("  Žádné subdomény nenalezeny.")

    if scan_choices['reverse_ip']:
        print(f"\n{os.linesep}\033[1m--- Reverzní IP Domény ({len(all_found_data['reverse_ip_domains'])}) ---\033[0m")
        if all_found_data['reverse_ip_domains']:
            # Zobrazit IP adresu pouze pokud byla úspěšně získána
            if all_found_data['target_ip']:
                print(f"  \033[34mIP adresa: {all_found_data['target_ip']}\033[0m")
            else:
                print(f"  \033[34mIP adresa: Nezjištěna\033[0m")
            
            for i, domain_name in enumerate(sorted(list(all_found_data['reverse_ip_domains']))):
                if display_limits['reverse_ip'] != 0 and i >= display_limits['reverse_ip']:
                    print(f"  \033[38;5;198m- ... a dalších {len(all_found_data['reverse_ip_domains']) - i} domén.\033[0m")
                    break
                print(f"  \033[38;5;198m- {domain_name}\033[0m")
        else:
            print("  Žádné domény na stejné IP adrese nenalezeny.")

    if scan_choices['wayback_machine']:
        print(f"\n{os.linesep}\033[1m--- Wayback Machine Archívy ({len(all_found_data['wayback_archives'])}) ---\033[0m")
        if all_found_data['wayback_archives']:
            # Seřadit archivy od nejnovějších po nejstarší pro lepší přehled
            sorted_archives = sorted(all_found_data['wayback_archives'], key=lambda x: x['timestamp'], reverse=True)
            for i, archive in enumerate(sorted_archives):
                if display_limits['wayback_machine'] != 0 and i >= display_limits['wayback_machine']:
                    print(f"  \033[38;5;198m- ... a dalších {len(all_found_data['wayback_archives']) - i} archivů.\033[0m")
                    break
                # Formátování času pro lepší čitelnost
                timestamp_str = f"{archive['timestamp'][0:4]}-{archive['timestamp'][4:6]}-{archive['timestamp'][6:8]} {archive['timestamp'][8:10]}:{archive['timestamp'][10:12]}:{archive['timestamp'][12:14]}"
                print(f"  \033[38;5;198m- Datum: {timestamp_str}, Původní URL: {archive['original_url']}, Archiv URL: {archive['archive_url']}\033[0m")
        else:
            print("  Žádné archívy v Wayback Machine nenalezeny.")
        
    print("\n" + "=" * (os.get_terminal_size().columns - 1) if os.get_terminal_size().columns > 1 else "=")


def main():
    """Hlavní funkce pro spuštění OSINT Harvesteru."""
    global visited_urls
    global global_crawl_delay

    try:
        while True:
            clear_screen()
            print(ascii_logo)
            print("\n--- OSINT Harvester (Komplexní průzkum) ---")
            print("Zadejte URL webové stránky ke skenování (například 'https://example.com').")
            print("Pro ukončení zadejte 'konec'.")
            print("\n\033[31m!!! Pamatujte na etické a právní zásady web scrapingu !!!\033[0m")
            print("\033[31m!!! Scrapujte POUZE veřejně dostupná data a respektujte robots.txt a ToS !!!\033[0m")
            
            target_url = input("\nZadejte cílovou URL: ").strip()
            
            if target_url.lower() == 'konec':
                print("Ukončuji OSINT Harvester. Na shledanou!")
                break
            
            if not target_url:
                print("Cílová URL nemůže být prázdná. Zkuste to znovu.")
                input("\nStiskněte Enter pro pokračování...")
                continue

            # Zkontrolujeme, zda URL začíná http/https
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
                print(f"[*] URL upravena na: {target_url}")

            # --- Interaktivní volba typů informací ---
            scan_choices = {
                'emails': input("Hledat e-mailové adresy? (a/n, výchozí a): ").lower().startswith('a') or True,
                'phones': input("Hledat telefonní čísla? (a/n, výchozí a): ").lower().startswith('a') or True,
                'social_links': input("Hledat odkazy na sociální média? (a/n, výchozí a): ").lower().startswith('a') or True,
                'http_headers': input("Analyzovat HTTP hlavičky? (a/n, výchozí a): ").lower().startswith('a') or True,
                'meta_tags': input("Analyzovat HTML meta tagy? (a/n, výchozí a): ").lower().startswith('a') or True,
                'comments': input("Hledat HTML/JS komentáře? (a/n, výchozí a): ").lower().startswith('a') or True,
                'api_keys': input("Hledat potenciální API klíče/tokeny? (a/n, výchozí n): ").lower().startswith('a'),
                'error_messages': input("Hledat chybové zprávy? (a/n, výchozí n): ").lower().startswith('a'),
                'subdomains': input("Hledat subdomény (pasivně přes crt.sh)? (a/n, výchozí n): ").lower().startswith('a'),
                'reverse_ip': input("Provádět reverzní IP lookup (pasivně přes HackerTarget.com)? (a/n, výchozí n): ").lower().startswith('a'), # Změněn název služby
                'wayback_machine': input("Hledat archívy na Wayback Machine (pasivně)? (a/n, výchozí n): ").lower().startswith('a')
            }
            
            # --- Nastavitelný počet zobrazených položek ---
            display_limits = {}
            print("\n--- Nastavte počet zobrazených položek (0 pro vše, prázdné pro výchozí) ---")
            
            def get_limit_input(prompt, default_limit):
                while True:
                    try:
                        user_input = input(f"{prompt} (výchozí {default_limit}): ").strip()
                        if not user_input:
                            return default_limit
                        limit = int(user_input)
                        if limit < 0:
                            print("\033[31mPočet položek nemůže být záporný. Zadejte prosím nezáporné číslo.\033[0m")
                        else:
                            return limit
                    except ValueError:
                        print("\033[31mNeplatný vstup. Zadejte prosím číslo.\033[0m")

            display_limits['comments'] = get_limit_input("Zobrazit komentáře", 5)
            display_limits['api_keys'] = get_limit_input("Zobrazit API klíče/tokeny", 3)
            display_limits['error_messages'] = get_limit_input("Zobrazit chybové zprávy", 3)
            display_limits['subdomains'] = get_limit_input("Zobrazit subdomény", 10)
            display_limits['reverse_ip'] = get_limit_input("Zobrazit reverzní IP domény", 10)
            display_limits['wayback_machine'] = get_limit_input("Zobrazit archívy Wayback Machine", 5)
            
            # --- Nastavitelná hloubka skenování ---
            while True:
                try:
                    max_depth_input = input("Zadejte maximální hloubku skenování (0 pro jen hlavní stránku, 1 pro hlavní + 1 úroveň, atd., výchozí 1): ")
                    if not max_depth_input:
                        max_depth = 1
                    else:
                        max_depth = int(max_depth_input)
                    
                    if max_depth < 0:
                        print("\033[31mHloubka nemůže být záporná. Zadejte prosím nezáporné číslo.\033[0m")
                    else:
                        break
                except ValueError:
                    print("\033[31mNeplatný vstup. Zadejte prosím číslo.\033[0m")

            # Resetujeme navštívené URL a data pro každé nové skenování cíle
            visited_urls.clear() 
            all_found_data = {
                'emails': set(),
                'phones': set(),
                'social_links': set(),
                'http_headers': {},
                'meta_tags': {},
                'comments': set(),
                'api_keys': set(),
                'error_messages': set(),
                'technologies': {},
                'subdomains': set(),
                'reverse_ip_domains': set(),
                'target_ip': None, # Uložíme IP adresu cíle
                'wayback_archives': []
            }

            # Získání domény pro externí OSINT dotazy
            parsed_target_url = urlparse(target_url)
            target_domain = parsed_target_url.netloc
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:] # Odstranit www. pro lepší výsledky

            # Nejprve zkontrolujeme robots.txt pro hlavní URL
            check_robots_txt(target_url)

            # --- Spuštění externích OSINT modulů ---
            if scan_choices['subdomains']:
                print(f"\n\033[33m[*] Získávám subdomény pro {target_domain} z crt.sh...\033[0m")
                found_subdomains = get_subdomains_from_crtsh(target_domain)
                for sd in found_subdomains:
                    all_found_data['subdomains'].add(sd)
                time.sleep(global_crawl_delay) # Prodleva po externím dotazu

            if scan_choices['reverse_ip']:
                print(f"\n\033[33m[*] Provádím reverzní IP lookup pro {target_domain} přes HackerTarget.com...\033[0m") # Změněn název služby
                found_reverse_ip_domains = get_reverse_ip_from_hackertarget(target_domain, all_found_data) # Předáváme all_found_data
                for rid in found_reverse_ip_domains:
                    all_found_data['reverse_ip_domains'].add(rid)
                time.sleep(global_crawl_delay) # Prodleva po externím dotazu

            if scan_choices['wayback_machine']:
                print(f"\n\033[33m[*] Získávám archívy z Wayback Machine pro {target_url}...\033[0m")
                found_wayback_archives = get_wayback_machine_archives(target_url)
                all_found_data['wayback_archives'].extend(found_wayback_archives)
                time.sleep(global_crawl_delay) # Prodleva po externím dotazu


            # Používáme frontu pro BFS (Breadth-First Search) pro hlubší skenování
            urls_to_visit = deque([(target_url, 0)])

            print(f"\n\033[33m[*] Spouštím hluboké skenování do hloubky {max_depth}...\033[0m")

            while urls_to_visit:
                current_url, current_depth = urls_to_visit.popleft()

                if current_depth > max_depth:
                    continue

                new_internal_links = get_page_content_and_info(current_url, all_found_data, scan_choices, current_depth, max_depth)
                
                if current_depth < max_depth:
                    for link in new_internal_links:
                        if link not in visited_urls:
                            urls_to_visit.append((link, current_depth + 1))
                
                print(f"\n{os.linesep}\033[33m[*] Čekám {global_crawl_delay} sekund...\033[0m")
                time.sleep(global_crawl_delay)

            display_results(all_found_data, scan_choices, display_limits)
            
            input("\nStiskněte Enter pro skenování další URL, nebo 'konec'...")

    except KeyboardInterrupt:
        print("\nProgram byl ukončen uživatelem.")
    except Exception as e:
        print(f"\n\033[31m❌ Vyskytla se kritická chyba: {e}\033[0m")
    finally:
        sys.stdout.write("\033[0m\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()

