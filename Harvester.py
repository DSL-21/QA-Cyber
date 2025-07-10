import requests
from bs4 import BeautifulSoup
import re
import os
import sys
import time
from urllib.parse import urljoin, urlparse
from collections import deque # Pro správu fronty URL pro skenování

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

def extract_info_from_page(soup, response_text, all_found_data, scan_choices):
    """
    Extrahuje různé typy informací z BeautifulSoup objektu a textu odpovědi.
    """
    
    # --- Extrakce e-mailových adres ---
    if scan_choices['emails']:
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        found_emails = set(re.findall(email_pattern, response_text)) # Hledáme v celém textu odpovědi
        for email in found_emails:
            all_found_data['emails'].add(email)

    # --- Extrakce telefonních čísel ---
    if scan_choices['phones']:
        phone_pattern = r'(?:\+\d{1,3}[ -]?)?(?:\(\d{1,4}\)[ -]?)?\d{2,4}[ -]?\d{2,4}[ -]?\d{2,4}(?:[ -]?\d{1,4})?'
        found_phones = set(re.findall(phone_pattern, soup.get_text()))
        
        cleaned_phones = set()
        for phone in found_phones:
            digits = re.sub(r'\D', '', phone)
            if 7 <= len(digits) <= 15:
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
        # Hledáme HTML komentáře
        html_comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in html_comments:
            all_found_data['comments'].add(comment.strip())
        
        # Hledáme JS komentáře uvnitř <script> tagů (zjednodušeně)
        for script_tag in soup.find_all('script', string=True):
            script_content = script_tag.string
            # Jednoduchý regex pro // a /* */ komentáře v JS
            js_comment_pattern = r'//.*|/\*[\s\S]*?\*/'
            found_js_comments = re.findall(js_comment_pattern, script_content)
            for comment in found_js_comments:
                all_found_data['comments'].add(comment.strip())

    # --- Extrakce potenciálních API klíčů/tokenů ---
    if scan_choices['api_keys']:
        # Velmi jednoduché vzory pro demonstrační účely.
        # Reálné API klíče mají složitější a různorodější formáty.
        api_key_patterns = [
            r'(?:api_key|apikey|token|secret|client_id|client_secret)=([a-zA-Z0-9_-]{16,64})', # Obecný klíč/token
            r'sk-[a-zA-Z0-9]{32,}', # Příklad pro OpenAI-like klíče
            r'AIza[0-9A-Za-z-_]{35}', # Příklad pro Google API klíče
            r'pk_live_[a-zA-Z0-9]{24}', # Příklad pro Stripe public keys
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
                # Pokusíme se zachytit kontext chyby
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
    print(f"\n{prefix_indent}\033[1m--- Skenuji stránku (Hloubka {current_depth}): {url} ---\033[0m")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # --- Extrakce HTTP Hlaviček (vždy, protože jsou základní) ---
        if scan_choices['http_headers']:
            for header_name in ['Server', 'X-Powered-By', 'Content-Type', 'Date', 
                                'Strict-Transport-Security', 'X-Frame-Options', 
                                'Content-Security-Policy', 'X-XSS-Protection', 'X-Content-Type-Options']:
                if header_name in response.headers:
                    all_found_data['http_headers'][header_name] = response.headers[header_name]

        # Extrahujeme další informace na základě voleb uživatele
        extract_info_from_page(soup, response.text, all_found_data, scan_choices)

        # Hledáme interní odkazy pro hlubší skenování, pokud jsme nedosáhli max_depth
        internal_links = set()
        if current_depth < max_depth:
            base_domain = urlparse(url).netloc
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                parsed_full_url = urlparse(full_url)

                # Kontrola, zda je odkaz interní a není soubor
                if parsed_full_url.netloc == base_domain and \
                   not re.search(r'\.(pdf|jpg|jpeg|png|gif|zip|rar|doc|docx|xls|xlsx|ppt|pptx)$', parsed_full_url.path, re.IGNORECASE):
                    # Zde můžeme přidat i filtrování na "důležité" odkazy, nebo skenovat všechny,
                    # pro hlubší skenování je obvykle lepší skenovat všechny interní odkazy.
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

def display_results(all_found_data, scan_choices):
    """
    Zobrazí všechny shromážděné informace na základě voleb uživatele.
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
            for comment in sorted(list(all_found_data['comments'])):
                print(f"  \033[34m- {comment}\033[0m")
        else:
            print("  Žádné komentáře nenalezeny.")

    if scan_choices['api_keys']:
        print(f"\n{os.linesep}\033[1m--- Potenciální API klíče/tokeny ({len(all_found_data['api_keys'])}) ---\033[0m")
        if all_found_data['api_keys']:
            print("\033[33m  Upozornění: Toto jsou vzory. Nemusí jít o aktivní klíče. Pro vzdělávací účely.\033[0m")
            for key in sorted(list(all_found_data['api_keys'])):
                print(f"  \033[34m- {key}\033[0m")
        else:
            print("  Žádné potenciální API klíče/tokeny nenalezeny.")

    if scan_choices['error_messages']:
        print(f"\n{os.linesep}\033[1m--- Nalezené chybové zprávy ({len(all_found_data['error_messages'])}) ---\033[0m")
        if all_found_data['error_messages']:
            print("\033[33m  Upozornění: Nalezené chybové zprávy mohou naznačovat problémy, ale nejsou vždy zranitelností.\033[0m")
            for msg in sorted(list(all_found_data['error_messages'])):
                print(f"  \033[34m- {msg}\033[0m")
        else:
            print("  Žádné chybové zprávy nenalezeny.")
        
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
            print("Zadejte URL webové stránky ke skenování (např. 'https://example.com').")
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
                'emails': input("Hledat e-mailové adresy? (a/n): ").lower().startswith('a'),
                'phones': input("Hledat telefonní čísla? (a/n): ").lower().startswith('a'),
                'social_links': input("Hledat odkazy na sociální média? (a/n): ").lower().startswith('a'),
                'http_headers': input("Analyzovat HTTP hlavičky? (a/n): ").lower().startswith('a'),
                'meta_tags': input("Analyzovat HTML meta tagy? (a/n): ").lower().startswith('a'),
                'comments': input("Hledat HTML/JS komentáře? (a/n): ").lower().startswith('a'),
                'api_keys': input("Hledat potenciální API klíče/tokeny? (a/n): ").lower().startswith('a'),
                'error_messages': input("Hledat chybové zprávy? (a/n): ").lower().startswith('a')
            }
            
            # --- Nastavitelná hloubka skenování ---
            while True:
                try:
                    max_depth_input = input("Zadejte maximální hloubku skenování (0 pro jen hlavní stránku, 1 pro hlavní + 1 úroveň, atd.): ")
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
                'error_messages': set()
            }

            # Nejprve zkontrolujeme robots.txt pro hlavní URL
            check_robots_txt(target_url)

            # Používáme frontu pro BFS (Breadth-First Search) pro hlubší skenování
            # Každá položka ve frontě je (url, depth)
            urls_to_visit = deque([(target_url, 0)])

            print(f"\n\033[33m[*] Spouštím hluboké skenování do hloubky {max_depth}...\033[0m")

            while urls_to_visit:
                current_url, current_depth = urls_to_visit.popleft()

                if current_depth > max_depth:
                    continue # Přeskočit, pokud jsme překročili maximální hloubku

                # Získejte obsah stránky a extrahujte informace
                # get_page_content_and_info nyní vrací interní odkazy
                new_internal_links = get_page_content_and_info(current_url, all_found_data, scan_choices, current_depth, max_depth)
                
                # Přidáme nové interní odkazy do fronty, pokud jsme nedosáhli max_depth
                if current_depth < max_depth:
                    for link in new_internal_links:
                        if link not in visited_urls: # Přidáme jen ty, které jsme ještě nenavštívili
                            urls_to_visit.append((link, current_depth + 1))
                
                # Dodržujeme crawl-delay po každém požadavku
                print(f"\n\033[33m[*] Čekám {global_crawl_delay} sekund...\033[0m")
                time.sleep(global_crawl_delay)

            # Zobrazíme souhrn všech shromážděných dat
            display_results(all_found_data, scan_choices)
            
            input("\nStiskněte Enter pro skenování další URL, nebo 'konec'...")

    except KeyboardInterrupt:
        print("\nProgram byl ukončen uživatelem.")
    except Exception as e:
        print(f"\n\033[31m❌ Vyskytla se kritická chyba: {e}\033[0m")
    finally:
        sys.stdout.write("\033[0m\n")
        sys.stdout.flush()

if __name__ == "__main__":
    from bs4 import Comment # Importujeme Comment pro detekci HTML komentářů
    main()

