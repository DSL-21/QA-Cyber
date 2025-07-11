import requests
import os
import sys
from urllib.parse import urlparse, urlencode, parse_qs

# --- ASCII ART LOGO ---
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
# \033[32m - Zelená barva (nalezeno)
# \033[33m - Žlutá barva (upozornění/průběh)
# \033[31m - Červená barva (chyba)
# \033[36m - Azurová barva (informace)

def clear_screen():
    """Vymaže obrazovku terminálu."""
    os.system('clear' if os.name == 'posix' else 'cls')

def scan_xss(url):
    """
    Pokusí se detekovat základní XSS zranitelnosti v GET parametrech URL.
    """
    print(f"\n\033[33m[*] Spouštím XSS skenování pro: {url}\033[0m")

    # Běžné XSS payloady pro testování
    xss_payloads = [
        "<script>alert(1)</script>",
        "\"'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "';alert(1)//",
        "</script><script>alert(1)</script>"
    ]

    # Parsujeme URL, abychom získali parametry
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Pokud URL nemá žádné parametry, zkusíme přidat fiktivní parametr 'q'
    if not query_params:
        print("\033[33m[*] URL nemá žádné GET parametry. Zkusím testovat s fiktivním parametrem 'q'.\033[0m")
        # Vytvoříme novou URL s fiktivním parametrem
        base_url_without_query = parsed_url._replace(query="").geturl()
        test_url = f"{base_url_without_query}?q="
        
        # Testujeme s každým payloadem
        for payload in xss_payloads:
            full_test_url = f"{test_url}{payload}"
            print(f"\033[36m    Testuji: {full_test_url}\033[0m")
            try:
                response = requests.get(full_test_url, timeout=10)
                if payload in response.text:
                    print(f"\033[32m[+] POTENCIÁLNÍ XSS ZRANITELNOST NALEZENA!\033[0m")
                    print(f"    Zranitelná URL: {full_test_url}")
                    print(f"    Použitý Payload: {payload}\n")
                    return True # Nalezena zranitelnost, můžeme ukončit
            except requests.exceptions.RequestException as e:
                print(f"\033[31m[-] Chyba při požadavku na {full_test_url}: {e}\033[0m")
        print("\033[33m[*] Skenování s fiktivním parametrem 'q' dokončeno. Žádné XSS nenalezeno.\033[0m")
        return False

    # Pokud URL má parametry, testujeme každý parametr
    found_vulnerability = False
    for param_name, param_values in query_params.items():
        for payload in xss_payloads:
            # Vytvoříme nové parametry s vloženým payloadem do aktuálního parametru
            new_query_params = query_params.copy()
            new_query_params[param_name] = payload # Nahradíme hodnotu parametru payloadem
            
            # Rekonstruujeme URL s novými parametry
            encoded_query = urlencode(new_query_params, quote_via=requests.utils.quote) # Správné kódování payloadu
            full_test_url = parsed_url._replace(query=encoded_query).geturl()

            print(f"\033[36m    Testuji parametr '{param_name}' s payloadem: {payload}\033[0m")
            try:
                response = requests.get(full_test_url, timeout=10)
                # Kontrolujeme, zda se payload odrazil v HTML odpovědi
                if payload in response.text:
                    print(f"\033[32m[+] POTENCIÁLNÍ XSS ZRANITELNOST NALEZENA!\033[0m")
                    print(f"    Zranitelná URL: {full_test_url}")
                    print(f"    Použitý Payload: {payload}\n")
                    found_vulnerability = True
                    # Pokračujeme, abychom našli všechny zranitelné parametry
            except requests.exceptions.RequestException as e:
                print(f"\033[31m[-] Chyba při požadavku na {full_test_url}: {e}\033[0m")
    
    if not found_vulnerability:
        print("\033[33m[*] Skenování dokončeno. Žádné XSS zranitelnosti v GET parametrech nenalezeny.\033[0m")
    return found_vulnerability


def main():
    """Hlavní funkce pro spuštění XSS skeneru."""
    try:
        while True:
            clear_screen()
            print(ascii_logo)
            print("\n--- Základní XSS Skener ---")
            print("Zadejte URL webové stránky ke skenování (například 'https://example.com/search?q=test').")
            print("Pro ukončení zadejte 'konec'.")
            
            target_url = input("\nZadejte cílovou URL: ").strip()
            
            if target_url.lower() == 'konec':
                print("Ukončuji XSS Skener. Na shledanou!")
                break
            
            if not target_url:
                print("Cílová URL nemůže být prázdná. Zkuste to znovu.")
                input("\nStiskněte Enter pro pokračování...")
                continue

            # Zkontrolujeme, zda URL začíná http/https
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
                print(f"[*] URL upravena na: {target_url}")

            scan_xss(target_url)
            
            input("\nStiskněte Enter pro nové skenování, nebo 'konec'...")

    except KeyboardInterrupt:
        print("\nProgram byl ukončen uživatelem.")
    except Exception as e:
        print(f"\n\033[31m❌ Vyskytla se kritická chyba: {e}\033[0m")
    finally:
        sys.stdout.write("\033[0m\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()

