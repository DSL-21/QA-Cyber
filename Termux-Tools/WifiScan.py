import subprocess
import json
import os
import sys
import time

# --- ASCII ART LOGO (stejné jako v Harvester.py) ---
ascii_logo = (
    "  ____  ____  __    _  _  _  _  ____ \n"
    " (    \\(  __)(  )  / )( \\( \\/ )(  __)\n"
    "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n"
    " (____/(____)\\____/\\____/(_/\\_)(____)\n"
    "***************************************\n"
    "* Copyright 2025, ★DSL★           *\n"
    "* https://github.com/DSL-21           *\n"
    "***************************************"
)

# ANSI escape kódy pro barvy a styly v terminálu
# \033[1m - Bold (tučné)
# \033[0m - Reset (resetuje styl na výchozí)
# \033[32m - Zelená barva (silný signál/nalezeno)
# \033[33m - Žlutá barva (střední signál/upozornění)
# \033[31m - Červená barva (slabý signál/chyba)
# \033[36m - Azurová barva (hlavičky)
# \033[35m - Purpurová barva (detaily)
# \033[34m - Modrá barva (průběh)

def clear_screen():
    """Vymaže obrazovku terminálu."""
    os.system('clear' if os.name == 'posix' else 'cls')

def get_wifi_scan_results():
    """
    Spustí termux-wifi-scaninfo a vrátí JSON výstup.
    """
    try:
        # Spuštění termux-wifi-scaninfo a zachycení výstupu
        result = subprocess.run(['termux-wifi-scaninfo'], capture_output=True, text=True, check=True)
        # Parsujeme JSON výstup
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("\033[31m[-] Chyba: 'termux-wifi-scaninfo' nebyl nalezen.")
        print("    Ujistěte se, že máte nainstalovaný 'termux-api' (pkg install termux-api).\033[0m")
        return None
    except subprocess.CalledProcessError as e:
        print(f"\033[31m[-] Chyba při spouštění 'termux-wifi-scaninfo': {e}\033[0m")
        print(f"    Chybový výstup: {e.stderr}")
        return None
    except json.JSONDecodeError:
        print("\033[31m[-] Chyba: Nelze parsovat JSON výstup z 'termux-wifi-scaninfo'.\033[0m")
        return None
    except Exception as e:
        print(f"\033[31m[-] Vyskytla se neočekávaná chyba při získávání výsledků skenování: {e}\033[0m")
        return None

def get_signal_color(rssi):
    """Vrátí ANSI barvu na základě síly signálu (RSSI)."""
    # RSSI by zde již mělo být int
    if rssi >= -50:
        return "\033[32m" # Zelená (výborný)
    elif rssi >= -70:
        return "\033[33m" # Žlutá (dobrý)
    else:
        return "\033[31m" # Červená (slabý)

def display_wifi_networks(networks, filter_options, sort_by):
    """
    Zobrazí seznam Wi-Fi sítí s aplikovanými filtry a řazením.
    """
    processed_networks = []
    for net in networks:
        ssid = net.get('ssid', 'Neznámé SSID')
        bssid = net.get('bssid', 'Neznámé BSSID')
        capabilities = net.get('capabilities', 'Neznámé zabezpečení')
        
        # --- Robustní konverze RSSI a frekvence ---
        # Zpracování RSSI
        original_rssi_str = net.get('level', 'N/A')
        try:
            # Pokusíme se převést na int, pokud je to možné
            rssi_val = int(str(original_rssi_str).strip()) 
        except (ValueError, TypeError):
            # Pokud konverze selže (např. je to "N/A" nebo prázdné), použijeme velmi nízkou hodnotu
            # pro účely řazení/filtrování, ale pro zobrazení ponecháme "N/A"
            rssi_val = -1000 # Velmi nízká hodnota, aby se to řadilo na konec
            
        # Zpracování frekvence
        original_frequency_val = net.get('frequency', 'N/A')
        try:
            frequency_val = int(str(original_frequency_val).strip())
        except (ValueError, TypeError):
            frequency_val = 0 # Použijeme 0 pro interní zpracování, pokud chybí
        
        # Přidáme zpracované hodnoty do slovníku sítě pro konzistentní přístup
        net['processed_rssi'] = rssi_val
        net['display_rssi'] = original_rssi_str # Uložíme původní string pro zobrazení
        net['processed_frequency'] = frequency_val
        net['display_frequency'] = original_frequency_val # Uložíme původní string pro zobrazení

        # Aplikace filtrů
        if filter_options['ssid'] and filter_options['ssid'].lower() not in ssid.lower():
            continue
        if filter_options['bssid'] and filter_options['bssid'].lower() not in bssid.lower():
            continue
        if filter_options['security'] and filter_options['security'].lower() not in capabilities.lower():
            continue
        # Nyní porovnáváme s processed_rssi, které je vždy int
        if filter_options['min_rssi'] is not None and net['processed_rssi'] < filter_options['min_rssi']:
            continue
        
        processed_networks.append(net)
    
    # Řazení
    if sort_by == 'rssi':
        # Používáme již zpracovanou int hodnotu RSSI pro řazení
        processed_networks.sort(key=lambda x: x['processed_rssi'], reverse=True)
    elif sort_by == 'ssid':
        processed_networks.sort(key=lambda x: x.get('ssid', '').lower())

    print(f"\n{os.linesep}\033[1m--- Nalezené Wi-Fi sítě ({len(processed_networks)}/{len(networks)} celkem) ---\033[0m")
    if not processed_networks:
        print("  Žádné sítě neodpovídají zadaným kritériím.")
        return

    for net in processed_networks:
        ssid = net.get('ssid', 'Neznámé SSID')
        bssid = net.get('bssid', 'Neznámé BSSID')
        capabilities = net.get('capabilities', 'Neznámé zabezpečení')
        
        # Používáme hodnoty pro zobrazení
        rssi_display = net['display_rssi']
        rssi_for_color = net['processed_rssi'] # Použijeme numerickou hodnotu pro barvu
        frequency_display = net['display_frequency']
        frequency_val = net['processed_frequency'] # Použijeme numerickou hodnotu pro kanál
        
        channel = ""
        # Přibližný výpočet kanálu z frekvence (pouze pro 2.4 GHz)
        if 2412 <= frequency_val <= 2484:
            channel = f" (Kanál {(frequency_val - 2412) // 5 + 1})"
        elif 5180 <= frequency_val <= 5825:
             # Pro 5GHz je to složitější, jen pro informaci
            channel = f" (5GHz pásmo)"

        color = get_signal_color(rssi_for_color) # Předáváme int hodnotu pro barvu
        
        print(f"  {color}SSID: {ssid}\033[0m")
        print(f"    \033[35mBSSID:\033[0m {bssid}")
        print(f"    \033[35mRSSI:\033[0m {rssi_display} dBm {color}({get_signal_color(rssi_for_color).strip('\033[')[:-1]}Signál)\033[0m")
        print(f"    \033[35mFrekvence:\033[0m {frequency_display} MHz{channel}")
        print(f"    \033[35mZabezpečení:\033[0m {capabilities}\n")
    
    print("\n" + "=" * (os.get_terminal_size().columns - 1) if os.get_terminal_size().columns > 1 else "=")


def main():
    """Hlavní funkce pro spuštění WifiScan."""
    try:
        while True:
            clear_screen()
            print(ascii_logo)
            print("\n--- Pokročilý Wi-Fi Skener ---")
            print("\n\033[31m!!! DŮLEŽITÉ ETIKÉ UPOZORNĚNÍ !!!\033[0m")
            print("\033[31m!!! Tento nástroj je určen POUZE pro legální účely, jako je optimalizace vaší vlastní sítě, zjišťování informací o veřejných sítích, nebo pro testování, ke kterému máte VÝSLOVNÉ POVOLENÍ. !!!\033[0m")
            print("\033[31m!!! Zneužití pro neoprávněný přístup nebo narušení soukromí je NEZÁKONNÉ a NEETICKÉ. !!!\033[0m")

            # --- Interaktivní volby filtru a řazení ---
            filter_ssid = input("\nFiltr dle SSID (název sítě, prázdné pro vše): ").strip()
            filter_bssid = input("Filtr dle BSSID (MAC adresa, prázdné pro vše): ").strip()
            filter_security = input("Filtr dle zabezpečení (např. WPA2, WPA3, WEP, prázdné pro vše): ").strip()
            
            min_rssi = None
            while True:
                rssi_input = input("Minimální síla signálu RSSI (např. -70, prázdné pro vše): ").strip()
                if not rssi_input:
                    break
                try:
                    min_rssi = int(rssi_input)
                    break
                except ValueError:
                    print("\033[31mNeplatný vstup. Zadejte prosím celé číslo (např. -70).\033[0m")

            filter_options = {
                'ssid': filter_ssid,
                'bssid': filter_bssid,
                'security': filter_security,
                'min_rssi': min_rssi
            }

            sort_by = ""
            while sort_by not in ['rssi', 'ssid', '']:
                sort_by = input("Seřadit podle (rssi pro sílu signálu, ssid pro název, prázdné pro bez řazení): ").lower().strip()
                if sort_by not in ['rssi', 'ssid', '']:
                    print("\033[31mNeplatná volba. Zadejte 'rssi', 'ssid' nebo nechte prázdné.\033[0m")

            continuous_scan = input("Provádět nepřetržité skenování? (a/n, výchozí n): ").lower().startswith('a')
            scan_interval = 0
            if continuous_scan:
                while True:
                    try:
                        interval_input = input("Interval skenování v sekundách (např. 5, výchozí 10): ").strip()
                        if not interval_input:
                            scan_interval = 10
                        else:
                            scan_interval = int(interval_input)
                        if scan_interval <= 0:
                            print("\033[31mInterval musí být kladné číslo.\033[0m")
                        else:
                            break
                    except ValueError:
                        print("\033[31mNeplatný vstup. Zadejte prosím celé číslo.\033[0m")

            if continuous_scan:
                print(f"\n\033[33m[*] Spouštím nepřetržité skenování každých {scan_interval} sekund. Pro ukončení stiskněte Ctrl+C.\033[0m")
                while True:
                    networks = get_wifi_scan_results()
                    if networks:
                        clear_screen() # Vyčistit obrazovku pro nový výstup
                        print(ascii_logo)
                        print("\n--- Pokročilý Wi-Fi Skener (Nepřetržitý režim) ---")
                        display_wifi_networks(networks, filter_options, sort_by)
                    else:
                        print("\033[31m[-] Nelze získat výsledky skenování. Zkontrolujte termux-api a oprávnění.\033[0m")
                    time.sleep(scan_interval)
            else:
                networks = get_wifi_scan_results()
                if networks:
                    display_wifi_networks(networks, filter_options, sort_by)
                else:
                    print("\033[31m[-] Nelze získat výsledky skenování. Zkontrolujte termux-api a oprávnění.\033[0m")
                
                input("\nStiskněte Enter pro nové skenování, nebo 'konec'...")
                if input().lower() == 'konec':
                    print("Ukončuji Wi-Fi Skener. Na shledanou!")
                    break

    except KeyboardInterrupt:
        print("\nProgram byl ukončen uživatelem.")
    except Exception as e:
        print(f"\n\033[31m❌ Vyskytla se kritická chyba: {e}\033[0m")
    finally:
        sys.stdout.write("\033[0m\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()

