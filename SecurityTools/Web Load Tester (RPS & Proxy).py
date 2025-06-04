# -*- coding: utf-8 -*-
# Python 3

# --- Importujeme knihovny, které nám pomáhají pracovat se sítí a řídit program ---
# Každá knihovna přidává do našeho Python programu nové schopnosti.

import requests  # ❤️ Toto je nejdůležitější knihovna! Umožňuje nám snadno posílat HTTP požadavky,
                 # jako by to dělal webový prohlížeč (GET, POST atd.).
import time      # Pomáhá nám pracovat s časem – například "uspat" program na chvíli (sleep)
                 # nebo změřit, jak dlouho něco trvalo (time.time()).
import threading # Umožňuje nám spouštět více částí kódu najednou (vícevláknové programování).
                 # To je klíčové pro odesílání mnoha požadavků paralelně.
import sys       # Modul pro interakci se systémem. Používáme ho hlavně pro tisk chybových zpráv
                 # nebo pro aktuální stav na stejný řádek (sys.stdout.write).
import queue     # Pomáhá nám s "frontami". Představ si to jako řadu lidí čekajících na lístek.
                 # Použijeme to k řízení, kolik požadavků se odešle za sekundu (RPS).
import random    # (Aktuálně není použit, ale může se hodit pro budoucí rozšíření, např. náhodné zpoždění.)

# --- Vizuálně Atraktivnější Etický Disclaimer ---
# Toto upozornění je naprosto KLÍČOVÉ! Přečti si ho pečlivě a rozuměj mu.
# Jeho cílem je zajistit, abys kód používal/a zodpovědně a legálně.
print("""
#####################################################################################################
#                                                                                                   #
#                             ❗ DŮLEŽITÉ ETICKÉ A PRÁVNÍ UPOZORNĚNÍ ❗                            #
#                                                                                                   #
#           Tento kód je vytvořen **výhradně pro vzdělávací a demonstrativní účely**.               #
#                                                                                                   #
#           Jeho cílem je ukázat, jak lze programovat síťové zátěžové testy.                        #
#           **NIKDY** nepoužívejte tento kód k testování systémů, které nevlastníte,                #
#           nebo k nimž nemáte **VÝSLOVNÉ, PÍSEMNÉ POVOLENÍ** od vlastníka.                         #
#                                                                                                   #
#           **Jakékoli neoprávněné použití je nelegální a může mít vážné právní následky,**         #
#           **včetně vysokých pokut a trestu odnětí svobody.**                                      #
#                                                                                                   #
#           **Za jakékoli zneužití tohoto kódu nesete plnou zodpovědnost VY.**                      #
#           Autor tohoto kódu (a ani nástroj, který ho vygeneroval) nenesou                         #
#           žádnou odpovědnost za jeho nesprávné nebo nelegální použití.                            #
#                                                                                                   #
#####################################################################################################
""")

# --- Globální proměnné pro sběr statistik ---
# Tyto proměnné jsou "globální", což znamená, že k nim má přístup a může je měnit
# jakákoli část našeho programu (včetně různých vláken).
# Používáme 'threading.Lock()' k ochraně těchto proměnných, aby se zabránilo chybám,
# když se více vláken snaží aktualizovat stejnou proměnnou najednou.
success_count = 0         # Počet úspěšně dokončených požadavků (server odpověděl status kódem 2xx).
fail_count = 0            # Počet neúspěšných požadavků (chybný status kód, vypršel čas, síťová chyba).
total_response_time = 0.0 # Celkový součet dob odezvy všech požadavků (v milisekundách).
sent_requests = 0         # Celkový počet požadavků, které jsme se pokusili odeslat.
lock = threading.Lock()   # Toto je "zámek" – pokud jedno vlákno používá proměnné chráněné zámkem,
                          # ostatní vlákna musí počkat, dokud zámek neuvolní.

# --- Fronta pro řízení počtu požadavků za sekundu (RPS) ---
# Tato fronta nám pomáhá "dávkovat" požadavky a udržet je pod nastaveným limitem RPS.
request_queue = queue.Queue() # Vytváříme prázdnou frontu, kam budeme dávat "tokeny" (povolení k odeslání požadavku).
rps_limit = 0                 # Zde si uložíme maximální RPS, které uživatel zadá.
                              # Pokud je 0, znamená to, že neomezujeme rychlost.
stop_event = threading.Event() # Speciální "praporek" (událost). Když ho nastavíme,
                               # dáme tím vědět všem vláknům, že se mají připravit na ukončení práce.

def read_int_input(prompt, min_val, max_val, default_val):
    """
    Tato funkce se stará o to, abychom od uživatele dostali platné číslo.
    Je "bezpečná", protože kontroluje, zda uživatel zadal číslo a zda je v povoleném rozsahu.

    :param prompt: Text, který se uživateli zobrazí (např. "Zadej počet: ").
    :param min_val: Nejnižší povolené číslo.
    :param max_val: Nejvyšší povolené číslo.
    :param default_val: Hodnota, která se použije, když uživatel nic nezadá (jen stiskne Enter).
    :return: Platné celé číslo zadané uživatelem nebo předvolená hodnota.
    """
    while True: # Nekonečná smyčka, která se opakuje, dokud nedostaneme platný vstup.
        value = input(prompt) # Zobrazí se "prompt" a program čeká na to, co uživatel napíše.
        if not value: # Pokud uživatel nic nenapsal (stiskl jen Enter).
            print(f"  Používám výchozí hodnotu: {default_val}")
            return default_val # Vrátíme výchozí hodnotu a opustíme funkci.
        try:
            value = int(value) # Zkusíme text od uživatele převést na celé číslo.
            if min_val <= value <= max_val: # Zkontrolujeme, zda je číslo mezi minimem a maximem.
                return value # Pokud je všechno v pořádku, vrátíme číslo.
            else:
                # Pokud je číslo mimo rozsah, upozorníme uživatele a zopakujeme dotaz.
                print(f"  Zadejte číslo v rozsahu {min_val} až {max_val}. (Výchozí: {default_val})")
        except ValueError:
            # Pokud uživatel zadal text místo čísla (např. "ahoj"), upozorníme ho.
            print("  Neplatné číslo. Zadejte prosím platné celé číslo.")

def worker_thread(target_url, http_method, request_body, custom_headers, proxy_config):
    """
    Tato funkce je srdcem našeho testeru. Každé spuštěné vlákno vykonává právě tuto funkci.
    Je to "dělník", který posílá HTTP požadavky.

    :param target_url: Webová adresa, na kterou budeme posílat požadavky.
    :param http_method: Typ HTTP požadavku (např. "GET" pro získání dat, "POST" pro odeslání dat).
    :param request_body: Data, která se posílají s požadavky POST, PUT atd. (např. JSON data).
    :param custom_headers: Speciální informace, které chceme poslat serveru (např. "User-Agent").
    :param proxy_config: Nastavení proxy serveru, pokud ho chceme použít.
    """
    global success_count, fail_count, total_response_time, sent_requests # Říkáme Pythonu, že budeme měnit tyto globální proměnné.

    # Toto je hlavní smyčka vlákna. Běží tak dlouho, dokud není nastaven "stop_event".
    while not stop_event.is_set():
        try:
            # --- Řízení RPS: Čekáme na "token" z fronty ---
            # Vlákno se pokusí získat token z 'request_queue'.
            # Pokud není k dispozici, počká max. 1 sekundu (`timeout=1`).
            # Tím se zajistí, že pokud RPS limiter nikoho nepustí, vlákno nezamrzne a může zkontrolovat, zda se má ukončit.
            request_queue.get(timeout=1)

            start_time = time.time() # Zaznamenáme přesný čas, kdy začínáme s požadavkem.
            response = None          # Proměnná pro uložení odpovědi, kterou dostaneme od serveru.

            try:
                # --- Odeslání HTTP požadavku ---
                # Knihovna 'requests' je super! Podle HTTP metody automaticky zavoláme správnou funkci.
                # 'timeout_settings' určuje, jak dlouho budeme čekat na připojení a odpověď.
                timeout_settings = (10, 10) # 10 sekund na připojení, 10 sekund na přečtení odpovědi.

                if http_method.upper() == "GET":
                    response = requests.get(target_url, headers=custom_headers, proxies=proxy_config, timeout=timeout_settings)
                elif http_method.upper() == "POST":
                    response = requests.post(target_url, data=request_body, headers=custom_headers, proxies=proxy_config, timeout=timeout_settings)
                elif http_method.upper() == "PUT":
                    response = requests.put(target_url, data=request_body, headers=custom_headers, proxies=proxy_config, timeout=timeout_settings)
                elif http_method.upper() == "DELETE":
                    response = requests.delete(target_url, headers=custom_headers, proxies=proxy_config, timeout=timeout_settings)
                else: # Pro jiné metody (např. HEAD, OPTIONS, PATCH), které nejsou tak běžné.
                    response = requests.request(http_method.upper(), target_url, data=request_body, headers=custom_headers, proxies=proxy_config, timeout=timeout_settings)

                end_time = time.time() # Zaznamenáme čas, kdy jsme dostali celou odpověď.
                response_time = (end_time - start_time) * 1000 # Vypočítáme, jak dlouho to trvalo (v milisekundách).

                # --- Aktualizace globálních statistik (chráněno zámkem!) ---
                # Aby se dvě vlákna navzájem nepřepisovala, použijeme náš 'lock'.
                with lock: # Vše, co je uvnitř 'with lock:', je bezpečné, protože k tomu má přístup jen jedno vlákno najednou.
                    sent_requests += 1 # Zvýšíme počet odeslaných požadavků.
                    total_response_time += response_time # Přidáme dobu odezvy k celkovému součtu.
                    if 200 <= response.status_code < 300: # Pokud status kód začíná 2xx (např. 200 OK), je to úspěch.
                        success_count += 1
                    else: # Jinak to považujeme za selhání (např. 404 Not Found, 500 Internal Server Error).
                        fail_count += 1
                        # print(f"❌ Chyba status kódu ({response.status_code}): {target_url}", file=sys.stderr) # Odkomentuj pro detailní ladění chyb.

            # --- Zachycení chyb při požadavku ---
            except requests.exceptions.RequestException as e: # Zachytí všechny chyby související s knihovnou 'requests' (např. server neodpovídá).
                end_time = time.time()
                response_time = (end_time - start_time) * 1000
                with lock: # Opět chráníme naše statistiky.
                    fail_count += 1 # Započítáme jako selhání.
                    sent_requests += 1 # I neúspěšný pokus je pokus o odeslání.
                    # print(f"❌ Chyba při požadavku: {e}", file=sys.stderr) # Odkomentuj pro detailní ladění chyb.
            finally:
                if response:
                    # Toto zajistí, že spojení se serverem je řádně uzavřeno a uvolní se zdroje.
                    response.close()

            # --- Označení úkolu jako dokončeného ---
            request_queue.task_done() # Důležité! Řekneme frontě, že jsme dokončili práci s tokenem.
                                      # Metoda `request_queue.join()` pak ví, kdy už jsou všechny tokeny zpracovány.

        except queue.Empty:
            # Pokud 'request_queue.get(timeout=1)' vyprší timeout a fronta je prázdná,
            # znamená to, že RPS limiter zatím nedodal žádné nové tokeny.
            # Vlákno se pak vrátí na začátek smyčky `while` a zkontroluje 'stop_event'.
            pass # Tady nic neděláme, jen necháme vlákno pokračovat v cyklu.
        except Exception as e:
            # Zachycení jakékoli neočekávané (a vážné) chyby ve vlákně.
            print(f"Neočekávaná kritická chyba ve vlákně: {e}", file=sys.stderr)
            stop_event.set() # Dáme signál pro zastavení VŠECH vláken, abychom předešli dalším problémům.
            break # Ukončíme toto konkrétní chybné vlákno.


def rps_limiter_thread():
    """
    Tato funkce běží v samostatném vlákně a je jako "dodavatel tokenů".
    Její práce je dodávat tokeny do 'request_queue' přesně tak rychle,
    aby se dodržel uživatelem nastavený limit RPS.
    """
    global request_queue, rps_limit # Přístup k globálním proměnným.

    if rps_limit <= 0: # Pokud uživatel zadal RPS 0 (žádné omezení), toto vlákno se nemusí spouštět.
        return

    tokens_per_second = rps_limit   # Kolik tokenů chceme přidat do fronty za každou sekundu.
    interval = 1.0 / tokens_per_second # Jak dlouho (v sekundách) bychom měli čekat mezi jednotlivými tokeny.
                                     # Např. pro 100 RPS je interval 1.0/100 = 0.01 sekundy.

    last_put_time = time.time() # Zaznamenáme čas, kdy byl naposledy token přidán.

    while not stop_event.is_set(): # Smyčka běží, dokud nedostaneme signál k ukončení.
        current_time = time.time() # Aktuální čas.

        # Spočítáme, kolik tokenů bychom měli přidat od posledního přidání,
        # na základě uplynulého času a našeho 'intervalu'.
        tokens_to_add = int((current_time - last_put_time) / interval)

        if tokens_to_add > 0: # Pokud bychom měli přidat alespoň jeden token.
            for _ in range(tokens_to_add): # Pro každý vypočítaný token.
                if not stop_event.is_set(): # Znovu kontrolujeme 'stop_event', abychom se mohli ukončit i během této smyčky.
                    try:
                        request_queue.put_nowait(1) # Vložíme token (hodnotu '1') do fronty.
                                                   # `put_nowait` znamená, že nečekáme, pokud je fronta plná.
                                                   # V ideálním případě fronta nebude plná, protože pracovní vlákna tokeny odebírají.
                    except queue.Full:
                        # Pokud by se fronta z nějakého důvodu zaplnila (což by nemělo být při správném řízení),
                        # prostě tento token přeskočíme a budeme pokračovat.
                        pass
                else:
                    break # Pokud dostaneme signál k ukončení, přerušíme tuto vnitřní smyčku.
            last_put_time = current_time # Resetujeme čas, kdy jsme naposledy přidávali tokeny.

        # Spíme na krátkou dobu, abychom nezatěžovali procesor neustálým ověřováním času.
        # Spíme polovinu intervalu tokenu, nebo velmi krátkou dobu (0.001 sekundy), pokud je interval velmi malý.
        time.sleep(interval / 2 if interval > 0 else 0.001)

def main():
    """
    Hlavní funkce programu, která řídí celý průběh zátěžového testu.
    Zde se ptáme uživatele na nastavení, spouštíme vlákna a zobrazujeme výsledky.
    """
    # Získání přístupu k globálním proměnným, které budou modifikovány touto funkcí.
    global success_count, fail_count, total_response_time, sent_requests, rps_limit

    # V Pythonu je 'input()' přímo funkce pro čtení z konzole.
    scanner = input

    print("\n--- Pokročilý Webový Zátěžový Tester (s RPS a Proxy) ---\n")

    # --- Získání vstupních parametrů od uživatele ---
    # .strip() na konci odstraní mezery z začátku a konce textu, který uživatel zadá.
    target_url = scanner("  Zadejte cílovou URL (např. http://localhost:8080/): ").strip()

    # Používáme naši funkci `read_int_input` pro bezpečné získání čísel.
    # 'sys.maxsize' je největší možné celé číslo v Pythonu, takže neomezujeme shora.
    num_requests = read_int_input("  Zadejte počet CELKOVÝCH požadavků, které chcete odeslat (např. 1000): ", 1, sys.maxsize, 1000)
    concurrent_users = read_int_input("  Zadejte počet SOUBĚŽNÝCH uživatelů/vláken (např. 10 pro 10 požadavků najednou): ", 1, sys.maxsize, 10)
    rps_limit = read_int_input("  Zadejte maximální počet POŽADAVKŮ ZA SEKUNDU (RPS). Zadejte 0 pro maximální rychlost bez omezení: ", 0, sys.maxsize, 0)

    http_method = scanner("  Zadejte HTTP metodu (GET, POST, PUT, DELETE, HEAD, OPTIONS, ...): ").strip().upper()
    valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] # Seznam povolených metod.
    if http_method not in valid_methods: # Kontrola, zda uživatel zadal platnou metodu.
        print("  Neplatná HTTP metoda. Používám výchozí GET.")
        http_method = "GET"

    request_body = "" # Tělo požadavku (pro POST, PUT). Na začátku je prázdné.
    if http_method in ["POST", "PUT", "PATCH"]: # Pokud je metoda jedna z těch, které posílají data.
        request_body = scanner("  Zadejte tělo požadavku (např. JSON: {\"key\":\"value\"}). Pokud není potřeba, nechte prázdné: ")

    custom_headers = {} # Prázdný slovník (mapa) pro ukládání vlastních HTTP hlaviček.
    if scanner("  Chcete přidat vlastní HTTP hlavičky? (ano/ne): ").strip().lower() == "ano":
        print("  Zadávejte hlavičky ve formátu 'Název: Hodnota'. Pro ukončení zadejte prázdný řádek.")
        while True:
            header_line = scanner("  ").strip() # Získáme řádek hlavičky od uživatele.
            if not header_line: # Prázdný řádek znamená konec zadávání.
                break
            parts = header_line.split(":", 1) # Rozdělí řádek jen u prvního dvojtečkového znaku (např. "Content-Type: application/json").
            if len(parts) == 2:
                custom_headers[parts[0].strip()] = parts[1].strip() # Uloží název a hodnotu do slovníku.
            else:
                print("  Neplatný formát hlavičky. Zkuste 'Název: Hodnota'.")

    proxy_config = None # Proměnná pro uložení nastavení proxy serveru. Na začátku žádná proxy.
    if scanner("  Chcete použít HTTP proxy? (ano/ne): ").strip().lower() == "ano":
        proxy_host = scanner("  Zadejte IP/Hostname proxy serveru (např. 127.0.0.1): ").strip()
        proxy_port = read_int_input("  Zadejte port proxy serveru (např. 8080): ", 1, 65535, 8080)
        proxy_config = {
            "http": f"http://{proxy_host}:{proxy_port}",  # Konfigurace HTTP proxy pro obyčejné HTTP požadavky.
            "https": f"http://{proxy_host}:{proxy_port}" # Konfigurace HTTPS proxy (posíláme přes HTTP proxy) pro HTTPS požadavky.
        }

    # --- Souhrn nastavení před spuštěním testu ---
    print(f"\n🚀 Spouštím zátěžový test na: {target_url}")
    print(f"👥 Souběžných uživatelů (vláken): {concurrent_users}")
    print(f"⚡ Max RPS (Požadavků za sekundu): {'Bez omezení' if rps_limit == 0 else rps_limit}")
    if proxy_config:
        print(f"👻 Používám proxy server: {proxy_config['http']}")
    print("-" * 50) # Oddělovací čára pro lepší přehlednost.

    start_time_total = time.time() # Zaznamenáme přesný čas, kdy se celý test spustil.

    # --- Spuštění vlákna pro řízení RPS (pokud je limit nastaven) ---
    limiter_thread = None
    if rps_limit > 0: # Pokud uživatel zadal limit RPS (větší než 0).
        limiter_thread = threading.Thread(target=rps_limiter_thread) # Vytvoříme nové vlákno pro RPS limiter.
        limiter_thread.daemon = True # Nastavíme, že je to "daemon" vlákno – ukončí se samo, když skončí hlavní program.
        limiter_thread.start() # Spustíme toto vlákno.

        # Na začátku testu naplníme frontu "tokeny" pro první sekundu,
        # aby pracovní vlákna mohla hned začít odesílat požadavky bez čekání.
        for _ in range(rps_limit):
            request_queue.put_nowait(1) # Vložíme token do fronty. `put_nowait` znamená, že se nečeká, pokud by byla fronta plná.

    # --- Spuštění pracovních vláken ---
    threads = [] # Seznam, kam si uložíme všechna naše "pracovní" vlákna.
    for _ in range(concurrent_users): # Vytvoříme tolik pracovních vláken, kolik uživatel zadal.
        thread = threading.Thread(target=worker_thread, args=(target_url, http_method, request_body, custom_headers, proxy_config))
        thread.daemon = True # Také je nastavíme jako "daemon" vlákna.
        threads.append(thread) # Přidáme nové vlákno do našeho seznamu.
        thread.start() # A spustíme ho!

    # --- Hlavní smyčka pro "naplánování" celkového počtu požadavků ---
    # Tato smyčka NENÍ zodpovědná za rychlost odesílání (tu řídí RPS limiter).
    # Jen zajišťuje, že se celkem naplánuje 'num_requests' operací.
    for i in range(num_requests):
        if stop_event.is_set(): # Pokud bylo signalizováno ukončení (např. kvůli chybě), smyčku přerušíme.
            break

        if rps_limit == 0: # Pokud NEMÁME nastavený RPS limit.
            # Vkládáme tokeny do fronty, aby je pracovní vlákna mohla ihned zpracovat.
            # Metoda `put(1)` blokuje (čeká), pokud je fronta plná, což nepřímo omezuje rychlost
            # na základě počtu 'concurrent_users' (jakmile je fronta plná a všechna vlákna zaneprázdněna).
            request_queue.put(1)
        else:
            # Pokud je RPS limit nastaven (rps_limit > 0), nebudeme do fronty přidávat tokeny zde.
            # Celkové množství tokenů a jejich rychlost dávkování řídí výhradně `rps_limiter_thread`.
            # Hlavní smyčka pouze pokračuje dál a spoléhá na to, že `worker_thread`
            # si vezme tokeny, až budou k dispozici.
            pass

        # --- Průběžný výpis stavu ---
        # Abychom viděli, co se děje, budeme každých 100 požadavků (nebo na konci)
        # aktualizovat stav na stejný řádek konzole.
        if (i + 1) % 100 == 0 or (i + 1) == num_requests:
            sys.stdout.write(f"\rOdesláno: {sent_requests}/{num_requests} (Úspěšných: {success_count}, Chybných: {fail_count})")
            sys.stdout.flush() # Okamžitě vypíše text na konzoli.

    # --- Zajištění, že všechny požadavky byly zpracovány a všechna vlákna se ukončí ---
    print("\n\n⏱️ Čekám na dokončení všech požadavků a úklid vláken...")
    request_queue.join() # Zablokuje hlavní program, dokud všechny tokeny, které byly do fronty vloženy,
                         # nejsou označeny jako "dokončené" (pomocí `task_done()` ve `worker_thread`).

    stop_event.set() # Nyní, když jsou všechny úkoly zpracovány, nastavíme 'stop_event'.
                     # To dá signál všem běžícím vláknům (`worker_thread`, `rps_limiter_thread`),
                     # že se mají ukončit, protože jejich smyčka `while not stop_event.is_set():` se přeruší.

    # Počkáme, až se všechna vlákna skutečně ukončí. Nastavíme timeout (5 sekund),
    # aby program nezamrzl, pokud by se nějaké vlákno zaseklo.
    for thread in threads:
        thread.join(timeout=5)
    if limiter_thread:
        limiter_thread.join(timeout=5)

    # --- Výpočet a zobrazení závěrečných statistik ---
    end_time_total = time.time() # Zaznamenáme přesný čas, kdy test skončil.
    total_duration_seconds = end_time_total - start_time_total # Celková doba, po kterou test běžel.

    # Výpočty průměrné doby odezvy a skutečné propustnosti.
    # Podmínka `if sent_requests > 0` zabraňuje chybě dělení nulou, pokud žádné požadavky nebyly odeslány.
    average_response_time = (total_response_time / sent_requests) if sent_requests > 0 else 0
    requests_per_second_actual = sent_requests / total_duration_seconds if total_duration_seconds > 0 else 0

    print("\n--- ✅ Zátěžový test DOKONČEN! ✅ ---")
    print(f"📊 Celkem odesláno požadavků: {sent_requests}")
    print(f"👍 Úspěšné odpovědi (2xx): {success_count}")
    print(f"👎 Chybové odpovědi / Neúspěšné: {fail_count}")
    print(f"⏱️ Celkový čas trvání testu: {total_duration_seconds:.2f} sekund.") # '.2f' formátuje číslo na dvě desetinná místa.
    print(f"⚡ Průměrná doba odezvy: {average_response_time:.2f} ms.")
    print(f" throughput: {requests_per_second_actual:.2f} požadavků/sekundu.") # "throughput" je anglický výraz pro propustnost.

# --- Hlavní spouštěcí blok ---
# Tento blok kódu říká Pythonu: "Spusť funkci 'main()' pouze tehdy, když je tento skript
# spuštěn přímo (např. z příkazové řádky), ne když je importován do jiného Python souboru."
if __name__ == "__main__":
    main()
