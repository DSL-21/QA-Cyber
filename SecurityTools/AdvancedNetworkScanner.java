package SecurityTools;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class AdvancedNetworkScanner {

	private static final int THREAD_POOL_SIZE = 50; // Počet vláken pro paralelní skenování
	private static final int DEFAULT_TIMEOUT_MS = 500; // Výchozí timeout pro připojení
	private static final String RESULTS_FILE = "scan_results.txt";

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		// *** VELMI DŮLEŽITÉ ETIKEcké UPOZORNĚNÍ ***
		System.out.println("**********************************************************************************");
		System.out.println("!!! UPOZORNĚNÍ: Toto je nástroj pro vzdělávací a demonstrativní účely !!!");
		System.out.println("!!! NIKDY NEPOUŽÍVEJTE tento kód pro neoprávněné skenování sítí !!!");
		System.out.println("!!! Neoprávněné skenování je NELEGÁLNÍ a může vést k VÁŽNÝM PRÁVNÍM DŮSLEDKŮM !!!");
		System.out.println("!!! Testujte POUZE na systémech, k nimž máte VÝSLOVNÉ, PÍSEMNÉ POVOLENÍ od vlastníka. !!!");
		System.out.println("**********************************************************************************\n");

		System.out.println("--- Pokročilý Síťový Skener ---");

		System.out.println("Zadejte IP adresu nebo rozsah IP adres (např. 127.0.0.1 nebo 192.168.1.1-192.168.1.254):");
		String ipRange = scanner.nextLine().trim();

		System.out.println("Zadejte počáteční port pro skenování (např. 1):");
		int startPort = readIntInput(scanner, 1, 65535, 1);

		System.out.println("Zadejte koncový port pro skenování (např. 1024):");
		int endPort = readIntInput(scanner, startPort, 65535, 1024);

		System.out.println("Zadejte časový limit pro připojení k portu v milisekundách (např. 500):");
		int timeout = readIntInput(scanner, 1, Integer.MAX_VALUE, DEFAULT_TIMEOUT_MS);

		System.out.println("Chcete provést Banner Grabbing na otevřených portech? (ano/ne):");
		boolean doBannerGrabbing = scanner.nextLine().trim().equalsIgnoreCase("ano");

		List<String> ipsToScan = parseIpRange(ipRange);
		if (ipsToScan.isEmpty()) {
			System.err.println("❌ Chyba: Neplatný formát IP adresy nebo rozsahu.");
			scanner.close();
			return;
		}

		System.out.println("\nSpouštím skenování na " + ipsToScan.size() + " IP adresách, od portu " + startPort
				+ " do " + endPort + "...");

		long startTime = System.currentTimeMillis();
		ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
		AtomicInteger openPortsCount = new AtomicInteger(0);

		List<String> results = new ArrayList<>();
		results.add("--- Výsledky skenování ---");
		results.add("Čas spuštění: " + new java.util.Date());
		results.add("Skenovaný rozsah IP: " + ipRange);
		results.add("Skenované porty: " + startPort + "-" + endPort);
		results.add("Timeout: " + timeout + "ms");
		results.add("Banner Grabbing: " + (doBannerGrabbing ? "Ano" : "Ne"));
		results.add("-------------------------\n");

		for (String ip : ipsToScan) {
			for (int port = startPort; port <= endPort; port++) {
				final String currentIp = ip;
				final int currentPort = port;
				executor.submit(() -> {
					try {
						Socket socket = new Socket();
						socket.connect(new InetSocketAddress(currentIp, currentPort), timeout);
						socket.close();
						String message = "✅ Host: " + currentIp + ", Port: " + currentPort + " je OTEVŘENÝ";
						if (doBannerGrabbing) {
							String banner = grabBanner(currentIp, currentPort, timeout);
							if (banner != null && !banner.isEmpty()) {
								message += " | Banner: " + banner;
							} else {
								message += " | Banner: N/A";
							}
						}
						System.out.println(message);
						results.add(message);
						openPortsCount.incrementAndGet();

					} catch (SocketTimeoutException e) {
						// System.out.println("Host: " + currentIp + ", Port: " + currentPort + " je
						// FILTROVANÝ (timeout)");
					} catch (IOException e) {
						// System.out.println("Host: " + currentIp + ", Port: " + currentPort + " je
						// ZAVŘENÝ nebo CHYBA: " + e.getMessage());
					} catch (SecurityException e) {
						System.err.println("❌ Host: " + currentIp + ", Port: " + currentPort
								+ " - Chyba zabezpečení (nedostatečná oprávnění): " + e.getMessage());
					} catch (IllegalArgumentException e) {
						System.err.println("❌ Host: " + currentIp + ", Chyba: Neplatný port " + currentPort + ": "
								+ e.getMessage());
					}
				});
			}
		}

		executor.shutdown(); // Ukončí přidávání nových úloh
		try {
			// Čeká, dokud se všechny úlohy nedokončí, nebo dokud nevyprší čas
			System.out.println("\nČekám na dokončení skenování (to může trvat delší dobu)...");
			executor.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS); // Čeká prakticky neomezeně
		} catch (InterruptedException e) {
			System.err.println("Skenování bylo přerušeno.");
		}

		long endTime = System.currentTimeMillis();
		long durationMs = (endTime - startTime);

		System.out.println("\n--- Pokročilé síťové skenování dokončeno ---");
		System.out.println("Celkový čas trvání: " + (durationMs / 1000.0) + " sekund.");
		System.out.println("Nalezeno otevřených portů: " + openPortsCount.get());
		System.out.println("Výsledky jsou uloženy do souboru: " + RESULTS_FILE);

		// Uložení výsledků do souboru
		try (PrintWriter writer = new PrintWriter(new FileWriter(RESULTS_FILE))) {
			for (String line : results) {
				writer.println(line);
			}
			writer.println("\n--- Konec výsledků ---");
		} catch (IOException e) {
			System.err.println("❌ Chyba při ukládání výsledků do souboru: " + e.getMessage());
		}

		scanner.close();
	}

	/**
	 * Vypočítá a vrátí další IP adresu v sekvenci. Předpokládá platnou IPv4 adresu.
	 */
	private static String getNextIp(String ipAddress) {
		try {
			byte[] ipBytes = InetAddress.getByName(ipAddress).getAddress();
			for (int i = ipBytes.length - 1; i >= 0; i--) {
				if (ipBytes[i] == (byte) 0xFF) {
					ipBytes[i] = 0;
				} else {
					ipBytes[i]++;
					break;
				}
			}
			return InetAddress.getByAddress(ipBytes).getHostAddress();
		} catch (UnknownHostException e) {
			return null; // Mělo by se řešit už při parsování
		}
	}

	/**
	 * Parsuje vstup uživatele pro IP adresy nebo rozsah IP adres.
	 */
	private static List<String> parseIpRange(String ipRange) {
		List<String> ips = new ArrayList<>();
		if (ipRange.contains("-")) {
			String[] parts = ipRange.split("-");
			if (parts.length != 2)
				return ips; // Neplatný formát rozsahu

			String startIp = parts[0].trim();
			String endIp = parts[1].trim();

			try {
				InetAddress start = InetAddress.getByName(startIp);
				InetAddress end = InetAddress.getByName(endIp);

				if (start.getAddress().length != 4 || end.getAddress().length != 4) {
					System.err.println("Podporováno je pouze IPv4.");
					return ips;
				}

				String currentIp = startIp;
				while (true) {
					ips.add(currentIp);
					if (currentIp.equals(endIp)) {
						break;
					}
					currentIp = getNextIp(currentIp);
					if (currentIp == null || !isIpInRange(currentIp, start, end)) { // Prevence nekonečné smyčky
						break;
					}
				}
			} catch (UnknownHostException e) {
				return ips; // Neplatná IP adresa v rozsahu
			}
		} else {
			// Jedna IP adresa
			try {
				InetAddress.getByName(ipRange); // Zkusí ji validovat
				ips.add(ipRange);
			} catch (UnknownHostException e) {
				// Není platná IP
			}
		}
		return ips;
	}

	/**
	 * Pomocná metoda pro kontrolu, zda je IP v rozsahu (pro getNextIp).
	 */
	private static boolean isIpInRange(String ipStr, InetAddress start, InetAddress end) {
		try {
			byte[] currentBytes = InetAddress.getByName(ipStr).getAddress();
			byte[] startBytes = start.getAddress();
			byte[] endBytes = end.getAddress();

			// Porovnání jako unsigned byty
			for (int i = 0; i < 4; i++) {
				int c = currentBytes[i] & 0xFF;
				int s = startBytes[i] & 0xFF;
				int e = endBytes[i] & 0xFF;

				if (c < s && i <= 3)
					return false; // Není v rozsahu (nižší než start)
				if (c > e && i <= 3)
					return false; // Není v rozsahu (vyšší než end)
				if (c > s && c < e)
					return true; // Je jasně v rozsahu
			}
			return true; // Je rovno startu nebo endu
		} catch (UnknownHostException e) {
			return false;
		}
	}

	/**
	 * Pokusí se získat banner z otevřeného portu.
	 * 
	 * @param ip      IP adresa cíle.
	 * @param port    Port, ze kterého se má získat banner.
	 * @param timeout Timeout pro připojení a čtení.
	 * @return Získaný banner nebo prázdný řetězec.
	 */
	private static String grabBanner(String ip, int port, int timeout) {
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress(ip, port), timeout);
			socket.setSoTimeout(timeout); // Timeout pro čtení

			// Pokus o čtení prvních pár řádků
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
				StringBuilder banner = new StringBuilder();
				// Odeslání CRLF, aby některé služby poslaly banner
				PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
				writer.println("\r\n");
				writer.flush(); // Zajištění odeslání požadavku

				char[] buffer = new char[1024];
				int bytesRead = reader.read(buffer, 0, buffer.length); // Pokusí se přečíst data

				if (bytesRead != -1) {
					banner.append(buffer, 0, bytesRead);
				}

				String bannerStr = banner.toString().trim();
				// Omezení délky banneru pro čitelnost
				return bannerStr.length() > 100 ? bannerStr.substring(0, 100) + "..." : bannerStr;

			} catch (SocketTimeoutException e) {
				// Připojení OK, ale nic se nečetlo v daném timeoutu (časté u HTTP)
				return "No banner (read timeout)";
			} catch (IOException e) {
				return "No banner (read error)"; // Chyba při čtení
			}
		} catch (IOException e) {
			// Chyba při připojení (už by mělo být zachyceno v main metodě jako "otevřený
			// port")
			return null; // Nemělo by se stávat, pokud je port opravdu otevřený
		}
	}

	/**
	 * Bezpečné čtení celého čísla z konzole s validací.
	 */
	private static int readIntInput(Scanner scanner, int min, int max, int defaultValue) {
		int value;
		while (true) {
			try {
				value = Integer.parseInt(scanner.nextLine());
				if (value >= min && value <= max) {
					return value;
				} else {
					System.out.println(
							"Zadejte číslo v rozsahu " + min + " až " + max + ". (Výchozí: " + defaultValue + "):");
				}
			} catch (NumberFormatException e) {
				System.out.println("Neplatné číslo. Zadejte platné číslo. (Výchozí: " + defaultValue + "):");
			}
		}
	}
}