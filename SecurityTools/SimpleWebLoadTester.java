package SecurityTools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI; // Nový import pro URI
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

public class SimpleWebLoadTester {

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		// *** VELMI DŮLEŽITÉ ETIKEcké UPOZORNĚNÍ ***
		System.out.println("**********************************************************************************");
		System.out.println("!!! UPOZORNĚNÍ: Toto je nástroj pro vzdělávací a demonstrativní účely !!!");
		System.out.println("!!! NIKDY NEPOUŽÍVEJTE tento kód pro neoprávněné zátěžové testování nebo DDoS útoky !!!");
		System.out.println("!!! Neoprávněné použití je NELEGÁLNÍ a může vést k VÁŽNÝM PRÁVNÍM DŮSLEDKŮM !!!");
		System.out.println("!!! Testujte POUZE na systémech, k nimž máte VÝSLOVNÉ, PÍSEMNÉ POVOLENÍ od vlastníka. !!!");
		System.out.println("**********************************************************************************\n");

		System.out.println("--- Jednoduchý Webový Zátěžový Tester ---");
		System.out.println("Zadejte cílovou URL (např. http://localhost:8080/):");
		String targetUrl = scanner.nextLine();

		System.out.println("Zadejte počet požadavků, které chcete odeslat (např. 100):");
		int numRequests = 0;
		try {
			numRequests = Integer.parseInt(scanner.nextLine());
			if (numRequests <= 0) {
				System.out.println("Počet požadavků musí být kladné číslo. Používám výchozí 10.");
				numRequests = 10;
			}
		} catch (NumberFormatException e) {
			System.out.println("Neplatný počet. Používám výchozí 10.");
			numRequests = 10;
		}

		System.out
				.println("Zadejte zpoždění mezi požadavky v milisekundách (např. 50 pro 50ms, 0 pro žádné zpoždění):");
		int delayMs = 0;
		try {
			delayMs = Integer.parseInt(scanner.nextLine());
			if (delayMs < 0)
				delayMs = 0;
		} catch (NumberFormatException e) {
			System.out.println("Neplatné zpoždění. Používám výchozí 0ms.");
			delayMs = 0;
		}

		System.out.println("\nSpouštím zátěžový test na " + targetUrl + " s " + numRequests + " požadavky...");

		long startTime = System.currentTimeMillis();
		AtomicInteger successCount = new AtomicInteger(0);
		AtomicInteger failCount = new AtomicInteger(0);

		for (int i = 0; i < numRequests; i++) {
			System.out.print("Odesílám požadavek #" + (i + 1) + "... ");
			HttpURLConnection connection = null; // Deklarujeme mimo try, aby bylo viditelné ve finally

			try {
				// Řešení pro "The constructor URL(String) is deprecated"
				// Nejdříve vytvoříme URI, pak ho převedeme na URL
				URI uri = new URI(targetUrl);
				URL url = uri.toURL();

				connection = (HttpURLConnection) url.openConnection();
				connection.setRequestMethod("GET");
				connection.setConnectTimeout(5000); // 5 sekund timeout pro připojení
				connection.setReadTimeout(5000); // 5 sekund timeout pro čtení

				int responseCode = connection.getResponseCode();
				System.out.println("Status: " + responseCode);

				if (responseCode >= 200 && responseCode < 300) {
					successCount.incrementAndGet();
				} else {
					failCount.incrementAndGet();
				}

				// Řešení pro "The value of the local variable line is not used"
				// Přečteme celý obsah odpovědi do StringBuideru a pak ho můžeme např. zahodit
				// nebo vypsat pro debug
				try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
					StringBuilder responseBody = new StringBuilder();
					String line;
					while ((line = in.readLine()) != null) {
						responseBody.append(line); // Nyní je 'line' použita pro sestavení responseBody
					}
					// Pokud nechceš vypisovat celý body, můžeš ho prostě zahodit po přečtení.
					// Např. System.out.println("Response body length: " + responseBody.length());
					// // Pro debug
				} catch (Exception e) {
					// Ignorujeme chyby při čtení, pokud spojení uspělo
				}

				if (delayMs > 0) {
					Thread.sleep(delayMs); // Zpoždění mezi požadavky
				}

			} catch (Exception e) {
				System.err.println("❌ Chyba při požadavku #" + (i + 1) + ": " + e.getMessage());
				failCount.incrementAndGet();
			} finally {
				// Ujistíme se, že se připojení vždy uzavře
				if (connection != null) {
					connection.disconnect();
				}
			}
		}

		long endTime = System.currentTimeMillis();
		long totalDurationSeconds = (endTime - startTime) / 1000;

		System.out.println("\n--- Zátěžový test dokončen ---");
		System.out.println("Odesláno požadavků: " + numRequests);
		System.out.println("Úspěšné odpovědi (2xx): " + successCount.get());
		System.out.println("Chybové odpovědi / Neúspěšné: " + failCount.get());
		System.out.println("Celkový čas trvání: " + totalDurationSeconds + " sekund.");

		scanner.close();
	}
}