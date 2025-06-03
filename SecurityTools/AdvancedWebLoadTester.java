package SecurityTools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class AdvancedWebLoadTester {

	private static final int DEFAULT_TIMEOUT_MS = 10000; // Výchozí timeout pro připojení a čtení
	private static final int DEFAULT_CONCURRENT_USERS = 10; // Výchozí počet souběžných "uživatelů"

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		// *** VELMI DŮLEŽITÉ ETIKEcké UPOZORNĚNÍ ***
		System.out.println("**********************************************************************************");
		System.out.println("!!! UPOZORNĚNÍ: Toto je nástroj pro vzdělávací a demonstrativní účely !!!");
		System.out.println("!!! NIKDY NEPOUŽÍVEJTE tento kód pro neoprávněné zátěžové testování nebo DDoS útoky !!!");
		System.out.println("!!! Neoprávněné použití je NELEGÁLNÍ a může vést k VÁŽNÝM PRÁVNÍM DŮSLEDKŮM !!!");
		System.out.println("!!! Testujte POUZE na systémech, k nimž máte VÝSLOVNÉ, PÍSEMNÉ POVOLENÍ od vlastníka. !!!");
		System.out.println("**********************************************************************************\n");

		System.out.println("--- Pokročilý Webový Zátěžový Tester ---");

		System.out.println("Zadejte cílovou URL (např. http://localhost:8080/nebo http://testphp.vulnweb.com/):");
		String targetUrl = scanner.nextLine().trim();

		System.out.println("Zadejte počet celkových požadavků, které chcete odeslat (např. 1000):");
		int numRequests = readIntInput(scanner, 1, Integer.MAX_VALUE, 1000);

		System.out.println("Zadejte počet souběžných uživatelů/vláken (např. 10 pro 10 požadavků najednou):");
		int concurrentUsers = readIntInput(scanner, 1, Integer.MAX_VALUE, DEFAULT_CONCURRENT_USERS);

		System.out.println("Zadejte HTTP metodu (GET, POST, PUT, DELETE, HEAD, OPTIONS, ...):");
		String httpMethod = scanner.nextLine().trim().toUpperCase();
		if (!isValidHttpMethod(httpMethod)) {
			System.out.println("Neplatná HTTP metoda. Používám výchozí GET.");
			httpMethod = "GET";
		}

		String requestBody = "";
		if (httpMethod.equals("POST") || httpMethod.equals("PUT")) {
			System.out.println(
					"Zadejte tělo požadavku (např. JSON: {\"key\":\"value\"}). Pokud není potřeba, nechte prázdné:");
			requestBody = scanner.nextLine();
		}

		Map<String, String> customHeaders = new HashMap<>();
		System.out.println("Chcete přidat vlastní HTTP hlavičky? (ano/ne):");
		if (scanner.nextLine().trim().equalsIgnoreCase("ano")) {
			System.out.println("Zadávejte hlavičky ve formátu 'Název: Hodnota'. Pro ukončení zadejte prázdný řádek.");
			while (true) {
				String headerLine = scanner.nextLine().trim();
				if (headerLine.isEmpty()) {
					break;
				}
				String[] parts = headerLine.split(":", 2);
				if (parts.length == 2) {
					customHeaders.put(parts[0].trim(), parts[1].trim());
				} else {
					System.out.println("Neplatný formát hlavičky. Zkuste 'Název: Hodnota'.");
				}
			}
		}

		System.out.println("\nSpouštím zátěžový test na " + targetUrl + " s " + numRequests + " požadavky, "
				+ concurrentUsers + " souběžně...");

		long startTime = System.currentTimeMillis();
		AtomicInteger successCount = new AtomicInteger(0);
		AtomicInteger failCount = new AtomicInteger(0);
		AtomicLong totalResponseTime = new AtomicLong(0);

		ExecutorService executor = Executors.newFixedThreadPool(concurrentUsers);

		for (int i = 0; i < numRequests; i++) {
			final int requestNum = i + 1;
			final String currentMethod = httpMethod;
			final String currentBody = requestBody;

			executor.submit(() -> {
				long requestStartTime = System.currentTimeMillis();
				HttpURLConnection connection = null;

				try {
					URI uri = new URI(targetUrl);
					URL url = uri.toURL();

					connection = (HttpURLConnection) url.openConnection();
					connection.setRequestMethod(currentMethod);
					connection.setConnectTimeout(DEFAULT_TIMEOUT_MS);
					connection.setReadTimeout(DEFAULT_TIMEOUT_MS);

					// Nastavení vlastních hlaviček
					for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
						connection.setRequestProperty(entry.getKey(), entry.getValue());
					}

					// Odeslání těla požadavku pro POST/PUT
					if (currentMethod.equals("POST") || currentMethod.equals("PUT")) {
						connection.setDoOutput(true); // Povolit odesílání dat
						if (!currentBody.isEmpty()) {
							connection.setRequestProperty("Content-Type", "application/json"); // Předpokládáme JSON,
																								// můžeš změnit
							try (OutputStream os = connection.getOutputStream()) {
								byte[] input = currentBody.getBytes(StandardCharsets.UTF_8);
								os.write(input, 0, input.length);
							}
						}
					}

					int responseCode = connection.getResponseCode();

					// Přečtení odpovědi, aby se uvolnilo spojení
					try (BufferedReader in = new BufferedReader(new InputStreamReader(
							(responseCode >= 200 && responseCode < 400) ? connection.getInputStream()
									: connection.getErrorStream(),
							StandardCharsets.UTF_8))) {
						while (in.readLine() != null) {
							// Jen čteme, abychom spotřebovali data a uvolnili spojení
						}
					}

					long requestEndTime = System.currentTimeMillis();
					long responseTime = requestEndTime - requestStartTime;
					totalResponseTime.addAndGet(responseTime);

					if (responseCode >= 200 && responseCode < 300) {
						successCount.incrementAndGet();
						System.out.println("✅ Požadavek #" + requestNum + " (Status: " + responseCode + ", Čas: "
								+ responseTime + "ms)");
					} else {
						failCount.incrementAndGet();
						System.err.println("❌ Požadavek #" + requestNum + " (Status: " + responseCode + ", Čas: "
								+ responseTime + "ms)");
					}

				} catch (Exception e) {
					System.err.println("❌ Chyba při požadavku #" + requestNum + ": " + e.getMessage());
					failCount.incrementAndGet();
				} finally {
					if (connection != null) {
						connection.disconnect();
					}
				}
			});
		}

		executor.shutdown(); // Ukončí přijímání nových úkolů
		try {
			System.out.println("\nČekám na dokončení všech požadavků...");
			executor.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS); // Čeká na dokončení všech úkolů
		} catch (InterruptedException e) {
			System.err.println("Test byl přerušen.");
			Thread.currentThread().interrupt();
		}

		long endTime = System.currentTimeMillis();
		long totalDurationMs = (endTime - startTime);
		double totalDurationSeconds = totalDurationMs / 1000.0;

		double averageResponseTime = (successCount.get() + failCount.get()) > 0
				? (double) totalResponseTime.get() / (successCount.get() + failCount.get())
				: 0;
		double requestsPerSecond = totalDurationSeconds > 0
				? (successCount.get() + failCount.get()) / totalDurationSeconds
				: 0;

		System.out.println("\n--- Zátěžový test dokončen ---");
		System.out.println("Odesláno celkem požadavků: " + numRequests);
		System.out.println("Úspěšné odpovědi (2xx): " + successCount.get());
		System.out.println("Chybové odpovědi / Neúspěšné: " + failCount.get());
		System.out.println("Celkový čas trvání: " + String.format("%.2f", totalDurationSeconds) + " sekund.");
		System.out.println("Průměrná doba odezvy: " + String.format("%.2f", averageResponseTime) + " ms.");
		System.out.println("Propustnost: " + String.format("%.2f", requestsPerSecond) + " požadavků/sekundu.");

		scanner.close();
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

	/**
	 * Kontroluje, zda je zadaná HTTP metoda platná.
	 */
	private static boolean isValidHttpMethod(String method) {
		switch (method) {
		case "GET":
		case "POST":
		case "PUT":
		case "DELETE":
		case "HEAD":
		case "OPTIONS":
		case "PATCH":
			return true;
		default:
			return false;
		}
	}
}