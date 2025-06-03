package SecurityTools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class AuthenticatedWebTester {

	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36";
	private static final int TIMEOUT_MS = 10000; // 10 sekund timeout

	// Tato proměnná bude uchovávat cookies pro relaci
	private String sessionCookies = "";

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);
		AuthenticatedWebTester tester = new AuthenticatedWebTester();

		// *** VELMI DŮLEŽITÉ ETIKEcké UPOZORNĚNÍ ***
		System.out.println("**********************************************************************************");
		System.out.println("!!! UPOZORNĚNÍ: Toto je nástroj pro vzdělávací a demonstrativní účely !!!");
		System.out.println("!!! NIKDY NEPOUŽÍVEJTE tento kód pro neoprávněné testování nebo útoky !!!");
		System.out.println("!!! Testujte POUZE na systémech, k nimž máte VÝSLOVNÉ, PÍSEMNÉ POVOLENÍ od vlastníka. !!!");
		System.out.println("!!! Testování přihlašovacích formulářů je citlivé a může být detekováno! !!!");
		System.out.println("**********************************************************************************\n");

		System.out.println("--- Pokročilý Webový Tester s Autentikací ---");

		System.out.println("Zadejte URL přihlašovací stránky (např. http://localhost/login.php):");
		String loginUrl = scanner.nextLine().trim();

		System.out.println("Zadejte jméno uživatele pro přihlášení:");
		String username = scanner.nextLine().trim();

		System.out.println("Zadejte heslo pro přihlášení:");
		String password = scanner.nextLine().trim();

		System.out.println("Zadejte URL chráněné stránky/endpointu, kterou chcete testovat po přihlášení:");
		String protectedUrl = scanner.nextLine().trim();

		System.out.println("\nSpouštím proces přihlášení a testování...");

		try {
			// Krok 1: Přihlášení
			boolean loggedIn = tester.performLogin(loginUrl, username, password);

			if (loggedIn) {
				System.out.println("✅ Úspěšně přihlášen!");
				System.out.println("Pokračuji k testování chráněné URL: " + protectedUrl);

				// Krok 2: Provedení autentikovaného požadavku
				// Zde můžeme demonstrovat jednoduchý XSS test na chráněné stránce
				// Předpokládáme, že chráněná URL může mít parametr, do kterého můžeme vložit
				// payload
				System.out.println("Chcete provést jednoduchý XSS test na chráněné stránce? (ano/ne)");
				if (scanner.nextLine().trim().equalsIgnoreCase("ano")) {
					String xssPayload = "<script>alert('XSS v autentikované relaci!');</script>";
					// Předpokládejme, že chráněná URL má parametr 'query'
					String testUrl = protectedUrl + "?query="
							+ URLEncoder.encode(xssPayload, StandardCharsets.UTF_8.toString());
					System.out.println("Odesílám autentikovaný požadavek s XSS payloadem na: " + testUrl);
					tester.sendAuthenticatedRequest(testUrl);
				} else {
					System.out.println("Odesílám jednoduchý autentikovaný GET požadavek na: " + protectedUrl);
					tester.sendAuthenticatedRequest(protectedUrl);
				}

			} else {
				System.out.println("❌ Přihlášení selhalo.");
			}

		} catch (Exception e) {
			System.err.println("❌ Došlo k chybě: " + e.getMessage());
			e.printStackTrace();
		} finally {
			scanner.close();
			System.out.println("\nTest dokončen.");
		}
	}

	/**
	 * Pokusí se přihlásit do webové aplikace a uloží session cookies. Předpokládá,
	 * že přihlašovací formulář odesílá data pomocí POST. Bude se snažit zachytit
	 * Set-Cookie hlavičky z odpovědi.
	 *
	 * @param loginUrl URL přihlašovací stránky.
	 * @param username Uživatelské jméno.
	 * @param password Heslo.
	 * @return True, pokud se zdá, že přihlášení proběhlo úspěšně, jinak False.
	 * @throws Exception Pokud dojde k chybě sítě/URL.
	 */
	private boolean performLogin(String loginUrl, String username, String password) throws Exception {
		HttpURLConnection connection = null;
		try {
			URI uri = new URI(loginUrl);
			URL url = uri.toURL();

			connection = (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("POST");
			connection.setConnectTimeout(TIMEOUT_MS);
			connection.setReadTimeout(TIMEOUT_MS);
			connection.setRequestProperty("User-Agent", USER_AGENT);
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); // Pro data formuláře
			connection.setDoOutput(true); // Umožňuje odesílání dat

			// Příklad těla požadavku s přihlašovacími údaji.
			// Názvy 'username' a 'password' jsou nejběžnější, ale mohou se lišit (např.
			// 'user', 'pass', 'login_user').
			// Toto je třeba přizpůsobit cílové aplikaci.
			String postData = "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8.toString())
					+ "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8.toString());

			try (OutputStream os = connection.getOutputStream()) {
				byte[] input = postData.getBytes(StandardCharsets.UTF_8);
				os.write(input, 0, input.length);
			}

			int responseCode = connection.getResponseCode();
			System.out.println("Přihlašovací URL: " + loginUrl + ", Kód odpovědi: " + responseCode);

			// Získání cookies z hlaviček odpovědi
			Map<String, List<String>> headers = connection.getHeaderFields();
			List<String> cookies = headers.get("Set-Cookie");
			if (cookies != null) {
				StringBuilder sb = new StringBuilder();
				for (String cookie : cookies) {
					// Extract only the cookie value part (before ';')
					sb.append(cookie.split(";")[0]).append(";");
				}
				sessionCookies = sb.toString();
				System.out.println("Získané session cookies: " + sessionCookies);
			} else {
				System.out.println("Žádné Set-Cookie hlavičky v odpovědi.");
			}

			// Předpoklad: úspěšné přihlášení se projeví kódem 200 OK nebo přesměrováním
			// (302)
			// Reálný tester by musel analyzovat tělo odpovědi pro potvrzení úspěchu (např.
			// hledat 'Welcome' text)
			if (responseCode >= 200 && responseCode < 400) { // Úspěch nebo přesměrování
				// Pokud je přesměrování, můžeme ho sledovat, ale pro jednoduchost stačí cookies
				return true;
			} else {
				// Přečtení chybového proudu pro debug
				try (BufferedReader errorReader = new BufferedReader(
						new InputStreamReader(connection.getErrorStream()))) {
					String line;
					StringBuilder errorResponse = new StringBuilder();
					while ((line = errorReader.readLine()) != null) {
						errorResponse.append(line);
					}
					System.err.println("Chybová odpověď přihlášení: " + errorResponse.toString());
				} catch (Exception e) {
					// Ignorujeme
				}
				return false;
			}

		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	/**
	 * Odešle HTTP GET požadavek na danou URL s použitím získaných session cookies.
	 *
	 * @param targetUrl URL, na kterou se má poslat autentikovaný požadavek.
	 * @throws Exception Pokud dojde k chybě sítě/URL.
	 */
	private void sendAuthenticatedRequest(String targetUrl) throws Exception {
		HttpURLConnection connection = null;
		try {
			URI uri = new URI(targetUrl);
			URL url = uri.toURL();

			connection = (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("GET");
			connection.setConnectTimeout(TIMEOUT_MS);
			connection.setReadTimeout(TIMEOUT_MS);
			connection.setRequestProperty("User-Agent", USER_AGENT);

			// Nastavení získaných cookies pro tento požadavek
			if (!sessionCookies.isEmpty()) {
				connection.setRequestProperty("Cookie", sessionCookies);
				System.out.println("Odesílám s cookies: "
						+ sessionCookies.substring(0, Math.min(sessionCookies.length(), 50)) + "...");
			} else {
				System.out.println("Odesílám požadavek bez cookies (relace nebyla navázána).");
			}

			int responseCode = connection.getResponseCode();
			System.out.println("Autentikovaná URL: " + targetUrl + ", Kód odpovědi: " + responseCode);

			// Přečtení a zobrazení prvních pár řádků odpovědi
			try (BufferedReader in = new BufferedReader(
					new InputStreamReader((responseCode >= 200 && responseCode < 400) ? connection.getInputStream()
							: connection.getErrorStream(), StandardCharsets.UTF_8))) {
				String line;
				int lineCount = 0;
				System.out.println("--- Začátek odpovědi ---");
				while ((line = in.readLine()) != null && lineCount < 5) { // Omezíme na prvních 5 řádků pro čitelnost
					System.out.println(line);
					lineCount++;
				}
				if (lineCount >= 5)
					System.out.println("...(zbytek odpovědi zkrácen)");
				System.out.println("--- Konec odpovědi ---");
			}

		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
}