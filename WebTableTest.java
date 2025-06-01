package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import java.time.Duration;
import java.util.List;

import io.github.bonigarcia.wdm.WebDriverManager;

public class WebTableTest {

	public static String browser = "Chrome"; // nebo "Edge"
	public static WebDriver driver;

	public static void setUpDriver() {
		if (browser.equalsIgnoreCase("Edge")) {
			WebDriverManager.edgedriver().setup();
			driver = new EdgeDriver();
		} else {
			WebDriverManager.chromedriver().setup();
			driver = new ChromeDriver();
		}
		driver.manage().window().maximize();
	}

	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		setUpDriver();
		WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
		System.out.println("🧪 Spuštěn test webové tabulky na w3schools.com");

		String tableUrl = "https://www.w3schools.com/html/html_tables.asp";

		try {
			driver.get(tableUrl);

			// Počkej na načtení tabulky
			WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("customers")));
			System.out.println("✅ Tabulka nalezena.");

			// Získání všech řádků tabulky (kromě hlavičky)
			List<WebElement> rows = table.findElements(By.xpath(".//tr")); // Najde všechny <tr> v tabulce
			System.out.println("Nalezeno " + (rows.size() - 1) + " datových řádků (bez hlavičky)."); // odečteme
																										// hlavičku

			// Ověření konkrétní buňky - například, že 'Alfreds Futterkiste' má 'Germany'
			// jako zemi
			System.out.println("\n--- Ověření konkrétní buňky ---");
			String expectedCompany = "Alfreds Futterkiste";
			String expectedCountry = "Germany";
			boolean found = false;

			// Iterace přes řádky (začínáme od indexu 1, abychom přeskočili hlavičku)
			for (int i = 1; i < rows.size(); i++) {
				WebElement row = rows.get(i);
				List<WebElement> cells = row.findElements(By.tagName("td")); // Získá všechny <td> (buňky) v daném řádku

				// Zkontroluj, zda je alespoň 3 buňky (Společnost, Kontakt, Země)
				if (cells.size() >= 3) {
					String company = cells.get(0).getText(); // První buňka (index 0) = Společnost
					String country = cells.get(2).getText(); // Třetí buňka (index 2) = Země

					if (company.equals(expectedCompany) && country.equals(expectedCountry)) {
						System.out.println(
								"✅ Nalezeno: Společnost '" + company + "' a země '" + country + "' jsou správné.");
						found = true;
						break; // Našli jsme, co jsme hledali, můžeme skončit
					}
				}
			}

			if (!found) {
				System.out.println("❌ Chyba: Společnost '" + expectedCompany + "' s očekávanou zemí '" + expectedCountry
						+ "' nebyla nalezena.");
			}
			pause(2);

			// Příklad: Vypsání obsahu celé tabulky do konzole
			System.out.println("\n--- Obsah celé tabulky ---");
			for (int i = 0; i < rows.size(); i++) {
				WebElement row = rows.get(i);
				List<WebElement> cells = row.findElements(By.tagName("td")); // Získá <td> pro data, <th> pro hlavičku
				if (cells.isEmpty()) { // Může se stát u hlavičky <th>
					cells = row.findElements(By.tagName("th")); // Pokud to není <td>, zkusí <th>
				}

				for (WebElement cell : cells) {
					System.out.print(cell.getText() + "\t"); // Vypíše text buňky s tabulátorem
				}
				System.out.println(); // Nový řádek po každém řádku tabulky
			}
			System.out.println("✅ Obsah tabulky vypsán do konzole.");
			pause(3);

		} catch (Exception e) {
			System.err.println("🚨 Během testu došlo k chybě: " + e.getMessage());
			e.printStackTrace();
		} finally {
			if (driver != null) {
				driver.quit();
				System.out.println("\n🔚 Test webové tabulky dokončen.");
			}
		}
	}
}