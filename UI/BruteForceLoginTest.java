package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class BruteForceLoginTest {

	public static String browser = "Chrome"; // Změň na "Edge" podle potřeby
	public static WebDriver driver;

	// Nastavení prohlížeče
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

	// Pauza mezi útoky
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		setUpDriver();
		driver.get("https://www.saucedemo.com/");
		System.out.println("🎯 Spuštěn brute-force test na saucedemo.com");

		// Testovací kombinace hesel
		String[] testPasswords = { "123456", "password", "letmein", "qwerty", "secret_sauce", // správné
				"admin", "standard_user" };

		// Fixní uživatelské jméno
		String username = "standard_user";

		// Nastav počet pokusů (např. 5)
		int maxAttempts = 5;

		for (int i = 0; i < maxAttempts && i < testPasswords.length; i++) {
			driver.get("https://www.saucedemo.com/");
			System.out.println("🔁 Pokus #" + (i + 1) + " s heslem: " + testPasswords[i]);

			WebElement userField = driver.findElement(By.id("user-name"));
			WebElement passField = driver.findElement(By.id("password"));
			WebElement loginBtn = driver.findElement(By.id("login-button"));

			userField.clear();
			passField.clear();

			userField.sendKeys(username);
			passField.sendKeys(testPasswords[i]);
			loginBtn.click();

			// Pauza po každém pokusu
			pause(2);

			// Kontrola úspěšného přihlášení
			if (driver.getCurrentUrl().contains("inventory.html")) {
				System.out.println("✅ Úspěšné přihlášení s heslem: " + testPasswords[i]);
				break;
			} else {
				System.out.println("❌ Neplatné přihlášení");
			}
		}

		pause(2);
		driver.quit();
		System.out.println("🔚 Test dokončen.");
	}
}
