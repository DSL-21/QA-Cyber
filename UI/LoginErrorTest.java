package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class LoginErrorTest {

	public static void main(String[] args) {

		// Nastavení Chromedriveru
		WebDriverManager.chromedriver().setup();
		WebDriver driver = new ChromeDriver();

		// Maximalizace okna a otevření webu
		driver.manage().window().maximize();
		driver.get("https://www.saucedemo.com/");
		System.out.println("Otevřen Swag Labs");

		// Zadání platného uživatelského jména, ale špatného hesla
		driver.findElement(By.id("user-name")).sendKeys("standard_user");
		driver.findElement(By.id("password")).sendKeys("wrong_password");
		driver.findElement(By.id("login-button")).click();

		// Ověření, že se zobrazí chybová hláška
		try {
			WebElement errorMsg = driver.findElement(By.cssSelector("h3[data-test='error']"));
			String errorText = errorMsg.getText();

			if (errorText.contains("Username and password do not match")) {
				System.out.println("✅ Test prošel – správná chybová hláška: " + errorText);
			} else {
				System.out.println("❌ Test selhal – neočekávaná hláška: " + errorText);
			}
		} catch (Exception e) {
			System.out.println("❌ Chybová hláška nebyla nalezena. Test selhal.");
		}

		// Pauza pro vizuální kontrolu (volitelné)
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// Zavření prohlížeče
		driver.quit();
		System.out.println("Test dokončen.");
	}
}
