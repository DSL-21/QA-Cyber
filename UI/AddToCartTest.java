package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class AddToCartTest {

	public static String browser = "Chrome"; // Změň na "Edge" pokud chceš
	public static WebDriver driver;

	// Nastaví prohlížeč podle proměnné 'browser'
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

	// Pauza v sekundách (pro pomalé sledování)
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		setUpDriver();

		// Otevři Swag Labs
		driver.get("https://www.saucedemo.com/");
		System.out.println("🟢 Otevřen Swag Labs");
		pause(2);

		// Přihlas se
		driver.findElement(By.id("user-name")).sendKeys("standard_user");
		System.out.println("✏️ Zadané uživatelské jméno");
		pause(1);

		driver.findElement(By.id("password")).sendKeys("secret_sauce");
		System.out.println("✏️ Zadané heslo");
		pause(1);

		driver.findElement(By.id("login-button")).click();
		System.out.println("🔐 Přihlášení odesláno");
		pause(2);

		// Přidání produktu do košíku
		driver.findElement(By.id("add-to-cart-sauce-labs-backpack")).click();
		System.out.println("🛒 Přidán produkt 'Sauce Labs Backpack' do košíku");
		pause(2);

		// Přejdi do košíku
		driver.findElement(By.className("shopping_cart_link")).click();
		System.out.println("🛍️ Otevřen košík");
		pause(2);

		// Ověř produkt v košíku
		WebElement itemName = driver.findElement(By.className("inventory_item_name"));
		String nameText = itemName.getText();

		if (nameText.equals("Sauce Labs Backpack")) {
			System.out.println("✅ Produkt v košíku je správný: " + nameText);
		} else {
			System.out.println("❌ Neočekávaný produkt: " + nameText);
		}

		pause(3); // vizuální kontrola

		driver.quit();
		System.out.println("🚪 Test ukončen.");
	}
}
