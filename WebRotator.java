package UI;

// Import potřebných tříd
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import io.github.bonigarcia.wdm.WebDriverManager;

public class WebRotator {

	public static String browser = "Chrome"; // Změň na "Edge" pokud chceš použít Edge
	public static WebDriver driver;

	public static void main(String[] args) {

		// Spuštění správného prohlížeče podle proměnné 'browser'
		if (browser.equals("Edge")) {
			WebDriverManager.edgedriver().setup();
			driver = new EdgeDriver();
		} else if (browser.equals("Chrome")) {
			WebDriverManager.chromedriver().setup();
			driver = new ChromeDriver();
		}

		driver.manage().window().maximize(); // Maximalizace okna prohlížeče

		// Otevření stránky Swag Labs (saucedemo.com)
		driver.get("https://www.saucedemo.com/");
		System.out.println("Aktuální URL: " + driver.getCurrentUrl());
		System.out.println("Titulek stránky: " + driver.getTitle());

		// Přihlášení do aplikace
		driver.findElement(By.id("user-name")).sendKeys("standard_user");
		driver.findElement(By.id("password")).sendKeys("secret_sauce");
		driver.findElement(By.id("login-button")).click();

		// Nalezení všech produktových bloků a výpis jejich počtu
		List<WebElement> webelements = driver.findElements(By.xpath("//div[@class='inventory_list']/div"));
		System.out.println("Počet nalezených produktů: " + webelements.size());

		// Přechod na stránku SugarCRM
		driver.navigate().to("https://www.sugarcrm.com/uk/");
		System.out.println("Přepnuto na SugarCRM");

		// Přijetí cookies banneru pomocí JavaScriptExecutor
		try {
			Thread.sleep(3000); // Pauza na zobrazení banneru

			WebElement cookieAcceptBtn = driver
					.findElement(By.xpath("//*[@id='CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll']"));
			JavascriptExecutor js = (JavascriptExecutor) driver;
			js.executeScript("arguments[0].click();", cookieAcceptBtn);
			System.out.println("Cookies byly přijaty přes JavaScript.");
		} catch (Exception e) {
			System.out.println("Nepodařilo se kliknout na cookies banner: " + e.getMessage());
		}

		// Kliknutí na tlačítko "Book a Demo"
		try {
			WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
			WebElement bookDemoBtn = wait
					.until(ExpectedConditions.elementToBeClickable(By.xpath("//a[contains(text(), 'Book a Demo')]")));
			bookDemoBtn.click();
			System.out.println("Kliknuto na Book a Demo.");
		} catch (Exception e) {
			System.out.println("Chyba při kliku na Book a Demo: " + e.getMessage());
		}

		// Výpis všech aktivních oken (pro kontrolu přesměrování nebo nového tabu)
		Set<String> windowHandles = driver.getWindowHandles();
		System.out.println("Otevřená okna: " + windowHandles);

		// Přechod na stránku Google
		driver.navigate().to("https://www.google.com");
		System.out.println("Navigováno na Google");

		// Pauza, aby bylo možné vizuálně zkontrolovat výsledek
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// Ukončení relace prohlížeče
		driver.quit();
		System.out.println("Test ukončen.");
	}
}
