package UI;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class DOMXssTest {

	public static String browser = "Chrome";
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

		// Zde můžeš použít svou vlastní testovací stránku
		String payload = "<script>alert('XSS')</script>";
		String testUrl = "https://your-local-test/xss.html#name=" + payload;

		driver.get(testUrl);
		System.out.println("🧪 Otevřen DOM-based XSS test");

		pause(2);

		// Test: pokusíme se detekovat alert pomocí JavaScriptu
		try {
			JavascriptExecutor js = (JavascriptExecutor) driver;
			String pageContent = (String) js.executeScript("return document.body.innerHTML;");

			if (pageContent.contains("XSS")) {
				System.out.println("🚨 DOM XSS detekován – payload se objevil ve stránce!");
			} else {
				System.out.println("✅ Žádný XSS efekt nebyl nalezen.");
			}
		} catch (Exception e) {
			System.out.println("❌ Chyba při kontrole DOM: " + e.getMessage());
		}

		pause(3);
		driver.quit();
		System.out.println("🔚 Test dokončen.");
	}
}
