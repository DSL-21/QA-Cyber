package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import static org.openqa.selenium.support.locators.RelativeLocator.with;

import io.github.bonigarcia.wdm.WebDriverManager;

public class Locators {

	public static String browser = "Chrome";
	public static WebDriver driver;

	public static void main(String[] args) {

		if (browser.equals("Edge")) {
			WebDriverManager.edgedriver().setup();
			driver = new EdgeDriver();
		} else if (browser.equals("Chrome")) {
			WebDriverManager.chromedriver().setup();
			driver = new ChromeDriver();
		}

		driver.get("https://www.saucedemo.com/");

		WebElement password = driver.findElement(By.id("password"));
		WebElement username = driver.findElement(with(By.tagName("input")).above(password));

		username.sendKeys("testing");

		// Jen aby zůstalo otevřené
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
		}
		driver.quit();
	}
}
