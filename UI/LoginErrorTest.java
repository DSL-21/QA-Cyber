package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class LoginErrorTest {

	public static void main(String[] args) {

		// Set up the ChromeDriver.
		WebDriverManager.chromedriver().setup();
		WebDriver driver = new ChromeDriver();

		// Maximize the browser window and open the website.
		driver.manage().window().maximize();
		driver.get("https://www.saucedemo.com/");
		System.out.println("Opened Swag Labs.");

		// Enter a valid username but an incorrect password.
		driver.findElement(By.id("user-name")).sendKeys("standard_user");
		driver.findElement(By.id("password")).sendKeys("wrong_password");
		driver.findElement(By.id("login-button")).click();

		// Verify that an error message is displayed.
		try {
			// Find the error message element.
			WebElement errorMsg = driver.findElement(By.cssSelector("h3[data-test='error']"));
			String errorText = errorMsg.getText(); // Get the text of the error message.

			// Check if the error message contains the expected text.
			if (errorText.contains("Username and password do not match")) {
				System.out.println("✅ Test passed – correct error message displayed: " + errorText);
			} else {
				System.out.println("❌ Test failed – unexpected message: " + errorText);
			}
		} catch (Exception e) {
			// Catch any exception if the error message element is not found.
			System.out.println("❌ Error message element not found. Test failed.");
		}

		// Optional: Pause for visual inspection.
		try {
			Thread.sleep(3000); // Wait for 3 seconds.
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// Close the browser.
		driver.quit();
		System.out.println("Test completed.");
	}
}
