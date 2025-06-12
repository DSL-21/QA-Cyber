package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class AddToCartTest {

	// This static variable determines which browser will be used for the test.
	// You can change "Chrome" to "Edge" if you want to run the test in Microsoft Edge.
	public static String browser = "Chrome"; 
	
	// The WebDriver instance, which is the primary interface for controlling the browser.
	public static WebDriver driver;

	// Sets up the WebDriver based on the 'browser' variable.
	// WebDriverManager automatically handles downloading and configuring the necessary browser driver.
	public static void setUpDriver() {
		if (browser.equalsIgnoreCase("Edge")) {
			WebDriverManager.edgedriver().setup(); // Setup for Edge browser.
			driver = new EdgeDriver(); // Initialize EdgeDriver.
		} else {
			WebDriverManager.chromedriver().setup(); // Setup for Chrome browser (default).
			driver = new ChromeDriver(); // Initialize ChromeDriver.
		}
		driver.manage().window().maximize(); // Maximize the browser window for better visibility during the test.
	}

	// Pauses the test execution for a specified number of seconds.
	// This can be useful for observing steps during a test run, though explicit waits are generally
	// preferred for more robust automation in production environments.
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000); // Thread.sleep expects milliseconds, so we multiply by 1000.
		} catch (InterruptedException e) {
			e.printStackTrace(); // Prints the stack trace if the thread is interrupted while sleeping.
			Thread.currentThread().interrupt(); // Re-interrupts the current thread.
		}
	}

	public static void main(String[] args) {

		// Initialize and set up the browser driver based on the chosen browser.
		setUpDriver();

		// Navigate to the Swag Labs website.
		driver.get("https://www.saucedemo.com/");
		System.out.println("🟢 Opened Swag Labs website.");
		pause(2); // Pause for 2 seconds to allow the page to fully load.

		// Locate the username field by its ID and enter the standard username.
		driver.findElement(By.id("user-name")).sendKeys("standard_user");
		System.out.println("✏️ Entered username.");
		pause(1); // Pause for 1 second.

		// Locate the password field by its ID and enter the secret password.
		driver.findElement(By.id("password")).sendKeys("secret_sauce");
		System.out.println("✏️ Entered password.");
		pause(1); // Pause for 1 second.

		// Locate the login button by its ID and click it to submit the credentials.
		driver.findElement(By.id("login-button")).click();
		System.out.println("🔐 Login submitted.");
		pause(2); // Pause for 2 seconds to allow navigation to the product page.

		// Add the "Sauce Labs Backpack" to the cart.
		// The element is located by its ID.
		driver.findElement(By.id("add-to-cart-sauce-labs-backpack")).click();
		System.out.println("🛒 Added 'Sauce Labs Backpack' to cart.");
		pause(2); // Pause for 2 seconds.

		// Navigate to the shopping cart by clicking its link, located by its class name.
		driver.findElement(By.className("shopping_cart_link")).click();
		System.out.println("🛍️ Opened shopping cart.");
		pause(2); // Pause for 2 seconds to view the cart contents.

		// Verify that the correct product is in the cart.
		// First, locate the element displaying the item's name within the cart.
		WebElement itemName = driver.findElement(By.className("inventory_item_name"));
		String nameText = itemName.getText(); // Get the text of the item name.

		// Compare the retrieved text with the expected product name.
		if (nameText.equals("Sauce Labs Backpack")) {
			System.out.println("✅ Product in cart is correct: " + nameText);
		} else {
			System.out.println("❌ Unexpected product found in cart: " + nameText);
		}

		pause(3); // A final pause for visual inspection of the test result.

		// Close the browser and terminate the WebDriver session.
		driver.quit();
		System.out.println("🚪 Test finished.");
	}
}
