package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class BruteForceLoginTest {

	// This static variable determines which browser will be used for the test.
	// You can change "Chrome" to "Edge" if you want to run the test in Microsoft
	// Edge.
	public static String browser = "Chrome";

	// The WebDriver instance, which is the primary interface for controlling the
	// browser.
	public static WebDriver driver;

	// Configures and initializes the WebDriver based on the 'browser' variable.
	// WebDriverManager handles downloading and setting up the appropriate browser
	// driver executable.
	public static void setUpDriver() {
		if (browser.equalsIgnoreCase("Edge")) {
			WebDriverManager.edgedriver().setup(); // Setup for Edge browser.
			driver = new EdgeDriver(); // Initialize EdgeDriver.
		} else {
			WebDriverManager.chromedriver().setup(); // Setup for Chrome browser (default).
			driver = new ChromeDriver(); // Initialize ChromeDriver.
		}
		driver.manage().window().maximize(); // Maximizes the browser window for better visibility during the test.
	}

	// Pauses the test execution for a specified number of seconds.
	// This is used to introduce delays between login attempts, mimicking a more
	// realistic
	// brute-force scenario or simply for observation during development.
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000); // Thread.sleep expects milliseconds.
		} catch (InterruptedException e) {
			e.printStackTrace(); // Prints the stack trace if the thread is interrupted.
			Thread.currentThread().interrupt(); // Re-interrupts the current thread.
		}
	}

	public static void main(String[] args) {

		// Initialize the browser driver.
		setUpDriver();

		// Navigate to the target login page.
		driver.get("https://www.saucedemo.com/");
		System.out.println("🎯 Starting brute-force test on saucedemo.com");

		// An array of passwords to attempt during the brute-force test.
		// It includes common weak passwords and the correct password for
		// `standard_user`.
		String[] testPasswords = { "123456", "password", "letmein", "qwerty", "secret_sauce", // This is the correct
																								// password for
																								// 'standard_user' on
																								// saucedemo.com
				"admin", "standard_user" };

		// The fixed username to be used for all login attempts.
		String username = "standard_user";

		// Defines the maximum number of login attempts to make.
		// This limits the test duration and prevents excessive requests.
		int maxAttempts = 5;

		// Loop through the password array, up to 'maxAttempts' or the total number of
		// passwords, whichever is smaller.
		for (int i = 0; i < maxAttempts && i < testPasswords.length; i++) {
			// Reload the login page before each attempt to ensure a clean state and clear
			// any previous error messages.
			driver.get("https://www.saucedemo.com/");
			System.out.println("🔁 Attempt #" + (i + 1) + " with password: " + testPasswords[i]);

			// Locate the username, password fields, and the login button using their IDs.
			WebElement userField = driver.findElement(By.id("user-name"));
			WebElement passField = driver.findElement(By.id("password"));
			WebElement loginBtn = driver.findElement(By.id("login-button"));

			// Clear any pre-filled text in the input fields from previous attempts.
			userField.clear();
			passField.clear();

			// Enter the username and the current test password into the respective fields.
			userField.sendKeys(username);
			passField.sendKeys(testPasswords[i]);

			// Click the login button to submit the credentials.
			loginBtn.click();

			// Pause after each attempt to observe the result and to avoid overwhelming the
			// server
			// (which could trigger rate-limiting or captchas on a real system).
			pause(2);

			// Check for successful login by verifying if the current URL contains
			// "inventory.html".
			// This is the expected URL after a successful login on saucedemo.com.
			if (driver.getCurrentUrl().contains("inventory.html")) {
				System.out.println("✅ Successful login with password: " + testPasswords[i]);
				break; // If login is successful, exit the loop as the test objective is met.
			} else {
				// If the URL doesn't change to "inventory.html", the login attempt failed.
				System.out.println("❌ Invalid login attempt.");
			}
		}

		pause(2); // A final pause before closing the browser.
		driver.quit(); // Close the browser and terminate the WebDriver session.
		System.out.println("🔚 Test completed.");
	}
}
