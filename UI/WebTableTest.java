package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import java.time.Duration;
import java.util.List;

import io.github.bonigarcia.wdm.WebDriverManager;

public class WebTableTest {

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

		// Set up an explicit wait for elements to appear, with a 10-second timeout.
		WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
		System.out.println("🧪 Starting web table test on w3schools.com");

		String tableUrl = "https://www.w3schools.com/html/html_tables.asp";

		try {
			// Navigate to the page with the table.
			driver.get(tableUrl);

			// Wait for the table to be visible on the page.
			WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("customers")));
			System.out.println("✅ Table found.");

			// Get all rows from the table (including the header row).
			List<WebElement> rows = table.findElements(By.xpath(".//tr"));
			System.out.println("Found " + (rows.size() - 1) + " data rows (excluding header).");

			// --- Verify a specific cell's content ---
			System.out.println("\n--- Verifying Specific Cell ---");
			String expectedCompany = "Alfreds Futterkiste";
			String expectedCountry = "Germany";
			boolean found = false;

			// Iterate through table rows, starting from index 1 to skip the header.
			for (int i = 1; i < rows.size(); i++) {
				WebElement row = rows.get(i);
				// Get all cell elements (<td>) within the current row.
				List<WebElement> cells = row.findElements(By.tagName("td"));

				// Check if there are enough cells (at least 3 for Company, Contact, Country).
				if (cells.size() >= 3) {
					String company = cells.get(0).getText(); // Get text from the first cell (Company).
					String country = cells.get(2).getText(); // Get text from the third cell (Country).

					// Compare cell contents with expected values.
					if (company.equals(expectedCompany) && country.equals(expectedCountry)) {
						System.out.println(
								"✅ Found: Company '" + company + "' and country '" + country + "' are correct.");
						found = true;
						break; // Stop iterating once the target row is found.
					}
				}
			}

			// Report if the specific company and country combination was not found.
			if (!found) {
				System.out.println("❌ Error: Company '" + expectedCompany + "' with expected country '"
						+ expectedCountry + "' not found.");
			}
			pause(2);

			// --- Print the entire table content to console ---
			System.out.println("\n--- Entire Table Content ---");
			// Iterate through all rows (including header this time).
			for (int i = 0; i < rows.size(); i++) {
				WebElement row = rows.get(i);
				List<WebElement> cells;
				// Try to find table data cells (<td>). If empty (e.g., for header row), try
				// table header cells (<th>).
				cells = row.findElements(By.tagName("td"));
				if (cells.isEmpty()) {
					cells = row.findElements(By.tagName("th"));
				}

				// Print the text of each cell in the row, separated by tabs.
				for (WebElement cell : cells) {
					System.out.print(cell.getText() + "\t");
				}
				System.out.println(); // Move to the next line after each row.
			}
			System.out.println("✅ Table content printed to console.");
			pause(3);

		} catch (Exception e) {
			// Catch and report any errors during the test.
			System.err.println("🚨 An error occurred during the test: " + e.getMessage());
			e.printStackTrace();
		} finally {
			// Ensure the browser is closed even if an error occurs.
			if (driver != null) {
				driver.quit();
				System.out.println("\n🔚 Web table test completed.");
			}
		}
	}
}
