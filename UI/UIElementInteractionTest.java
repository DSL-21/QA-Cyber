package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select; // Used for dropdown menus
import org.openqa.selenium.support.ui.WebDriverWait;
import java.time.Duration;

import io.github.bonigarcia.wdm.WebDriverManager;

public class UIElementInteractionTest {

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
		System.out.println("🧪 Starting UI element interaction test on formy-project.herokuapp.com");

		try {
			// Navigate to the form page.
			driver.get("https://formy-project.herokuapp.com/form");

			// 1. Interact with text fields
			System.out.println("\n--- Testing Text Fields ---");
			// Wait until the first name field is visible, then enter text.
			WebElement firstName = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("first-name")));
			firstName.sendKeys("Jan");
			System.out.println("✅ First name entered.");

			// Enter text into the last name field.
			WebElement lastName = driver.findElement(By.id("last-name"));
			lastName.sendKeys("Novak");
			System.out.println("✅ Last name entered.");

			// Enter text into the job title field.
			WebElement jobTitle = driver.findElement(By.id("job-title"));
			jobTitle.sendKeys("QA Tester");
			System.out.println("✅ Job title entered.");
			pause(1);

			// 2. Interact with radio buttons
			System.out.println("\n--- Testing Radio Buttons ---");
			// Find the 'High school' radio button.
			WebElement highestDegreeRadio = driver.findElement(By.id("radio-button-3")); 
			// Click it if it's not already selected.
			if (!highestDegreeRadio.isSelected()) {
				highestDegreeRadio.click();
				System.out.println("✅ 'High school' radio button selected.");
			} else {
				System.out.println("Info: 'High school' radio button was already selected.");
			}
			pause(1);

			// 3. Interact with a checkbox
			System.out.println("\n--- Testing Checkboxes ---");
			// Find the 'Male' checkbox.
			WebElement maleCheckbox = driver.findElement(By.id("checkbox-1"));
			// Click it if it's not already selected.
			if (!maleCheckbox.isSelected()) {
				maleCheckbox.click();
				System.out.println("✅ 'Male' checkbox checked.");
			} else {
				System.out.println("Info: 'Male' checkbox was already checked.");
			}
			pause(1);

			// 4. Interact with a dropdown menu (using the Select class)
			System.out.println("\n--- Testing Dropdown Menu ---");
			// Find the dropdown element.
			WebElement yearsOfExperienceDropdownElement = driver.findElement(By.id("select-menu"));
			// Create a Select object to interact with the dropdown.
			Select yearsOfExperience = new Select(yearsOfExperienceDropdownElement);

			// Select an option by its 'value' attribute.
			yearsOfExperience.selectByValue("2"); 
			System.out.println("✅ Selected experience '0-1 year'."); // Note: value "2" corresponds to "0-1" in this specific dropdown
			pause(1);

			// Select an option by its visible text.
			yearsOfExperience.selectByVisibleText("2-4"); 
			System.out.println("✅ Selected experience '2-4 years'.");
			pause(1);

			// 5. Submit the form
			System.out.println("\n--- Submitting Form ---");
			// Find the submit button.
			WebElement submitButton = driver.findElement(By.cssSelector(".btn.btn-lg.btn-primary")); 
			submitButton.click(); // Click the submit button.
			System.out.println("✅ Form submitted.");

			// Verify that a success message is displayed after submission.
			WebElement successMessage = wait
					.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector(".alert.alert-success")));
			if (successMessage.getText().contains("The form was successfully submitted!")) {
				System.out.println("✅ Form submitted successfully and confirmation message displayed.");
			} else {
				System.out.println("❌ Error: Confirmation message mismatch or not displayed.");
			}
			pause(3);

		} catch (Exception e) {
			// Catch any errors that occur during the test.
			System.err.println("🚨 An error occurred during the test: " + e.getMessage());
			e.printStackTrace();
		} finally {
			// Ensure the browser is closed even if an error occurs.
			if (driver != null) {
				driver.quit();
				System.out.println("\n🔚 UI element interaction test completed.");
			}
		}
	}
}
