package UI;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select; // Import pro práci s dropdown menu
import org.openqa.selenium.support.ui.WebDriverWait;
import java.time.Duration;

import io.github.bonigarcia.wdm.WebDriverManager;

public class UIElementInteractionTest {

	public static String browser = "Chrome"; // nebo "Edge"
	public static WebDriver driver;

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

	public static void pause(int seconds) {
		try {
			Thread.sleep(seconds * 1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		setUpDriver();
		WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
		System.out.println("🧪 Spuštěn test interakce s různými UI prvky na formy-project.herokuapp.com");

		try {
			driver.get("https://formy-project.herokuapp.com/form");

			// 1. Interakce s textovými poli
			System.out.println("\n--- Test textových polí ---");
			WebElement firstName = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("first-name")));
			firstName.sendKeys("Jan");
			System.out.println("✅ Vyplněno jméno.");

			WebElement lastName = driver.findElement(By.id("last-name"));
			lastName.sendKeys("Novak");
			System.out.println("✅ Vyplněno příjmení.");

			WebElement jobTitle = driver.findElement(By.id("job-title"));
			jobTitle.sendKeys("QA Tester");
			System.out.println("✅ Vyplněna pozice.");
			pause(1);

			// 2. Interakce s radio buttony
			System.out.println("\n--- Test radio buttonů ---");
			WebElement highestDegreeRadio = driver.findElement(By.id("radio-button-3")); // High school
			if (!highestDegreeRadio.isSelected()) {
				highestDegreeRadio.click();
				System.out.println("✅ Vybrán radio button 'High school'.");
			} else {
				System.out.println("Info: Radio button 'High school' již byl vybrán.");
			}
			pause(1);

			// 3. Interakce s checkboxem
			System.out.println("\n--- Test checkboxů ---");
			WebElement maleCheckbox = driver.findElement(By.id("checkbox-1"));
			if (!maleCheckbox.isSelected()) {
				maleCheckbox.click();
				System.out.println("✅ Zaškrtnut checkbox 'Male'.");
			} else {
				System.out.println("Info: Checkbox 'Male' již byl zaškrtnut.");
			}
			pause(1);

			// 4. Interakce s dropdown menu (pomocí třídy Select)
			System.out.println("\n--- Test dropdown menu ---");
			WebElement yearsOfExperienceDropdownElement = driver.findElement(By.id("select-menu"));
			Select yearsOfExperience = new Select(yearsOfExperienceDropdownElement);

			yearsOfExperience.selectByValue("2"); // Vybere "0-1" rok (value="0-1")
			System.out.println("✅ Vybrána zkušenost '0-1 year'.");
			pause(1);

			yearsOfExperience.selectByVisibleText("2-4"); // Vybere "2-4" roky
			System.out.println("✅ Vybrána zkušenost '2-4 years'.");
			pause(1);

			// 5. Odeslání formuláře
			System.out.println("\n--- Odeslání formuláře ---");
			WebElement submitButton = driver.findElement(By.cssSelector(".btn.btn-lg.btn-primary")); // Nebo
																										// By.xpath("//a[@role='button']")
			submitButton.click();
			System.out.println("✅ Formulář odeslán.");

			// Ověření, že jsme přesměrováni na stránku s potvrzením
			WebElement successMessage = wait
					.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector(".alert.alert-success")));
			if (successMessage.getText().contains("The form was successfully submitted!")) {
				System.out.println("✅ Formulář úspěšně odeslán a potvrzovací zpráva zobrazena.");
			} else {
				System.out.println("❌ Chyba: Potvrzovací zpráva se neshoduje nebo nebyla zobrazena.");
			}
			pause(3);

		} catch (Exception e) {
			System.err.println("🚨 Během testu došlo k chybě: " + e.getMessage());
			e.printStackTrace();
		} finally {
			if (driver != null) {
				driver.quit();
				System.out.println("\n🔚 Test interakce s UI prvky dokončen.");
			}
		}
	}
}