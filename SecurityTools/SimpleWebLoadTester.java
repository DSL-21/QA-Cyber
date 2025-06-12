package SecurityTools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

public class SimpleWebLoadTester {

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		// ASCII art logo for console output.
		String asciiArt = "  ____  ____  __    _  _  _  _  ____ \n" + " (    \\(  __)(  )  / )( \\( \\/ )(  __)\n"
				+ "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n" + " (____/(____)\\____/\\____/(_/\\_)(____)\n"
				+ "***************************************\n" + "* Copyright 2025, ★DSL★ 	      *\n"
				+ "* https://github.com/DSL-21   	      *\n" + "***************************************";
		System.out.println(asciiArt);

		System.out.println("--- Simple Web Load Tester ---");
		System.out.println("Enter the target URL (e.g., http://localhost:8080/):");
		String targetUrl = scanner.nextLine();

		System.out.println("Enter the number of requests to send (e.g., 100):");
		int numRequests = 0;
		try {
			numRequests = Integer.parseInt(scanner.nextLine());
			if (numRequests <= 0) {
				System.out.println("Number of requests must be positive. Using default 10.");
				numRequests = 10;
			}
		} catch (NumberFormatException e) {
			System.out.println("Invalid number. Using default 10.");
			numRequests = 10;
		}

		System.out.println("Enter delay between requests in milliseconds (e.g., 50 for 50ms, 0 for no delay):");
		int delayMs = 0;
		try {
			delayMs = Integer.parseInt(scanner.nextLine());
			if (delayMs < 0)
				delayMs = 0;
		} catch (NumberFormatException e) {
			System.out.println("Invalid delay. Using default 0ms.");
			delayMs = 0;
		}

		System.out.println("\nStarting load test on " + targetUrl + " with " + numRequests + " requests...");

		long startTime = System.currentTimeMillis();
		AtomicInteger successCount = new AtomicInteger(0); // Counter for successful responses.
		AtomicInteger failCount = new AtomicInteger(0); // Counter for failed responses.

		for (int i = 0; i < numRequests; i++) {
			System.out.print("Sending request #" + (i + 1) + "... ");
			HttpURLConnection connection = null; // Declare connection outside try for finally block.

			try {
				// Create URL from URI to handle deprecated URL constructor.
				URI uri = new URI(targetUrl);
				URL url = uri.toURL();

				connection = (HttpURLConnection) url.openConnection();
				connection.setRequestMethod("GET");
				connection.setConnectTimeout(5000); // 5-second connection timeout.
				connection.setReadTimeout(5000); // 5-second read timeout.

				int responseCode = connection.getResponseCode();
				System.out.println("Status: " + responseCode);

				// Check if response code indicates success (2xx).
				if (responseCode >= 200 && responseCode < 300) {
					successCount.incrementAndGet();
				} else {
					failCount.incrementAndGet();
				}

				// Read and discard response body (or process for debugging).
				try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
					StringBuilder responseBody = new StringBuilder();
					String line;
					while ((line = in.readLine()) != null) {
						responseBody.append(line);
					}
				} catch (Exception e) {
					// Ignore errors if connection succeeded but reading response failed.
				}

				// Apply delay if specified.
				if (delayMs > 0) {
					Thread.sleep(delayMs);
				}

			} catch (Exception e) {
				System.err.println("❌ Error during request #" + (i + 1) + ": " + e.getMessage());
				failCount.incrementAndGet();
			} finally {
				// Ensure the connection is always closed.
				if (connection != null) {
					connection.disconnect();
				}
			}
		}

		long endTime = System.currentTimeMillis();
		long totalDurationSeconds = (endTime - startTime) / 1000;

		System.out.println("\n--- Load Test Completed ---");
		System.out.println("Requests sent: " + numRequests);
		System.out.println("Successful responses (2xx): " + successCount.get());
		System.out.println("Error responses / Failed: " + failCount.get());
		System.out.println("Total duration: " + totalDurationSeconds + " seconds.");

		scanner.close();
	}
}
