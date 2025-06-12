package SecurityTools;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Scanner; // For user input.

public class SimplePortScanner {

	public static void main(String[] args) {
		// ASCII art logo for console output.
		String asciiArt = "  ____  ____  __    _  _  _  _  ____ \n" + " (    \\(  __)(  )  / )( \\( \\/ )(  __)\n"
				+ "  ) D ( ) _) / (_/\\) \\/ ( )  (  ) _) \n" + " (____/(____)\\____/\\____/(_/\\_)(____)\n"
				+ "***************************************\n" + "* Copyright 2025, ★DSL★           *\n"
				+ "* https://github.com/DSL-21           *\n" + "***************************************";
		System.out.println(asciiArt);
		System.out.println("--- Simple Port Scanner ---");

		Scanner scanner = new Scanner(System.in);

		System.out.println("Enter the IP address or hostname to scan (e.g., 127.0.0.1 or google.com):");
		String host = scanner.nextLine();

		System.out.println("Enter the starting port for the scan (e.g., 1):");
		int startPort = scanner.nextInt();

		System.out.println("Enter the ending port for the scan (e.g., 1024):");
		int endPort = scanner.nextInt();

		int timeout = 200; // Connection timeout in milliseconds.

		System.out.println("\nStarting port scan on " + host + " from " + startPort + " to " + endPort + "...");

		// Loop through each port in the specified range.
		for (int port = startPort; port <= endPort; port++) {
			try {
				// Attempt to establish a socket connection to the port.
				Socket socket = new Socket();
				socket.connect(new InetSocketAddress(host, port), timeout);
				socket.close(); // Close the socket if connection is successful.
				System.out.println("✅ Port " + port + " is OPEN");
			} catch (SocketTimeoutException e) {
				// Port is filtered/timed out. (Commented out for cleaner output).
				// System.out.println("Port " + port + " is FILTERED (timeout)");
			} catch (IOException e) {
				// Port is closed or another IO error occurred. (Commented out).
				// System.out.println("Port " + port + " is CLOSED or ERROR: " +
				// e.getMessage());
			} catch (SecurityException e) {
				// Handle security manager issues (e.g., insufficient permissions).
				System.out
						.println("❌ Port " + port + " - Security error (insufficient permissions): " + e.getMessage());
			} catch (IllegalArgumentException e) {
				// Handle invalid port numbers.
				System.out.println("❌ Error: Invalid port " + port + ": " + e.getMessage());
			}
		}

		System.out.println("\nPort scan completed.");
		scanner.close(); // Close the scanner.
	}
}
