package SecurityTools;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Scanner; // Pro uživatelský vstup

public class SimplePortScanner {

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		System.out.println("Zadejte IP adresu nebo název hostitele pro skenování (např. 127.0.0.1 nebo google.com):");
		String host = scanner.nextLine();

		System.out.println("Zadejte počáteční port pro skenování (např. 1):");
		int startPort = scanner.nextInt();

		System.out.println("Zadejte koncový port pro skenování (např. 1024):");
		int endPort = scanner.nextInt();

		int timeout = 200; // Časový limit pro připojení k portu v milisekundách

		System.out.println("\nSpouštím skenování portů na " + host + " od " + startPort + " do " + endPort + "...");

		for (int port = startPort; port <= endPort; port++) {
			try {
				// Pokus o navázání socketového spojení s portem
				Socket socket = new Socket();
				socket.connect(new InetSocketAddress(host, port), timeout);
				socket.close();
				System.out.println("✅ Port " + port + " je OTEVŘENÝ");
			} catch (SocketTimeoutException e) {
				// System.out.println("Port " + port + " je FILTROVANÝ (timeout)"); // Můžete
				// odkomentovat pro detailnější log
			} catch (IOException e) {
				// System.out.println("Port " + port + " je ZAVŘENÝ nebo CHYBA: " +
				// e.getMessage()); // Můžete odkomentovat
			} catch (SecurityException e) {
				System.out
						.println("❌ Port " + port + " - Chyba zabezpečení (nedostatečná oprávnění): " + e.getMessage());
			} catch (IllegalArgumentException e) {
				System.out.println("❌ Chyba: Neplatný port " + port + ": " + e.getMessage());
			}
		}

		System.out.println("\nSkener portů dokončen.");
		scanner.close();
	}
}