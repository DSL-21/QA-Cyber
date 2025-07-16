package main

import (
	"bufio"
	"crypto/tls"
	"flag" // Opětovný import pro argumenty příkazové řádky
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortScanResult uchovává informace o výsledku skenování jednoho portu
type PortScanResult struct {
	Port     int
	Status   string // "OPEN", "CLOSED", "FILTERED", "ERROR"
	Banner   string // Informace o službě, pokud je k dispozici
	Error    string // Detail chyby, pokud nastala
	Protocol string // "tcp" nebo "udp"
}

// probeService se pokusí identifikovat službu na otevřeném TCP portu
func probeService(conn net.Conn, port int, readTimeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	reader := bufio.NewReader(conn)
	buffer := make([]byte, 2048)

	var banner strings.Builder

	switch port {
	case 80: // HTTP
		_, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
		if err != nil {
			return fmt.Sprintf("Error sending HTTP GET: %v", err)
		}
		line, err := reader.ReadString('\n')
		if err == nil {
			banner.WriteString(strings.TrimSpace(line))
		}
	case 443: // HTTPS (Pokročilý TLS Probing)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Pro jednoduchost skenu, ve skutečném kódu by to mělo být false
		}
		tlsConn := tls.Client(conn, tlsConfig)
		defer tlsConn.Close()

		err := tlsConn.Handshake()
		if err != nil {
			return fmt.Sprintf("TLS Handshake failed: %v", err)
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			banner.WriteString(fmt.Sprintf("TLS/SSL, CommonName: %s", cert.Subject.CommonName))
			if len(cert.DNSNames) > 0 {
				banner.WriteString(fmt.Sprintf(", DNSNames: %s", strings.Join(cert.DNSNames, ", ")))
			}
		}
		_, err = tlsConn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
		if err == nil {
			line, err := bufio.NewReader(tlsConn).ReadString('\n')
			if err == nil {
				banner.WriteString(fmt.Sprintf(" HTTP: %s", strings.TrimSpace(line)))
			}
		}

	case 21: // FTP
		line, err := reader.ReadString('\n')
		if err == nil {
			banner.WriteString(strings.TrimSpace(line))
		}
	case 22: // SSH
		line, err := reader.ReadString('\n')
		if err == nil {
			banner.WriteString(strings.TrimSpace(line))
		}
	case 25, 587, 465: // SMTP
		line, err := reader.ReadString('\n')
		if err == nil {
			banner.WriteString(strings.TrimSpace(line))
		}
	default:
		n, err := reader.Read(buffer)
		if err == nil && n > 0 {
			banner.WriteString(string(buffer[:n]))
		} else if err != nil && err != io.EOF {
			return fmt.Sprintf("Error reading banner: %v", err)
		}
	}

	cleanedBanner := strings.TrimSpace(banner.String())
	if len(cleanedBanner) > 200 {
		cleanedBanner = cleanedBanner[:200] + "..."
	}
	if strings.Contains(cleanedBanner, "HTTP/1.0 400 Bad Request") || strings.Contains(cleanedBanner, "HTTP/1.1 400 Bad Request") {
		return ""
	}
	return cleanedBanner
}

// scanUDPPort skenuje jeden UDP port
func scanUDPPort(targetIP string, port int, timeout time.Duration) PortScanResult {
	result := PortScanResult{Port: port, Protocol: "udp"}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		result.Status = "ERROR"
		result.Error = fmt.Sprintf("UDP dial error: %v", err)
		return result
	}
	defer conn.Close()

	testData := []byte("hello")
	_, err = conn.Write(testData)
	if err != nil {
		result.Status = "ERROR"
		result.Error = fmt.Sprintf("UDP write error: %v", err)
		return result
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Status = "CLOSED/FILTERED (No response)"
		} else {
			result.Status = "ERROR"
			result.Error = fmt.Sprintf("UDP read error: %v", err)
		}
	} else if n > 0 {
		result.Status = "OPEN"
		result.Banner = strings.TrimSpace(string(buffer[:n]))
		if len(result.Banner) > 200 {
			result.Banner = result.Banner[:200] + "..."
		}
	} else {
		result.Status = "CLOSED/FILTERED (Empty response)"
	}

	return result
}

func main() {
	// --- Nastavení argumentů příkazové řádky ---
	hostPtr := flag.String("host", "", "IP address or hostname to scan (e.g., 127.0.0.1 or google.com)")
	portsPtr := flag.String("ports", "1-1024", "Port(s) or range to scan (e.g., 1-1024 or 22,80,443)")
	protocolPtr := flag.String("protocol", "tcp", "Protocol to scan (tcp or udp)")
	timeoutPtr := flag.Int("timeout", 500, "Connection/response timeout in milliseconds")
	bannerTimeoutPtr := flag.Int("banner-timeout", 1000, "Banner/UDP read timeout in milliseconds")
	workersPtr := flag.Int("workers", 100, "Number of concurrent goroutines (scanners)")
	verbosePtr := flag.Bool("verbose", false, "Show verbose output (includes CLOSED, FILTERED, and ERROR ports)")

	flag.Parse() // Zpracuje argumenty z příkazové řádky

	// Kontrola, zda byl zadán host
	if *hostPtr == "" {
		fmt.Println("Error: Host is required. Use --host <IP_or_hostname>")
		flag.Usage() // Zobrazí nápovědu k použití
		return
	}

	// ASCII art logo pro výstup konzole
	asciiArt := " ____ ____ __ _ _ _ _ ____ \n" +
		" ( \\( __)( __)( ) / )( \\( \\/ )( __)\n" +
		" ) D ( ) _) / (_/\\) \\/ ( ) ( ) _) \n" +
		" (____/(____)\\____/\\____/(_/\\_)(____)\n" +
		"***************************************\n" +
		"* Copyright 2025, ★DSL★           *\n" +
		"* https://github.com/DSL-21           *\n" +
		"***************************************"
	fmt.Println(asciiArt)
	fmt.Println("--- Advanced Go Port Scanner (CLI) ---") // Změněno na CLI

	host := *hostPtr
	portsInput := *portsPtr
	protocol := strings.ToLower(strings.TrimSpace(*protocolPtr))
	timeoutMs := *timeoutPtr
	readBannerTimeoutMs := *bannerTimeoutPtr
	numWorkers := *workersPtr
	verbose := *verbosePtr

	// --- Validace protokolu ---
	if protocol != "tcp" && protocol != "udp" {
		fmt.Println("Error: Invalid protocol. Please use 'tcp' or 'udp'.")
		flag.Usage()
		return
	}

	// --- Validace a parsání portů ---
	var ports []int
	if strings.Contains(portsInput, "-") {
		parts := strings.Split(portsInput, "-")
		if len(parts) != 2 {
			fmt.Println("Error: Invalid port range format. Use 'start-end' (e.g., 1-1024).")
			flag.Usage()
			return
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			fmt.Printf("Error: Invalid start port '%s': %v\n", parts[0], err)
			return
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			fmt.Printf("Error: Invalid end port '%s': %v\n", parts[1], err)
			return
		}
		if start < 1 || end > 65535 || start > end {
			fmt.Println("Error: Invalid port range. Ports must be between 1 and 65535, and start port must be less than or equal to end port.")
			return
		}
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else if strings.Contains(portsInput, ",") {
		portStrings := strings.Split(portsInput, ",")
		for _, s := range portStrings {
			p, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				fmt.Printf("Error: Invalid port '%s': %v\n", s, err)
				return
			}
			if p < 1 || p > 65535 {
				fmt.Printf("Error: Port %d is out of valid range (1-65535).\n", p)
				return
			}
			ports = append(ports, p)
		}
		if len(ports) == 0 {
			fmt.Println("Error: No valid ports specified for scan.")
			return
		}
	} else {
		p, err := strconv.Atoi(strings.TrimSpace(portsInput))
		if err != nil {
			fmt.Printf("Error: Invalid port '%s': %v\n", portsInput, err)
			return
		}
		if p < 1 || p > 65535 {
			fmt.Printf("Error: Port %d is out of valid range (1-65535).\n", p)
			return
		}
		ports = append(ports, p)
	}

	// --- Validace ostatních vstupů ---
	if timeoutMs <= 0 {
		fmt.Println("Error: Connection timeout must be a positive number.")
		return
	}
	if readBannerTimeoutMs <= 0 {
		fmt.Println("Error: Banner read timeout must be a positive number.")
		return
	}
	if numWorkers <= 0 {
		fmt.Println("Error: Number of workers must be a positive number.")
		return
	}

	// --- Inteligentní DNS Rozlišení ---
	ips, err := net.LookupIP(host)
	if err != nil {
		fmt.Printf("❌ Error: Could not resolve hostname '%s': %v\n", host, err)
		return
	}
	targetIP := ips[0].String()
	fmt.Printf("Resolved '%s' to IP address: %s\n", host, targetIP)

	// Nastavení timeoutů a počtu workerů z uživatelského vstupu
	connectionTimeout := time.Duration(timeoutMs) * time.Millisecond
	bannerReadTimeout := time.Duration(readBannerTimeoutMs) * time.Millisecond

	fmt.Printf("\nStarting %s port scan on %s (%s) for ports %s with %d workers, connection timeout %s, banner read timeout %s...\n",
		strings.ToUpper(protocol), host, targetIP, portsInput, numWorkers, connectionTimeout, bannerReadTimeout)
	startTime := time.Now()

	// Kanály a WaitGroup pro řízení souběžnosti
	portsToScanChan := make(chan int, numWorkers)
	resultsChan := make(chan PortScanResult)
	var wg sync.WaitGroup

	// Spuštění 'pracovních' gorutin (worker pool)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portsToScanChan {
				var result PortScanResult
				result.Port = p
				result.Protocol = protocol

				switch protocol {
				case "tcp":
					address := net.JoinHostPort(targetIP, fmt.Sprintf("%d", p))
					conn, err := net.DialTimeout("tcp", address, connectionTimeout)
					if err != nil {
						result.Status = "CLOSED"
						if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
							result.Status = "FILTERED"
						} else if opErr, ok := err.(*net.OpError); ok && opErr.Op == "dial" && opErr.Err.Error() == "connection refused" {
							result.Status = "CLOSED"
						} else {
							result.Status = "ERROR"
							result.Error = err.Error()
						}
					} else {
						result.Status = "OPEN"
						result.Banner = probeService(conn, p, bannerReadTimeout)
						conn.Close()
					}
				case "udp":
					result = scanUDPPort(targetIP, p, connectionTimeout)
				}
				resultsChan <- result
			}
		}()
	}

	// Gorutina pro odesílání všech portů do kanálu 'portsToScanChan'
	go func() {
		for _, p := range ports {
			portsToScanChan <- p
		}
		close(portsToScanChan)
	}()

	// Gorutina pro sběr a zpracování výsledků
	var finalResults []PortScanResult
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for r := range resultsChan {
			finalResults = append(finalResults, r)
		}
	}()

	wg.Wait()
	close(resultsChan)
	resultsWg.Wait()

	// Seřadíme výsledky podle čísla portu
	sort.Slice(finalResults, func(i, j int) bool {
		return finalResults[i].Port < finalResults[j].Port
	})

	elapsedTime := time.Since(startTime)

	fmt.Println("\n--- Scan Results ---")
	openCount := 0
	for _, res := range finalResults {
		if res.Status == "OPEN" {
			openCount++
			fmt.Printf("✅ %s Port %d is OPEN", strings.ToUpper(res.Protocol), res.Port)
			if res.Banner != "" {
				fmt.Printf(" (%s)", res.Banner)
			}
			fmt.Println()
		} else if verbose && res.Status == "CLOSED" {
			fmt.Printf("❌ %s Port %d is CLOSED\n", strings.ToUpper(res.Protocol), res.Port)
		} else if verbose && res.Status == "FILTERED" {
			fmt.Printf("⚠️ %s Port %d is FILTERED (timeout)\n", strings.ToUpper(res.Protocol), res.Port)
		} else if verbose && res.Status == "ERROR" || verbose && strings.HasPrefix(res.Status, "CLOSED/FILTERED") {
			fmt.Printf("❓ %s Port %d Status: %s, Error: %s\n", strings.ToUpper(res.Protocol), res.Port, res.Status, res.Error)
		}
	}

	fmt.Printf("\nFound %d open ports in %s.\n", openCount, elapsedTime.Round(time.Millisecond))
	fmt.Println("--- Scan Completed ---")
}
