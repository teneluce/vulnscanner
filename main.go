package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/teneluce/vulnscanner/nvd"
	"github.com/teneluce/vulnscanner/scanner"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	verbose := false
	fetchCVE := false
	apiKey := loadAPIKeyFromEnv()
	var ips []string

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-v" || arg == "--verbose" {
			verbose = true
		} else if arg == "-c" || arg == "--cve" {
			fetchCVE = true
		} else {
			ips = append(ips, arg)
		}
	}

	if len(ips) == 0 {
		printUsage()
		os.Exit(1)
	}

	s := scanner.New()
	s.Verbose = verbose

	if !s.IsNmapInstalled() {
		fmt.Println("Error: nmap is not installed or not in PATH")
		fmt.Println("\nInstallation:")
		fmt.Println("  Ubuntu/Debian: sudo apt install nmap")
		fmt.Println("  macOS:         brew install nmap")
		os.Exit(1)
	}

	fmt.Printf("Scanning %d IP address(es)...\n", len(ips))
	if verbose {
		fmt.Println("Verbose mode enabled")
	}
	if fetchCVE {
		fmt.Println("CVE lookup enabled")
		if apiKey != "" {
			fmt.Println("NVD API key loaded from .env")
		} else {
			fmt.Println("Warning: No API key found in .env (rate limit: 5 req/30s)")
		}
	}
	fmt.Println()

	results := s.ScanIPs(ips)
	displayResults(results, fetchCVE, apiKey)
}

func loadAPIKeyFromEnv() string {
	file, err := os.Open(".env")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "NIST_API_KEY" {
			return strings.TrimSpace(parts[1])
		}
	}

	return ""
}

func printUsage() {
	fmt.Println("Usage: vulnscanner [OPTIONS] <IP1> <IP2> ... <IPN>")
	fmt.Println("\nOptions:")
	fmt.Println("  -v, --verbose    Verbose mode (show CPE mappings)")
	fmt.Println("  -c, --cve        Fetch CVEs from NVD API")
	fmt.Println("\nAPI Key:")
	fmt.Println("  Create a .env file with: NIST_API_KEY=your_key_here")
	fmt.Println("  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key")
	fmt.Println("\nExamples:")
	fmt.Println("  vulnscanner 192.168.1.1")
	fmt.Println("  vulnscanner -v 192.168.1.1 192.168.1.2")
	fmt.Println("  vulnscanner -c 192.168.1.1")
	fmt.Println("  vulnscanner -v -c 192.168.1.1")
}

func displayResults(results []scanner.ScanResult, fetchCVE bool, apiKey string) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("                       SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	totalCPEs := 0
	totalCVEs := 0

	var nvdClient *nvd.Client
	if fetchCVE {
		nvdClient = nvd.NewClient(apiKey)
	}

	for _, result := range results {
		fmt.Printf("\nIP: %s\n", result.IP)
		fmt.Println(strings.Repeat("-", 70))

		if result.Err != nil {
			fmt.Printf("Error: %v\n", result.Err)
			continue
		}

		if len(result.CPEs) == 0 {
			fmt.Println("No CPE found")
			continue
		}

		fmt.Printf("%d CPE(s) found (NIST format):\n", len(result.CPEs))
		for _, cpe := range result.CPEs {
			fmt.Printf("  - %s\n", cpe)
			totalCPEs++

			if fetchCVE && nvdClient != nil {
				fmt.Printf("    Searching for CVEs...\n")
				cves, err := nvdClient.GetCVEsForCPE(cpe)
				if err != nil {
					fmt.Printf("    Error: %v\n", err)
					continue
				}

				if len(cves) == 0 {
					fmt.Printf("    No CVE found\n")
				} else {
					fmt.Printf("    %d CVE(s) found:\n", len(cves))
					for _, cve := range cves {
						severity := "N/A"
						if cve.BaseScore > 0 {
							severity = fmt.Sprintf("%.1f (%s)", cve.BaseScore, cve.Severity)
						}
						fmt.Printf("      * %s [%s] %s\n", cve.ID, severity, truncate(cve.Description, 60))
						totalCVEs++
					}
				}
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Printf("Total: %d CPE(s) detected", totalCPEs)
	if fetchCVE {
		fmt.Printf(" | %d CVE(s) found", totalCVEs)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
