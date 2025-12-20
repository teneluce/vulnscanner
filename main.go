package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/teneluce/vulnscanner/nvd"
	"github.com/teneluce/vulnscanner/report"
	"github.com/teneluce/vulnscanner/scanner"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	verbose := false
	fetchCVE := false
	generateHTML := false
	apiKey := loadAPIKeyFromEnv()
	var ips []string

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-v" || arg == "--verbose" {
			verbose = true
		} else if arg == "-c" || arg == "--cve" {
			fetchCVE = true
		} else if arg == "-r" || arg == "--report" {
			generateHTML = true
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
	if generateHTML {
		fmt.Println("HTML report will be generated in ./output/html/")
	}
	fmt.Println()

	results := s.ScanIPs(ips)

	if fetchCVE {
		results = enrichWithCVEs(results, apiKey)
	}

	displayResults(results, fetchCVE)

	if generateHTML {
		outputFile, err := report.GenerateHTML(results)
		if err != nil {
			fmt.Printf("Error generating HTML report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nHTML report generated: %s\n", outputFile)
	}
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

func enrichWithCVEs(results []scanner.ScanResult, apiKey string) []scanner.ScanResult {
	nvdClient := nvd.NewClient(apiKey)

	for i := range results {
		if results[i].Err != nil {
			continue
		}

		for j := range results[i].CPEs {
			fmt.Printf("Searching CVEs for %s...\n", results[i].CPEs[j].Value)
			cves, err := nvdClient.GetCVEsForCPE(results[i].CPEs[j].Value)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			results[i].CPEs[j].CVEs = cves
		}
	}

	return results
}

func printUsage() {
	fmt.Println("Usage: vulnscanner [OPTIONS] <IP1> <IP2> ... <IPN>")
	fmt.Println("\nOptions:")
	fmt.Println("  -v, --verbose      Verbose mode (show CPE mappings)")
	fmt.Println("  -c, --cve          Fetch CVEs from NVD API")
	fmt.Println("  -r, --report       Generate HTML report in ./output/html/")
	fmt.Println("\nAPI Key:")
	fmt.Println("  Create a .env file with: NIST_API_KEY=your_key_here")
	fmt.Println("  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key")
	fmt.Println("\nExamples:")
	fmt.Println("  vulnscanner 192.168.1.1")
	fmt.Println("  vulnscanner -v 192.168.1.1 192.168.1.2")
	fmt.Println("  vulnscanner -c 192.168.1.1")
	fmt.Println("  vulnscanner -c -r 192.168.1.1")
}

func displayResults(results []scanner.ScanResult, fetchCVE bool) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("                       SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	totalCPEs := 0
	totalCVEs := 0

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
		for _, cpeItem := range result.CPEs {
			fmt.Printf("  - %s\n", cpeItem.Value)
			totalCPEs++

			if fetchCVE && len(cpeItem.CVEs) > 0 {
				fmt.Printf("    %d CVE(s) found:\n", len(cpeItem.CVEs))
				for _, cve := range cpeItem.CVEs {
					severity := "N/A"
					if cve.BaseScore > 0 {
						severity = fmt.Sprintf("%.1f (%s)", cve.BaseScore, cve.Severity)
					}
					fmt.Printf("      * %s [%s] %s\n", cve.ID, severity, truncate(cve.Description, 60))
					totalCVEs++
				}
			} else if fetchCVE {
				fmt.Printf("    No CVE found\n")
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
