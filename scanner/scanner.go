package scanner

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/teneluce/vulnscanner/cpe_mapping"
)

type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	Address Address `xml:"address"`
	Ports   Ports   `xml:"ports"`
	Status  Status  `xml:"status"`
}

type Status struct {
	State string `xml:"state,attr"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
}

type Ports struct {
	PortList []Port `xml:"port"`
}

type Port struct {
	PortID   string  `xml:"portid,attr"`
	Protocol string  `xml:"protocol,attr"`
	Service  Service `xml:"service"`
}

type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	CPEs    []CPE  `xml:"cpe"`
}

type CPE struct {
	Value string `xml:",chardata"`
}

type ScanResult struct {
	IP   string
	CPEs []string
	Err  error
}

type Scanner struct {
	Verbose bool
}

func New() *Scanner {
	return &Scanner{
		Verbose: false,
	}
}

func (s *Scanner) IsNmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

func (s *Scanner) ScanIPs(ips []string) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, len(ips))

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, addr string) {
			defer wg.Done()
			results[index] = s.scanSingleIP(addr)
		}(i, ip)
	}

	wg.Wait()
	return results
}

func (s *Scanner) scanSingleIP(ip string) ScanResult {
	result := ScanResult{IP: ip}

	cmd := exec.Command("nmap",
		"-sV",
		"--script", "vulners",
		"-oX", "-",
		ip)

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Err = fmt.Errorf("nmap error: %v", err)
		return result
	}

	var nmapRun NmapRun
	err = xml.Unmarshal(output, &nmapRun)
	if err != nil {
		result.Err = fmt.Errorf("XML parsing error: %v", err)
		return result
	}

	cpeSet := make(map[string]bool)
	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}
		for _, port := range host.Ports.PortList {
			for _, cpe := range port.Service.CPEs {
				if cpe.Value != "" {
					converted := ConvertCPE22to23(cpe.Value)
					normalized := s.NormalizeCPE(converted)
					cpeSet[normalized] = true
				}
			}
		}
	}

	for cpe := range cpeSet {
		result.CPEs = append(result.CPEs, cpe)
	}

	return result
}

func ConvertCPE22to23(cpe string) string {
	if len(cpe) >= 7 && cpe[:7] == "cpe:2.3" {
		return cpe
	}

	wfn, err := naming.UnbindURI(cpe)
	if err != nil {
		wfn2, err2 := naming.UnbindFS(cpe)
		if err2 != nil {
			return cpe
		}
		return naming.BindToFS(wfn2)
	}

	return naming.BindToFS(wfn)
}

func (s *Scanner) NormalizeCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return cpe
	}

	vendor := parts[3]
	product := parts[4]
	version := parts[5]

	originalProduct := product
	product = cpe_mapping.ApplyMappingRules(vendor, product)
	parts[4] = product

	if s.Verbose && originalProduct != product {
		fmt.Printf("[MAPPING] %s:%s -> %s:%s\n", vendor, originalProduct, vendor, product)
	}

	if s.Verbose && originalProduct == product && strings.HasPrefix(originalProduct, vendor+"_") {
		fmt.Printf("[INFO] Potentially unmapped CPE: %s:%s\n", vendor, product)
	}

	originalVersion := version
	version = cpe_mapping.NormalizeVersion(vendor, product, version)
	parts[5] = version

	if s.Verbose && originalVersion != version {
		fmt.Printf("[VERSION] %s:%s:%s -> %s\n", vendor, product, originalVersion, version)
	}

	versionUpdateRegex := regexp.MustCompile(`^(\d+(?:\.\d+)*)(p|rc|beta|alpha|b|a)(\d+)$`)
	if matches := versionUpdateRegex.FindStringSubmatch(version); matches != nil {
		parts[5] = matches[1]
		parts[6] = matches[2] + matches[3]
	}

	return strings.Join(parts, ":")
}