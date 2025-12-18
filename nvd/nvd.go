package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	rateLimit  *RateLimiter
}

type RateLimiter struct {
	requests    int
	windowStart time.Time
	maxRequests int
	window      time.Duration
}

type CVE struct {
	ID          string
	Description string
	BaseScore   float64
	Severity    string
	Published   string
	Modified    string
}

type NVDResponse struct {
	ResultsPerPage  int                 `json:"resultsPerPage"`
	StartIndex      int                 `json:"startIndex"`
	TotalResults    int                 `json:"totalResults"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	CVE CVEItem `json:"cve"`
}

type CVEItem struct {
	ID           string        `json:"id"`
	Descriptions []Description `json:"descriptions"`
	Published    string        `json:"published"`
	LastModified string        `json:"lastModified"`
	Metrics      Metrics       `json:"metrics"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetric `json:"cvssMetricV2"`
}

type CVSSMetric struct {
	CVSSData CVSSData `json:"cvssData"`
}

type CVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func NewClient(apiKey string) *Client {
	maxReqs := 5
	if apiKey != "" {
		maxReqs = 50
	}

	return &Client{
		apiKey:  apiKey,
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateLimit: &RateLimiter{
			maxRequests: maxReqs,
			window:      30 * time.Second,
			windowStart: time.Now(),
		},
	}
}

func (rl *RateLimiter) Wait() {
	now := time.Now()

	if now.Sub(rl.windowStart) >= rl.window {
		rl.requests = 0
		rl.windowStart = now
		return
	}

	if rl.requests >= rl.maxRequests {
		waitTime := rl.window - now.Sub(rl.windowStart)
		if waitTime > 0 {
			time.Sleep(waitTime)
		}
		rl.requests = 0
		rl.windowStart = time.Now()
	}

	rl.requests++
}

func (c *Client) GetCVEsForCPE(cpe string) ([]CVE, error) {
	c.rateLimit.Wait()

	params := url.Values{}
	params.Add("cpeName", cpe)

	reqURL := fmt.Sprintf(
		"%s?cpeName=%s",
		c.baseURL,
		cpe,
	)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation error: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Add("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response reading error: %w", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("JSON parsing error: %w", err)
	}

	cves := make([]CVE, 0, len(nvdResp.Vulnerabilities))
	for _, vuln := range nvdResp.Vulnerabilities {
		cve := CVE{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
			Modified:  vuln.CVE.LastModified,
		}

		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			cve.BaseScore = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			cve.Severity = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		} else if len(vuln.CVE.Metrics.CVSSMetricV30) > 0 {
			cve.BaseScore = vuln.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			cve.Severity = vuln.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
		} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
			cve.BaseScore = vuln.CVE.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
			cve.Severity = calculateSeverityV2(cve.BaseScore)
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

func calculateSeverityV2(score float64) string {
	if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	}
	return "LOW"
}
