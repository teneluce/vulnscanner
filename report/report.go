package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/teneluce/vulnscanner/scanner"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }
        .stat-card.critical { border-color: #e74c3c; }
        .stat-card.high { border-color: #e67e22; }
        .stat-card.medium { border-color: #f39c12; }
        .stat-card.low { border-color: #3498db; }
        .stat-card.info { border-color: #95a5a6; }
        .stat-card h3 {
            font-size: 0.9em;
            color: #7f8c8d;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #ecf0f1;
        }
        .tab {
            padding: 12px 24px;
            cursor: pointer;
            border: none;
            background: transparent;
            font-size: 1em;
            color: #7f8c8d;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab:hover {
            color: #667eea;
        }
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
            font-weight: 600;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .content-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h2 {
            margin-bottom: 20px;
            color: #2c3e50;
            font-size: 1.5em;
        }
        .asset {
            padding: 15px;
            border: 1px solid #ecf0f1;
            border-radius: 8px;
            margin-bottom: 10px;
            transition: all 0.3s;
        }
        .asset:hover {
            border-color: #667eea;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.2);
        }
        .asset-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .asset-ip {
            font-size: 1.2em;
            font-weight: 600;
            color: #2c3e50;
        }
        .asset-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .vuln-item {
            padding: 15px;
            border-left: 4px solid;
            background: #f8f9fa;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .vuln-item.critical { border-color: #e74c3c; background: #fadbd8; }
        .vuln-item.high { border-color: #e67e22; background: #fdebd0; }
        .vuln-item.medium { border-color: #f39c12; background: #fef5e7; }
        .vuln-item.low { border-color: #3498db; background: #d6eaf8; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .vuln-id {
            font-weight: 600;
            font-size: 1.1em;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        .severity-badge.critical { background: #e74c3c; }
        .severity-badge.high { background: #e67e22; }
        .severity-badge.medium { background: #f39c12; }
        .severity-badge.low { background: #3498db; }
        .vuln-cpe {
            font-size: 0.9em;
            color: #7f8c8d;
            margin-bottom: 5px;
            font-family: monospace;
        }
        .vuln-desc {
            color: #555;
            font-size: 0.95em;
        }
        #chartContainer {
            height: 300px;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Vulnerability Scan Report</h1>
            <p>Generated on {{.Timestamp}}</p>
        </header>

        <div class="stats">
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="value">{{.Stats.Critical}}</div>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="value">{{.Stats.High}}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="value">{{.Stats.Medium}}</div>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="value">{{.Stats.Low}}</div>
            </div>
            <div class="stat-card info">
                <h3>Total Assets</h3>
                <div class="value">{{.Stats.TotalAssets}}</div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('critical')">Critical ({{.Stats.Critical}})</button>
            <button class="tab" onclick="showTab('high')">High ({{.Stats.High}})</button>
            <button class="tab" onclick="showTab('medium')">Medium ({{.Stats.Medium}})</button>
            <button class="tab" onclick="showTab('low')">Low ({{.Stats.Low}})</button>
            <button class="tab" onclick="showTab('assets')">Assets</button>
        </div>

        <div id="critical" class="tab-content active">
            {{range .VulnsBySeverity.Critical}}
            <div class="vuln-item critical">
                <div class="vuln-header">
                    <span class="vuln-id">{{.ID}}</span>
                    <span class="severity-badge critical">{{.Severity}} {{.BaseScore}}</span>
                </div>
                <div class="vuln-cpe">{{.CPE}} ({{.IP}})</div>
                <div class="vuln-desc">{{.Description}}</div>
            </div>
            {{end}}
        </div>

        <div id="high" class="tab-content">
            {{range .VulnsBySeverity.High}}
            <div class="vuln-item high">
                <div class="vuln-header">
                    <span class="vuln-id">{{.ID}}</span>
                    <span class="severity-badge high">{{.Severity}} {{.BaseScore}}</span>
                </div>
                <div class="vuln-cpe">{{.CPE}} ({{.IP}})</div>
                <div class="vuln-desc">{{.Description}}</div>
            </div>
            {{end}}
        </div>

        <div id="medium" class="tab-content">
            {{range .VulnsBySeverity.Medium}}
            <div class="vuln-item medium">
                <div class="vuln-header">
                    <span class="vuln-id">{{.ID}}</span>
                    <span class="severity-badge medium">{{.Severity}} {{.BaseScore}}</span>
                </div>
                <div class="vuln-cpe">{{.CPE}} ({{.IP}})</div>
                <div class="vuln-desc">{{.Description}}</div>
            </div>
            {{end}}
        </div>

        <div id="low" class="tab-content">
            {{range .VulnsBySeverity.Low}}
            <div class="vuln-item low">
                <div class="vuln-header">
                    <span class="vuln-id">{{.ID}}</span>
                    <span class="severity-badge low">{{.Severity}} {{.BaseScore}}</span>
                </div>
                <div class="vuln-cpe">{{.CPE}} ({{.IP}})</div>
                <div class="vuln-desc">{{.Description}}</div>
            </div>
            {{end}}
        </div>

        <div id="assets" class="tab-content">
            <div class="content-grid">
                <div class="card">
                    <h2>Scanned Assets</h2>
                    {{range .Results}}
                    <div class="asset">
                        <div class="asset-header">
                            <span class="asset-ip">{{.IP}}</span>
                            <span class="asset-badge">{{len .CPEs}} CPE(s)</span>
                        </div>
                        {{range .CPEs}}
                        <div class="vuln-cpe">{{.Value}} - {{len .CVEs}} CVE(s)</div>
                        {{end}}
                    </div>
                    {{end}}
                </div>
                <div class="card">
                    <h2>Vulnerability Distribution</h2>
                    <div id="chartContainer">
                        <canvas id="vulnChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <footer>
            <p>Generated by VulnScanner | NIST NVD API</p>
        </footer>
    </div>

    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        const ctx = document.getElementById('vulnChart').getContext('2d');
        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [{{.Stats.Critical}}, {{.Stats.High}}, {{.Stats.Medium}}, {{.Stats.Low}}],
                    backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    </script>
</body>
</html>`

type ReportData struct {
	Timestamp       string
	Results         []scanner.ScanResult
	Stats           Statistics
	VulnsBySeverity VulnerabilityBySeverity
}

type Statistics struct {
	Critical    int
	High        int
	Medium      int
	Low         int
	TotalAssets int
}

type VulnerabilityBySeverity struct {
	Critical []VulnDetail
	High     []VulnDetail
	Medium   []VulnDetail
	Low      []VulnDetail
}

type VulnDetail struct {
	ID          string
	CPE         string
	IP          string
	BaseScore   float64
	Severity    string
	Description string
}

func GenerateHTML(results []scanner.ScanResult) (string, error) {
	timestamp := time.Now()

	outputDir := "./output/html"
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return "", fmt.Errorf("directory creation error: %w", err)
	}

	filename := fmt.Sprintf("report_%s.html", timestamp.Format("2006-01-02_15-04-05"))
	outputFile := filepath.Join(outputDir, filename)

	data := ReportData{
		Timestamp: timestamp.Format("2006-01-02 15:04:05"),
		Results:   results,
	}

	data.Stats.TotalAssets = len(results)

	vulnsBySeverity := VulnerabilityBySeverity{
		Critical: []VulnDetail{},
		High:     []VulnDetail{},
		Medium:   []VulnDetail{},
		Low:      []VulnDetail{},
	}

	for _, result := range results {
		for _, cpeItem := range result.CPEs {
			for _, cve := range cpeItem.CVEs {
				detail := VulnDetail{
					ID:          cve.ID,
					CPE:         cpeItem.Value,
					IP:          result.IP,
					BaseScore:   cve.BaseScore,
					Severity:    cve.Severity,
					Description: cve.Description,
				}

				if cve.BaseScore >= 9.0 {
					vulnsBySeverity.Critical = append(vulnsBySeverity.Critical, detail)
					data.Stats.Critical++
				} else if cve.BaseScore >= 7.0 {
					vulnsBySeverity.High = append(vulnsBySeverity.High, detail)
					data.Stats.High++
				} else if cve.BaseScore >= 4.0 {
					vulnsBySeverity.Medium = append(vulnsBySeverity.Medium, detail)
					data.Stats.Medium++
				} else {
					vulnsBySeverity.Low = append(vulnsBySeverity.Low, detail)
					data.Stats.Low++
				}
			}
		}
	}

	data.VulnsBySeverity = vulnsBySeverity

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("template parsing error: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return "", fmt.Errorf("file creation error: %w", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, data)
	if err != nil {
		return "", fmt.Errorf("template execution error: %w", err)
	}

	return outputFile, nil
}
