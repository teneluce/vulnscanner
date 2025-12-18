# Vulnscanner

Vulnscanner is kind of a vulnerability scanner developed in Go, based on NMAP. Basically, you specify IP addresses to the program. Then, it will launch an NMAP scan to get the target's CPEs (OS or applications). It will then interrogate NIST NVD database to get the CVEs that are correlated to those CPEs. FYI: this is how it is done in Nozomi Guardian, with their Threat Intelligence offer (but passively, on which I am working to adapt this tool to OT environment)

## Requirements
* Having Go installed in your system
* Having an NIST NVD API Key (to specify in an .env file)

## Setup
1. Download the repository
```git clone https://github.com/teneluce/vulnscanner.git```
2. Build the project
```go build github.com/teneluce/vulnscanner```

## How to use it
You have to specify the IP addresses that you want to scan. You also have to have root priviledges (to launch NMAP).
For example:
```sudo vulnscanner 192.168.1.1```

## Options
* ```-v```: verbose mode, to have the running details
* ```-c```: get the cves related to cpes (if you don't, it will only show CPEs)

## Next steps
The next steps are:
* Adapt this tool to OT environments (i.e. passively, without using NMAP, e.g. using port mirroring)
* Implement a GUI to make this tool more user-friendly