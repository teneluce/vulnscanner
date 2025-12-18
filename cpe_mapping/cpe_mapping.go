package cpe_mapping

import (
	"regexp"
	"strings"
)

var CPEMappings = map[string]string{
	"proxmox:proxmox_virtual_environment": "virtual_environment",
	"proxmox:proxmox_mail_gateway":        "mail_gateway",
	"proxmox:proxmox_backup_server":       "backup_server",

	"apache:http_server": "httpd",
	"apache:apache":      "httpd",
	"apache:tomcat":      "tomcat",

	"nginx:nginx": "nginx",

	"microsoft:internet_information_services": "iis",
	"microsoft:internet_information_server":   "iis",
	"microsoft:windows_server":                "windows_server",

	"mysql:mysql_server": "mysql",
	"mariadb:mariadb":    "mariadb",

	"postgresql:postgresql_server": "postgresql",

	"redis:redis_server": "redis",

	"mongodb:mongodb_server": "mongodb",

	"docker:docker_engine": "docker",

	"kubernetes:kubernetes": "kubernetes",

	"vmware:vsphere": "vcenter_server",
	"vmware:esxi":    "esxi",
	"vmware:vcenter": "vcenter_server",

	"cisco:ios":    "ios",
	"cisco:ios_xe": "ios_xe",
	"cisco:ios_xr": "ios_xr",

	"php:php": "php",

	"python:python": "python",

	"nodejs:node.js": "node.js",

	"elastic:elasticsearch": "elasticsearch",

	"jenkins:jenkins": "jenkins",

	"gitlab:gitlab": "gitlab",

	"wordpress:wordpress": "wordpress",
}

func ApplyMappingRules(vendor, product string) string {
	key := vendor + ":" + product

	if nistProduct, exists := CPEMappings[key]; exists {
		return nistProduct
	}

	if len(product) > len(vendor)+1 && product[:len(vendor)] == vendor && product[len(vendor)] == '_' {
		return product[len(vendor)+1:]
	}

	return product
}

func NormalizeVersion(vendor, product, version string) string {
	if vendor == "thekelleys" && product == "dnsmasq" && strings.HasPrefix(version, "gen_") {
		versionPart := strings.TrimPrefix(version, "gen_")
		if idx := strings.Index(versionPart, "_"); idx != -1 {
			return versionPart[:idx]
		}
		return versionPart
	}

	commonPrefixes := []string{"v", "ver", "version", "rel", "release"}
	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(version, prefix) && len(version) > len(prefix) {
			stripped := strings.TrimPrefix(version, prefix)
			if len(stripped) > 0 && stripped[0] >= '0' && stripped[0] <= '9' {
				version = stripped
				break
			}
		}
	}

	gitSuffixRegex := regexp.MustCompile(`-\d+-g[0-9a-f]+$`)
	version = gitSuffixRegex.ReplaceAllString(version, "")

	distroSuffixRegex := regexp.MustCompile(`-\d+[a-z]+[\d.]*$`)
	version = distroSuffixRegex.ReplaceAllString(version, "")

	return version
}
