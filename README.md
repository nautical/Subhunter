# Subhunter
## A fast subdomain takeover tool

<img src="banner.png" width="1300">

## Description:

Subdomain takeover is a common vulnerability that allows an attacker to gain control over a subdomain of a target domain and redirect users intended for an organization's domain to a website that performs malicious activities, such as phishing campaigns,
stealing user cookies, etc. It occurs when an attacker gains control over a subdomain of a target domain.
Typically, this happens when the subdomain has a CNAME in the DNS, but no host is providing content for it.
Subhunter takes a given list of subdomains and scans them to check this vulnerability.

## Features:

- Auto update
- Uses random user agents
- Built in Go
- Uses a fork of fingerprint data from well known sources ([can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md))
- Support for both single domain and bulk scanning
- JSON output support for easy integration with other tools
- Flexible domain input handling (accepts URLs with protocols, paths, and query parameters)
- Proper error handling for non-existent or unresolvable domains

## Installation:

### Option 1:

[Download](https://github.com/Nemesis0U/Subhunter/releases) from releases

### Option 2:
Build from source:

    $ git clone https://github.com/Nemesis0U/Subhunter.git
    $ go build subhunter.go

## Usage:

### Options:

```
Usage of subhunter:
  -d string
    	Single domain to scan
  -l string
    	File including a list of hosts to scan
  -o string
    	File to save results
  -t int
    	Number of threads for scanning (default 50)
  -timeout int
    	Timeout in seconds (default 20)
  --json
    	Output results in JSON format
```

### Examples:

#### Scan a single domain:
```
./subhunter -d example.com
```

#### Scan a domain with protocol and path (automatically normalized):
```
./subhunter -d https://example.com/path
```

#### Scan multiple domains from a file:
```
./subhunter -l subdomains.txt
```

#### Output results in JSON format:
```
./subhunter -d example.com --json
```

#### Save results to a file:
```
./subhunter -l subdomains.txt -o results.txt
```

#### Save results in JSON format:
```
./subhunter -l subdomains.txt --json -o results.json
```

### Domain Input Formats

Subhunter accepts various domain formats and automatically normalizes them:

- `example.com` - Basic domain
- `https://example.com` - Domain with protocol
- `http://example.com/path` - Domain with protocol and path
- `https://example.com/path?query=value` - Domain with protocol, path, and query parameters

All of these formats will be normalized to just the hostname (e.g., `example.com`).

### JSON Output Format:

When using the `--json` flag, Subhunter outputs results in a structured JSON format:

```json
[
  {
    "target": "example.com",
    "vulnerable": false
  },
  {
    "target": "vulnerable.example.com",
    "cname": "abandoned.service.com",
    "service": "Service Name",
    "vulnerable": true
  },
  {
    "target": "nonexistent.example.com",
    "vulnerable": false,
    "error": true,
    "error_message": "DNS resolution error: no such host"
  }
]
```

The JSON output includes the following fields:
- `target`: The domain being scanned
- `cname`: The CNAME record (if available)
- `service`: The service name (if identified)
- `vulnerable`: Boolean indicating if the domain is vulnerable to takeover
- `error`: Boolean indicating if an error occurred
- `error_message`: Description of the error (if any)

### Demo (Added fake fingerprint for POC):

```
./Subhunter -l subdomains.txt -o test.txt

  ____            _       _                       _
 / ___|   _   _  | |__   | |__    _   _   _ __   | |_    ___   _ __
 \___ \  | | | | | '_ \  | '_ \  | | | | | '_ \  | __|  / _ \ | '__|
  ___) | | |_| | | |_) | | | | | | |_| | | | | | | |_  |  __/ | |
 |____/   \__,_| |_.__/  |_| |_|  \__,_| |_| |_|  \__|  \___| |_|


A fast subdomain takeover tool

Created by Nemesis

Loaded 88 fingerprints for current scan

-----------------------------------------------------------------------------

[+] Nothing found at www.ubereats.com: Not Vulnerable
[+] Nothing found at testauth.ubereats.com: Not Vulnerable
[+] Nothing found at apple-maps-app-clip.ubereats.com: Not Vulnerable
[+] Nothing found at about.ubereats.com: Not Vulnerable
[+] Nothing found at beta.ubereats.com: Not Vulnerable
[+] Nothing found at ewp.ubereats.com: Not Vulnerable
[+] Nothing found at edgetest.ubereats.com: Not Vulnerable
[+] Nothing found at guest.ubereats.com: Not Vulnerable
[+] Google Cloud: Possible takeover found at testauth.ubereats.com: Vulnerable
[+] Nothing found at info.ubereats.com: Not Vulnerable
[+] Nothing found at learn.ubereats.com: Not Vulnerable
[+] Nothing found at merchants.ubereats.com: Not Vulnerable
[+] Nothing found at guest-beta.ubereats.com: Not Vulnerable
[+] Nothing found at merchant-help.ubereats.com: Not Vulnerable
[+] Nothing found at merchants-beta.ubereats.com: Not Vulnerable
[+] Nothing found at merchants-staging.ubereats.com: Not Vulnerable
[+] Nothing found at messages.ubereats.com: Not Vulnerable
[+] Nothing found at order.ubereats.com: Not Vulnerable
[+] Nothing found at restaurants.ubereats.com: Not Vulnerable
[+] Nothing found at payments.ubereats.com: Not Vulnerable
[+] Nothing found at static.ubereats.com: Not Vulnerable

Subhunter exiting...
Results written to test.txt


```

