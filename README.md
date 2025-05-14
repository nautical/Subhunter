# Subhunter
## A fast subdomain takeover tool

<img src="banner.png" width="1300">

## Description:

Subdomain takeover is a common vulnerability that allows an attacker to gain control over a subdomain of a target domain. This typically occurs when a subdomain has a CNAME record pointing to a service (like AWS S3, GitHub Pages, etc.) that is no longer in use or unclaimed. Attackers can then claim the service and gain control of the subdomain.

Subhunter performs comprehensive checks to identify potential subdomain takeover vulnerabilities by analyzing DNS records, service fingerprints, and response patterns.

## Features:

- Auto update of fingerprint database
- Port scanning support for custom service ports
- Protocol detection (HTTP/HTTPS)
- Smart service fingerprinting
- Uses random user agents
- Built in Go
- Uses curated fingerprint data from well-known sources
- Support for both single domain and bulk scanning
- JSON output support for easy integration
- Flexible domain input handling
- Proper error handling
- Smart fingerprint management with automatic updates

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
  -p int
        Port number to scan (default: 443)
  -t int
    	Number of threads for scanning (default 50)
  -timeout int
    	Timeout in seconds (default 20)
  --json
    	Output results in JSON format
  --update
        Force update of fingerprint data
```

### Examples:

#### Scan a single domain:
```
./subhunter -d example.com
```

#### Scan a domain on a specific port:
```
./subhunter -d example.com -p 8080
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

### Detection Methods

Subhunter uses a comprehensive approach to identify subdomain takeover vulnerabilities:

1. **DNS Analysis**:
   - Checks for CNAME records
   - Verifies if CNAME targets are resolvable
   - Identifies dangling CNAME records

2. **Service Detection**:
   - Supports custom port scanning
   - Automatic protocol detection (HTTP/HTTPS)
   - Response pattern matching
   - Header analysis

3. **Vulnerability Verification**:
   - Matches both CNAME patterns and service responses
   - Prevents false positives from self-hosted services
   - Identifies actual vulnerable services vs similar-looking responses

For example, when checking AWS S3 buckets:
- Must have CNAME pointing to s3.amazonaws.com
- Must return "NoSuchBucket" error
- Having only S3-like responses without proper CNAME is not considered vulnerable

### False Positive Prevention

Subhunter implements several measures to prevent false positives:

1. **Service Validation**:
   - Requires both CNAME and response pattern matches
   - Distinguishes between actual services and similar-looking responses

2. **DNS Verification**:
   - Checks for direct A/AAAA records
   - Validates CNAME chain resolution
   - Identifies properly configured services

3. **Response Analysis**:
   - Differentiates between service errors and actual vulnerabilities
   - Considers SSL certificates and headers
   - Identifies self-hosted service instances

### JSON Output Format:

When using the `--json` flag, Subhunter outputs results in a structured format:

```json
[
  {
    "target": "example.com",
    "vulnerable": false
  },
  {
    "target": "s3.example.com",
    "cname": "s3.amazonaws.com",
    "service": "AWS/S3",
    "vulnerable": true,
    "reason": "CNAME points to S3 and bucket doesn't exist"
  },
  {
    "target": "custom.example.com",
    "ip": "192.168.1.1",
    "port": 8080,
    "vulnerable": false,
    "reason": "Service responds normally"
  }
]
```

The JSON output includes:
- `target`: Domain being scanned
- `cname`: CNAME record (if present)
- `ip`: Resolved IP address
- `port`: Port scanned (if custom port specified)
- `service`: Identified service
- `vulnerable`: Vulnerability status
- `reason`: Detailed explanation
- `error`: Error information (if any)

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created by Nemesis
Contact: nemesisuks@protonmail.com

