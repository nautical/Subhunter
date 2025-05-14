// Created by Nemesis
// Contact: nemesisuks@protonmail.com

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/parnurzeal/gorequest"
)

// ANSI Color Codes
const (
	Reset  = "\x1b[0m"
	Red    = "\x1b[31;1m"
	Green  = "\x1b[32;1m"
	Blue   = "\x1b[34;1m"
	Yellow = "\x1b[33;1m"
)

// UpdateInfo stores the last update check information
type UpdateInfo struct {
	LastCheck time.Time `json:"last_check"`
	LastHash  string    `json:"last_hash"`
}

// Prints a result message with the specified color
func PrintResult(colorCode, resultMessage string) {
	if !JSONOutput {
		result := fmt.Sprintf("[%s+%s]%s %s%s", colorCode, Reset, colorCode, resultMessage, Reset)
		fmt.Println(result)
	}
}

// Structure of fingerprint.json
type FingerprintData struct {
	Name        string      `json:"service"`
	Cname       []string    `json:"cname"`
	Fingerprint interface{} `json:"fingerprint"`
	Response    []string    `json:"response"`
	Headers     []string    `json:"headers,omitempty"`
}

// Structure for JSON output
type ResultData struct {
	Target     string `json:"target"`
	CNAME      string `json:"cname,omitempty"`
	IP         string `json:"ip,omitempty"`
	Service    string `json:"service,omitempty"`
	Vulnerable bool   `json:"vulnerable"`
	Error      bool   `json:"error,omitempty"`
	ErrorMsg   string `json:"error_message,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

var Fingerprints []FingerprintData

var Targets []string

var (
	HostsList    string
	SingleDomain string
	Threads      int
	All          bool
	Verbose      bool
	Timeout      int
	OutputFile   string
	JSONOutput   bool
	ForceUpdate  bool
	Port         int
)

var VulnerableResults []string
var NotVulnerableResults []string
var JSONResults []ResultData

// NormalizeDomain removes protocol, trailing slashes, and path from domain
func NormalizeDomain(input string) string {
	// Ensure input has a protocol for url.Parse to work correctly
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}

	u, err := url.Parse(input)
	if err != nil {
		// If parsing fails, return the original input
		return input
	}

	// Return just the host part
	return u.Hostname()
}

// User agents
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.3",
	}

	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

// getConfigDir returns the platform-specific configuration directory
func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Use .subhunter in home directory for all platforms
	return filepath.Join(homeDir, ".subhunter"), nil
}

// getUpdateInfoPath returns the path to the update info file
func getUpdateInfoPath(configDir string) string {
	return filepath.Join(configDir, "update_info.json")
}

// loadUpdateInfo loads the last update check information
func loadUpdateInfo(configDir string) (*UpdateInfo, error) {
	infoPath := getUpdateInfoPath(configDir)
	if _, err := os.Stat(infoPath); os.IsNotExist(err) {
		return &UpdateInfo{}, nil
	}

	data, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read update info: %v", err)
	}

	var info UpdateInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse update info: %v", err)
	}

	return &info, nil
}

// saveUpdateInfo saves the update check information
func saveUpdateInfo(configDir string, info *UpdateInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal update info: %v", err)
	}

	infoPath := getUpdateInfoPath(configDir)
	if err := os.WriteFile(infoPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write update info: %v", err)
	}

	return nil
}

// getRemoteFileHash gets the SHA-256 hash of the remote file
func getRemoteFileHash(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch remote file: %v", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read remote file: %v", err)
	}

	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

// getLocalFileHash gets the SHA-256 hash of the local file
func getLocalFileHash(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read local file: %v", err)
	}

	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

// shouldCheckForUpdates determines if we should check for updates
func shouldCheckForUpdates(info *UpdateInfo, forceUpdate bool) bool {
	if forceUpdate {
		return true
	}

	// If we've never checked before
	if info.LastCheck.IsZero() {
		return true
	}

	// Check if 24 hours have passed since last check
	return time.Since(info.LastCheck) >= 24*time.Hour
}

// downloadFingerprints downloads the fingerprint.json file
func downloadFingerprints(filePath string) error {
	url := "https://raw.githubusercontent.com/nautical/Subhunter/main/fingerprint.json"

	if !JSONOutput {
		fmt.Println("Downloading fingerprint.json...")
	}

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download fingerprint.json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	if !JSONOutput {
		fmt.Println("Download complete.")
	}

	return nil
}

func InitializeFingerprints() {
	// Get configuration directory
	configDir, err := getConfigDir()
	if err != nil {
		log.Fatalf("Failed to get config directory: %v", err)
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Fatalf("Failed to create config directory: %v", err)
	}

	fingerprintPath := filepath.Join(configDir, "fingerprint.json")
	url := "https://raw.githubusercontent.com/nautical/Subhunter/main/fingerprint.json"

	// Load update info
	updateInfo, err := loadUpdateInfo(configDir)
	if err != nil {
		log.Fatalf("Failed to load update info: %v", err)
	}

	// Check if file exists
	fileExists := false
	if _, err := os.Stat(fingerprintPath); err == nil {
		fileExists = true
	}

	// If file exists and we should check for updates
	if fileExists && shouldCheckForUpdates(updateInfo, ForceUpdate) {
		localHash, err := getLocalFileHash(fingerprintPath)
		if err != nil {
			log.Fatalf("Failed to get local file hash: %v", err)
		}

		remoteHash, err := getRemoteFileHash(url)
		if err != nil {
			// If we can't get the remote hash, use the local file
			if !JSONOutput {
				fmt.Printf("Warning: Failed to check for fingerprint updates: %v\n", err)
			}
		} else {
			// If hashes are different or force update is true, update the file
			if localHash != remoteHash || ForceUpdate {
				if err := downloadFingerprints(fingerprintPath); err != nil {
					log.Fatalf("Failed to update fingerprints: %v", err)
				}
				if !JSONOutput {
					fmt.Println("Fingerprints updated successfully")
				}
			}

			// Update the last check time and hash
			updateInfo.LastCheck = time.Now()
			updateInfo.LastHash = remoteHash
			if err := saveUpdateInfo(configDir, updateInfo); err != nil {
				log.Fatalf("Failed to save update info: %v", err)
			}
		}
	} else if !fileExists {
		// Download if file doesn't exist
		if err := downloadFingerprints(fingerprintPath); err != nil {
			log.Fatalf("Failed to download fingerprints: %v", err)
		}
	}

	// Read and parse the fingerprint file
	raw, err := os.ReadFile(fingerprintPath)
	if err != nil {
		log.Fatalf("Failed to read fingerprint file: %v", err)
	}

	err = json.Unmarshal(raw, &Fingerprints)
	if err != nil {
		log.Fatalf("Failed to parse fingerprint file: %v", err)
	}
}

func ReadFile(file string) (lines []string, err error) {
	fileHandle, err := os.Open(file)
	if err != nil {
		return lines, err
	}

	defer fileHandle.Close()
	fileScanner := bufio.NewScanner(fileHandle)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		// Normalize each domain in the file
		normalizedDomain := NormalizeDomain(line)
		if normalizedDomain != "" {
			lines = append(lines, normalizedDomain)
		}
	}

	return lines, nil
}

func Get(url string, timeout int) (resp gorequest.Response, body string, errs []error) {
	// Default to HTTPS first
	protocol := "https"
	userAgent := getRandomUserAgent()

	// Format URL with port
	targetURL := url
	if Port != 443 && Port != 80 {
		targetURL = fmt.Sprintf("%s:%d", url, Port)
	}

	// Try HTTPS first
	fullURL := fmt.Sprintf("%s://%s/", protocol, targetURL)
	resp, body, errs = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		Timeout(time.Duration(timeout)*time.Second).Get(fullURL).
		Set("User-Agent", userAgent).
		End()

	// If HTTPS fails with protocol error, try HTTP
	if len(errs) > 0 && (strings.Contains(errs[0].Error(), "server gave HTTP response to HTTPS client") ||
		strings.Contains(errs[0].Error(), "malformed HTTP response")) {
		protocol = "http"
		fullURL = fmt.Sprintf("%s://%s/", protocol, targetURL)
		resp, body, errs = gorequest.New().
			Timeout(time.Duration(timeout)*time.Second).Get(fullURL).
			Set("User-Agent", userAgent).
			End()
	}

	return resp, body, errs
}

func ParseArguments() {
	flag.StringVar(&HostsList, "l", "", "File including a list of hosts to scan")
	flag.StringVar(&SingleDomain, "d", "", "Single domain to scan")
	flag.IntVar(&Timeout, "timeout", 20, "Timeout in seconds")
	flag.StringVar(&OutputFile, "o", "", "File to save results")
	flag.IntVar(&Threads, "t", 50, "Number of threads for scanning")
	flag.BoolVar(&JSONOutput, "json", false, "Output results in JSON format")
	flag.BoolVar(&ForceUpdate, "update", false, "Force update of fingerprint data")
	flag.IntVar(&Port, "p", 443, "Port number to scan (default: 443)")

	flag.Parse()

	// Normalize the single domain input if provided
	if SingleDomain != "" {
		SingleDomain = NormalizeDomain(SingleDomain)
	}
}

func CNAMEExists(key string) bool {
	for _, fingerprint := range Fingerprints {
		for _, cname := range fingerprint.Cname {
			if strings.Contains(key, cname) {
				return true
			}
		}
	}

	return false
}

// Check DNS resolution and connection for potential takeover
func CheckForTakeover(target string) {
	// Step 1: Initial DNS checks
	cname, cnameErr := net.LookupCNAME(target)
	hasCNAME := cnameErr == nil && cname != target+"."

	ips, ipErr := net.LookupIP(target)
	hasIP := ipErr == nil && len(ips) > 0

	// Step 2: Check for dangling CNAME
	if hasCNAME {
		cnameTarget := strings.TrimSuffix(cname, ".")
		_, err := net.LookupHost(cnameTarget)
		if err != nil {
			resultMessage := fmt.Sprintf("High risk: Dangling CNAME found - %s points to %s which doesn't resolve", target, cname)
			PrintResult(Green, resultMessage)
			VulnerableResults = append(VulnerableResults, resultMessage)
			if JSONOutput {
				JSONResults = append(JSONResults, ResultData{
					Target:     target,
					CNAME:      cname,
					Vulnerable: true,
					Reason:     "Dangling CNAME - target doesn't resolve",
				})
			}
			return
		}
	}

	// Step 3: Handle case where neither CNAME nor A record exists
	if !hasCNAME && !hasIP {
		if dnsErr, ok := ipErr.(*net.DNSError); ok && dnsErr.IsNotFound {
			resultMessage := fmt.Sprintf("Notice: %s - NXDOMAIN - Domain available for registration", target)
			PrintResult(Yellow, resultMessage)
			NotVulnerableResults = append(NotVulnerableResults, resultMessage)
			if JSONOutput {
				JSONResults = append(JSONResults, ResultData{
					Target:     target,
					Vulnerable: false,
					Error:      true,
					ErrorMsg:   "NXDOMAIN - Domain not registered",
				})
			}
		} else {
			resultMessage := fmt.Sprintf("Error: Failed to resolve %s - DNS error: %v", target, ipErr)
			PrintResult(Red, resultMessage)
			NotVulnerableResults = append(NotVulnerableResults, resultMessage)
			if JSONOutput {
				JSONResults = append(JSONResults, ResultData{
					Target:     target,
					Vulnerable: false,
					Error:      true,
					ErrorMsg:   fmt.Sprintf("DNS resolution error: %v", ipErr),
				})
			}
		}
		return
	}

	// Step 4: Check service response
	resp, body, errs := Get(target, Timeout)

	// Check for specific service patterns from fingerprints
	if len(errs) == 0 && resp != nil {
		for _, fingerprint := range Fingerprints {
			// Check CNAME patterns if we have a CNAME
			if hasCNAME {
				for _, cnamePattern := range fingerprint.Cname {
					if strings.Contains(strings.ToLower(cname), strings.ToLower(cnamePattern)) {
						// Found matching CNAME pattern, now check response patterns
						switch fp := fingerprint.Fingerprint.(type) {
						case string:
							if strings.Contains(body, fp) {
								resultMessage := fmt.Sprintf("%s: Potential takeover - %s with CNAME %s matches fingerprint", fingerprint.Name, target, cname)
								PrintResult(Green, resultMessage)
								VulnerableResults = append(VulnerableResults, resultMessage)
								if JSONOutput {
									JSONResults = append(JSONResults, ResultData{
										Target:     target,
										CNAME:      cname,
										Service:    fingerprint.Name,
										Vulnerable: true,
										Reason:     "CNAME and response pattern match service fingerprint",
									})
								}
								return
							}
						case []interface{}:
							for _, pattern := range fp {
								if str, ok := pattern.(string); ok {
									if strings.Contains(body, str) {
										resultMessage := fmt.Sprintf("%s: Potential takeover - %s with CNAME %s matches fingerprint", fingerprint.Name, target, cname)
										PrintResult(Green, resultMessage)
										VulnerableResults = append(VulnerableResults, resultMessage)
										if JSONOutput {
											JSONResults = append(JSONResults, ResultData{
												Target:     target,
												CNAME:      cname,
												Service:    fingerprint.Name,
												Vulnerable: true,
												Reason:     "CNAME and response pattern match service fingerprint",
											})
										}
										return
									}
								}
							}
						}
					}
				}
			}

			// Check response patterns
			if fingerprint.Response != nil {
				for _, response := range fingerprint.Response {
					if strings.Contains(body, response) {
						resultMessage := fmt.Sprintf("%s: Potential takeover - Service fingerprint detected on %s", fingerprint.Name, target)
						PrintResult(Green, resultMessage)
						VulnerableResults = append(VulnerableResults, resultMessage)
						if JSONOutput {
							JSONResults = append(JSONResults, ResultData{
								Target:     target,
								IP:         ips[0].String(),
								Service:    fingerprint.Name,
								Vulnerable: true,
								Reason:     "Response matches service fingerprint",
							})
						}
						return
					}
				}
			}
		}

		// Service responds but no fingerprint matches
		resultMessage := fmt.Sprintf("Info: %s responds on port %d - No fingerprint matches", target, Port)
		PrintResult(Blue, resultMessage)
		NotVulnerableResults = append(NotVulnerableResults, resultMessage)
		if JSONOutput {
			JSONResults = append(JSONResults, ResultData{
				Target:     target,
				IP:         ips[0].String(),
				Vulnerable: false,
				Reason:     "Service responds normally",
			})
		}
	} else {
		// Service is unreachable
		errMsg := "unknown error"
		if len(errs) > 0 {
			errMsg = errs[0].Error()
		}
		resultMessage := fmt.Sprintf("Warning: %s is unreachable on port %d - %s", target, Port, errMsg)
		PrintResult(Yellow, resultMessage)
		NotVulnerableResults = append(NotVulnerableResults, resultMessage)
		if JSONOutput {
			JSONResults = append(JSONResults, ResultData{
				Target:     target,
				IP:         ips[0].String(),
				Vulnerable: false,
				Error:      true,
				ErrorMsg:   errMsg,
			})
		}
	}
}

var CheckedTargetsMutex sync.Mutex         // Declares the mutex globally
var CheckedTargets = make(map[string]bool) // Declares CheckedTargets globally

func Checker(target string) {
	CheckedTargetsMutex.Lock()
	if !CheckedTargets[target] {
		CheckedTargets[target] = true
		CheckedTargetsMutex.Unlock()
		CheckForTakeover(target)
	} else {
		CheckedTargetsMutex.Unlock()
	}
}

func main() {
	All = true
	Verbose = true
	ParseArguments()

	// Initializes fingerprints before using them
	InitializeFingerprints()

	// Check if either a hosts list or a single domain is provided
	if HostsList == "" && SingleDomain == "" {
		fmt.Printf("Subhunter: No domain specified for the scan!")
		fmt.Printf("\n\nInfo: Use -l to specify a file with domains or -d to specify a single domain\n\n")
		os.Exit(1)
	}

	// Process hosts list if provided
	if HostsList != "" {
		Hosts, err := ReadFile(HostsList)
		if err != nil {
			fmt.Printf("\nread: %s\n", err)
			os.Exit(1)
		}
		Targets = append(Targets, Hosts...)
	}

	// Add single domain if provided
	if SingleDomain != "" {
		Targets = append(Targets, SingleDomain)
	}

	if !JSONOutput {
		fmt.Println("")
		Banner := figure.NewColorFigure("Subhunter", "", "red", true)
		Banner.Print()
		fmt.Println("\n\nA fast subdomain takeover tool\n")
		fmt.Println("Created by Nemesis")
		fmt.Printf("\nLoaded %d fingerprints for current scan\n", len(Fingerprints))
		fmt.Println("\n-----------------------------------------------------------------------------\n")
	}

	hosts := make(chan string, Threads)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(Threads)

	for i := 0; i < Threads; i++ {
		go func() {
			for {
				host := <-hosts
				if host == "" {
					break
				}

				Checker(host)
			}

			processGroup.Done()
		}()
	}

	for _, Host := range Targets {
		hosts <- Host
	}

	close(hosts)
	processGroup.Wait()

	if !JSONOutput {
		fmt.Printf("\nSubhunter exiting...\n")
	}

	// Output JSON results if JSON format is selected
	if JSONOutput {
		jsonData, err := json.MarshalIndent(JSONResults, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	}

	// Writes the results to the output file if provided
	if OutputFile != "" {
		if JSONOutput {
			WriteJSONResultsToFile(OutputFile, JSONResults)
		} else {
			WriteResultsToFile(OutputFile, VulnerableResults, NotVulnerableResults)
		}
	}
}

func WriteResultsToFile(filename string, vulnerableResults []string, notVulnerableResults []string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer file.Close()

	// Writes vulnerable results
	for _, result := range vulnerableResults {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Fatalf("Error writing to output file: %v", err)
		}
	}

	// Writes other results
	for _, result := range notVulnerableResults {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Fatalf("Error writing to output file: %v", err)
		}
	}

	fmt.Printf("Results written to %s\n", filename)
}

func WriteJSONResultsToFile(filename string, results []ResultData) {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	err = ioutil.WriteFile(filename, jsonData, 0644)
	if err != nil {
		log.Fatalf("Error writing JSON to file: %v", err)
	}

	fmt.Printf("JSON results written to %s\n", filename)
}
