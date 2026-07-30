package echproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BootstrapDoHEndpoint is a numeric HTTPS DoH seed. The literal IP prevents
// remote configuration bootstrap from depending on Android/system DNS, while
// ServerName keeps normal TLS SNI and certificate validation intact.
type bootstrapDoHEndpoint struct {
	ip         string
	serverName string
	path       string
}

var bootstrapDoHEndpoints = []bootstrapDoHEndpoint{
	{ip: "223.5.5.5", serverName: "dns.alidns.com", path: "/resolve"},
	{ip: "223.6.6.6", serverName: "dns.alidns.com", path: "/resolve"},
	{ip: "1.12.12.12", serverName: "doh.pub", path: "/dns-query"},
	{ip: "120.53.53.53", serverName: "doh.pub", path: "/dns-query"},
	{ip: "101.198.192.33", serverName: "doh.360.cn", path: "/resolve"},
}

// FetchBootstrapTxt reads a public TXT configuration record without using the
// platform resolver. It races several numeric DoH seeds and returns the first
// valid TXT response. The TXT record is public configuration, never secrets.
func FetchBootstrapTxt(name string) (string, error) {
	if !isTargetHost(name) {
		return "", errors.New("invalid config domain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	type result struct { value string; err error }
	results := make(chan result, len(bootstrapDoHEndpoints))
	for _, endpoint := range bootstrapDoHEndpoints {
		endpoint := endpoint
		go func() {
			value, err := fetchBootstrapTXT(ctx, endpoint, name)
			results <- result{value, err}
		}()
	}
	var failures []string
	for range bootstrapDoHEndpoints {
		result := <-results
		if result.err == nil && result.value != "" { return result.value, nil }
		if result.err != nil { failures = append(failures, result.err.Error()) }
	}
	return "", fmt.Errorf("remote TXT bootstrap failed: %s", strings.Join(failures, "; "))
}

func fetchBootstrapTXT(ctx context.Context, endpoint bootstrapDoHEndpoint, name string) (string, error) {
	requestURL := &url.URL{Scheme: "https", Host: endpoint.ip, Path: endpoint.path}
	query := requestURL.Query()
	query.Set("name", name)
	query.Set("type", "TXT")
	requestURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil { return "", err }
	req.Header.Set("Accept", "application/dns-json")
	req.Host = endpoint.serverName
	tlsConfig := &tls.Config{ServerName: endpoint.serverName, MinVersion: tls.VersionTLS12}
	if pool := loadAndroidCertPool(); pool != nil { tlsConfig.RootCAs = pool }
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
	}}
	resp, err := client.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return "", fmt.Errorf("DoH HTTP %d", resp.StatusCode) }
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil { return "", err }
	var decoded dohResp
	if err := json.Unmarshal(body, &decoded); err != nil { return "", err }
	if decoded.Status != 0 { return "", fmt.Errorf("DoH DNS status %d", decoded.Status) }
	var values []string
	for _, answer := range decoded.Answer {
		if answer.Type != 16 { continue }
		value := answer.Data
		if matches := quotedRe.FindAllStringSubmatch(value, -1); len(matches) > 0 {
			var joined strings.Builder
			for _, match := range matches { joined.WriteString(match[1]) }
			value = joined.String()
		}
		if value = strings.TrimSpace(value); value != "" { values = append(values, value) }
	}
	if len(values) == 0 { return "", errors.New("no TXT records") }
	return strings.Join(values, "\n"), nil
}
