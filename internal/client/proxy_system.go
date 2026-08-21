package client

import (
	"context"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// systemProxyForURL reads only the platform's ordinary user proxy settings.
// Commands use fixed arguments, no shell, a short deadline, and discarded
// stderr. Missing tools or malformed settings mean direct connection.
func systemProxyForURL(target *url.URL) *url.URL {
	if target == nil {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		return macOSSystemProxy(target)
	case "linux":
		return linuxSystemProxy(target)
	case "windows":
		return windowsSystemProxy(target)
	default:
		return nil
	}
}

func runSystemCommand(name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return "", false
	}
	return string(output), true
}

func linuxSystemProxy(target *url.URL) *url.URL {
	mode, ok := runSystemCommand("gsettings", "get", "org.gnome.system.proxy", "mode")
	if !ok || strings.Trim(strings.TrimSpace(mode), "'\"") != "manual" {
		return nil
	}

	// GNOME stores separate settings for HTTP and HTTPS. An HTTPS setting is
	// preferred for HTTPS/WSS, with the HTTP proxy as a safe fallback.
	scheme := "http"
	if strings.EqualFold(target.Scheme, "https") || strings.EqualFold(target.Scheme, "wss") {
		scheme = "https"
	}
	host, port := gsettingsProxy(scheme)
	if host == "" && scheme == "https" {
		host, port = gsettingsProxy("http")
	}
	if host == "" || systemProxyBypass(target, gsettingsIgnoreHosts()) {
		return nil
	}
	return makeSystemProxy(host, port)
}

func gsettingsProxy(scheme string) (string, int) {
	hostOutput, hostOK := runSystemCommand("gsettings", "get", "org.gnome.system.proxy."+scheme, "host")
	portOutput, portOK := runSystemCommand("gsettings", "get", "org.gnome.system.proxy."+scheme, "port")
	if !hostOK || !portOK {
		return "", 0
	}
	host := settingString(hostOutput)
	port, err := strconv.Atoi(strings.TrimSpace(portOutput))
	if err != nil || port <= 0 || port > 65535 {
		return "", 0
	}
	return host, port
}

func gsettingsIgnoreHosts() string {
	output, ok := runSystemCommand("gsettings", "get", "org.gnome.system.proxy", "ignore-hosts")
	if !ok {
		return ""
	}
	output = strings.TrimSpace(output)
	output = strings.TrimPrefix(output, "[")
	output = strings.TrimSuffix(output, "]")
	var entries []string
	for _, part := range strings.Split(output, ",") {
		part = settingString(part)
		if part != "" {
			entries = append(entries, part)
		}
	}
	return strings.Join(entries, ",")
}

func macOSSystemProxy(target *url.URL) *url.URL {
	output, ok := runSystemCommand("scutil", "--proxy")
	if !ok {
		return nil
	}
	values := parseColonSettings(output)
	prefix := "HTTP"
	if strings.EqualFold(target.Scheme, "https") || strings.EqualFold(target.Scheme, "wss") {
		prefix = "HTTPS"
	}
	if values[prefix+"Enable"] != "1" && prefix == "HTTPS" {
		prefix = "HTTP"
	}
	if values[prefix+"Enable"] != "1" || systemProxyBypass(target, values["ExceptionsList"]) {
		return nil
	}
	port, err := strconv.Atoi(values[prefix+"Port"])
	if err != nil || port <= 0 || port > 65535 {
		return nil
	}
	return makeSystemProxy(values[prefix+"Proxy"], port)
}

func windowsSystemProxy(target *url.URL) *url.URL {
	output, ok := runSystemCommand("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if !ok {
		return nil
	}
	values := parseRegistrySettings(output)
	if values["ProxyEnable"] != "0x1" && values["ProxyEnable"] != "1" {
		return nil
	}
	if systemProxyBypass(target, values["ProxyOverride"]) {
		return nil
	}
	server := values["ProxyServer"]
	if strings.Contains(server, ";") {
		targetScheme := strings.ToLower(target.Scheme)
		if targetScheme == "ws" {
			targetScheme = "http"
		} else if targetScheme == "wss" {
			targetScheme = "https"
		}
		for _, part := range strings.Split(server, ";") {
			name, value, found := strings.Cut(part, "=")
			if found && strings.EqualFold(name, targetScheme) {
				server = value
				break
			}
		}
	}
	host, port := splitSystemProxy(server)
	return makeSystemProxy(host, port)
}

func parseColonSettings(output string) map[string]string {
	values := make(map[string]string)
	arrayKey := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if arrayKey != "" {
			if trimmed == ")" || strings.HasPrefix(trimmed, ")") || trimmed == "}" || strings.HasPrefix(trimmed, "}") {
				arrayKey = ""
				continue
			}
			if _, item, ok := strings.Cut(trimmed, ":"); ok {
				trimmed = item
			}
			item := settingString(strings.TrimSuffix(trimmed, ","))
			if item != "" {
				if values[arrayKey] != "" {
					values[arrayKey] += ","
				}
				values[arrayKey] += item
			}
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "(" || (strings.Contains(value, "<array>") && strings.Contains(value, "{")) {
			arrayKey = key
			values[key] = ""
			continue
		}
		values[key] = value
	}
	return values
}

func parseRegistrySettings(output string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			values[fields[0]] = fields[len(fields)-1]
		}
	}
	return values
}

func systemProxyBypass(target *url.URL, entries string) bool {
	for _, entry := range strings.FieldsFunc(entries, func(r rune) bool { return r == ',' || r == ';' }) {
		entry = strings.TrimSpace(entry)
		if entry == "<local>" && !strings.Contains(target.Hostname(), ".") {
			return true
		}
		entry = strings.TrimPrefix(entry, "*")
		if entry != "" {
			if matched, _ := noProxyMatchesURL(target, entry); matched {
				return true
			}
		}
	}
	return false
}

func settingString(value string) string {
	return strings.Trim(strings.TrimSpace(value), "'\"")
}

func splitSystemProxy(value string) (string, int) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	if parsed, err := url.Parse("http://" + value); err == nil {
		port, _ := strconv.Atoi(parsed.Port())
		return parsed.Hostname(), port
	}
	return "", 0
}

func makeSystemProxy(host string, port int) *url.URL {
	if host == "" || port <= 0 || port > 65535 {
		return nil
	}
	host = strings.Trim(host, "[]")
	proxy, err := url.Parse("http://" + net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	return proxy
}
