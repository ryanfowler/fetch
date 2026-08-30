package dnsinspect

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

func renderIPLiteral(p *core.Printer, host string) {
	renderInspectionSection(p, "Lookup")
	writeInspectionField(p, "Name", host)
	writeInspectionField(p, "Status", "IP literal — DNS not performed")
}

const maxPartialErrorBytes = 256

func conciseDiagnostic(text string) string {
	if len(text) <= maxPartialErrorBytes {
		return text
	}
	cut := maxPartialErrorBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

func render(p *core.Printer, res *result) {
	renderInspection(p, res)
}

func inspectionTransportSummary(res *result) string {
	if res.tcpFallback && res.transport == "UDP" {
		return "UDP → TCP fallback"
	}
	return res.transport
}

func renderResolverDetails(p *core.Printer, res *result) {
	var fields int
	write := func(label, value string) {
		if value == "" {
			return
		}
		if fields == 0 {
			writeInspectionBlankLine(p)
			heading := "Resolver details"
			if res.resolverRouting != "" || len(res.configuredNameservers) > 0 {
				heading = "System resolver"
			}
			renderInspectionSection(p, heading)
		}
		fields++
		writeInspectionField(p, label, value)
	}

	// Extra verbosity always records the exact absolute name sent to the
	// resolver, including when it is equivalent to the user-facing name.
	if res.queryName != "" {
		write("Query name", res.queryName)
	}
	if len(res.configuredNameservers) > 0 {
		write("Configured nameservers", strings.Join(res.configuredNameservers, ", "))
	}
	if res.resolverAttempts > 0 {
		write("Resolver attempts", countPhrase(res.resolverAttempts, "per nameserver", "per nameserver"))
	}
	if res.resolverTimeout > 0 {
		write("Resolver timeout", formatDuration(res.resolverTimeout))
	}
	write("Resolver rotation", res.resolverRotation)
	write("Configuration", res.resolverConfiguration)
	write("Routing", res.resolverRouting)
	write("Search domains", res.resolverSearchDomains)
	write("OS resolver routing", res.resolverOSRouting)
	write("macOS routing", res.resolverPlatformRouting)
	write("Bootstrap", res.resolverBootstrap)
}

func renderQueryDetails(p *core.Printer, queries []queryResult) {
	if len(queries) == 0 {
		return
	}

	writeInspectionBlankLine(p)
	renderInspectionSection(p, "Queries")
	for _, query := range queries {
		status := "no data"
		switch query.status {
		case queryStatusData:
			status = countPhrase(len(query.records), "record", "records")
		case queryStatusFailed:
			status = "failed"
		}
		parts := []string{status}
		// Keep the fallback immediately after the status so the legacy focused
		// output remains easy to scan, then append the exact responder details.
		if query.tcpFallback {
			parts = append(parts, "UDP → TCP fallback")
		} else if query.transport != "" {
			parts = append(parts, displayTransport(query.transport))
		}
		if query.responder != "" {
			parts = append(parts, query.responder)
		}
		if query.duration > 0 {
			parts = append(parts, formatDuration(query.duration))
		}
		if query.attempts > 0 {
			parts = append(parts, countPhrase(query.attempts, "attempt", "attempts"))
		}
		writeInspectionField(p, query.typ.label, strings.Join(parts, " · "))
	}
}

// renderInspection writes the structured DNS diagnostic view. The lookup
// summary is deliberately separate from record rendering so that the output
// remains useful even when no record data is available.
func renderInspection(p *core.Printer, res *result) {
	renderInspectionSection(p, "Lookup")
	writeInspectionField(p, "Name", res.host)
	if queryNameDiffers(res.host, res.queryName) {
		writeInspectionField(p, "Query name", res.queryName)
	}
	if res.platformFallback {
		if res.resolver != "" {
			writeInspectionField(p, "Resolver", res.resolver)
		}
		if len(res.responders) > 0 {
			writeInspectionField(p, "Resolvers", strings.Join(res.responders, ", "))
		}
	} else if len(res.responders) > 1 {
		writeInspectionField(p, "Resolvers", strings.Join(res.responders, ", "))
	} else if res.resolver != "" {
		writeInspectionField(p, "Resolver", res.resolver)
	}
	if transport := inspectionTransportSummary(res); transport != "" {
		writeInspectionField(p, "Transport", transport)
	}
	if res.security != "" {
		writeInspectionField(p, "Transport security", displaySecurity(res.security))
	}
	if res.source != "" {
		writeInspectionField(p, "Source", res.source)
	}
	if res.platformFallback {
		writeInspectionField(p, "Fallback", "platform resolver used for addresses")
	}
	writeInspectionField(p, "Status", inspectionStatus(res))
	if summary := resultSummary(res); summary != "" {
		writeInspectionField(p, "Results", summary)
	}
	if summary := querySummary(res); summary != "" {
		writeInspectionField(p, "Queries", summary)
	}
	if res.duration > 0 {
		writeInspectionField(p, "Timing", formatDuration(res.duration))
	}
	if res.tcpFallback && res.transport != "UDP" {
		writeInspectionField(p, "TCP fallback", "used for truncated UDP response")
	}

	if len(res.failures) > 0 {
		writeInspectionBlankLine(p)
		renderInspectionSection(p, "Failures")
		renderFailures(p, res.failures)
	}
	if res.verbosity >= core.VExtraVerbose {
		renderResolverDetails(p, res)
		renderQueryDetails(p, res.queries)
	}
	writeInspectionBlankLine(p)
	renderInspectionSection(p, "Records")
	if recordCount(res) == 0 {
		return
	}
	for _, qt := range inspectTypes {
		renderSection(p, qt.label, res.records[qt.label])
	}
	renderOtherSections(p, res.records)
}

func renderFailures(p *core.Printer, failures []queryFailure) {
	type failureGroup struct {
		labels []string
		// Keep the complete error as the grouping key. The displayed value is
		// bounded, so a long resolver diagnostic cannot make the output grow
		// without limit while two distinct errors are not accidentally merged
		// because their prefixes happen to match.
		key string
		err string
	}
	groups := make([]failureGroup, 0, len(failures))
	indices := make(map[string]int, len(failures))
	for _, failure := range failures {
		key, errText := failureDiagnostic(failure.err)
		idx, ok := indices[key]
		if !ok {
			indices[key] = len(groups)
			groups = append(groups, failureGroup{key: key, err: errText})
			idx = len(groups) - 1
		}
		groups[idx].labels = append(groups[idx].labels, failure.label)
	}

	// Aggregation normally supplies failures in inspection order. Sort here as
	// well because renderFailures is also used by focused tests and should be
	// deterministic for any input order.
	for i := range groups {
		slices.SortFunc(groups[i].labels, compareInspectionLabels)
	}
	slices.SortFunc(groups, func(a, b failureGroup) int {
		if cmp := compareInspectionLabels(a.labels[0], b.labels[0]); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.key, b.key)
	})

	for _, group := range groups {
		label := strings.Join(group.labels, ", ")
		if allInspectionTypesFailed(group.labels) {
			label = "All record types"
		}
		writeInspectionField(p, label, group.err)
	}
}

func failureDiagnostic(err error) (key, display string) {
	if err == nil {
		return "query failed", "query failed"
	}
	key = err.Error()
	if key == "" {
		return "query failed", "query failed"
	}
	return key, conciseDiagnostic(key)
}

func allInspectionTypesFailed(labels []string) bool {
	if len(labels) != len(inspectTypes) {
		return false
	}
	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if _, ok := seen[label]; ok {
			return false
		}
		seen[label] = struct{}{}
	}
	for _, typ := range inspectTypes {
		if _, ok := seen[typ.label]; !ok {
			return false
		}
	}
	return true
}

func compareInspectionLabels(a, b string) int {
	rank := func(label string) int {
		for i, typ := range inspectTypes {
			if label == typ.label {
				return i
			}
		}
		return len(inspectTypes)
	}
	if aRank, bRank := rank(a), rank(b); aRank != bRank {
		if aRank < bRank {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// queryNameDiffers reports whether the absolute DNS name is meaningfully
// different from the name supplied by the user. The root terminator is
// implicit for ordinary multi-label hostnames, so it is not useful to repeat
// it in normal output. Single-label names are different: adding the root
// terminator makes the qualification explicit and avoids implying search
// domain behavior.
func queryNameDiffers(host, queryName string) bool {
	if queryName == "" {
		return false
	}
	if host == "." || strings.HasSuffix(host, ".") {
		return !strings.EqualFold(host, queryName)
	}
	if !strings.Contains(host, ".") && strings.EqualFold(absoluteName(host), queryName) {
		return true
	}
	return !strings.EqualFold(absoluteName(host), queryName)
}

func renderInspectionSection(p *core.Printer, heading string) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString(core.TerminalSafeText(heading))
	p.Reset()
	p.WriteString("\n")
}

func writeInspectionField(p *core.Printer, label, value string) {
	p.WriteInfoPrefix()
	p.WriteString("  ")
	p.WriteString(label)
	p.WriteString(": ")
	p.WriteString(core.TerminalSafeText(value))
	p.WriteString("\n")
}

func writeInspectionBlankLine(p *core.Printer) {
	p.WriteInfoPrefix()
	p.WriteString("\n")
}

func inspectionStatus(res *result) string {
	if len(res.failures) == 0 {
		return "complete"
	}
	if res.queryTotal > 0 {
		return fmt.Sprintf("incomplete — %d of %d queries failed", len(res.failures), res.queryTotal)
	}
	return "incomplete"
}

func resultSummary(res *result) string {
	addresses := len(res.records["A"]) + len(res.records["AAAA"])
	return strings.Join([]string{
		countPhrase(addresses, "address", "addresses"),
		countPhrase(recordCount(res), "record", "records"),
		countPhrase(recordTypeCount(res), "record type", "record types"),
	}, " · ")
}

func querySummary(res *result) string {
	if res.queryTotal == 0 {
		return ""
	}
	parts := []string{
		queryCountPhrase(res.queryTotal, "total"),
		queryCountPhrase(res.queryWithData, "with data"),
		queryCountPhrase(res.queryNoData, "no data"),
	}
	if len(res.failures) > 0 {
		parts = append(parts, queryCountPhrase(len(res.failures), "failed"))
	}
	return strings.Join(parts, " · ")
}
