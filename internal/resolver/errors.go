package resolver

import "fmt"

// RCodeError reports a DNS response with a non-zero response code.
type RCodeError struct {
	// Prefix names the response, such as "DNS response".
	Prefix string
	Code   uint16
}

func (e *RCodeError) Error() string {
	return e.Prefix + ": " + RCodeName(e.Code)
}

// rcodeNXDomain is the NXDOMAIN response code.
const rcodeNXDomain = 3

// errNoAddresses reports that every address family answered without
// addresses. It is a NODATA result, with the message that Go's resolver uses.
var errNoAddresses error = &noDataError{msg: "no such host"}

// noDataError is a NODATA result with its own message.
type noDataError struct{ msg string }

func (e *noDataError) Error() string { return e.msg }
func (e *noDataError) Unwrap() error { return errDNSNoData }

// bootstrapError reports that the address of a DNS server could not be
// resolved. The lookup that failed is not the query that the caller asked
// for, and it usually runs over plaintext DNS. Its result, such as
// NXDOMAIN, therefore says nothing about the queried name.
type bootstrapError struct {
	server string
	err    error
}

func (e *bootstrapError) Error() string {
	return fmt.Sprintf("resolve %s: %v", e.server, e.err)
}

func (e *bootstrapError) Unwrap() error { return e.err }
