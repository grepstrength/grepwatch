package diff

import (
	"net/url" //parses a URL string
	"regexp" //needed for pattern matching 
	"strings" //for simpler substring checks

	"github.com/grepstrength/grepwatch/model" //every grepfunction returns model.Signal
)

/*compiled once at packge load via regexp.MustCompile rather than inside each function call
compiling regex can be taxing, so compiling once then reusing it across multiple package scans is more economical
*/
var (
	reOutboundURL = regexp.MustCompile(`https?://[^\s"'` + "`" + `)]+`) //self explanatory... matches http(s) URLs
	reRawIP = regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`) //matches an http/https URL with a host of a raw IPv4 address... legit packages almost always use domainnames. hardcoded IPs are likely C2s
	reInstallHook = regexp.MustCompile(`(?i)"(?:pre|post)?install"\s*:\s*"([^"]*)"`)//matchs common install-time execution hooks across ecosystems... malware will often use these to run code the moment a package is installed
	reDangerousImport = regexp.MustCompile(`\b(?:child_process|subprocess|os/exec|socket|eval|vm|net)\b`) //matches the dangersous tokens ONLY as standalone words
)

/*
this uses my namesake because this searches for new network desitnations
it compares URls found in the new version vs the old and returns a Signal for anything that's new

FYI new outbound URLs aren't inherently malicious, but a new URL pointing at a random IP address is weighted must more heavily
*/
func grepOutboundURLs(oldSrc, newSrc string) []model.Signal {
	oldURLs := sliceToSet(reOutboundURL.FindAllString(oldSrc, -1))
	newURLs := reOutboundURL.FindAllString(newSrc, -1)
	var added []string 
	for _, u := range newURLs {
		if !oldURLs[u] && !isNoiseURL(u) { //added isNoiseURL
			added = append(added, u)
		}
	}
	if len(added) == 0 {
		return nil 
	}
	weight := 2
	for _, u := range added {
		if reRawIP.MatchString(u) || isPayloadHost(u) { //added isPayloadHost
			weight = 4
			break
		}
	}
	return []model.Signal{{
		Kind:			"new_outbound_url",
		Description:	"Package version introduced new network destination(s)",
		Evidence:		added,
		Weight:			weight,
	}}
}

/*grepImports searches for import/rquire statements that appear in the new version but not the old. 
new imports of dangerous modules like child_process, os/exec, etc. signal tat a package gained the ability to execute commands or open network comms it couldn't previously

***FYI*** this is intentionally simple for v1... this allows me to have substring matching work against all six ecosystems without writing six different parsers
this will have FPs, which is why this is a weighted score
*/
func grepImports(oldSrc, newSrc string) []model.Signal {
	oldMods := sliceToSet(reDangerousImport.FindAllString(oldSrc, -1)) //dangerous tokens already in the previous version. only flag tokens that are newlyintroduced
	newMods := reDangerousImport.FindAllString(newSrc, -1) //every dangerous token match in the new version
	seen := make(map[string]bool) //tokens already added, so each appears once
	var added []string
	for _, mod := range newMods {
		if oldMods[mod] || seen[mod] { //skip if it existed before OR we've recorded it
			continue
		}
		seen[mod] = true
		added = append(added, mod)
	}
	if len(added) == 0 {
		return nil
	}
	return []model.Signal{{
		Kind:        "new_dangerous_import",
		Description: "Package version introduced imports granting code execution or network access",
		Evidence:    added,
		Weight:      3,
	}}
}

/*
the grepStrings function searches for high-entropy string literals that appear in the new version but not the old

this catches encoded payloads, embedded keys, and obfuscated configs (e.g. a new base64-encoded blob or encrypted const randomly showing up in a package update)

FYI, this relies on the entropy scorer in entropy.go
*/
func grepStrings(oldSrc, newSrc string) []model.Signal {
	//this regex is intentionally loosey goosey
	reStringLit := regexp.MustCompile(`"[^"\n]{20,}"`) //string literals of 20+ chars, single-line only... \n stops the match from swallowing whole files between distant double-quotes
	oldStrings := sliceToSet(reStringLit.FindAllString(oldSrc, -1))
	newStrings := reStringLit.FindAllString(newSrc, -1)

	var suspicious []string
	for _, s := range newStrings {
		if oldStrings[s] {
			continue //if existed befroe but not newly introduced
		}
		if isHighEntropy(s) {
			suspicious = append(suspicious, s)
		}
	}

	if len(suspicious) == 0 {
		return nil
	}

	return []model.Signal{{
		Kind:        "high_entropy_string",
		Description: "Package version introduced high-entropy string(s) consistent with encoded payloads",
		Evidence:    suspicious,
		Weight:      3,
	}}
}

/*
grepInstallHooks searches for install-time execution hooks that were added or modified in the new version
these hooks run automatically during package installation, before any application code imports the package

this is one of the most exploited software supply chain vectors
*/
func grepInstallHooks(oldSrc, newSrc string) []model.Signal {
	oldHooks := sliceToSet(reInstallHook.FindAllString(oldSrc, -1)) //oldHooks is the set of install-hook lines that already existed in the previous version
	newHooks := reInstallHook.FindAllString(newSrc, -1) //every install-hook line in the new version

	//this only flags if hooks appear in the new version and did not exist in the old 
	//install hooks that were always present are normal behavior
	var added []string
	for _, hook := range newHooks {
		if !oldHooks[hook] {
			added = append(added, hook)
		}
	}

	if len(added) == 0 {
		return nil
	}
	return []model.Signal{{
		Kind:        "new_install_hook",
		Description: "Package version added install-time execution hook",
		Evidence:    added, //change from previous version - the evidence is now the real hook line(s) and the command they run
		Weight:      3,
	}}
}
/* 
this is the helper function to conert a slice of strings into a set for 0(1) membership

this is used throughout the grep* functions to check if something in the new version previously existed in the old version

named sliceToSet and not grepSliceToSet because no searching is being performed... it just acts as a data structure helper
*/
func sliceToSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}
/*
isReservedHost is a helper function called by isNoiseURL
it reports whether a URL points at a host that can never be a eal network desitnation:
loopback address (127.0.0.1), RFC 2606 reserved example domains, and test client placeholders 

a URL to any of this is never capable of exfiltration and are safe to drop regardless of what file theyre in
*/
func isReservedHost(u string) bool {
	parsed, err := url.Parse(u) //splits "http://testserver/api/" into its constituent parts. "err" is not nli only if the string isn't a valid URL
	if err != nil {
		return false //if it can't parse it, let it through
	}
	host := strings.ToLower(parsed.Hostname()) //Hostname() pulls just the host out of "parsed" while dropping any :port. use ToLower so "Testserver" and "testserver" compare equally
	switch host { //exact match for reserved or test-only hosts
	case "testserver", "localhost", "127.0.0.1", "0.0.0.0", "::1",
		"example.com", "example.org", "example.net":
		return true
	}
	//reserved TLDs... anything ending in these is a placeholder and non-routable
	for _, suffix := range []string{".localhost", ".local", ".invalid", ".test", ".example"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	return false
}
/*
isDocHost reports if a URL points at known documentation host: crates python packages and go modules oten embed links into their own docs
these hosts serve generated documents but not raw downloadable files, so a URL to one is almost always  reference and never a payload

this is why doc hosts are safe for allowlists, but github.com wasn't... it uses raw.githubusercontent for arbitrary file hosting
docs.rs has no raw-file path so nothing executable can hie behind it
*/
func isDocHost(u string) bool {
	parsed, err := url.Parse(u) //reusing url.Parse, same as isReservedHost
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname()) //just the host, lowercase
	for _, d := range []string{
		"docs.rs",
		"docs.python.org",
		"readthedocs.io",
		"readthedocs.org",
		"pkg.go.dev",
		"godoc.org",
		"javadoc.io",
	} {
		if host == d || strings.HasSuffix(host, "."+d) { //exact host or subdomain
			return true
		}
	}
	return false
}

/*
this marks URLs that are descriptive or navigational than runtim fetch or exfil targets
repo clone URLs (.git) or doc achors (#frament) and repo navigation (issues, pulls, blobs, etc)
this SHOULD NOT exclude raw-content hosts, /releases/download/, or IPs, which are still potential attack
*/
func isNoiseURL(u string) bool {
	if isReservedHost(u) { //testserver, localhost, example.com, etc. are never real destinations
		return true
	}
	if isDocHost(u) { //docs.rs, pkg.go.dev, etc. 
		return true
	}

	if strings.ContainsAny(u, "{}") { //any templated or formatted address, like {addr} or {port}
		return true
	}
	if strings.Contains(u, "#") || strings.HasSuffix(u, ".git") {
		return true
	}
	for _, seg := range []string{"/issues/", "/pull/", "/blob/", "/tree/", "/wiki/", "/commit/", "/discussions/"} {
		if strings.Contains(u, seg) {
			return true
		}
	}
	return false
}
//this flags the URL shapes that are typically used in malware
//isNoiseUR filters noise, while isPayloadHost escalates malware indicators
func isPayloadHost(u string) bool {
	lower := strings.ToLower(u)
	for _, h := range []string{"raw.githubusercontent.com", "gist.githubusercontent.com", "gist.github.com", "pastebin.com"} {
		if strings.Contains(lower, h) {
			return true
		}
	}
	for _, ext := range []string{".sh", ".ps1", ".exe", ".bin", ".dll", ".scr"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}