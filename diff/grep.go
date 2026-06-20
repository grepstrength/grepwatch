package diff

import (
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
	reInstallHook = regexp.MustCompile(`(?i)(preinstall|postinstall|install)\s*[":]`)//matchs common install-time execution hooks across ecosystems... malware will often use these to run code the moment a package is installed
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
	dangerous := []string{ //these are modules that grant command execution or network access... any new import of these warrants investigation
		"child_process", //Node
		"subprocess",//Python
		"os/exec",//Go
		"socket", //Python raw sockets
		"net", //Go networking
		"vm", //Node code evaluation
		"eval", //dynamic code execution across languages
	}
	var added []string 
	for _, mod := range dangerous { 
		if strings.Contains(newSrc, mod) && !strings.Contains(oldSrc, mod) { //if the dangerous module appears in the new source, but not the old, i was newly introduced in this version
			added = append(added, mod)
		}
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
	oldHooks := reInstallHook.MatchString(oldSrc)
	newHooks := reInstallHook.MatchString(newSrc)

	//this only flags if hooks appear in the new version and did not exist in the old 
	//install hooks that were always present are normal behavior
	if newHooks && !oldHooks {
		return []model.Signal{{
			Kind:        "new_install_hook",
			Description: "Package version added install-time execution hook",
			Evidence:    []string{"install hook detected in new version"},
			Weight:      3,
		}}
	}

	return nil
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

//this marks URLs that are descriptive or navigational than runtim fetch or exfil targets
//repo clone URLs (.git) or doc achors (#frament) and repo navigation (issues, pulls, blobs, etc)
//this SHOULD NOT exclude raw-content hosts, /releases/download/, or IPs, which are still potential attacks
func isNoiseURL(u string) bool {
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