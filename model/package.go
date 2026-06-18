package model

import "time"

type Ecosystem string //using a named string type isntead of a raw string gives you a compiler that will catch typos and you can define valid values as constants

const (
	EcosystemNPM	Ecosystem = "npm"
	EcosystemPyPI	Ecosystem = "pypi"
	EcosystemGo		Ecosystem = "go"
	EcosystemCargo	Ecosystem = "cargo"
	EcosystemMaven	Ecosystem = "maven"
	EcosystemNuGet	Ecosystem = "nuget"
)

//the Severity is an integer scrore from 0-5 representing how malicious a finding looks. thisis defined as its own type

type Severity int //this is int and not a string becuase you need to do math on it. you cant sum a string

const (
	SeverityNone		Severity = 0
	SeverityLow			Severity = 1
	SeverityMedium		Severity = 2
	SeverityHigh		Severity = 3
	SeverityCritical	Severity = 4
)

//Package is the unit of work that crawlers produce and the diff engine consumes. they represent specific versions of a specific package in a spcific ecosystem
type Package struct {
	Ecosystem	Ecosystem	`json:"ecosystem"`
	Name		string		`json:"name"`
	Version		string		`json:"version"`
	SourceURL	string		`json:"source_url"`
}

//Signal is a suspicious observeation produced by a grep* function
//by keeping signals granular means the alert engine can explain exactly WHY a package was scored the way it was. It's not just "high", but "three new outbound URLs + obfuscated string detected"

type Signal struct {
	Kind		string		`json:"kind"` //for example, "new_import" or "high_entropy_string"
	Description	string		`json:"description"` //this is so its human-readable
	Evidence	[]string	`json:"evidence"`//the raw extracted values, like URLs or strings
	Weight		int			`json:"weight"`//this is the contribuion to the final severity score
}

//Finding's what the diff engine produces after analyzing two versions of a package... contained are all Signals found, the computed Severity, and metadata for storage and display
type Finding struct {
	Package			Package		`json:"package"`
	PrevVersion		string		`json:"prev_version"`
	Signals			[]Signal	`json:"signals"`
	Severity		Severity	`json:"severity"`
	AnalyzedAt		time.Time	`json:"analyzed_at"`
}
//embeds the original Package and adds the four fields the diff engine needs
type ResolvedPackage struct {
	Package       Package
	SourceURL     string
	PrevVersion   string
	PrevSourceURL string
}