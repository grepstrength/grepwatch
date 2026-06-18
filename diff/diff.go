package diff

import (
	"archive/tar" //npm and pypi packages ship as gzipped tarballs
	"archive/zip"  //cargo, maven, nuget, and go packages ship as zip archives
	"bytes"    
	"compress/gzip" //npm and pypi packages ship as gzipped tarballs
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grepstrength/grepwatch/model"
)
/*
maxSourceBytes caps how much source we read from any single package because some packages are enormous (e.g. bundled dependencies)
reading all of it in memory woul let a single malicious or malformed package exhaust the worker's RAM
it's set to 40MB which is generous

the limit is set to 40MB deliberatly because it protects against decompression bombs and extremely large packages
zip archies cannot be streamed (like tar)... the whole archive must be buffered in memory because a zip's directory index lives at the end ofthe file
*/
const maxSourceBytes = 40 * 1024 * 1024

/*
Analyze is the public entry point for the diff package
this returns a nil Finding whn both versions fetch and diff successfully but nothig suspicious is found
*/
func Analyze(ctx context.Context, pkg model.Package, prevVersion string) (*model.Finding, error) {
	newSrc, err := fetchSource(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("diff: fetch new version: %w", err)
	}

	prevPkg := pkg
	prevPkg.Version = prevVersion
	oldSrc, err := fetchSource(ctx, prevPkg)
	if err != nil {
		return nil, fmt.Errorf("diff: fetch previous version: %w", err)
	}
	var signals []model.Signal //run every grep* search function and collect all the signals
	signals = append(signals, grepOutboundURLs(oldSrc, newSrc)...)
	signals = append(signals, grepImports(oldSrc, newSrc)...)
	signals = append(signals, grepStrings(oldSrc, newSrc)...)
	signals = append(signals, grepInstallHooks(oldSrc, newSrc)...)

	finding := &model.Finding{
		Package:     pkg,
		PrevVersion: prevVersion,
		Signals:     signals,
		AnalyzedAt:  time.Now().UTC(),
	}

	return finding, nil
}

/*
this downloads a package version's archive and extracts all text content into a single string for the grep functions to scan 

it detects the archive fomat from the file's magic bytes rather than trusting the URL's extension or the server's COntent-Type
*/
func fetchSource(ctx context.Context, pkg model.Package) (string, error) {
	if pkg.SourceURL == "" {
		return "", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pkg.SourceURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "grepWatch/0.1 (https://grepwatch.com)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch archive: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes)) //buffer the body up to the size cap... must be read fully because zip needs random access 
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	switch {
	case len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b:
		return extractTarGz(bytes.NewReader(body))
	case len(body) >= 2 && body[0] == 'P' && body[1] == 'K':
		return extractZip(body)
	default:
		return "", nil //if there's an unknon or unsupported format, this soft fails
	}
}

//extractTarGz decompresses gzip stream, walks the tar archive and concatenates the contents of every text file into one string
func extractTarGz(r io.Reader) (string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", nil //if its not actually gzip, this soft fails
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var builder strings.Builder

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}
		if !isTextFile(header.Name) {
			continue
		}

		if _, err := io.Copy(&builder, tr); err != nil {
			return "", fmt.Errorf("read file %s: %w", header.Name, err)
		}
		builder.WriteByte('\n')
	}
	return builder.String(), nil
}


/*extractZip reads a zip archive from a byte slice and concatenates the contents of everytext file into one string

unlike tar, zip can't be streamed... its central directoryindex lives at the end of the archive, so zip.NewReader needs the full buffer and its length up front
*/
func extractZip(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", nil //if its not actually zip, this soft fails
	}

	var builder strings.Builder

	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !isTextFile(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("open %s: %w", f.Name, err)
		}
		if _, err := io.Copy(&builder, io.LimitReader(rc, maxSourceBytes)); err != nil { //guard each indiidual file with a size cap. LimitReader caps each file extraction
			rc.Close()
			return "", fmt.Errorf("read %s: %w", f.Name, err)
		}
		rc.Close()
		builder.WriteByte('\n')
	}

	return builder.String(), nil
}

//isTextFile reports if a filename looks like source code, a manifest, or a script
//FYI it checks the file extension only
func isTextFile(name string) bool {
	textExtensions := []string{
		".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", //JavaScript/TypeScript
		".py", ".pyi", //Python
		".go", //Go
		".rs", //Rust
		".java", ".kt", ".scala", //JVM
		".cs", //C#
		".json", ".toml", ".yaml", ".yml", ".xml", //manifests
		".sh", ".bash", ".ps1", //scripts
		".txt", ".md", //text
	}

	lower := strings.ToLower(name)
	for _, ext := range textExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}