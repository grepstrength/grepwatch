package diff

import "math" //need math.Log2 fo the entropy calc

/* next function is important... shannonEntropy calculates the Shannon entropy of a string in bits per character


the result ranges from 0 to lo2(n) where n is the number of distinct characters

- English prose will score around 3.5-4.5
- Base64-encoding scores approx 5.5-6.0
- random or encrypted bytes approach 8.0

this is used to flag strings that look like encoded payloads, embedded keys, or obfuscated configs intro'd in a new package version
*/

func shannonEntropy(s string) float64 {
	if len(s) == 0 { //this prevents a divide-by-zero 
		return 0
	}
	//this next one counts how many times each byte appears
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	//this applies the Shannon entropy formula: H = -sum(p * log2(p)) for each distinct character where p is the probability of that character appearing
	//.... i needed help with this
	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

/*
isBase64Char reports if a single byte c belongs to the base64 alphabet.
this is treated as an encoding alphabet for run detection. note that the hex alphabet is a strict subset

c is a single byte because the string is scanned byte by byte in a logestEncodeRun.
The base64 alphabet is pure ASCII so bytyes are safe 
*/
func isBase64Char(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z': //uppercase letters
		return true
	case c >= 'a' && c <= 'z': //lowercase
		return true
	case c >= '0' && c <= '9': //numerical digits
		return true
	case c >= '+' || c == '/' || c == '=': //base64's two symbols plus '=' padding
		return true
	}
	return false
}
/*
logestEncodedRun scans the variable s and returns the longest contiguous substring made entirely of base64 alphabet characters
this is the heart of the composition gate... a real encoded payload is a dense unbroken block of encoding characters
but JS, SQL, etc are encodedish chars broken up by spaces, punctionation, ^, etc
s = the candidate string lieral we're judging
longest = th best/longest run found so far
start = the index where the curret run began
*/
func longestEncodedRun(s string) string {
	longest := ""
	start := -1 //needed because Go doesn't have an "is this loop variable set?", so this is used to mean that no run is currently open
	for i := 0; i < len(s); i++ {
		if isBase64Char(s[i]) {
			if start < 0 { //entered a new run, remember where it began
				start = i
			}
			continue //still inside a run, so keep walking through
		}
		//if you hit a non-base64 byte, any run that was openends here at index i 
		if start >= 0 {
			if i-start > len(longest) { //this run is longer than the best so far
				longest = s[start:i] //slice captures the run, excluding the s[i]
			}
			start = -1 //close the run 
		}
	}
	if start >= 0 && len(s)-start > len(longest) { //a run can run all the way to the end of s without ever hitting a closing non-base64 byte, so handle the tail case after the loop
		longest = s[start:]
	}
	return longest
}

/*this funtion reports whether a string's entropy exeeds the threshold that's considered suspicious. 5 bits per character is the line. going above it the string is unlikely to be normal source code or human-written strings
the threshold is purposefully conservative... becuase I'm already skipping over base64 of plaintext (4.7) and hex (4.0)
the tradeoff is we're losing some potential detections to be a bit more precise
don't wanna cry wolf
*/
func isHighEntropy(s string) bool {
	run := longestEncodedRun(s) //the densest base64/hex block inside s

	//this next one is a length gate. if there is no meaningful encoded block, there's no payload
	//24 chars is the floor, to be short enough to catch a 16-byte key but long eough that ordinary identifiers and broken plaintext fall below it
	const minRunLen = 24
	if len(run) < minRunLen {
		return false
	}
    const threshold = 5.0 //the original value, 4.5, was TOO conservative...
    return shannonEntropy(run) > threshold
}