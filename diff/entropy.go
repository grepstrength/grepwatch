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
/*this funtion reports whether a string's entropy exeeds the threshold that's considered suspicious. 4.5 bits per character is the line. going above it the string is unlikely to be normal source code or human-written strings
the threshold is purposefully conservative... would rather flag an iffy string than miss an actual encoded payload
let analysts decide  
*/
func isHighEntropy(s string) bool {
	const threshold = 4.5
	return shannonEntropy(s) > threshold
}