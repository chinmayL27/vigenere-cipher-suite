package main

import (
    "fmt"
    "os"
    "strings"
	"log"
	"bufio"
	"math"
	"strconv"
)

const maxSize = 100 * 1024 // 100 KB
const keySizeLimit = 32
var letterFreqEng = [26]float64 {
									.08167, .01492, .02792, .04253, .12702,
									.02280, .02015, .06094, .06966, .01530,
									.07720, .04025, .02406, .06749, .07507,
									.01929, .00950, .05987, .06327, .09056,
									.02758, .00978, .02360, .00150, .01974,
									.0074,
								}

func main() {
	ciphertext := processFile(os.Args[1])
	keylength, _ := strconv.Atoi(os.Args[2])
	cryptAnalysis(ciphertext, keylength)
}

func processFile(input_file string) string {
	fileInfo, errInfo := os.Stat(input_file)
	
	if errInfo != nil {
		log.Fatal(errInfo)
	}
	if fileInfo.Size() > int64(maxSize) {
		log.Fatal("Invalid File Size (limit = 100KB)")
	}

	file, err := os.Open(input_file)
	defer file.Close()

	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)

	var processed_file strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		
		var filtered_line strings.Builder
		for _, c := range line {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				filtered_line.WriteRune(c)
			}
		}
		line = filtered_line.String()
		processed_file.WriteString(line)
	}

	if errScan := scanner.Err(); errScan != nil {
		log.Fatal(errScan)
	}

	return strings.ToUpper(processed_file.String())
}

func cryptAnalysis(ciphertext string, keylength int) {
	// keylength := getKeylength(ciphertext)
	// fmt.Println("-----", keylength)

	proposedKey := ""

	for i := 0; i < keylength; i++ {
    	bucket := ""
    	for itr := i; itr < len(ciphertext); itr += keylength {
    		bucket += string(ciphertext[itr])
    	}

     	var chiSquare [26]float64

    	for j := 0; j < 26; j++ {
    		shiftedSequence := ""
    		for k := 0; k < len(bucket); k++ {
    			currLetter := bucket[k]
    			currLetter = (currLetter - (byte)(j) - 65 + 26) % 26
    			shiftedSequence += string(currLetter + 65)
    		}
    		totalChi := 0.0
    		
    		for l:= 0; l < 26; l++ {
    			letter := string(l + 65)

    			observed := strings.Count(shiftedSequence, letter)	// frequency of the alphabet
    			expected := float64(letterFreqEng[l]) * float64(len(bucket))	// expected frequency score
    			chiSquared := math.Pow(float64(observed) - expected, 2)	// X^2
    			currentChi := float64(chiSquared) / expected

				totalChi += currentChi
    		}
    		chiSquare[j] += totalChi
    	}

		min := 0

    	for m := 0; m < 26; m++ {
    		if (chiSquare[m] < chiSquare[min]) {
    			min = m
    		}
    	}

    	proposedKey += string(min + 65)
    }
    fmt.Println(proposedKey)
}