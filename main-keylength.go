package main

import (
    "fmt"
    "os"
    "strings"
	"log"
	"bufio"
)

const maxSize = 100 * 1024 // 100 KB
const keySizeLimit = 32

func main() {
	ciphertext := processFile(os.Args[1])
	fmt.Println(getKeylength(ciphertext))
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

func getKeylength(ciphertext string) int {
	max := 0
    var IC [keySizeLimit]float64
    
	for i := 1; i <= keySizeLimit; i++ {
		for j := 0; j < i; j++ {
			group := ""

			for itr := j; itr < len(ciphertext); itr += i {
				group += string(ciphertext[itr])
			}

			IC[i-1] += calulateIC(group)
		}

		IC[i - 1] /= float64(i)

		if IC[i-1] > 0.06 {
    		max = i - 1
    		break
    	} else if IC[i-1] > float64(IC[max]) {
    		max = i - 1
    	}

	}

	return max + 1
}

func calulateIC(group string) float64 {
	groupLength := len(group)
	cumulativeProb := float64(0)

	for k := 0; k < 26; k++ {
		letter := string(k + int('A'))
		letterFreq := strings.Count(group, letter)
		prob1 := float64(letterFreq) / float64(groupLength)		// probability of selecting letter in first trial
		prob2 := float64(letterFreq - 1) / float64(groupLength - 1)		// probability of selecting letter in second trial
		cumulativeProb += prob1 * prob2
	}

	return cumulativeProb
}