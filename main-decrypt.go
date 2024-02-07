package main

import (
	"fmt"
	"os"
	"strings"
	"log"
	"bufio"
)

const maxSize = 100 * 1024 // 100 KB

func main() {
	secret_key := os.Args[1] 
	input_file := os.Args[2]
	// fmt.Println(secret_key, input_file)
	decrpyt(secret_key, input_file)
}

func decrpyt(secret_key, input_file string) {
	processed_key := processKey(secret_key)
	processed_input := processFile(input_file)
	deciphertext := vigenere("dec", processed_key, processed_input)
	fmt.Println(deciphertext)
	// writeToFile("deciphertext.txt", deciphertext)
}

func processKey(secret_key string) string {
	if len(secret_key) > 32 {
		fmt.Println("Invalid Key (ONLY UPPER-CASE APLPHABETS AND SIZE LIMIT = 32)!!")
		os.Exit(1)
	}
	for _, c := range secret_key {
		if !((c >= 'A' && c <= 'Z')) {
			fmt.Println("Invalid Key (ONLY UPPER-CASE APLPHABETS AND SIZE LIMIT = 32)!!")
			os.Exit(1)
		}
	}
	return secret_key
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

func vigenere(method, processed_key, processed_input string) string {
	j := 0
	key_size := len(processed_key)

	var ciphertext strings.Builder

	for _, r := range processed_input {
		offsetInput := int(r) - int('A')

		j = j % key_size
		offsetKey := int(processed_key[j]) - 'A'
		j++
		
		var offsetCipher int

		if method == "enc" {
			offsetCipher = (offsetInput + offsetKey) % 26
		} else if method == "dec" {
			offsetCipher = (offsetInput - offsetKey + 26) % 26
		} else {
			log.Fatal("INCORRECT METHOD : " + method)
		}

		c := rune(offsetCipher + int('A'))
		ciphertext.WriteRune(c)
	}

	return ciphertext.String()
}