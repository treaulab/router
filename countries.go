package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

type country struct {
	Code string
	Name string
}

// Mirrors the list from the Python prototype.
var commonCountries = []country{
	{"de", "Germany"},
	{"nl", "Netherlands"},
	{"ch", "Switzerland"},
	{"us", "United States"},
	{"gb", "United Kingdom"},
	{"fr", "France"},
	{"jp", "Japan"},
	{"ca", "Canada"},
	{"se", "Sweden"},
	{"at", "Austria"},
	{"fi", "Finland"},
	{"no", "Norway"},
	{"ro", "Romania"},
	{"pl", "Poland"},
	{"is", "Iceland"},
}

func countryName(code string) string {
	if code == "any" {
		return "Any (automatic)"
	}
	for _, c := range commonCountries {
		if c.Code == code {
			return c.Name
		}
	}
	return strings.ToUpper(code)
}

func resolveCountry(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "any":
		return "any", nil
	case "random":
		return randomCountry(), nil
	}
	if len(value) == 2 && isASCIILetter(value[0]) && isASCIILetter(value[1]) {
		return value, nil
	}
	return "", fmt.Errorf("invalid country %q (use a two-letter code, any, or random)", value)
}

func randomCountry() string {
	return commonCountries[rand.IntN(len(commonCountries))].Code
}

func isASCIILetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func printCountryList() {
	fmt.Printf("%2d  %-8s %s\n", 0, "any", "Any (automatic)")
	for i, c := range commonCountries {
		fmt.Printf("%2d  %-8s %s\n", i+1, c.Code, c.Name)
	}
	fmt.Printf("    %-8s %s\n", "random", "Random country")
}

func nextCountry(current string) string {
	if current == "any" {
		return commonCountries[0].Code
	}
	for i, c := range commonCountries {
		if c.Code == current {
			return commonCountries[(i+1)%len(commonCountries)].Code
		}
	}
	return "any"
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
