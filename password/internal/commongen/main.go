// Command commongen regenerates ../../common_passwords.txt.gz from pinned
// SecLists (MIT) lists: run `go generate ./password`.
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

const base = "https://raw.githubusercontent.com/danielmiessler/SecLists/8420764ea28d5cdc1a8bbb8311736a2235be28c4/Passwords/Common-Credentials/"

// Short entries are kept only from the 10k list, for hosts that lower MinLength.
var sources = []struct {
	name   string
	minLen int
}{
	{"10k-most-common.txt", 1},
	{"100k-most-used-passwords-NCSC.txt", 8},
	{"Pwdb_top-1000000.txt", 8},
}

func main() {
	seen := map[string]struct{}{}
	for _, src := range sources {
		resp, err := http.Get(base + src.name)
		if err != nil || resp.StatusCode != http.StatusOK {
			fail(fmt.Errorf("fetch %s: %v %v", src.name, err, resp))
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			pw := strings.ToLower(strings.TrimRight(sc.Text(), "\r"))
			if n := utf8.RuneCountInString(pw); n >= src.minLen && n <= 128 && !strings.ContainsAny(pw, "\n") {
				seen[pw] = struct{}{}
			}
		}
		resp.Body.Close()
		if err := sc.Err(); err != nil {
			fail(err)
		}
	}
	list := make([]string, 0, len(seen))
	for pw := range seen {
		list = append(list, pw)
	}
	slices.Sort(list)
	f, err := os.Create("common_passwords.txt.gz")
	if err != nil {
		fail(err)
	}
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	if _, err := zw.Write([]byte(strings.Join(list, "\n") + "\n")); err != nil {
		fail(err)
	}
	if err := zw.Close(); err != nil {
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	fmt.Println(len(list), "entries")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
