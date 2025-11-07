package arp

import (
	"bufio"
	"os"
	"strings"
)

type Table map[string]string

func ReadTable(filename string) (Table, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer fp.Close()

	table := make(Table)

	scanner := bufio.NewScanner(fp)
	scanner.Scan() // skip header
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		ip := fields[0]
		if table[ip] != "" {
			return nil, &duplicateError{ipAddrKind, ip}
		}

		hw := fields[3]
		if hw == "00:00:00:00:00:00" {
			continue
		}
		if table[hw] != "" {
			return nil, &duplicateError{hwAddrKind, hw}
		}

		table[ip] = hw
		table[hw] = ip
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return table, nil
}
