package detect

import (
	"strings"
	"time"
)

var creationKeys = []string{
	"Creation Date:",
	"Created On:",
	"Domain Create Date:",
	"Registered On:",
	"Registration Time:",
}

var creationLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05Z",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
}

func parseWhoisCreationDate(raw string) *time.Time {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, key := range creationKeys {
			if strings.HasPrefix(trimmed, key) {
				value := strings.TrimSpace(strings.TrimPrefix(trimmed, key))
				value = strings.Trim(value, "'\"")
				for _, layout := range creationLayouts {
					if parsed, err := time.Parse(layout, value); err == nil {
						p := parsed.UTC()
						return &p
					}
				}
			}
		}
	}
	return nil
}
