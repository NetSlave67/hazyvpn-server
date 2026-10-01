package wgconf

import (
	"fmt"
	"strings"
)

// dangerousHookKeys are [Interface] directives that run arbitrary shell
// commands as root on every interface up/down. Imported configs carrying
// these are refused outright — same rule the client-side TUI enforces on
// import, for the same reason.
var dangerousHookKeys = []string{"PreUp", "PostUp", "PreDown", "PostDown"}

// ParsedConfig is a generic, section-based view of a WireGuard .conf file:
// one [Interface] section and zero or more [Peer] sections, each a map of
// directive name to raw value.
type ParsedConfig struct {
	Interface map[string]string
	Peers     []map[string]string
}

// Parse parses the textual contents of a WireGuard .conf file into sections.
// It does not validate semantic correctness (valid keys, CIDRs, etc.) —
// callers combine it with ipam.Validate and wgconf key parsing for that.
func Parse(text string) (*ParsedConfig, error) {
	cfg := &ParsedConfig{Interface: map[string]string{}}
	var current map[string]string

	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(strings.Trim(line, "[]")) {
			case "interface":
				current = cfg.Interface
			case "peer":
				current = map[string]string{}
				cfg.Peers = append(cfg.Peers, current)
			default:
				return nil, fmt.Errorf("wgconf: line %d: unknown section %q", lineNo+1, line)
			}
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("wgconf: line %d: directive before any [Section]", lineNo+1)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("wgconf: line %d: expected 'Key = value', got %q", lineNo+1, line)
		}
		current[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	if len(cfg.Interface) == 0 {
		return nil, fmt.Errorf("wgconf: no [Interface] section found")
	}
	return cfg, nil
}

// DangerousHooks returns the names of any PreUp/PostUp/PreDown/PostDown
// directives present in the config's [Interface] section.
func (c *ParsedConfig) DangerousHooks() []string {
	var found []string
	for _, key := range dangerousHookKeys {
		if _, ok := c.Interface[key]; ok {
			found = append(found, key)
		}
	}
	return found
}
