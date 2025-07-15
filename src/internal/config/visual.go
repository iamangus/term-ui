package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type VisualConfig struct {
	Terminal TerminalConfig `json:"terminal"`
	Theme    ThemeConfig    `json:"theme"`
	Font     FontConfig     `json:"font"`
}

type TerminalConfig struct {
	FontSize      int    `json:"font_size"`
	FontFamily    string `json:"font_family"`
	CursorBlink   bool   `json:"cursor_blink"`
	Scrollback    int    `json:"scrollback"`
	AllowProposed bool   `json:"allow_proposed_api"`
}

type ThemeConfig struct {
	Background         string `json:"background"`
	Foreground         string `json:"foreground"`
	Cursor             string `json:"cursor"`
	CursorAccent       string `json:"cursor_accent"`
	SelectionBackground string `json:"selection_background"`
}

type FontConfig struct {
	Family string `json:"family"`
	Size   int    `json:"size"`
}

func LoadVisualConfig() (*VisualConfig, error) {
	// Try to load from home directory first
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return DefaultVisualConfig(), nil
	}

	configPath := filepath.Join(homeDir, ".terminalrc")
	
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultVisualConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read visual config: %w", err)
	}

	var config VisualConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse visual config: %w", err)
	}

	return &config, nil
}

func DefaultVisualConfig() *VisualConfig {
	return &VisualConfig{
		Terminal: TerminalConfig{
			FontSize:      14,
			FontFamily:    "Monaco, Menlo, \"DejaVu Sans Mono\", \"Lucida Console\", monospace",
			CursorBlink:   true,
			Scrollback:    1000,
			AllowProposed: true,
		},
		Theme: ThemeConfig{
			Background:          "#000000",
			Foreground:          "#ffffff",
			Cursor:              "#ffffff",
			CursorAccent:        "#000000",
			SelectionBackground: "#3366aa",
		},
		Font: FontConfig{
			Family: "Monaco, Menlo, \"DejaVu Sans Mono\", \"Lucida Console\", monospace",
			Size:   14,
		},
	}
}

func SaveVisualConfig(config *VisualConfig) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".terminalrc")
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}