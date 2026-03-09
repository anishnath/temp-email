package compiler

import (
	"reflect"
	"testing"
)

func TestParseLog_UndefinedControlSequence(t *testing.T) {
	log := []string{
		"l.42 \\unknown",
		"! Undefined control sequence.",
	}
	pl := ParseLog(log)
	if len(pl.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(pl.Errors))
	}
	if pl.Errors[0].Message != "Unknown LaTeX command: \\unknown on line 42" {
		t.Errorf("got %q", pl.Errors[0].Message)
	}
}

func TestParseLog_MissingDollar(t *testing.T) {
	log := []string{
		"l.10",
		"! Missing $ inserted.",
	}
	pl := ParseLog(log)
	if len(pl.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(pl.Errors))
	}
	if pl.Errors[0].Message != "Math mode error near line 10" {
		t.Errorf("got %q", pl.Errors[0].Message)
	}
}

func TestParseLog_FileNotFound(t *testing.T) {
	log := []string{
		"l.5",
		"! LaTeX Error: File `figure.png' not found.",
	}
	pl := ParseLog(log)
	if len(pl.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(pl.Errors))
	}
	exp := "Image or file not found: figure.png"
	if pl.Errors[0].Message != exp {
		t.Errorf("got %q, want %q", pl.Errors[0].Message, exp)
	}
}

func TestParseLog_RunawayArgument(t *testing.T) {
	log := []string{
		"l.15",
		"! Runaway argument?",
	}
	pl := ParseLog(log)
	if len(pl.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(pl.Errors))
	}
	if pl.Errors[0].Message != "Missing closing brace near line 15" {
		t.Errorf("got %q", pl.Errors[0].Message)
	}
}

func TestParseLog_EmergencyStop(t *testing.T) {
	log := []string{
		"l.3",
		"! Emergency stop.",
	}
	pl := ParseLog(log)
	if len(pl.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(pl.Errors))
	}
	if pl.Errors[0].Message != "Fatal error — check syntax near line 3" {
		t.Errorf("got %q", pl.Errors[0].Message)
	}
}

func TestParseLog_OverfullHbox(t *testing.T) {
	log := []string{
		"l.20",
		"Overfull \\hbox (10pt too wide)",
	}
	pl := ParseLog(log)
	if len(pl.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(pl.Warnings))
	}
	if pl.Warnings[0].Text != "Overfull \\hbox" {
		t.Errorf("got %q", pl.Warnings[0].Text)
	}
}

func TestParseLog_NoErrors(t *testing.T) {
	log := []string{
		"This is pdfTeX, Version 3.14159265-2.6-1.40.21",
		"Output written on document.pdf (1 page, 12345 bytes).",
	}
	pl := ParseLog(log)
	if len(pl.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(pl.Errors))
	}
	if !reflect.DeepEqual(pl.RawLines, log) {
		t.Error("RawLines should match input")
	}
}
