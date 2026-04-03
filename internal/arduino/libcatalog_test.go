package arduino

import "testing"

func TestLibraryAllowedForDockerCompile(t *testing.T) {
	if !LibraryAllowedForDockerCompile("Servo") {
		t.Fatal("Servo should be allowed")
	}
	if !LibraryAllowedForDockerCompile("Adafruit NeoPixel") {
		t.Fatal("Adafruit NeoPixel should be allowed")
	}
	if LibraryAllowedForDockerCompile("TotallyFakeLibrary123") {
		t.Fatal("unknown lib should not be allowed")
	}
	if !LibraryAllowedForDockerCompile("Wire") {
		t.Fatal("Wire from core map should be allowed")
	}
}

func TestBundledDockerLibraryNamesCount(t *testing.T) {
	if len(BundledDockerLibraryNames) < 10 {
		t.Fatalf("expected many bundled names, got %d", len(BundledDockerLibraryNames))
	}
}
