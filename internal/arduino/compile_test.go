package arduino

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFQBNPicoAccepted(t *testing.T) {
	for _, fqbn := range []string{
		"arduino:avr:uno",
		"rp2040:rp2040:rpipico",
		"rp2040:rp2040:rpipicow",
		"esp32:esp32:esp32",
		"esp32:esp32:esp32c3",
	} {
		if !fqbnPattern.MatchString(fqbn) {
			t.Fatalf("FQBN should be accepted: %q", fqbn)
		}
	}
}

func TestParseSketchSizes(t *testing.T) {
	raw := `
Sketch uses 924 bytes (2%) of program storage space. Maximum is 32256 bytes.
Global variables use 9 bytes (0%) of dynamic memory, leaving 2039 bytes for local variables. Maximum is 2048 bytes.
`
	p, m := parseSketchSizes(raw)
	if p != 924 || m != 32256 {
		t.Fatalf("got program=%d max=%d", p, m)
	}
	p2, _ := parseSketchSizes("Sketch uses 100 bytes of program storage space.")
	if p2 != 100 {
		t.Fatalf("alt: got %d", p2)
	}
}

func TestParseErrors(t *testing.T) {
	raw := `/tmp/x/sketch/sketch.ino: In function 'void loop()':
/tmp/x/sketch/sketch.ino:3:12: error: 'digitalWrit' was not declared in this scope
    3 |   digitalWrit(13, HIGH);
      |   ^~~~~~~~~~~
      |   digitalWrite
`
	errs := parseErrors(raw)
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %d: %#v", len(errs), errs)
	}
	if errs[0].Line != 3 || errs[0].Column != 12 {
		t.Fatalf("line/col: %+v", errs[0])
	}
	if !strings.Contains(errs[0].Message, "digitalWrit") {
		t.Fatalf("message: %q", errs[0].Message)
	}
}

func TestCompileFailureResponseFromOutputElapsed(t *testing.T) {
	start := time.Now().Add(-2 * time.Second)
	r := compileFailureResponseFromOutput(start, "error")
	if r.CompileTimeMs < 1000 {
		t.Fatalf("expected ms ~2000, got %d", r.CompileTimeMs)
	}
}

func TestCollectSketchFiles(t *testing.T) {
	const max = 10000
	_, err := collectSketchFiles(&Request{}, max)
	if err == nil {
		t.Fatal("expect error for empty request")
	}
	_, err = collectSketchFiles(&Request{Sketch: "void setup(){}\nvoid loop(){}\n"}, max)
	if err != nil {
		t.Fatal(err)
	}
	_, err = collectSketchFiles(&Request{
		Sketch: "void setup(){}\nvoid loop(){}\n",
		Files:  []SketchFile{{Name: "config.h", Content: "#define X 1\n"}},
	}, max)
	if err != nil {
		t.Fatal(err)
	}
	_, err = collectSketchFiles(&Request{
		Files: []SketchFile{
			{Name: "sketch.ino", Content: "void setup(){}\nvoid loop(){}\n"},
			{Name: "Tab.ino", Content: "// tab\n"},
		},
	}, max)
	if err != nil {
		t.Fatal(err)
	}
	_, err = collectSketchFiles(&Request{
		Sketch: "x",
		Files:  []SketchFile{{Name: "sketch.ino", Content: "y"}},
	}, max)
	if err == nil {
		t.Fatal("expect duplicate sketch.ino error")
	}
	_, err = collectSketchFiles(&Request{
		Files: []SketchFile{{Name: "../evil.h", Content: "x"}},
	}, max)
	if err == nil {
		t.Fatal("expect path rejection")
	}
}

func TestFindBuildArtifact(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "build")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "sketch.ino.hex"), []byte(":10000000"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, kind, err := findBuildArtifact(dir)
	if err != nil || kind != "hex" || !strings.HasSuffix(p, "sketch.ino.hex") {
		t.Fatalf("hex: path=%q kind=%q err=%v", p, kind, err)
	}

	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "sketch.ino.uf2"), []byte("UF2"), 0o644); err != nil {
		t.Fatal(err)
	}
	p2, kind2, err2 := findBuildArtifact(dir2)
	if err2 != nil || kind2 != "uf2" || !strings.HasSuffix(p2, "sketch.ino.uf2") {
		t.Fatalf("uf2: path=%q kind=%q err=%v", p2, kind2, err2)
	}

	dirBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirBin, "sketch.ino.bin"), []byte{0x00, 0xe9}, 0o644); err != nil {
		t.Fatal(err)
	}
	pb, kindb, errb := findBuildArtifact(dirBin)
	if errb != nil || kindb != "bin" || !strings.HasSuffix(pb, "sketch.ino.bin") {
		t.Fatalf("bin: path=%q kind=%q err=%v", pb, kindb, errb)
	}

	dir3 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir3, "bootloader.hex"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err3 := findBuildArtifact(dir3)
	if err3 == nil {
		t.Fatal("expected error when only bootloader artifact exists")
	}
}

func TestFindSketchMergedBin(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "sketch.ino.merged.bin"), []byte{1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	p := findSketchMergedBin(dir)
	if p == "" || !strings.HasSuffix(filepath.ToSlash(p), "sketch.ino.merged.bin") {
		t.Fatalf("got %q", p)
	}
}

func TestIsESP32Board(t *testing.T) {
	if !isESP32Board("esp32:esp32:esp32c3") {
		t.Fatal("esp32 FQBN")
	}
	if isESP32Board("rp2040:rp2040:rpipico") {
		t.Fatal("not esp32")
	}
}
