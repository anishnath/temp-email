package arduino

import "testing"

func TestValidateLibrariesForDocker(t *testing.T) {
	if err := validateLibrariesForDocker(nil); err != nil {
		t.Fatal(err)
	}
	if err := validateLibrariesForDocker([]string{"Servo", "Wire"}); err != nil {
		t.Fatal(err)
	}
	if err := validateLibrariesForDocker([]string{"Adafruit NeoPixel", "neopixel"}); err != nil {
		t.Fatal(err)
	}
	if err := validateLibrariesForDocker([]string{"UnknownLib"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDockerExtraInstallCanonical(t *testing.T) {
	c, ok := dockerExtraInstallCanonical("Servo")
	if ok || c != "" {
		t.Fatalf("bundled: ok=%v c=%q", ok, c)
	}
	c, ok = dockerExtraInstallCanonical("neopixel")
	if ok || c != "" {
		t.Fatalf("neopixel is baked in image: ok=%v c=%q", ok, c)
	}
	c, ok = dockerExtraInstallCanonical("Adafruit Unified Sensor")
	if ok || c != "" {
		t.Fatalf("bundled dependency: ok=%v c=%q", ok, c)
	}
}

func TestValidateDockerImageRef(t *testing.T) {
	if err := validateDockerImageRef("arduino-compile:local"); err != nil {
		t.Fatal(err)
	}
	if err := validateDockerImageRef("registry.io/foo/bar@sha256:abc123"); err != nil {
		t.Fatal(err)
	}
	if err := validateDockerImageRef("bad;rm"); err == nil {
		t.Fatal("expected error")
	}
}
