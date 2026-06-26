package simon

import "testing"

func TestSimon3264KnownVector(t *testing.T) {
	key := uint64(0x1918111109181111)
	pt := uint32(0x65656877)
	want := uint32(0xc69461a7)

	keys, err := KeySchedule3264(key, MaxRounds3264)
	if err != nil {
		t.Fatal(err)
	}
	got := Encrypt3264(pt, keys)
	if got != want {
		t.Fatalf("Encrypt3264: got 0x%08x, want 0x%08x", got, want)
	}
}

func TestSimon3264ReducedRounds(t *testing.T) {
	key := uint64(0x1918111109181111)
	pt := uint32(0x65656877)

	keys8, err := KeySchedule3264(key, 8)
	if err != nil {
		t.Fatal(err)
	}
	got8 := Encrypt3264(pt, keys8)

	keys32, err := KeySchedule3264(key, MaxRounds3264)
	if err != nil {
		t.Fatal(err)
	}
	got32 := Encrypt3264(pt, keys32)

	if got8 == got32 {
		t.Fatal("8 轮与 32 轮密文不应相同")
	}

	gotBlock, err := EncryptBlock3264(pt, key, 8)
	if err != nil {
		t.Fatal(err)
	}
	if gotBlock != got8 {
		t.Fatalf("EncryptBlock3264: got 0x%08x, want 0x%08x", gotBlock, got8)
	}
}

func TestValidateRounds(t *testing.T) {
	if err := ValidateRounds(0); err == nil {
		t.Fatal("expected error for 0 rounds")
	}
	if err := ValidateRounds(33); err == nil {
		t.Fatal("expected error for 33 rounds")
	}
}

func TestFeistelDecryptStep16(t *testing.T) {
	x, y := uint16(0x6565), uint16(0x6877)
	k := uint16(0x0000)

	lp, rp := FeistelStep16(x, y, k)
	l, r := FeistelDecryptStep16(lp, rp, k)
	if l != x || r != y {
		t.Fatalf("round-trip failed: got (0x%04x,0x%04x), want (0x%04x,0x%04x)", l, r, x, y)
	}
}
