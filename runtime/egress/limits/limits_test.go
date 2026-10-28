package limits

import (
	"sync"
	"testing"
	"time"
)

func TestPoolReservesSlotsForEveryCaller(t *testing.T) {
	p := NewPool(2, 4, 4)
	var releases []func()
	take := func(caller string, want bool) {
		t.Helper()
		release, ok := p.Acquire(caller)
		if ok != want {
			t.Fatalf("Acquire(%s) = %v, want %v (open %d, shared %d)", caller, ok, want, p.Open(caller), p.SharedInUse())
		}
		if ok {
			releases = append(releases, release)
		}
	}
	// alpha takes its 2 reserved slots plus 2 shared, then hits its cap.
	for i := 0; i < 4; i++ {
		take("alpha", true)
	}
	take("alpha", false)
	// beta takes the rest of the shared pool.
	for i := 0; i < 4; i++ {
		take("beta", true)
	}
	if p.SharedInUse() != 4 {
		t.Fatalf("shared in use = %d", p.SharedInUse())
	}
	// The shared pool is empty, yet sealed-agent still has its reserved slots.
	take("sealed-agent", true)
	take("sealed-agent", true)
	take("sealed-agent", false)
	// Releasing a borrowed slot gives the pool back to whoever asks next.
	releases[0]()
	releases[0]() // idempotent
	if p.Open("alpha") != 3 || p.SharedInUse() != 3 {
		t.Fatalf("after release: alpha %d shared %d", p.Open("alpha"), p.SharedInUse())
	}
	take("sealed-agent", true)
	for _, r := range releases {
		r()
	}
	if p.SharedInUse() != 0 || p.Open("alpha") != 0 || p.Open("beta") != 0 || p.Open("sealed-agent") != 0 {
		t.Fatalf("leaked slots: shared %d", p.SharedInUse())
	}
}

func TestPoolConcurrent(t *testing.T) {
	p := NewPool(3, 10, 20)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		caller := []string{"a", "b", "c", "d"}[g%4]
		wg.Go(func() {
			for i := 0; i < 500; i++ {
				if release, ok := p.Acquire(caller); ok {
					if p.Open(caller) > 10 {
						t.Error("over the per-caller cap")
					}
					release()
				}
			}
		})
	}
	wg.Wait()
	if p.SharedInUse() != 0 {
		t.Fatalf("shared in use after all releases: %d", p.SharedInUse())
	}
}

func TestRateRefillsPerKey(t *testing.T) {
	now := time.Unix(1000, 0)
	r := NewRate(10, 3)
	r.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !r.Allow("alpha") {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if r.Allow("alpha") {
		t.Fatal("allowed past the burst")
	}
	if !r.Allow("sealed-agent") {
		t.Fatal("another key shares alpha's bucket")
	}
	now = now.Add(150 * time.Millisecond) // 1.5 tokens
	if !r.Allow("alpha") || r.Allow("alpha") {
		t.Fatal("refill is not proportional to elapsed time")
	}
	now = now.Add(time.Hour)
	n := 0
	for r.Allow("alpha") {
		n++
	}
	if n != 3 {
		t.Fatalf("refill exceeded the burst: %d", n)
	}
}

func TestInflight(t *testing.T) {
	f := NewInflight(2)
	d1, ok1 := f.Begin("alpha")
	_, ok2 := f.Begin("alpha")
	_, ok3 := f.Begin("alpha")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("Begin = %v %v %v", ok1, ok2, ok3)
	}
	if _, ok := f.Begin("beta"); !ok {
		t.Fatal("beta blocked by alpha")
	}
	d1()
	d1()
	if _, ok := f.Begin("alpha"); !ok {
		t.Fatal("slot not returned")
	}
	if _, ok := f.Begin("alpha"); ok {
		t.Fatal("double done returned two slots")
	}
}

func TestWithDefaults(t *testing.T) {
	c := Config{ConnsReserved: 600, ConnsPerCaller: 100}.WithDefaults()
	if c.ConnsReserved != 100 || c.ConnsShared != Defaults.ConnsShared || c.DNSRate != Defaults.DNSRate || c.ConnLifetime != Defaults.ConnLifetime {
		t.Fatalf("WithDefaults = %+v", c)
	}
	if (Config{}).WithDefaults() != Defaults {
		t.Fatal("zero config is not Defaults")
	}
}
