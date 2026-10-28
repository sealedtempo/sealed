// SPDX-License-Identifier: Apache-2.0

// Command sealed-logship exports the container logs of a Sealed debug guest to the customer project's Cloud
// Logging (spec 5.8). It is built only into the debug variant of the Sealed dstack OS image, which is registered
// with isDebug = true and never receives production secrets. The production image does not contain it.
//
// It follows every running container through the Docker API (so it works with any log driver that supports
// reading, including the "local" driver the composer selects for debug stacks), batches lines and writes them with
// entries:write. Credentials and the monitored resource come from the GCE metadata server, so the debug VM needs a
// service account with roles/logging.logWriter and the logging.write scope. It uses only the Go standard library,
// so the image build compiles it offline with the pinned toolchain.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type config struct {
	dockerSocket  string
	dockerURL     string // tests: a TCP base URL instead of the unix socket
	metadataURL   string
	loggingURL    string
	logName       string
	pollInterval  time.Duration
	flushInterval time.Duration
	maxBatch      int
	maxBatchBytes int
	maxBuffer     int
	maxLineBytes  int
	maxBackoff    time.Duration
}

func defaultConfig() config {
	return config{
		dockerSocket:  "/var/run/docker.sock",
		metadataURL:   "http://169.254.169.254/computeMetadata/v1",
		loggingURL:    "https://logging.googleapis.com/v2/entries:write",
		logName:       "sealed-debug-containers",
		pollInterval:  3 * time.Second,
		flushInterval: 2 * time.Second,
		maxBatch:      500,
		maxBatchBytes: 4 << 20,
		maxBuffer:     20000,
		maxLineBytes:  64 << 10,
		maxBackoff:    60 * time.Second,
	}
}

func main() {
	cfg := defaultConfig()
	flag.StringVar(&cfg.dockerSocket, "docker-socket", cfg.dockerSocket, "Docker API unix socket")
	flag.StringVar(&cfg.metadataURL, "metadata-url", cfg.metadataURL, "GCE metadata server base URL")
	flag.StringVar(&cfg.loggingURL, "logging-url", cfg.loggingURL, "Cloud Logging entries:write URL")
	flag.StringVar(&cfg.logName, "log-name", cfg.logName, "log name under projects/<project>/logs/")
	flag.DurationVar(&cfg.flushInterval, "flush-interval", cfg.flushInterval, "maximum time a line waits before it is sent")
	flag.IntVar(&cfg.maxBuffer, "max-buffer", cfg.maxBuffer, "lines kept while Cloud Logging is unreachable; older lines are dropped")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := run(ctx, cfg, os.Stderr); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "sealed-logship: %v\n", err)
		os.Exit(1)
	}
}

// run waits for the instance identity, then follows containers and ships their lines until ctx is cancelled.
func run(ctx context.Context, cfg config, logw io.Writer) error {
	lg := newLimitedLog(logw, time.Minute)
	md := &metadataClient{base: cfg.metadataURL, http: &http.Client{Timeout: 10 * time.Second}}
	var res resource
	backoff := time.Second
	for {
		var err error
		res, err = md.resource(ctx)
		if err == nil {
			break
		}
		lg.printf("metadata", "waiting for the GCE metadata server: %v", err)
		if !sleepCtx(ctx, backoff) {
			return ctx.Err()
		}
		backoff = minDuration(backoff*2, cfg.maxBackoff)
	}
	fmt.Fprintf(logw, "sealed-logship: exporting container logs to projects/%s/logs/%s\n", res.ProjectID, cfg.logName)

	s := newSink(cfg, res, md, &http.Client{Timeout: 30 * time.Second}, lg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loop(ctx)
	}()
	w := newWatcher(cfg, newDockerClient(cfg.dockerSocket, cfg.dockerURL), s, lg)
	w.loop(ctx)
	wg.Wait()
	return ctx.Err()
}

// limitedLog prints at most one message per key and interval, so a long outage does not flood the console.
type limitedLog struct {
	mu    sync.Mutex
	w     io.Writer
	every time.Duration
	last  map[string]time.Time
	now   func() time.Time
}

func newLimitedLog(w io.Writer, every time.Duration) *limitedLog {
	return &limitedLog{w: w, every: every, last: map[string]time.Time{}, now: time.Now}
}

func (l *limitedLog) printf(key, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.every {
		return
	}
	l.last[key] = now
	fmt.Fprintf(l.w, "sealed-logship: "+format+"\n", args...)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
