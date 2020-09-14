package main

import (
	"context"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/papertrail/go-tail/follower"
	"github.com/pkg/errors"
)

var logFile = "/var/log/asterisk/notice"

// Offender describes an IP address from which a failed registration or call has been made
type Offender struct {

	// IP indicates the IP address of the offender
	IP string

	// Count indicates the tally of offenses
	Count int

	// Last is the timestamp of the last-seen offense
	Last time.Time
}

var mu sync.RWMutex

// Offenders is the list of current offenders
var Offenders map[string]*Offender

var processInterval = time.Minute

var blockThreshold = 5

var offenderExpiry = time.Hour

const rsBanTable = "rsban"

func main() {
	Offenders = make(map[string]*Offender)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Process log entries as they arrive
	go processLog(ctx)

	// Periodically analyze the Offenders
	t := time.NewTicker(processInterval)

	for {
		select {
		case <-ctx.Done():
			break
		case <-t.C:
			processOffenders()
		}
	}

}

func processLog(ctx context.Context) {
	t, err := follower.New(logFile, follower.Config{
		Whence: io.SeekEnd,
		Offset: 0,
		Reopen: true,
	})
	if err != nil {
		log.Fatalf("failed to open file %s: %v", logFile, err)
	}

	go func() {
		<-ctx.Done()
		t.Close()
	}()

	for line := range t.Lines() {
		addOffender(ipFromLine(line.String()))
	}
}

func ipFromLine(line string) string {
	if !strings.Contains(line, "failed for") {
		return ""
	}

	pieces := strings.Split(line, "'")
	if len(pieces) < 5 {
		return ""
	}
	return pieces[4]
}

func addOffender(ip string) {
	if ip == "" {
		return
	}

	o, ok := Offenders[ip]
	if !ok {
		o = &Offender{
			IP: ip,
		}
		Offenders[ip] = o
	}
	o.Count++
	o.Last = time.Now()
}

func processOffenders() error {
	mu.RLock()
	defer mu.RUnlock()

	var blocked []string

	for ip, o := range Offenders {
		// Expire old offenders first
		if time.Since(o.Last) > offenderExpiry {
			mu.Lock()
			delete(Offenders, ip)
			mu.Unlock()
		}

		// If the offender is over the threshold, add it to the blocked list
		if o.Count > blockThreshold {
			blocked = append(blocked, ip)
		}
	}

	return updateBlocklist(blocked)
}

func updateBlocklist(list []string) error {
	// Flush the current table first
	ipt, err := iptables.New()
	if err != nil {
		return errors.Wrap(err, "failed to access iptables")
	}

	err = ipt.ClearChain("filter", rsBanTable)
	if err != nil {
		return errors.Wrapf(err, "failed to clear %s chain", rsBanTable)
	}

	sort.Strings(list)
	for _, ip := range list {
		if err = ipt.AppendUnique("filter", rsBanTable, "-s", ip, "-j", "DROP"); err != nil {
			return errors.Wrapf(err, "failed to add ip %s to chain %s", ip, rsBanTable)
		}
	}

	return nil
}
