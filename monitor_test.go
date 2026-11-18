package nftables_test

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/internal/nftest"
)

func ExampleNewMonitor() {
	conn, err := nftables.New()
	if err != nil {
		log.Fatal(err)
	}

	mon := nftables.NewMonitor()
	defer mon.Close()
	events, err := conn.AddMonitor(mon)
	if err != nil {
		log.Fatal(err)
	}
	for ev := range events {
		log.Printf("ev: %+v, data = %T", ev, ev.Data)
		switch ev.Type {
		case nftables.MonitorEventTypeNewTable:
			log.Printf("data = %+v", ev.Data.(*nftables.Table))

			// …more cases if needed…
		}
	}
}

func TestMonitor(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	// default to monitor all
	monitor := nftables.NewMonitor()
	events, err := c.AddMonitor(monitor)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()

	var gotTable *nftables.Table
	var gotChain *nftables.Chain
	var gotRule *nftables.Rule
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		count := int32(0)
		for {
			event, ok := <-events
			if !ok {
				return
			}
			if event.Error != nil {
				err = fmt.Errorf("monitor err: %s", event.Error)
				return
			}
			switch event.Type {
			case nftables.MonitorEventTypeNewTable:
				gotTable = event.Data.(*nftables.Table)
				atomic.AddInt32(&count, 1)
			case nftables.MonitorEventTypeNewChain:
				gotChain = event.Data.(*nftables.Chain)
				atomic.AddInt32(&count, 1)
			case nftables.MonitorEventTypeNewRule:
				gotRule = event.Data.(*nftables.Rule)
				atomic.AddInt32(&count, 1)
			}
			if atomic.LoadInt32(&count) == 3 {
				return
			}
		}
	}()

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	postrouting := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	rule := c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: []expr.Any{
			// payload load 4b @ network header + 12 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			// cmp eq reg 1 0x0245a8c0
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP("192.168.69.2").To4(),
			},

			// masq
			&expr.Masq{},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if gotTable.Family != nat.Family || gotTable.Name != nat.Name {
		t.Fatal("no want table", gotTable.Family, gotTable.Name)
	}
	if gotChain.Type != postrouting.Type || gotChain.Name != postrouting.Name ||
		*gotChain.Hooknum != *postrouting.Hooknum {
		t.Fatal("no want chain", gotChain.Type, gotChain.Name, gotChain.Hooknum)
	}
	if len(gotRule.Exprs) != len(rule.Exprs) {
		t.Fatal("no want rule")
	}
}

// drainMonitorEvents collects events until none arrive for the given idle period.
func drainMonitorEvents(t *testing.T, events chan *nftables.MonitorEvent, idle time.Duration) []*nftables.MonitorEvent {
	t.Helper()
	var got []*nftables.MonitorEvent
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return got
			}
			if event.Error != nil {
				t.Fatal(event.Error)
			}
			got = append(got, event)
		case <-time.After(idle):
			return got
		}
	}
}

func TestMonitorCoalescesRuleEventsForChainFlush(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	chain := c.AddChain(&nftables.Chain{
		Name:  "input",
		Table: table,
	})
	for i := 0; i < 100; i++ {
		c.AddRule(&nftables.Rule{
			Table: chain.Table,
			Chain: chain,
			Exprs: []expr.Any{&expr.Counter{}},
		})
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	monitor := nftables.NewMonitor(
		nftables.WithMonitorAction(nftables.MonitorActionDel),
		nftables.WithMonitorObject(nftables.MonitorObjectRules),
	)
	events, err := c.AddMonitor(monitor)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()

	c.FlushChain(chain)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	// The kernel splits large changes across message groups (or sends one message per
	// group on older kernels), so the limiter reduces events rather than guaranteeing one.
	got := drainMonitorEvents(t, events, 500*time.Millisecond)
	if len(got) == 0 {
		t.Fatal("no rule event received for chain flush")
	}
	if len(got) >= 100 {
		t.Fatalf("rule events = %d, want fewer than one per deleted rule", len(got))
	}
	for _, event := range got {
		if event.Type != nftables.MonitorEventTypeDelRule {
			t.Fatalf("event type = %v, want %v", event.Type, nftables.MonitorEventTypeDelRule)
		}
	}
}

func TestMonitorCoalescesRuleEventsPerTable(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	var chains []*nftables.Chain
	for _, name := range []string{"filter", "other"} {
		table := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   name,
		})
		chain := c.AddChain(&nftables.Chain{
			Name:  "input",
			Table: table,
		})
		for i := 0; i < 5; i++ {
			c.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{&expr.Counter{}},
			})
		}
		chains = append(chains, chain)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	monitor := nftables.NewMonitor(
		nftables.WithMonitorAction(nftables.MonitorActionDel),
		nftables.WithMonitorObject(nftables.MonitorObjectRules),
	)
	events, err := c.AddMonitor(monitor)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()

	for _, chain := range chains {
		c.FlushChain(chain)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	tables := map[string]bool{}
	for _, event := range drainMonitorEvents(t, events, 500*time.Millisecond) {
		tables[event.Data.(*nftables.Rule).Table.Name] = true
	}
	for _, chain := range chains {
		if !tables[chain.Table.Name] {
			t.Fatalf("no rule event for table %q; a change in one table must not hide another", chain.Table.Name)
		}
	}
}

func TestMonitorEmitsReplaceRuleEvents(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	chain := c.AddChain(&nftables.Chain{
		Name:  "output",
		Table: table,
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}

	// Watch all actions, like ng-agent: a replace sends DELRULE then NEWRULE from the
	// same process and table, and both must come through.
	monitor := nftables.NewMonitor(
		nftables.WithMonitorObject(nftables.MonitorObjectRules),
	)
	events, err := c.AddMonitor(monitor)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()

	c.ReplaceRule(&nftables.Rule{
		Table:  table,
		Chain:  chain,
		Handle: rules[0].Handle,
		Exprs:  []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	var gotDel, gotNew bool
	for _, event := range drainMonitorEvents(t, events, 500*time.Millisecond) {
		switch event.Type {
		case nftables.MonitorEventTypeDelRule:
			gotDel = true
		case nftables.MonitorEventTypeNewRule:
			gotNew = true
			if len(event.Data.(*nftables.Rule).Exprs) == 0 {
				t.Fatal("replacement rule event has no expressions")
			}
		}
	}
	if !gotDel || !gotNew {
		t.Fatalf("replace events: DelRule=%v NewRule=%v, want both", gotDel, gotNew)
	}
}
