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

func TestMonitorEmitsOneEventForRuleOnlyBatch(t *testing.T) {
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

	select {
	case event := <-events:
		if event.Error != nil {
			t.Fatal(event.Error)
		}
		if event.Type != nftables.MonitorEventTypeDelRule {
			t.Fatalf("event type = %v, want %v", event.Type, nftables.MonitorEventTypeDelRule)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no rule event received for chain flush")
	}

	select {
	case event := <-events:
		t.Fatalf("unexpected additional rule event: %+v", event)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestMonitorEmitsReplaceRuleEvent(t *testing.T) {
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

	monitor := nftables.NewMonitor(
		nftables.WithMonitorAction(nftables.MonitorActionNew),
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

	select {
	case event := <-events:
		if event.Error != nil {
			t.Fatal(event.Error)
		}
		if event.Type != nftables.MonitorEventTypeNewRule {
			t.Fatalf("event type = %v, want %v", event.Type, nftables.MonitorEventTypeNewRule)
		}
		if event.Data.(*nftables.Rule).Handle != rules[0].Handle {
			t.Fatalf("rule handle = %d, want %d", event.Data.(*nftables.Rule).Handle, rules[0].Handle)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no rule event received for rule replacement")
	}
}
