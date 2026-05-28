// MFTracer end-to-end test using LaunderNetEvm41 ground-truth CSV data.
//
// Mirrors the two-phase algorithm in the paper:
//
//   Phase 1 – Graph Search  (paper §3.2–3.3)
//     Build a Subgraph (CSR adjacency list) from the CSV rows, then run BFS
//     (ClosureInSubgraphFromSrc) from each source address.  Nodes with more
//     than SearchOutDegreeLimit out-edges are treated as exchange hubs and
//     skipped, matching the pruning strategy described in the paper.
//
//   Phase 2 – Fund Flow Tracking  (paper §3.4)
//     Filter transfers to the edges inside the discovered main graph, sort by
//     block position, then propagate with the ThresholdAge rule:
//       • an intermediate node only forwards funds if its bucket ≥ Threshold
//         (eliminates dust / noise)
//       • funds stop propagating after AgeLimit hops
//     The amount at each node is tracked as totalIn − totalOut ("remaining").
//     Nodes with remaining > 0 are predicted terminal addresses.
//
//   Evaluation  (paper §5)
//     Precision, Recall, and F1 against the published terminal-address list.
package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"transfer-graph-evm/flow"
	"transfer-graph-evm/model"
	"transfer-graph-evm/search"
	"transfer-graph-evm/utils"
)

// ── row type ──────────────────────────────────────────────────────────────────

type csvRow struct {
	block     uint64
	unixTime  uint32 // unix seconds, fits in uint32 until 2106
	from, to  model.Address
	usdValue  float64
	timestamp string // RFC3339
}

// ── loaders ───────────────────────────────────────────────────────────────────

// loadFlowCSV reads flow records.csv
// Header: Timestamp,Block,Tx_hash,From,From_label,To,To_label,Value_in_USD
func loadFlowCSV(path string) ([]csvRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	all, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	out := make([]csvRow, 0, len(all))
	for i, r := range all {
		if i == 0 || len(r) < 8 {
			continue
		}
		block, err := strconv.ParseUint(strings.TrimSpace(r[1]), 10, 64)
		if err != nil {
			continue
		}
		usd, err := strconv.ParseFloat(strings.TrimSpace(r[7]), 64)
		if err != nil || usd <= 0 {
			continue
		}
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(r[0]), time.UTC)
		if err != nil {
			continue
		}
		out = append(out, csvRow{
			block:     block,
			unixTime:  uint32(ts.Unix()),
			from:      model.HexToAddress(strings.TrimSpace(r[3])),
			to:        model.HexToAddress(strings.TrimSpace(r[5])),
			usdValue:  usd,
			timestamp: ts.Format(time.RFC3339),
		})
	}
	return out, nil
}

// loadAddressFile reads one hex address per line (no header).
func loadAddressFile(path string) ([]model.Address, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var addrs []model.Address
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			addrs = append(addrs, model.HexToAddress(line))
		}
	}
	return addrs, sc.Err()
}

// ── Phase 1a: build Subgraph ──────────────────────────────────────────────────
//
// Paper §3.2 "Transfer Graph Construction"
//
// A Subgraph is a CSR (Compressed Sparse Row) adjacency list keyed on
// (token, block-range).  Each edge carries a [minTimestamp, maxTimestamp]
// window; BFS enforces temporal ordering via the supMinTimestamp constraint.
// We build one subgraph covering the entire CSV (no block sharding needed
// for this small-scale test).

func buildSubgraph(rows []csvRow) *model.Subgraph {
	addrMap := make(map[string]uint32)
	nextID := func(a model.Address) uint32 {
		k := string(a.Bytes())
		if v, ok := addrMap[k]; ok {
			return v
		}
		v := uint32(len(addrMap))
		addrMap[k] = v
		return v
	}

	// Merge parallel edges into a single [minTS, maxTS] window.
	type key struct{ src, des uint32 }
	merged := make(map[key][2]uint32)
	for _, r := range rows {
		k := key{nextID(r.from), nextID(r.to)}
		if v, ok := merged[k]; !ok {
			merged[k] = [2]uint32{r.unixTime, r.unixTime}
		} else {
			if r.unixTime < v[0] {
				v[0] = r.unixTime
			}
			if r.unixTime > v[1] {
				v[1] = r.unixTime
			}
			merged[k] = v
		}
	}

	// Build CSR: neighbours must be sorted by destination ID.
	n := uint32(len(addrMap))
	type nb struct {
		des uint32
		ts  [2]uint32
	}
	adj := make([][]nb, n)
	for k, ts := range merged {
		adj[k.src] = append(adj[k.src], nb{k.des, ts})
	}
	for i := range adj {
		sort.Slice(adj[i], func(a, b int) bool { return adj[i][a].des < adj[i][b].des })
	}

	nodePtrs := make([]uint32, n+1)
	for i := uint32(0); i < n; i++ {
		nodePtrs[i+1] = nodePtrs[i] + uint32(len(adj[i]))
	}
	total := nodePtrs[n]
	columns := make([]uint32, total)
	timestamps := make([][2]uint32, total)
	for i := uint32(0); i < n; i++ {
		base := nodePtrs[i]
		for j, e := range adj[i] {
			columns[base+uint32(j)] = e.des
			timestamps[base+uint32(j)] = e.ts
		}
	}
	return &model.Subgraph{
		BlockID:    0,
		Token:      utils.USDTAddress,
		Timestamps: timestamps,
		Columns:    columns,
		NodePtrs:   nodePtrs,
		AddressMap: addrMap,
	}
}

// ── Phase 1b: BFS closure ─────────────────────────────────────────────────────
//
// Paper §3.3 "Main Graph Search"
//
// search.ClosureInSubgraphFromSrc does iterative BFS on the Subgraph.
// getNextHop (inside the search package) enforces:
//   • out-degree pruning  — skip nodes with degree > model.SearchOutDegreeLimit
//   • temporal ordering   — only traverse edge (u→v) if edge.maxTS >= u.supMinTS
//   • depth limit         — stop at model.SearchDepth hops
//
// We union the closures of all source addresses to form the reachable set.

func graphSearch(sg *model.Subgraph, srcs []model.Address) map[string]struct{} {
	// These globals shadow config.toml values.  Override for a small dataset.
	model.SearchOutDegreeLimit = 1000
	model.SearchDepth = 20

	rMap := model.ReverseAddressMap(sg.AddressMap)
	reachable := make(map[string]struct{})

	for _, src := range srcs {
		// model.Address is defined as `type Address common.Address`, so the
		// explicit conversion below is always valid.
		commonAddr := gcommon.Address(src)
		_, closure := search.ClosureInSubgraphFromSrc(sg, commonAddr)
		for nodeID := range closure {
			reachable[rMap[nodeID]] = struct{}{}
		}
		// Include the source node itself.
		reachable[string(src.Bytes())] = struct{}{}
	}
	return reachable
}

// ── Phase 2 helpers ───────────────────────────────────────────────────────────

// filterTransfers returns only transfers whose both endpoints are in the main graph.
// Transfer.Value is stored as integer micro-dollars (USD × 10^6) so that
// NewPriceCacheHooked (USDT price=1e6, decimals=6) converts it back to USD.
func filterTransfers(rows []csvRow, reachable map[string]struct{}) []*model.Transfer {
	out := make([]*model.Transfer, 0, len(rows))
	for _, r := range rows {
		if _, ok := reachable[string(r.from.Bytes())]; !ok {
			continue
		}
		if _, ok := reachable[string(r.to.Bytes())]; !ok {
			continue
		}
		valueMicro := new(big.Int).SetInt64(int64(r.usdValue * 1e6))
		out = append(out, &model.Transfer{
			Pos:       r.block << 16,
			Type:      uint16(model.TransferTypeEvent),
			From:      r.from,
			To:        r.to,
			Token:     utils.USDTAddress,
			Value:     (*hexutil.Big)(valueMicro),
			Timestamp: r.timestamp,
		})
	}
	return out
}

// ── Phase 2a: ThresholdAge flow (paper §3.4) ─────────────────────────────────
//
// activate_threshold=$100, age_limit=10 hops.  ε=0 (no reserve rate).

func flowComputation(rows []csvRow, reachable map[string]struct{}, srcs []model.Address) *flow.FlowGraph {
	filtered := filterTransfers(rows, reachable)
	srcStrs := make([]string, len(srcs))
	for i, a := range srcs {
		srcStrs[i] = string(a.Bytes())
	}
	fe := flow.NewTransfersSortedByTime(filtered, false, nil, 0, nil)
	fg := flow.NewFlowGraph(
		&flow.ThresholdAgeFlowNode{
			Config: &flow.ThresholdAgeFlowNodeConfig{
				Threshold: 100,
				AgeLimit:  10,
			},
		},
		fe, srcStrs, nil,
	)
	fg.FlowToEnd()
	return fg
}

// ── Phase 2b: RPFlow with reserve rate ε (paper §3.4) ────────────────────────
//
// RPFlowNode.Config = ε.  out() limits forwarding to bucket*(1-ε), so:
//   ε=0.0 → forward everything (no reserve)
//   ε=0.2 → keep 20% permanently, forward up to 80% of current bucket
//
// Unlike ThresholdAgeFlowNode, RPFlowNode has no threshold or age gate,
// which isolates the pure effect of the reserve-rate parameter.

func flowComputationRP(rows []csvRow, reachable map[string]struct{}, srcs []model.Address, epsilon float64) *flow.FlowGraph {
	filtered := filterTransfers(rows, reachable)
	srcStrs := make([]string, len(srcs))
	for i, a := range srcs {
		srcStrs[i] = string(a.Bytes())
	}
	fe := flow.NewTransfersSortedByTime(filtered, false, nil, 0, nil)
	fg := flow.NewFlowGraph(
		&flow.RPFlowNode{Config: flow.RPFlowConfig(epsilon)},
		fe, srcStrs, nil,
	)
	fg.FlowToEnd()
	return fg
}

// ── Evaluation ────────────────────────────────────────────────────────────────
//
// Paper §5: nodes with remaining balance (totalIn > totalOut) are predicted
// as terminal addresses (money stopped there).

type evalResult struct {
	predicted int
	tp        int
	prec      float64
	rec       float64
	f1        float64
}

func evalMetrics(fg *flow.FlowGraph, gt map[string]struct{}) evalResult {
	type pred struct {
		addrBytes string
		rem       float64
	}
	preds := make([]pred, 0, len(fg.Nodes))
	for a, n := range fg.Nodes {
		if rem := n.TotalI() - n.TotalO(); rem > 0 {
			preds = append(preds, pred{a, rem})
		}
	}
	tp := 0
	for _, p := range preds {
		if _, ok := gt[p.addrBytes]; ok {
			tp++
		}
	}
	prec, rec, f1 := 0.0, 0.0, 0.0
	if len(preds) > 0 {
		prec = float64(tp) / float64(len(preds))
	}
	if len(gt) > 0 {
		rec = float64(tp) / float64(len(gt))
	}
	if prec+rec > 0 {
		f1 = 2 * prec * rec / (prec + rec)
	}
	return evalResult{len(preds), tp, prec, rec, f1}
}

func evaluate(fg *flow.FlowGraph, gtAddrs []model.Address) {
	gt := make(map[string]struct{}, len(gtAddrs))
	for _, a := range gtAddrs {
		gt[string(a.Bytes())] = struct{}{}
	}
	r := evalMetrics(fg, gt)

	fmt.Println("\n=== Evaluation (vs. LaunderNetEvm41 ground truth) ===")
	fmt.Printf("Ground-truth terminal addresses : %d\n", len(gt))
	fmt.Printf("Predicted terminal addresses    : %d\n", r.predicted)
	fmt.Printf("True positives                  : %d\n", r.tp)
	fmt.Printf("Precision : %.3f\n", r.prec)
	fmt.Printf("Recall    : %.3f\n", r.rec)
	fmt.Printf("F1        : %.3f\n", r.f1)

	type pred struct {
		addrBytes string
		rem       float64
	}
	preds := make([]pred, 0, len(fg.Nodes))
	for a, n := range fg.Nodes {
		if rem := n.TotalI() - n.TotalO(); rem > 0 {
			preds = append(preds, pred{a, rem})
		}
	}
	sort.Slice(preds, func(i, j int) bool { return preds[i].rem > preds[j].rem })
	fmt.Println("\nTop-10 predicted terminal nodes:")
	for i, p := range preds {
		if i >= 10 {
			break
		}
		addr := model.BytesToAddress([]byte(p.addrBytes))
		mark := ""
		if _, ok := gt[p.addrBytes]; ok {
			mark = "  <- ground truth"
		}
		fmt.Printf("  [%2d] %s  remaining=$%.2f%s\n", i+1, addr.Hex(), p.rem, mark)
	}
}

// ── entry point ───────────────────────────────────────────────────────────────

func main() {
	// Cluster 1 = Atomic Wallet hack (Jun 2023, ~$10M, 389 addresses, 1080 flows).
	// Change to "../LaunderNetEvm41/cluster 2" … "cluster 5" or "../LaunderNetEvm41"
	// (full dataset) to test other cases.
	base := "../LaunderNetEvm41/cluster 1"

	fmt.Println("=== MFTracer paper-algorithm test ===")
	fmt.Printf("Dataset : %s\n\n", base)

	rows, err := loadFlowCSV(base + "/flow records.csv")
	if err != nil {
		panic(err)
	}
	srcAddrs, err := loadAddressFile(base + "/source addresses.csv")
	if err != nil {
		panic(err)
	}
	termAddrs, err := loadAddressFile(base + "/terminal addresses.csv")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Transfers : %d\n", len(rows))
	fmt.Printf("Sources   : %d\n", len(srcAddrs))
	fmt.Printf("Terminals : %d  (ground truth)\n", len(termAddrs))

	// ── Phase 1a: build transfer graph (§3.2) ─────────────────────────────────
	fmt.Println("\n--- Phase 1a: building transfer subgraph (CSR) ---")
	sg := buildSubgraph(rows)
	numEdges := int(sg.NodePtrs[len(sg.NodePtrs)-1])
	fmt.Printf("Nodes: %d   Unique edges: %d\n", len(sg.AddressMap), numEdges)

	// ── Phase 1b: BFS forward closure (§3.3) ──────────────────────────────────
	fmt.Println("\n--- Phase 1b: graph search – BFS from source addresses ---")
	fmt.Printf("SearchOutDegreeLimit = %d   SearchDepth = %d\n",
		model.SearchOutDegreeLimit, model.SearchDepth)
	reachable := graphSearch(sg, srcAddrs)
	fmt.Printf("Reachable addresses : %d\n", len(reachable))

	// ── Phase 2: ThresholdAge flow (§3.4) ─────────────────────────────────────
	fmt.Println("\n--- Phase 2: fund flow tracking – ThresholdAge ---")
	fg := flowComputation(rows, reachable, srcAddrs)
	fmt.Printf("Flow-graph nodes : %d\n", len(fg.Nodes))
	fmt.Printf("Transfer events  : %d\n", len(fg.LeachDigests))
	fmt.Printf("Total volume     : $%.2f\n", fg.TotalVolume())

	// ── Evaluation (§5) ───────────────────────────────────────────────────────
	evaluate(fg, termAddrs)

	// ── ε sensitivity sweep (paper §3.4 reserve rate) ─────────────────────────
	//
	// RPFlowNode.Config = ε: each node keeps ε fraction of its bucket permanently
	// and forwards at most (1-ε) of its current balance.
	//   ε=0.0 → forward everything (no reserve)  ← baseline
	//   ε→1.0 → money never flows past the first hop (all stays at sources)
	//
	// This sweep isolates the reserve-rate effect from the threshold/age gates.
	fmt.Println("\n=== ε sensitivity – RPFlowNode reserve rate (paper §3.4) ===")
	fmt.Printf("%-8s  %-10s  %-6s  %-9s  %-8s  %-6s\n",
		"epsilon", "Predicted", "TP", "Precision", "Recall", "F1")
	fmt.Println(strings.Repeat("-", 55))

	gt := make(map[string]struct{}, len(termAddrs))
	for _, a := range termAddrs {
		gt[string(a.Bytes())] = struct{}{}
	}

	for _, eps := range []float64{0.0, 0.05, 0.1, 0.2, 0.3, 0.5} {
		fgRP := flowComputationRP(rows, reachable, srcAddrs, eps)
		r := evalMetrics(fgRP, gt)
		fmt.Printf("ε=%-5.2f  %-10d  %-6d  %-9.3f  %-8.3f  %.3f\n",
			eps, r.predicted, r.tp, r.prec, r.rec, r.f1)
	}
}
