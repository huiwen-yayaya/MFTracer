// single.go – single-source fund-flow topology printer for MFTracer.
//
// Usage:
//
//	go run single/single.go <hex-address>     trace one source address
//	go run single/single.go                   list all valid source addresses
//
// The address must appear in the source addresses.csv file.
// Dataset path is relative to the codes/ directory (../../LaunderNetEvm41/cluster 1).
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

const datasetBase = "../LaunderNetEvm41/cluster 1"

// ── data types ────────────────────────────────────────────────────────────────

type csvRow struct {
	block     uint64
	unixTime  uint32
	from, to  model.Address
	usdValue  float64
	timestamp string
	fromLabel string
	toLabel   string
}

// ── loaders ───────────────────────────────────────────────────────────────────

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
			fromLabel: strings.TrimSpace(r[4]),
			toLabel:   strings.TrimSpace(r[6]),
		})
	}
	return out, nil
}

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

// ── label helpers ─────────────────────────────────────────────────────────────

func buildAddrLabels(rows []csvRow) map[string]string {
	m := make(map[string]string)
	for _, r := range rows {
		if r.fromLabel != "" {
			m[string(r.from.Bytes())] = r.fromLabel
		}
		if r.toLabel != "" {
			m[string(r.to.Bytes())] = r.toLabel
		}
	}
	return m
}

// isHackInfra identifies hacker-controlled relay nodes (laundering hops, not
// terminal storage). These are filtered from predicted-terminal counts.
func isHackInfra(label string) bool {
	return strings.Contains(label, "Hack") ||
		strings.Contains(label, "Phishing") ||
		strings.Contains(label, "Fake")
}

// ── Phase 1: build CSR subgraph ───────────────────────────────────────────────

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

// ── Phase 2: ThresholdAge flow ────────────────────────────────────────────────

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

// ── topology printer ──────────────────────────────────────────────────────────

func traceSource(rows []csvRow, srcAddr model.Address, termAddrs []model.Address, addrLabels map[string]string) {
	termSet := make(map[string]struct{}, len(termAddrs))
	for _, a := range termAddrs {
		termSet[string(a.Bytes())] = struct{}{}
	}
	srcStr := string(srcAddr.Bytes())

	// Phase 1: build subgraph + BFS from this source
	fmt.Println("--- Phase 1: building subgraph and running BFS ---")
	sg := buildSubgraph(rows)
	model.SearchOutDegreeLimit = 1000
	model.SearchDepth = 20
	rMap := model.ReverseAddressMap(sg.AddressMap)
	reachable := make(map[string]struct{})
	_, closure := search.ClosureInSubgraphFromSrc(sg, gcommon.Address(srcAddr))
	for nodeID := range closure {
		reachable[rMap[nodeID]] = struct{}{}
	}
	reachable[srcStr] = struct{}{}
	fmt.Printf("Reachable nodes (incl. source): %d\n", len(reachable))

	// Phase 2: ThresholdAge fund flow (activate_threshold=$100, age_limit=10)
	fmt.Println("--- Phase 2: ThresholdAge fund flow (threshold=$100, age≤10) ---")
	filtered := filterTransfers(rows, reachable)
	fe := flow.NewTransfersSortedByTime(filtered, false, nil, 0, nil)
	fg := flow.NewFlowGraph(
		&flow.ThresholdAgeFlowNode{
			Config: &flow.ThresholdAgeFlowNodeConfig{Threshold: 100, AgeLimit: 10},
		},
		fe, []string{srcStr}, nil,
	)
	fg.FlowToEnd()
	fmt.Printf("Flow-graph nodes: %d   transfer events: %d\n", len(fg.Nodes), len(fg.LeachDigests))

	// Build adjacency from flow digests (from → sorted children by total flow)
	type edge struct {
		to    string
		total float64
	}
	rawEdges := make(map[string]map[string]float64)
	for _, d := range fg.LeachDigests {
		if d.UsedValue <= 0 {
			continue
		}
		if rawEdges[d.From] == nil {
			rawEdges[d.From] = make(map[string]float64)
		}
		rawEdges[d.From][d.To] += d.UsedValue
	}
	children := make(map[string][]edge)
	for from, tos := range rawEdges {
		for to, val := range tos {
			children[from] = append(children[from], edge{to, val})
		}
		sort.Slice(children[from], func(i, j int) bool {
			return children[from][i].total > children[from][j].total
		})
	}

	// DFS tree printer — cycle-safe via visited map
	visited := make(map[string]bool)
	var printNode func(addr, prefix string, isLast bool, inFlow float64)
	printNode = func(addr, prefix string, isLast bool, inFlow float64) {
		addrHex := model.BytesToAddress([]byte(addr)).Hex()
		label := addrLabels[addr]
		_, isTerm := termSet[addr]

		branch := "├─→ "
		nextPrefix := prefix + "│   "
		if isLast {
			branch = "└─→ "
			nextPrefix = prefix + "    "
		}

		var nodeInfo string
		if n, ok := fg.Nodes[addr]; ok {
			rem := n.TotalI() - n.TotalO()
			nodeInfo = fmt.Sprintf("$%.0f→rem:$%.0f", inFlow, rem)
		} else {
			nodeInfo = fmt.Sprintf("$%.0f", inFlow)
		}
		labelStr := ""
		if label != "" {
			labelStr = " [" + label + "]"
		}
		termStr := ""
		if isTerm {
			termStr = " ★TERMINAL"
		}

		if visited[addr] {
			fmt.Printf("%s%s%s  %s%s%s  (→ converges, see above)\n",
				prefix, branch, addrHex, nodeInfo, labelStr, termStr)
			return
		}
		visited[addr] = true
		fmt.Printf("%s%s%s  %s%s%s\n",
			prefix, branch, addrHex, nodeInfo, labelStr, termStr)
		for i, kid := range children[addr] {
			printNode(kid.to, nextPrefix, i == len(children[addr])-1, kid.total)
		}
	}

	// Print root
	srcHex := model.BytesToAddress([]byte(srcStr)).Hex()
	srcLabel := addrLabels[srcStr]
	var srcOut float64
	if n, ok := fg.Nodes[srcStr]; ok {
		srcOut = n.TotalO()
	}
	labelStr := ""
	if srcLabel != "" {
		labelStr = " [" + srcLabel + "]"
	}
	fmt.Printf("\n=== Flow topology: %s%s ===\n", srcHex, labelStr)
	fmt.Printf("[SOURCE]  total sent: $%.2f\n\n", srcOut)

	kids := children[srcStr]
	for i, kid := range kids {
		printNode(kid.to, "", i == len(kids)-1, kid.total)
	}

	// Summary (remaining > $10K, non-infra nodes only)
	var predCount, tpCount int
	var tpVolume, totalRem float64
	for a, n := range fg.Nodes {
		rem := n.TotalI() - n.TotalO()
		if rem < 10000 {
			continue
		}
		if lbl, ok := addrLabels[a]; ok && isHackInfra(lbl) {
			continue
		}
		predCount++
		totalRem += rem
		if _, ok := termSet[a]; ok {
			tpCount++
			tpVolume += rem
		}
	}
	fmt.Printf("\n--- Summary (remaining > $10K, non-infra) ---\n")
	fmt.Printf("Source sent         : $%.2f\n", srcOut)
	fmt.Printf("Predicted terminals : %d\n", predCount)
	fmt.Printf("  True positives    : %d   volume = $%.2f\n", tpCount, tpVolume)
	fmt.Printf("  False positives   : %d   volume = $%.2f\n", predCount-tpCount, totalRem-tpVolume)
	fmt.Printf("Total remaining     : $%.2f\n", totalRem)
	fmt.Printf("Unaccounted         : $%.2f  (retained at intermediate nodes < $10K)\n",
		srcOut-totalRem)
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	rows, err := loadFlowCSV(datasetBase + "/flow records.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR loading flow records:", err)
		os.Exit(1)
	}
	srcAddrs, err := loadAddressFile(datasetBase + "/source addresses.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR loading source addresses:", err)
		os.Exit(1)
	}
	termAddrs, err := loadAddressFile(datasetBase + "/terminal addresses.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR loading terminal addresses:", err)
		os.Exit(1)
	}
	addrLabels := buildAddrLabels(rows)

	// Build lookup: lowercase "0x..." → model.Address
	srcIndex := make(map[string]model.Address, len(srcAddrs))
	for _, a := range srcAddrs {
		srcIndex[strings.ToLower(a.Hex())] = a
	}

	// No argument: list all valid source addresses
	if len(os.Args) < 2 {
		fmt.Printf("Dataset : %s\n", datasetBase)
		fmt.Printf("%d source addresses:\n\n", len(srcAddrs))
		for i, a := range srcAddrs {
			lbl := addrLabels[string(a.Bytes())]
			if lbl != "" {
				fmt.Printf("  [%2d] %s  [%s]\n", i+1, a.Hex(), lbl)
			} else {
				fmt.Printf("  [%2d] %s\n", i+1, a.Hex())
			}
		}
		fmt.Println("\nUsage: go run single/single.go <hex-address>")
		return
	}

	// Normalize and validate the input address
	input := strings.ToLower(strings.TrimSpace(os.Args[1]))
	if !strings.HasPrefix(input, "0x") {
		input = "0x" + input
	}
	srcAddr, ok := srcIndex[input]
	if !ok {
		fmt.Fprintf(os.Stderr, "ERROR: %q is not in source addresses.csv\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "\nValid source addresses:")
		for i, a := range srcAddrs {
			lbl := addrLabels[string(a.Bytes())]
			if lbl != "" {
				fmt.Fprintf(os.Stderr, "  [%2d] %s  [%s]\n", i+1, a.Hex(), lbl)
			} else {
				fmt.Fprintf(os.Stderr, "  [%2d] %s\n", i+1, a.Hex())
			}
		}
		os.Exit(1)
	}

	fmt.Printf("Dataset : %s\n", datasetBase)
	fmt.Printf("Transfers loaded : %d\n", len(rows))
	fmt.Printf("Source addresses : %d   Terminal addresses : %d\n\n",
		len(srcAddrs), len(termAddrs))

	traceSource(rows, srcAddr, termAddrs, addrLabels)
}
