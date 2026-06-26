package differential

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

const DefaultBeamWidth = 100

// Transition 描述轮函数 DDT 中一步传播 ΔF(ΔL): ΔL→β。
type Transition struct {
	Beta  uint16
	Count uint32
	Prob  float64
	Log2P float64
}

// SparseDDT 仅保存非零传播项，便于路径扩展。
type SparseDDT map[uint16][]Transition

// DiffPair Feistel 状态下的左右半字差分 (ΔL, ΔR)。
type DiffPair struct {
	DL, DR uint16
}

// Trail Feistel 差分路径 (ΔL0,ΔR0)→(ΔL1,ΔR1)→… 及其累积概率。
type Trail struct {
	States []DiffPair
	Log2P  float64
	Prob   float64
}

// PathSearchConfig 高概率路径搜索参数。
type PathSearchConfig struct {
	StartL, StartR uint16
	Rounds         int
	BeamWidth      int
}

// ParseDiffPair 解析起始差分对，支持 "0,1" / "0x0,0x1" / "(0, 1)" 等形式。
func ParseDiffPair(s string) (DiffPair, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	s = strings.TrimSpace(s)

	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return DiffPair{}, fmt.Errorf("请输入 (ΔL, ΔR) 格式，例如 0,1 或 0x0,0x1")
	}
	dl, err := ParseDiff(parts[0])
	if err != nil {
		return DiffPair{}, fmt.Errorf("ΔL 解析失败: %w", err)
	}
	dr, err := ParseDiff(parts[1])
	if err != nil {
		return DiffPair{}, fmt.Errorf("ΔR 解析失败: %w", err)
	}
	return DiffPair{DL: dl, DR: dr}, nil
}

// feistelStepDiff 根据 Feistel 差分传播规则扩展一步：
// ΔL' = ΔR ⊕ ΔF(ΔL)，ΔR' = ΔL（ΔF 由 DDT[ΔL] 给出）。
func feistelStepDiff(dL, dR uint16, t Transition) DiffPair {
	return DiffPair{
		DL: t.Beta ^ dR,
		DR: dL,
	}
}

// LoadSparseDDT 从 CSV 一次性加载稀疏 DDT（仅非零项）。
func LoadSparseDDT(path string) (SparseDDT, error) {
	path = resolvePath(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 DDT 文件失败: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	if !scanner.Scan() {
		return nil, fmt.Errorf("DDT 文件为空")
	}

	ddt := make(SparseDDT)
	for dx := 0; dx < WordSize; dx++ {
		if !scanner.Scan() {
			return nil, fmt.Errorf("DDT 行数不足: 期望 %d 行，在第 %d 行结束", WordSize, dx)
		}
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) != WordSize+1 {
			return nil, fmt.Errorf("DDT 行格式错误 (Δx=%d): 期望 %d 列，实际 %d 列", dx, WordSize+1, len(parts))
		}

		var transitions []Transition
		for df := 0; df < WordSize; df++ {
			c, err := parseCount(parts[df+1])
			if err != nil {
				return nil, fmt.Errorf("解析 DDT[%d][%d] 失败: %w", dx, df, err)
			}
			if c == 0 {
				continue
			}
			prob := float64(c) / WordSize
			transitions = append(transitions, Transition{
				Beta:  uint16(df),
				Count: c,
				Prob:  prob,
				Log2P: math.Log2(prob),
			})
		}
		if len(transitions) > 0 {
			ddt[uint16(dx)] = transitions
		}

		if dx%4096 == 0 && dx > 0 {
			fmt.Printf("  稀疏 DDT 加载进度: %6.2f%%\n", float64(dx)/WordSize*100)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 DDT 失败: %w", err)
	}
	return ddt, nil
}

func parseCount(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// BeamSearch 在 Feistel 状态空间上执行 Beam Search。
// 每轮对当前 (ΔL,ΔR) 查 DDT[ΔL]，对每个 ΔF=β 生成 (β⊕ΔR, ΔL)。
func BeamSearch(ddt SparseDDT, cfg PathSearchConfig) []Trail {
	if cfg.BeamWidth <= 0 {
		cfg.BeamWidth = DefaultBeamWidth
	}
	if cfg.Rounds <= 0 {
		return nil
	}

	beam := []Trail{{
		States: []DiffPair{{DL: cfg.StartL, DR: cfg.StartR}},
		Log2P:  0,
		Prob:   1,
	}}

	for round := 0; round < cfg.Rounds; round++ {
		candidates := make([]Trail, 0, len(beam)*8)
		for _, path := range beam {
			curr := path.States[len(path.States)-1]
			transitions, ok := ddt[curr.DL]
			if !ok {
				continue
			}
			for _, t := range transitions {
				next := feistelStepDiff(curr.DL, curr.DR, t)
				newStates := append(append([]DiffPair(nil), path.States...), next)
				candidates = append(candidates, Trail{
					States: newStates,
					Log2P:  path.Log2P + t.Log2P,
					Prob:   path.Prob * t.Prob,
				})
			}
		}

		if len(candidates) == 0 {
			return nil
		}

		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].Log2P == candidates[j].Log2P {
				return len(candidates[i].States) < len(candidates[j].States)
			}
			return candidates[i].Log2P > candidates[j].Log2P
		})

		if len(candidates) > cfg.BeamWidth {
			candidates = candidates[:cfg.BeamWidth]
		}
		beam = candidates
	}
	return beam
}

// SearchHighProbPaths 加载 DDT 并执行 Beam Search。
func SearchHighProbPaths(csvPath string, cfg PathSearchConfig) ([]Trail, error) {
	if cfg.BeamWidth <= 0 {
		cfg.BeamWidth = DefaultBeamWidth
	}
	fmt.Println("正在加载稀疏 DDT（仅非零项）...")
	ddt, err := LoadSparseDDT(csvPath)
	if err != nil {
		return nil, err
	}
	fmt.Printf("稀疏 DDT 加载完成，共 %d 个非空输入差分。\n", len(ddt))

	fmt.Printf("Beam Search: 起点 (ΔL,ΔR)=(0x%04x,0x%04x), 轮数=%d, K=%d\n",
		cfg.StartL, cfg.StartR, cfg.Rounds, cfg.BeamWidth)
	fmt.Println("Feistel 传播: ΔL' = ΔR ⊕ ΔF(ΔL),  ΔR' = ΔL")

	trails := BeamSearch(ddt, cfg)
	if len(trails) == 0 {
		return nil, fmt.Errorf("未找到有效差分路径（请检查起始差分或轮数）")
	}
	return trails, nil
}

func formatDiffPair(p DiffPair) string {
	return fmt.Sprintf("(0x%04x,0x%04x)", p.DL, p.DR)
}

func formatTrailChain(states []DiffPair) string {
	var b strings.Builder
	for i, s := range states {
		if i > 0 {
			b.WriteString(" → ")
		}
		b.WriteString(formatDiffPair(s))
	}
	return b.String()
}

// PrintPathSearchResults 打印 Beam Search 结果。
func PrintPathSearchResults(cfg PathSearchConfig, trails []Trail) {
	fmt.Printf("\n起始状态 (ΔL,ΔR) = (0x%04x, 0x%04x)，轮数 = %d，Beam 宽度 K = %d\n",
		cfg.StartL, cfg.StartR, cfg.Rounds, cfg.BeamWidth)
	fmt.Printf("保留路径数: %d\n\n", len(trails))

	fmt.Printf("%-6s %-60s %-14s %s\n", "排名", "Feistel 差分路径", "总概率 P", "log2(P)")
	r := min(len(trails), 20)
	for i, t := range trails[:r] {
		fmt.Printf("%-6d %-60s %-14.6e  %.4f\n",
			i+1, formatTrailChain(t.States), t.Prob, t.Log2P)
	}

	if len(trails) > 0 {
		best := trails[0]
		fmt.Printf("\n最优路径: %s\n", formatTrailChain(best.States))
		fmt.Printf("总概率 P = %.6e = 2^(%.4f)，总代价 w = %.4f bit\n",
			best.Prob, best.Log2P, -best.Log2P)
	}
}

// QueryPathSearch 功能 3：高概率 Feistel 差分路径搜索并打印结果。
func QueryPathSearch(csvPath string, cfg PathSearchConfig) error {
	trails, err := SearchHighProbPaths(csvPath, cfg)
	if err != nil {
		return err
	}
	PrintPathSearchResults(cfg, trails)
	return nil
}
