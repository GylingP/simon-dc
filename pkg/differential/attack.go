package differential

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"simon-dc/pkg/simon"
)

const (
	AttackRounds       = 14
	AttackRoundKeyIdx  = AttackRounds - 1
	AttackPairCount    = 1 << 37
	AttackWorkers      = 20
	AttackInputDL      = 0x0000
	AttackInputDR      = 0x0004
	AttackFilterDL     = 0x0400
	AttackFilterDR     = 0x0000
	KeyCountOutputPath = "key_count.csv"
	progressBarWidth   = 40
	progressBatchSize  = 65536
	knownKeyBits       = 12
	suffixKeyBits      = 4
	suffixKeySpace     = 1 << suffixKeyBits // 后 4 位，共 16 种
)

// AttackTrail13 13 轮差分路径（第 14 轮密钥恢复前）。
var AttackTrail13 = []DiffPair{
	{0x0000, 0x0004},
	{0x0004, 0x0000},
	{0x0010, 0x0004},
	{0x0044, 0x0010},
	{0x0100, 0x0044},
	{0x0444, 0x0100},
	{0x1010, 0x0444},
	{0x4404, 0x1010},
	{0x0001, 0x4404},
	{0x4400, 0x0001},
	{0x1000, 0x4400},
	{0x0400, 0x1000},
	{0x0000, 0x0400},
	{0x0400, 0x0000},
}

// KeyCountEntry 密钥计数条目。
type KeyCountEntry struct {
	Key     uint16 // 完整 16 位轮密钥
	Suffix4 uint16 // 后 4 位猜测值
	Count   uint64
}

// SuffixCounter 后 4 位密钥猜测计数（0..15）。
type SuffixCounter [suffixKeySpace]uint64

// workerResult 单个 worker 的局部计数与处理量。
type workerResult struct {
	counters  SuffixCounter
	processed uint64
}

// pairRNG 为每个 worker 分配独立、不重叠的明文对序列。
type pairRNG struct {
	workerID  int
	baseIndex uint64
	seed      uint64
}

func newPairRNG(baseSeed uint64, workerID int, baseIndex uint64) *pairRNG {
	seed := baseSeed
	seed ^= uint64(workerID+1) * 0xD1B54A32D192ED03
	seed ^= uint64(workerID+1) << 33
	seed += baseIndex * 0x9E3779B97F4A7C15
	return &pairRNG{
		workerID:  workerID,
		baseIndex: baseIndex,
		seed:      seed,
	}
}

func mix64(x uint64) uint64 {
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

func (r *pairRNG) nextPair(localIdx uint64) (uint16, uint16) {
	globalIdx := r.baseIndex + localIdx
	s0 := r.seed + globalIdx*0xC2B2AE3D27D4EB4F + uint64(r.workerID)<<17
	s1 := s0 ^ 0xA0761D6478BD642F ^ (globalIdx << 11)
	pL := uint16(mix64(s0))
	pR := uint16(mix64(s1))
	return pL, pR
}

// knownKeyPrefix 取 16 位轮密钥的高 12 位（低 4 位清零）。
func knownKeyPrefix(fullKey uint16) uint16 {
	return fullKey & 0xFFF0
}

// buildKeyGuess 将已知前 12 位与后 4 位猜测合并为完整轮密钥。
func buildKeyGuess(prefix12 uint16, suffix4 int) uint16 {
	return prefix12 | uint16(suffix4&0xF)
}

// ParseMasterKey 解析 64 位主密钥（十进制或 0x 十六进制）。
func ParseMasterKey(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("主密钥不能为空")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("无效的十六进制主密钥: %w", err)
		}
		return v, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效的主密钥: %w", err)
	}
	return v, nil
}

// PrintAttackInfo 输出差分攻击基本信息。
func PrintAttackInfo() {
	fmt.Println("\n========== 第 14 轮轮密钥差分攻击模拟 ==========")
	fmt.Printf("算法: SIMON32/64 减轮加密 (%d 轮)\n", AttackRounds)
	fmt.Printf("攻击目标: 第 %d 轮轮密钥 k%d\n", AttackRounds, AttackRoundKeyIdx)
	fmt.Printf("输入差分: (ΔL, ΔR) = (0x%04x, 0x%04x)\n", AttackInputDL, AttackInputDR)
	fmt.Printf("过滤条件: 单轮解密后差分 = (0x%04x, 0x%04x)\n", AttackFilterDL, AttackFilterDR)
	fmt.Printf("明文对数量: 2^37 = %d\n", AttackPairCount)
	fmt.Printf("并行 worker 数: %d\n", AttackWorkers)
	fmt.Printf("密钥搜索: 已知前 %d 位，爆破后 %d 位（%d 种候选）\n",
		knownKeyBits, suffixKeyBits, suffixKeySpace)
	fmt.Println("\n13 轮差分路径 (Trail):")
	for i, s := range AttackTrail13 {
		fmt.Printf("  轮 %2d: (0x%04x, 0x%04x)\n", i, s.DL, s.DR)
	}
	fmt.Println("\n攻击流程:")
	fmt.Println("  1. 随机生成差分为 (0x0000,0x0004) 的明文对")
	fmt.Println("  2. 使用用户主密钥 14 轮加密")
	fmt.Println("  3. 已知第 14 轮密钥高 12 位，仅遍历后 4 位猜测")
	fmt.Println("  4. 统计使解密差分满足 (0x0400,0x0000) 的后 4 位")
	fmt.Printf("  5. 输出 Top 候选并保存计数至 %s\n", KeyCountOutputPath)
}

func encryptN(x, y uint16, keys []uint16) (uint16, uint16) {
	for i := 0; i < len(keys); i++ {
		x, y = simon.FeistelStep16(x, y, keys[i])
	}
	return x, y
}

func decryptRound14Match(cl, cr, cl2, cr2, kGuess uint16) bool {
	l, r := simon.FeistelDecryptStep16(cl, cr, kGuess)
	l2, r2 := simon.FeistelDecryptStep16(cl2, cr2, kGuess)
	return l^l2 == AttackFilterDL && r^r2 == AttackFilterDR
}

func processPair(cl, cr, cl2, cr2 uint16, prefix12 uint16, counters *SuffixCounter) {
	for suffix := 0; suffix < suffixKeySpace; suffix++ {
		kGuess := buildKeyGuess(prefix12, suffix)
		if decryptRound14Match(cl, cr, cl2, cr2, kGuess) {
			counters[suffix]++
		}
	}
}

func mergeAllCounters(dst *SuffixCounter, parts []workerResult) {
	for _, part := range parts {
		for i := 0; i < suffixKeySpace; i++ {
			dst[i] += part.counters[i]
		}
	}
}

func renderProgressBar(current, total uint64, start time.Time) {
	if total == 0 {
		return
	}
	pct := float64(current) / float64(total)
	filled := int(pct * progressBarWidth)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	bar := strings.Repeat("=", filled)
	if filled < progressBarWidth {
		bar += ">"
		bar += strings.Repeat(" ", progressBarWidth-filled-1)
	}
	elapsed := time.Since(start)
	var eta time.Duration
	if current > 0 {
		eta = time.Duration(float64(elapsed) / float64(current) * float64(total-current))
	}
	rate := float64(current) / elapsed.Seconds()
	fmt.Printf("\r[%s] %7.4f%%  %d / %d  速度 %.0f 对/秒  已用 %v  剩余 %v   ",
		bar, pct*100, current, total, rate, elapsed.Round(time.Second), eta.Round(time.Second))
}

func runProgressReporter(done <-chan struct{}, processed *atomic.Uint64, start time.Time) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			renderProgressBar(processed.Load(), AttackPairCount, start)
			fmt.Println()
			return
		case <-ticker.C:
			renderProgressBar(processed.Load(), AttackPairCount, start)
		}
	}
}

func attackWorker(
	workerID int,
	pairCount uint64,
	baseIndex uint64,
	baseSeed uint64,
	prefix12 uint16,
	roundKeys []uint16,
	processed *atomic.Uint64,
) workerResult {
	rng := newPairRNG(baseSeed, workerID, baseIndex)
	var local SuffixCounter
	var localProcessed uint64

	for i := uint64(0); i < pairCount; i++ {
		pL, pR := rng.nextPair(i)
		pL2 := pL
		pR2 := pR ^ AttackInputDR

		cl, cr := encryptN(pL, pR, roundKeys)
		cl2, cr2 := encryptN(pL2, pR2, roundKeys)
		processPair(cl, cr, cl2, cr2, prefix12, &local)

		localProcessed++
		if localProcessed%progressBatchSize == 0 {
			processed.Add(progressBatchSize)
		}
	}

	remainder := localProcessed % progressBatchSize
	if remainder > 0 {
		processed.Add(remainder)
	}

	return workerResult{counters: local, processed: localProcessed}
}

// RunDifferentialAttack 执行差分攻击模拟（20 worker 并行 + 进度条）。
func RunDifferentialAttack(masterKey uint64) error {
	roundKeys, err := simon.KeySchedule3264(masterKey, AttackRounds)
	if err != nil {
		return err
	}
	targetKey := roundKeys[AttackRoundKeyIdx]
	prefix12 := knownKeyPrefix(targetKey)
	targetSuffix := targetKey & 0xF

	fmt.Printf("\n第 %d 轮轮密钥真实值（攻击目标）: 0x%04x (%d)\n",
		AttackRounds, targetKey, targetKey)
	fmt.Printf("已知前 12 位: 0x%04x    待爆破后 4 位: xxxx（真实后缀 = 0x%x）\n",
		prefix12, targetSuffix)
	fmt.Printf("\n启动 %d 个 worker 并行计算（每 worker 独立随机流，全局索引分区不重叠）...\n", AttackWorkers)

	var counters SuffixCounter
	var processed atomic.Uint64
	start := time.Now()
	baseSeed := uint64(start.UnixNano()) ^ masterKey ^ 0xA5A5A5A5A5A5A5A5

	done := make(chan struct{})
	go runProgressReporter(done, &processed, start)

	pairsPerWorker := AttackPairCount / uint64(AttackWorkers)
	remainder := AttackPairCount % uint64(AttackWorkers)

	results := make([]workerResult, AttackWorkers)
	var wg sync.WaitGroup
	var baseIndex uint64

	for w := 0; w < AttackWorkers; w++ {
		n := pairsPerWorker
		if w == AttackWorkers-1 {
			n += remainder
		}
		wg.Add(1)
		go func(id int, count, indexOffset uint64) {
			defer wg.Done()
			results[id] = attackWorker(id, count, indexOffset, baseSeed, prefix12, roundKeys, &processed)
		}(w, n, baseIndex)
		baseIndex += n
	}

	wg.Wait()
	close(done)
	time.Sleep(250 * time.Millisecond)

	mergeAllCounters(&counters, results)
	fmt.Printf("统计完成，总耗时 %v，并行 worker 数 %d\n", time.Since(start).Round(time.Second), AttackWorkers)

	top := topSuffixCounts(&counters, prefix12, suffixKeySpace)
	fmt.Println("\n=== 后 4 位猜测计数排名（完整密钥 = 已知高12位 | 后缀）===")
	fmt.Printf("%-6s %-8s %-12s %-10s %s\n", "排名", "后4位", "完整密钥", "计数", "备注")
	for i, e := range top {
		mark := ""
		if e.Suffix4 == targetSuffix {
			mark = "  <-- 真实后缀"
		}
		fmt.Printf("%-6d 0x%x      0x%04x       %-10d%s\n",
			i+1, e.Suffix4, e.Key, e.Count, mark)
	}

	if err := saveSuffixCounts(KeyCountOutputPath, prefix12, &counters); err != nil {
		return fmt.Errorf("保存计数文件失败: %w", err)
	}
	fmt.Printf("\n后 4 位密钥空间计数已保存至 %s\n", KeyCountOutputPath)
	return nil
}

func topSuffixCounts(counters *SuffixCounter, prefix12 uint16, n int) []KeyCountEntry {
	all := make([]KeyCountEntry, suffixKeySpace)
	for i := 0; i < suffixKeySpace; i++ {
		all[i] = KeyCountEntry{
			Key:     buildKeyGuess(prefix12, i),
			Suffix4: uint16(i),
			Count:   counters[i],
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count == all[j].Count {
			return all[i].Suffix4 < all[j].Suffix4
		}
		return all[i].Count > all[j].Count
	})
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

func saveSuffixCounts(path string, prefix12 uint16, counters *SuffixCounter) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	if _, err := w.WriteString("suffix4,full_key_hex,full_key_dec,count\n"); err != nil {
		return err
	}
	for i := 0; i < suffixKeySpace; i++ {
		full := buildKeyGuess(prefix12, i)
		line := fmt.Sprintf("0x%x,0x%04x,%d,%d\n", i, full, full, counters[i])
		if _, err := w.WriteString(line); err != nil {
			return err
		}
	}
	return w.Flush()
}

// QueryDifferentialAttack 功能 4：交互式差分攻击模拟。
func QueryDifferentialAttack(masterKey uint64) error {
	PrintAttackInfo()
	return RunDifferentialAttack(masterKey)
}
