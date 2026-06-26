package differential

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"simon-dc/pkg/simon"
)

const (
	// WordSize 16 位字空间大小。
	WordSize = 65536
	// DefaultPath 默认 DDT CSV 路径（相对当前工作目录）。
	DefaultPath = "ddt.csv"
)

// Table 差分分布表：Table[Δx][Δf] 记录满足条件的 (x1,x2) 对数。
type Table [WordSize][WordSize]uint32

// Entry 描述一条差分特征及其概率。
type Entry struct {
	Dx, Df uint16
	Count  uint32
	Prob   float64
	Log2P  float64
}

func resolvePath(path string) string {
	if path == "" {
		return DefaultPath
	}
	return path
}

func precomputeF16() [WordSize]uint16 {
	var table [WordSize]uint16
	for x := 0; x < WordSize; x++ {
		table[x] = simon.F16(uint16(x))
	}
	return table
}

func buildTable() *Table {
	ft := precomputeF16()
	ddt := new(Table)

	start := time.Now()
	for x1 := 0; x1 < WordSize; x1++ {
		fx1 := ft[x1]
		for x2 := 0; x2 < WordSize; x2++ {
			dx := x1 ^ x2
			df := int(fx1) ^ int(ft[x2])
			ddt[dx][df]++
		}
		if x1%256 == 0 && x1 > 0 {
			elapsed := time.Since(start)
			pct := float64(x1) / WordSize * 100
			fmt.Printf("  进度: %6.2f%%  已用 %v\n", pct, elapsed.Round(time.Second))
		}
	}
	fmt.Printf("  DDT 构建完成，耗时 %v\n", time.Since(start).Round(time.Millisecond))
	return ddt
}

// FindBest 在 DDT 中寻找最高概率差分（忽略 Δx=0）。
func FindBest(ddt *Table) Entry {
	best := Entry{}
	for dx := 1; dx < WordSize; dx++ {
		for df := 0; df < WordSize; df++ {
			c := ddt[dx][df]
			if c > best.Count {
				best = Entry{
					Dx:    uint16(dx),
					Df:    uint16(df),
					Count: c,
					Prob:  float64(c) / WordSize,
					Log2P: math.Log2(float64(c) / WordSize),
				}
			}
		}
	}
	return best
}

// TopN 返回概率最高的前 n 条差分（Δx≠0），流式维护，内存安全。
func TopN(ddt *Table, n int) []Entry {
	bestList := make([]Entry, 0, n)

	for dx := 1; dx < WordSize; dx++ {
		for df := 0; df < WordSize; df++ {
			c := ddt[dx][df]
			if c == 0 {
				continue
			}
			if len(bestList) >= n && c <= bestList[len(bestList)-1].Count {
				continue
			}

			entry := Entry{
				Dx:    uint16(dx),
				Df:    uint16(df),
				Count: c,
				Prob:  float64(c) / WordSize,
				Log2P: math.Log2(float64(c) / WordSize),
			}

			inserted := false
			for i := 0; i < len(bestList); i++ {
				if entry.Count > bestList[i].Count {
					bestList = append(bestList, Entry{})
					copy(bestList[i+1:], bestList[i:])
					bestList[i] = entry
					inserted = true
					break
				}
			}
			if !inserted && len(bestList) < n {
				bestList = append(bestList, entry)
			}
			if len(bestList) > n {
				bestList = bestList[:n]
			}
		}
	}
	return bestList
}

func writeCSV(path string, ddt *Table) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建 CSV 文件失败: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 4*1024*1024)
	start := time.Now()

	if _, err := w.WriteString("dx"); err != nil {
		return err
	}
	for df := 0; df < WordSize; df++ {
		if _, err := w.WriteString("," + strconv.Itoa(df)); err != nil {
			return err
		}
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}

	buf := make([]byte, 0, 512*1024)
	for dx := 0; dx < WordSize; dx++ {
		buf = buf[:0]
		buf = append(buf, strconv.Itoa(dx)...)
		row := ddt[dx]
		for df := 0; df < WordSize; df++ {
			buf = append(buf, ',')
			buf = strconv.AppendUint(buf, uint64(row[df]), 10)
		}
		buf = append(buf, '\n')
		if _, err := w.Write(buf); err != nil {
			return err
		}
		if dx%256 == 0 {
			pct := float64(dx) / WordSize * 100
			fmt.Printf("  CSV 写入进度: %6.2f%%\n", pct)
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("  CSV 写入完成，耗时 %v，文件: %s\n", time.Since(start).Round(time.Second), path)
	return nil
}

// Exists 检查 DDT CSV 是否已存在。
func Exists(path string) bool {
	path = resolvePath(path)
	_, err := os.Stat(path)
	return err == nil
}

// GenerateAndSave 构建 f16 的 DDT 并导出为 CSV。
func GenerateAndSave(path string) error {
	path = resolvePath(path)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("构建 DDT 前内存占用: %.1f MiB\n", float64(m.Alloc)/1024/1024)
	fmt.Printf("DDT 理论大小: %.1f GiB（%d × %d × 4 字节）\n\n",
		float64(WordSize*WordSize*4)/1024/1024/1024, WordSize, WordSize)

	fmt.Println("正在遍历全部 x1, x2 ∈ [0, 65535] ...")
	ddt := buildTable()

	runtime.ReadMemStats(&m)
	fmt.Printf("DDT 构建后内存占用: %.1f MiB\n", float64(m.Alloc)/1024/1024)

	fmt.Printf("\n正在导出完整 DDT 到 %s（65536×65536，文件较大，请耐心等待）...\n", path)
	if err := writeCSV(path, ddt); err != nil {
		return fmt.Errorf("导出 CSV 失败: %w", err)
	}
	return nil
}

// Ensure 检查本地 DDT CSV；若不存在则生成。返回是否原本已存在。
func Ensure(path string) (alreadyExists bool, err error) {
	path = resolvePath(path)
	if Exists(path) {
		return true, nil
	}
	fmt.Printf("未找到 %s，开始生成 DDT 表...\n", path)
	if err := GenerateAndSave(path); err != nil {
		return false, err
	}
	return false, nil
}

// Prepare 供功能 2-4 使用：确保 DDT CSV 已就绪。
func Prepare(path string) error {
	path = resolvePath(path)
	exists, err := Ensure(path)
	if err != nil {
		return err
	}
	if exists {
		fmt.Printf("已检测到本地 %s，继续执行。\n", path)
	}
	return nil
}

// ParseDiff 解析 16 位差分值，支持十进制或 0x 前缀十六进制。
func ParseDiff(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("差分值不能为空")
	}
	var v uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = strconv.ParseUint(s[2:], 16, 16)
	} else {
		v, err = strconv.ParseUint(s, 10, 16)
	}
	if err != nil {
		return 0, fmt.Errorf("无效的差分值 %q: %w", s, err)
	}
	return uint16(v), nil
}

// readRowFromCSV 从 DDT CSV 中读取指定 Δx 对应的一行计数（不含首列 dx）。
func readRowFromCSV(path string, dx int) ([]uint32, error) {
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

	for i := 0; i < dx; i++ {
		if !scanner.Scan() {
			return nil, fmt.Errorf("输入差分 Δx=%d 超出 DDT 范围", dx)
		}
	}
	if !scanner.Scan() {
		return nil, fmt.Errorf("输入差分 Δx=%d 超出 DDT 范围", dx)
	}

	parts := strings.Split(scanner.Text(), ",")
	if len(parts) != WordSize+1 {
		return nil, fmt.Errorf("DDT 行格式错误: 期望 %d 列，实际 %d 列", WordSize+1, len(parts))
	}

	row := make([]uint32, WordSize)
	for df := 0; df < WordSize; df++ {
		c, err := strconv.ParseUint(parts[df+1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("解析 Δf=%d 计数失败: %w", df, err)
		}
		row[df] = uint32(c)
	}
	return row, nil
}

// MaxProbOutputs 给定输入差分 Δx，返回 DDT 中所有最高概率的输出差分及其频数、频率。
func MaxProbOutputs(path string, dx uint16) ([]Entry, error) {
	row, err := readRowFromCSV(path, int(dx))
	if err != nil {
		return nil, err
	}

	var maxCount uint32
	for _, c := range row {
		if c > maxCount {
			maxCount = c
		}
	}
	if maxCount == 0 {
		return nil, nil
	}

	prob := float64(maxCount) / WordSize
	log2p := math.Log2(prob)

	var results []Entry
	for df, c := range row {
		if c == maxCount {
			results = append(results, Entry{
				Dx:    dx,
				Df:    uint16(df),
				Count: maxCount,
				Prob:  prob,
				Log2P: log2p,
			})
		}
	}
	return results, nil
}

// PrintMaxProbOutputs 打印指定输入差分的全部最高概率输出差分。
func PrintMaxProbOutputs(dx uint16, entries []Entry) {
	fmt.Printf("\n输入差分 Δx = 0x%04x (%d)\n", dx, dx)
	if len(entries) == 0 {
		fmt.Println("无有效输出差分（该行全为 0）。")
		return
	}

	e0 := entries[0]
	fmt.Printf("最高概率 = %.6f = 2^(%.4f)，频数 = %d / %d\n",
		e0.Prob, e0.Log2P, e0.Count, WordSize)
	fmt.Printf("全部最高概率输出差分（共 %d 条）:\n\n", len(entries))
	fmt.Printf("%-10s %-10s %-10s %-14s %s\n", "Δx", "Δf", "频数", "频率", "log2(p)")
	for _, e := range entries {
		fmt.Printf("0x%04x     0x%04x     %-10d %-14.6f %.4f\n",
			e.Dx, e.Df, e.Count, e.Prob, e.Log2P)
	}
}

// QueryPropagation 功能 2：查询指定输入差分的传播概率并打印结果。
func QueryPropagation(path string, dx uint16) error {
	entries, err := MaxProbOutputs(path, dx)
	if err != nil {
		return err
	}
	PrintMaxProbOutputs(dx, entries)
	return nil
}
