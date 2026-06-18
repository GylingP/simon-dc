package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"
)

const wordSize = 65536

// DDT 差分分布表：ddt[Δx][Δf]，记录 (x1,x2) 满足 x1⊕x2=Δx 且 f(x1)⊕f(x2)=Δf 的次数。
type DDT [wordSize][wordSize]uint32

// precomputeF16 预计算 f16 查表，加速内层循环。
func precomputeF16() [wordSize]uint16 {
	var table [wordSize]uint16
	for x := 0; x < wordSize; x++ {
		table[x] = f16(uint16(x))
	}
	return table
}

// buildDDT 遍历全部 16 位 x1、x2，在 ddt[Δx][Δf] 处累加。
func buildDDT() *DDT {
	ft := precomputeF16()
	ddt := new(DDT)

	start := time.Now()
	for x1 := 0; x1 < wordSize; x1++ {
		fx1 := ft[x1]
		for x2 := 0; x2 < wordSize; x2++ {
			dx := x1 ^ x2
			df := int(fx1) ^ int(ft[x2])
			ddt[dx][df]++
		}
		if x1%256 == 0 && x1 > 0 {
			elapsed := time.Since(start)
			pct := float64(x1) / wordSize * 100
			fmt.Printf("  进度: %6.2f%%  已用 %v\n", pct, elapsed.Round(time.Second))
		}
	}
	fmt.Printf("  DDT 构建完成，耗时 %v\n", time.Since(start).Round(time.Millisecond))
	return ddt
}

type diffEntry struct {
	dx, df uint16
	count  uint32
	prob   float64
	log2p  float64
}

// findBestDifferential 在 DDT 中寻找最高概率差分（忽略 Δx=0 的平凡情况）。
func findBestDifferential(ddt *DDT) diffEntry {
	best := diffEntry{}
	for dx := 1; dx < wordSize; dx++ {
		for df := 0; df < wordSize; df++ {
			c := ddt[dx][df]
			if c > best.count {
				best = diffEntry{
					dx:    uint16(dx),
					df:    uint16(df),
					count: c,
					prob:  float64(c) / wordSize,
					log2p: math.Log2(float64(c) / wordSize),
				}
			}
		}
	}
	return best
}

// // topDifferentials 返回概率最高的前 n 条差分（Δx≠0）。
// func topDifferentials(ddt *DDT, n int) []diffEntry {
// 	all := make([]diffEntry, 0, 1024)
// 	for dx := 1; dx < wordSize; dx++ {
// 		for df := 0; df < wordSize; df++ {
// 			c := ddt[dx][df]
// 			if c == 0 {
// 				continue
// 			}
// 			all = append(all, diffEntry{
// 				dx:    uint16(dx),
// 				df:    uint16(df),
// 				count: c,
// 				prob:  float64(c) / wordSize,
// 				log2p: math.Log2(float64(c) / wordSize),
// 			})
// 		}
// 	}
// 	// 简单选择前 n 个最大值
// 	for i := 0; i < len(all) && i < n; i++ {
// 		maxIdx := i
// 		for j := i + 1; j < len(all); j++ {
// 			if all[j].count > all[maxIdx].count {
// 				maxIdx = j
// 			}
// 		}
// 		all[i], all[maxIdx] = all[maxIdx], all[i]
// 	}
// 	if len(all) > n {
// 		all = all[:n]
// 	}
// 	return all
// }

// 优化后的 topDifferentials：无需保存所有差分，内存安全
func topDifferentials(ddt *DDT, n int) []diffEntry {
	// 维护一个固定大小为 n 的有序切片（从大到小）
	bestList := make([]diffEntry, 0, n)

	for dx := 1; dx < wordSize; dx++ {
		for df := 0; df < wordSize; df++ {
			c := ddt[dx][df]
			if c == 0 {
				continue
			}

			// 如果当前计数比列表里最小的还小，且列表已满，直接略过
			if len(bestList) >= n && c <= bestList[len(bestList)-1].count {
				continue
			}

			entry := diffEntry{
				dx:    uint16(dx),
				df:    uint16(df),
				count: c,
				prob:  float64(c) / wordSize,
				log2p: math.Log2(float64(c) / wordSize),
			}

			// 插入排序
			inserted := false
			for i := 0; i < len(bestList); i++ {
				if entry.count > bestList[i].count {
					// 插入到位置 i
					bestList = append(bestList, diffEntry{})
					copy(bestList[i+1:], bestList[i:])
					bestList[i] = entry
					inserted = true
					break
				}
			}
			if !inserted && len(bestList) < n {
				bestList = append(bestList, entry)
			}

			// 保持切片长度不超过 n
			if len(bestList) > n {
				bestList = bestList[:n]
			}
		}
	}
	return bestList
}

// writeDDTToCSV 将完整 DDT 矩阵写入 CSV（65536 行 × 65536 列，首列为 Δx，其余列为各 Δf 计数）。
func writeDDTToCSV(path string, ddt *DDT) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建 CSV 文件失败: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 4*1024*1024)
	start := time.Now()

	// 表头：dx, df_0, df_1, ..., df_65535
	if _, err := w.WriteString("dx"); err != nil {
		return err
	}
	for df := 0; df < wordSize; df++ {
		if _, err := w.WriteString("," + strconv.Itoa(df)); err != nil {
			return err
		}
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}

	buf := make([]byte, 0, 512*1024)
	for dx := 0; dx < wordSize; dx++ {
		buf = buf[:0]
		buf = append(buf, strconv.Itoa(dx)...)
		row := ddt[dx]
		for df := 0; df < wordSize; df++ {
			buf = append(buf, ',')
			buf = strconv.AppendUint(buf, uint64(row[df]), 10)
		}
		buf = append(buf, '\n')
		if _, err := w.Write(buf); err != nil {
			return err
		}

		if dx%256 == 0 {
			pct := float64(dx) / wordSize * 100
			fmt.Printf("  CSV 写入进度: %6.2f%%\n", pct)
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("  CSV 写入完成，耗时 %v，文件: %s\n", time.Since(start).Round(time.Second), path)
	return nil
}

func runDifferentialAnalysis() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("构建 DDT 前内存占用: %.1f MiB\n", float64(m.Alloc)/1024/1024)
	fmt.Printf("DDT 理论大小: %.1f GiB（%d × %d × 4 字节）\n\n",
		float64(wordSize*wordSize*4)/1024/1024/1024, wordSize, wordSize)

	fmt.Println("正在遍历全部 x1, x2 ∈ [0, 65535] ...")
	ddt := buildDDT()

	runtime.ReadMemStats(&m)
	fmt.Printf("DDT 构建后内存占用: %.1f MiB\n\n", float64(m.Alloc)/1024/1024)

	best := findBestDifferential(ddt)
	fmt.Println("=== f16 最高概率差分（Δx ≠ 0）===")
	fmt.Printf("  Δx     = 0x%04x (%d)\n", best.dx, best.dx)
	fmt.Printf("  Δf16   = 0x%04x (%d)\n", best.df, best.df)
	fmt.Printf("  计数   = %d / %d\n", best.count, wordSize)
	fmt.Printf("  概率   = %.6f = 2^(%.4f)\n", best.prob, best.log2p)

	fmt.Println("\n=== 概率最高的前 10 条差分 ===")
	fmt.Printf("%-8s %-8s %-8s %-12s %s\n", "Δx", "Δf16", "计数", "概率", "log2(p)")
	for _, e := range topDifferentials(ddt, 10) {
		fmt.Printf("0x%04x   0x%04x   %-8d %-12.6f %.4f\n",
			e.dx, e.df, e.count, e.prob, e.log2p)
	}

	// 平凡行 Δx=0 的统计
	fmt.Printf("\nΔx=0 时仅 Δf=0 有计数: ddt[0][0] = %d（概率 1.0，平凡差分）\n", ddt[0][0])

	fmt.Println("\n正在导出完整 DDT 到 ddt.csv（65536×65536，文件较大，请耐心等待）...")
	if err := writeDDTToCSV("ddt.csv", ddt); err != nil {
		fmt.Printf("导出 CSV 失败: %v\n", err)
		return
	}
}
