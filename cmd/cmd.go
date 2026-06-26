package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"simon-dc/pkg/differential"
)

func printMenu() {
	fmt.Println()
	fmt.Println("========== SIMON f16 差分分析工具 ==========")
	fmt.Println("1. 计算轮函数 DDT 表")
	fmt.Println("2. 查询指定差分传播概率")
	fmt.Println("3. 高概率差分路径搜索")
	fmt.Println("4. 差分路径模拟攻击")
	fmt.Println("0. 退出")
	fmt.Print("请选择功能编号: ")
}

func readChoice(scanner *bufio.Scanner) (int, error) {
	if !scanner.Scan() {
		return 0, scanner.Err()
	}
	line := strings.TrimSpace(scanner.Text())
	if line == "" {
		return -1, nil
	}
	choice, err := strconv.Atoi(line)
	if err != nil {
		return -1, nil
	}
	return choice, nil
}

func runFeature1() {
	fmt.Println("\n>>> 功能 1：计算轮函数 DDT 表")
	exists, err := differential.Ensure(differential.DefaultPath)
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}
	if exists {
		fmt.Printf("本地已存在 %s，DDT 表计算完成。\n", differential.DefaultPath)
		return
	}
	fmt.Printf("DDT 表已生成并保存至 %s。\n", differential.DefaultPath)
}

func runFeature2(scanner *bufio.Scanner) {
	fmt.Println("\n>>> 功能 2：查询指定差分传播概率")
	if err := differential.Prepare(differential.DefaultPath); err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}
	fmt.Print("请输入输入差分 Δx（十进制或 0x 十六进制）: ")
	if !scanner.Scan() {
		fmt.Printf("读取输入失败: %v\n", scanner.Err())
		return
	}
	dx, err := differential.ParseDiff(scanner.Text())
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}
	if err := differential.QueryPropagation(differential.DefaultPath, dx); err != nil {
		fmt.Printf("错误: %v\n", err)
	}
}

func runFeature3(scanner *bufio.Scanner) {
	fmt.Println("\n>>> 功能 3：高概率差分路径搜索")
	if err := differential.Prepare(differential.DefaultPath); err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}

	fmt.Print("请输入起始差分 (ΔL, ΔR)，例如 0,1 或 0x0,0x1: ")
	if !scanner.Scan() {
		fmt.Printf("读取输入失败: %v\n", scanner.Err())
		return
	}
	start, err := differential.ParseDiffPair(scanner.Text())
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}

	fmt.Print("请输入搜索轮数 r: ")
	if !scanner.Scan() {
		fmt.Printf("读取输入失败: %v\n", scanner.Err())
		return
	}
	rounds, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil || rounds <= 0 {
		fmt.Println("错误: 轮数必须为正整数")
		return
	}

	fmt.Printf("请输入 Beam 宽度 K（直接回车默认 %d）: ", differential.DefaultBeamWidth)
	if !scanner.Scan() {
		fmt.Printf("读取输入失败: %v\n", scanner.Err())
		return
	}
	beamText := strings.TrimSpace(scanner.Text())
	beamWidth := differential.DefaultBeamWidth
	if beamText != "" {
		beamWidth, err = strconv.Atoi(beamText)
		if err != nil || beamWidth <= 0 {
			fmt.Println("错误: Beam 宽度必须为正整数")
			return
		}
	}

	cfg := differential.PathSearchConfig{
		StartL:    start.DL,
		StartR:    start.DR,
		Rounds:    rounds,
		BeamWidth: beamWidth,
	}
	if err := differential.QueryPathSearch(differential.DefaultPath, cfg); err != nil {
		fmt.Printf("错误: %v\n", err)
	}
}

func runFeature4(scanner *bufio.Scanner) {
	fmt.Println("\n>>> 功能 4：差分路径模拟攻击")
	if err := differential.Prepare(differential.DefaultPath); err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}
	differential.PrintAttackInfo()
	fmt.Print("\n请输入 64 位主密钥（十进制或 0x 十六进制）: ")
	if !scanner.Scan() {
		fmt.Printf("读取输入失败: %v\n", scanner.Err())
		return
	}
	masterKey, err := differential.ParseMasterKey(scanner.Text())
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}
	if err := differential.RunDifferentialAttack(masterKey); err != nil {
		fmt.Printf("错误: %v\n", err)
	}
}

// Run 启动交互式命令行工具。
func Run() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		printMenu()
		choice, err := readChoice(scanner)
		if err != nil {
			fmt.Printf("读取输入失败: %v\n", err)
			return
		}

		switch choice {
		case 1:
			runFeature1()
		case 2:
			runFeature2(scanner)
		case 3:
			runFeature3(scanner)
		case 4:
			runFeature4(scanner)
		case 0:
			fmt.Println("再见。")
			return
		default:
			fmt.Println("无效选项，请输入 0-4。")
		}
	}
}
