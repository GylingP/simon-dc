package main

// 32位分组，16 位字长

// 循环左移
func rotl16(x uint16, s uint) uint16 {
	s &= 15
	return (x << s) | (x >> (16 - s))
}

// 核心非线性轮函数
func f16(x uint16) uint16 {
	return rotl16(x, 1)&rotl16(x, 8) ^ rotl16(x, 2)
}

// 轮函数
func simonRound16(x, y, k uint16) uint16 {
	return f16(x) ^ y ^ k
}

// 一轮变换
func feistelStep16(x, y, k uint16) (uint16, uint16) {
	return simonRound16(x, y, k), x
}
