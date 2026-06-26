package simon

import "fmt"

// SIMON32/64 参数：32 位分组，64 位主密钥，16 位字长，标准 32 轮。

const (
	WordBits      = 16
	KeyWords      = 4
	MaxRounds3264 = 32
	KeyConstantC  = 0xFFFC // 2^16 - 4
)

// z0 序列前 32 位（SIMON32/64 使用）。
var z0 = [MaxRounds3264]uint16{
	1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1,
	0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
}

// ValidateRounds 校验减轮实验使用的轮数（1..32）。
func ValidateRounds(rounds int) error {
	if rounds < 1 || rounds > MaxRounds3264 {
		return fmt.Errorf("轮数必须在 1..%d 之间，当前为 %d", MaxRounds3264, rounds)
	}
	return nil
}

// Rotl16 对 16 位字做循环左移。
func Rotl16(x uint16, s uint) uint16 {
	s &= 15
	return (x << s) | (x >> (16 - s))
}

// Ror16 对 16 位字做循环右移。
func Ror16(x uint16, s uint) uint16 {
	s &= 15
	return (x >> s) | (x << (16 - s))
}

// F16 是 16 位字上的核心非线性轮函数：
// f(x) = (x <<< 1 & x <<< 8) XOR (x <<< 2)
func F16(x uint16) uint16 {
	return Rotl16(x, 1)&Rotl16(x, 8) ^ Rotl16(x, 2)
}

// SimonRound16 计算 f(x) XOR y XOR k。
func SimonRound16(x, y, k uint16) uint16 {
	return F16(x) ^ y ^ k
}

// FeistelStep16 执行一轮加密 Feistel 步：
// (L', R') = (f(L) XOR R XOR k, L)
func FeistelStep16(x, y, k uint16) (uint16, uint16) {
	return SimonRound16(x, y, k), x
}

// FeistelDecryptStep16 执行一轮解密（单轮 Feistel 的逆变换）：
// 已知轮后状态 (L', R') 与轮密钥 k，恢复轮前 (L, R)。
// L = R'，R = L' XOR f(R') XOR k
func FeistelDecryptStep16(lp, rp, k uint16) (uint16, uint16) {
	l := rp
	r := lp ^ F16(rp) ^ k
	return l, r
}

// KeySchedule3264 将 64 位主密钥扩展为 rounds 个 16 位轮密钥 k0..k_{rounds-1}。
// 主密钥按 (k0, k1, k2, k3) 从高字到低字拆分。
//
// 对 i = 4..rounds-1：
//
//	t = ROR(k[i-1], 3) XOR k[i-3] XOR ROR(t, 1)
//	k[i] = c XOR z[i-4] XOR k[i-4] XOR t
func KeySchedule3264(masterKey uint64, rounds int) ([]uint16, error) {
	if err := ValidateRounds(rounds); err != nil {
		return nil, err
	}

	keys := make([]uint16, rounds)
	keys[0] = uint16(masterKey >> 48)
	keys[1] = uint16(masterKey >> 32)
	keys[2] = uint16(masterKey >> 16)
	keys[3] = uint16(masterKey)

	for i := 4; i < rounds; i++ {
		t := Ror16(keys[i-1], 3)
		t ^= keys[i-3]
		t ^= Ror16(t, 1)
		keys[i] = KeyConstantC ^ z0[i-4] ^ keys[i-4] ^ t
	}
	return keys, nil
}

// Encrypt3264 使用 roundKeys 指定的轮数进行 Feistel 加密。
// 明文高 16 位为左半字 x，低 16 位为右半字 y。
func Encrypt3264(plaintext uint32, roundKeys []uint16) uint32 {
	x := uint16(plaintext >> 16)
	y := uint16(plaintext)
	for i := 0; i < len(roundKeys); i++ {
		x, y = FeistelStep16(x, y, roundKeys[i])
	}
	return uint32(x)<<16 | uint32(y)
}

// EncryptBlock3264 从主密钥加密单个 32 位分组，rounds 为用户指定的轮数。
func EncryptBlock3264(plaintext uint32, masterKey uint64, rounds int) (uint32, error) {
	keys, err := KeySchedule3264(masterKey, rounds)
	if err != nil {
		return 0, err
	}
	return Encrypt3264(plaintext, keys), nil
}
