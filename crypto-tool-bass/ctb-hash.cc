#include <iostream>
#include <iomanip>
#include <algorithm>
#include "ctb-hash.h"



namespace ctb
{
namespace hash
{

union vec512_t {
	uint64_t  u64[8]{};
	uint32_t u32[16];
	uint16_t u16[32];
	uint8_t   u8[64];
	vec512_t() = default;
	vec512_t(uint64_t v) { u64[0] = v; }
	template<typename... V> vec512_t(V... v): u64{v...} {}

};


const uint8_t message[] {
		0xd1,0xe5,0x20,0xe2,0xe5,0xf2,0xf0,0xe8,
		0x2c,0x20,0xd1,0xf2,0xf0,0xe8,0xe1,0xee,
		0xe6,0xe8,0x20,0xe2,0xed,0xf3,0xf6,0xe8,
		0x2c,0x20,0xe2,0xe5,0xfe,0xf2,0xfa,0x20,
		0xf1,0x20,0xec,0xee,0xf0,0xff,0x20,0xf1,
		0xf2,0xf0,0xe5,0xeb,0xe0,0xec,0xe8,0x20,
		0xed,0xe0,0x20,0xf5,0xf5,0xe0,0xe1,0xf0,
		0xfb,0xff,0x20,0xef,0xeb,0xfa,0xea,0xfb,
		0x20,0xc8,0xe3,0xee,0xf0,0xe5,0xe2,0xfb // 9*8 = 72
};
const uint8_t message2[] {
		0x32,0x31,0x30,0x39,0x38,0x37,0x36,0x35,
		0x34,0x33,0x32,0x31,0x30,0x39,0x38,0x37,
		0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x39,
		0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,
		0x30,0x39,0x38,0x37,0x36,0x35,0x34,0x33,
		0x32,0x31,0x30,0x39,0x38,0x37,0x36,0x35,
		0x34,0x33,0x32,0x31,0x30,0x39,0x38,0x37,
		0x36,0x35,0x34,0x33,0x32,0x31,0x30 // 7*8+7 = 63
};
const uint8_t message3[] {
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
		0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,
		0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,
		0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,
		0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
		0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,
		0x36,0x37,0x38,0x39,0x30,0x31,0x32// 7*8+7 = 63
};

vec512_t operator^ (const vec512_t &v1, const vec512_t &v2)
{
  vec512_t result {};
  for (int i = 0; i < 8; i++)
	  result.u64[i] = v1.u64[i] ^ v2.u64[i];
  return result;
}

vec512_t operator+ (const vec512_t &a, const vec512_t &b)
{
  vec512_t result {};
  int t = 0;
  for (int i = 0; i < 64; i++)
  {
	  t = a.u8[i] + b.u8[i] + (t >> 8);
	  result.u8[i] = t;
  }
  return result;
}

vec512_t &operator+=(vec512_t &lhs ,const vec512_t &rhs)
{

    return lhs = lhs + rhs;
}

std::ostream &operator <<(std::ostream &out, const vec512_t &v)
{

	int mess_length = sizeof(v)/sizeof(uint8_t);
	for (int i = 0; i < mess_length; i++)
	{
	  char buf[4];
	  sprintf(buf, " %02x", v.u8[i]);
	  out << buf;
	  if (i%16 == 15) out << std::endl;
	}
	return out;
}

uint64_t swapLong(uint64_t X) {
  uint64_t x = (uint64_t) X;
x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
x = (x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8;
return x;
}

static const uint8_t TABLE_PI[256] {
	252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77, 233, 119, 240, 219, 147,  46, 153,
	186,  23,  54, 241, 187,  20, 205,  95, 193, 249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,   5, 132,
	  2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31, 235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104,
	162, 253,  58, 206, 204, 181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,  21, 161, 150,  41,  16,
	123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,  50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195,
	189,  13,  87, 223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3, 224,  15, 236, 222, 122, 148,
	176, 188, 220, 232,  40,  80,  78,  51,  10,  74, 167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65, 173,
	 69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,   7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107,
	228, 136, 217, 231, 137, 225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,  32, 113, 103,
	164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,  89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,
	 57,  75,  99, 182
							  };

static const uint8_t TABLE_TAU[64] {
	0,  8, 16, 24, 32, 40, 48, 56,
	1,  9, 17, 25, 33, 41, 49, 57,
	2, 10, 18, 26, 34, 42, 50, 58,
	3, 11, 19, 27, 35, 43, 51, 59,
	4, 12, 20, 28, 36, 44, 52, 60,
	5, 13, 21, 29, 37, 45, 53, 61,
	6, 14, 22, 30, 38, 46, 54, 62,
	7, 15, 23, 31, 39, 47, 55, 63
};
//   0xULL
static const uint64_t TABLE_A[64] {
	0x8e20faa72ba0b470ULL, 0x47107ddd9b505a38ULL, 0xad08b0e0c3282d1cULL, 0xd8045870ef14980eULL,
	0x6c022c38f90a4c07ULL, 0x3601161cf205268dULL, 0x1b8e0b0e798c13c8ULL, 0x83478b07b2468764ULL,
	0xa011d380818e8f40ULL, 0x5086e740ce47c920ULL, 0x2843fd2067adea10ULL, 0x14aff010bdd87508ULL,
	0x0ad97808d06cb404ULL, 0x05e23c0468365a02ULL, 0x8c711e02341b2d01ULL, 0x46b60f011a83988eULL,
	0x90dab52a387ae76fULL, 0x486dd4151c3dfdb9ULL, 0x24b86a840e90f0d2ULL, 0x125c354207487869ULL,
	0x092e94218d243cbaULL, 0x8a174a9ec8121e5dULL, 0x4585254f64090fa0ULL, 0xaccc9ca9328a8950ULL,
	0x9d4df05d5f661451ULL, 0xc0a878a0a1330aa6ULL, 0x60543c50de970553ULL, 0x302a1e286fc58ca7ULL,
	0x18150f14b9ec46ddULL, 0x0c84890ad27623e0ULL, 0x0642ca05693b9f70ULL, 0x0321658cba93c138ULL,
	0x86275df09ce8aaa8ULL, 0x439da0784e745554ULL, 0xafc0503c273aa42aULL, 0xd960281e9d1d5215ULL,
	0xe230140fc0802984ULL, 0x71180a8960409a42ULL, 0xb60c05ca30204d21ULL, 0x5b068c651810a89eULL,
	0x456c34887a3805b9ULL, 0xac361a443d1c8cd2ULL, 0x561b0d22900e4669ULL, 0x2b838811480723baULL,
	0x9bcf4486248d9f5dULL, 0xc3e9224312c8c1a0ULL, 0xeffa11af0964ee50ULL, 0xf97d86d98a327728ULL,
	0xe4fa2054a80b329cULL, 0x727d102a548b194eULL, 0x39b008152acb8227ULL, 0x9258048415eb419dULL,
	0x492c024284fbaec0ULL, 0xaa16012142f35760ULL, 0x550b8e9e21f7a530ULL, 0xa48b474f9ef5dc18ULL,
	0x70a6a56e2440598eULL, 0x3853dc371220a247ULL, 0x1ca76e95091051adULL, 0x0edd37c48a08a6d8ULL,
	0x07e095624504536cULL, 0x8d70c431ac02a736ULL, 0xc83862965601dd1bULL, 0x641c314b2b8ee083ULL
};
//b1085bda1ecadae9 ebcb2f81c0657c1f 2f6a76432e45d016 714eb88d7585c4fc
//378ee767f11631ba d21380b00449b17a cda43c32bcdf1d77 f82012d430219f9b
//5d80ef9d1891cc86 e71da4aa88e12852 faf417d5d9b21b99 48bc924af11bd720



static const vec512_t TABLE_C[12]
{
	{ 		0xdd806559f2a64507ULL,
			0x05767436cc744d23ULL,
			0xa2422a08a460d315ULL,
			0x4b7ce09192676901ULL,
			0x714eb88d7585c4fcULL,
			0x2f6a76432e45d016ULL,
			0xebcb2f81c0657c1fULL,
			0xb1085bda1ecadae9ULL},
		{ 	0xe679047021b19bb7ULL,
			0x55dda21bd7cbcd56ULL,
			0x5cb561c2db0aa7caULL,
			0x9ab5176b12d69958ULL,
			0x61d55e0f16b50131ULL,
			0xf3feea720a232b98ULL,
			0x4fe39d460f70b5d7ULL,
			0x6fa3b58aa99d2f1aULL},
		{ 	0x991e96f50aba0ab2ULL,
			0xc2b6f443867adb31ULL,
			0xc1c93a376062db09ULL,
			0xd3e20fe490359eb1ULL,
			0xf2ea7514b1297b7bULL,
			0x06f15e5f529c1f8bULL,
			0x0a39fc286a3d8435ULL,
			0xf574dcac2bce2fc7ULL},
		{ 	0x220cbebc84e3d12eULL,
			0x3453eaa193e837f1ULL,
			0xd8b71333935203beULL,
			0xa9d72c82ed03d675ULL,
			0x9d721cad685e353fULL,
			0x488e857e335c3c7dULL,
			0xf948e1a05d71e4ddULL,
			0xef1fdfb3e81566d2ULL},
		{ 	0x601758fd7c6cfe57ULL,
			0x7a56a27ea9ea63f5ULL,
			0xdfff00b723271a16ULL,
			0xbfcd1747253af5a3ULL,
			0x359e35d7800fffbdULL,
			0x7f151c1f1686104aULL,
			0x9a3f410c6ca92363ULL,
			0x4bea6bacad474799ULL},
		{ 	0xfa68407a46647d6eULL,
			0xbf71c57236904f35ULL,
			0x0af21f66c2bec6b6ULL,
			0xcffaa6b71c9ab7b4ULL,
			0x187f9ab49af08ec6ULL,
			0x2d66c4f95142a46cULL,
			0x6fa4c33b7a3039c0ULL,
			0xae4faeae1d3ad3d9ULL},
		{ 	0x8886564d3a14d493ULL,
			0x3517454ca23c4af3ULL,
			0x06476983284a0504ULL,
			0x0992abc52d822c37ULL,
			0xd3473e33197a93c9ULL,
			0x399ec6c7e6bf87c9ULL,
			0x51ac86febf240954ULL,
			0xf4c70e16eeaac5ecULL},
		{ 	0xa47f0dd4bf02e71eULL,
			0x36acc2355951a8d9ULL,
			0x69d18d2bd1a5c42fULL,
			0xf4892bcb929b0690ULL,
			0x89b4443b4ddbc49aULL,
			0x4eb7f8719c36de1eULL,
			0x03e7aa020c6e4141ULL,
			0x9b1f5b424d93c9a7ULL},
		{ 	0x7261445183235adbULL,
			0x0e38dc92cb1f2a60ULL,
			0x7b2b8a9aa6079c54ULL,
			0x800a440bdbb2ceb1ULL,
			0x3cd955b7e00d0984ULL,
			0x3a7d3a1b25894224ULL,
			0x944c9ad8ec165fdeULL,
			0x378f5a541631229bULL},
		{ 	0x74b4c7fb98459cedULL,
			0x3698fad1153bb6c3ULL,
			0x7a1e6c303b7652f4ULL,
			0x9fe76702af69334bULL,
			0x1fffe18a1b336103ULL,
			0x8941e71cff8a78dbULL,
			0x382ae548b2e4f3f3ULL,
			0xabbedea680056f52ULL},
		{ 	0x6bcaa4cd81f32d1bULL,
			0xdea2594ac06fd85dULL,
			0xefbacd1d7d476e98ULL,
			0x8a1d71efea48b9caULL,
			0x2001802114846679ULL,
			0xd8fa6bbbebab0761ULL,
			0x3002c6cd635afe94ULL,
			0x7bcd9ed0efc889fbULL},
		{ 	0x48bc924af11bd720ULL,
			0xfaf417d5d9b21b99ULL,
			0xe71da4aa88e12852ULL,
			0x5d80ef9d1891cc86ULL,
			0xf82012d430219f9bULL,
			0xcda43c32bcdf1d77ULL,
			0xd21380b00449b17aULL,
			0x378ee767f11631baULL}
};

/*vec512_t X(const vec512_t &k, const vec512_t &a)
{
	vec512_t result;

	for (int i = 0; i < 64; i++)
		result.u8[i] = k->u8[i] ^ a->u8[i];

}*/


vec512_t S(const vec512_t &a)
{
	vec512_t result;
	for (int i = 0; i < 64; i++)
		result.u8[i] = TABLE_PI[a.u8[i]];
	return result;

}

vec512_t P(const vec512_t &a)
{
	vec512_t result;
	for (int i = 0; i < 64; i++)
	{
		result.u8[i] = a.u8[TABLE_TAU[i]];
	}
	return result;
}
// b383fc2eced4a574
vec512_t L(const vec512_t &a)
{
	vec512_t result;
	for (int i = 0; i < 8; i++){
		result.u64[i]  = 0;

		for (int j = 0; j < 64; j++)
		{
			if (a.u64[i] & (1ULL << j))
				result.u64[i] ^= TABLE_A[63 - j];
		}
	}

	return result;

}

vec512_t E(const vec512_t &k, const vec512_t &m)
{
	vec512_t result;
	vec512_t t;
	result = k ^ m;
	result = S(result);
	result = P(result);
	result = L(result);

	return result;

}

 void gn(const vec512_t &N,const vec512_t &h,const vec512_t &m, vec512_t &x)
{
	vec512_t E_k_m;
	vec512_t K[13];
	//1
	K[0] = L(P(S(h ^ N)));
	std::cout << K[0] << " = K[" << 1 << "] " << std::endl;
	E_k_m = E(K[0],m);
	std::cout << E_k_m << " = E " << 1 << std::endl;

	/*K[1] = L(P(S(K[0] ^ TABLE_C[0])));
	std::cout << K[1] << " = K[" << 2 << "] " << std::endl;
	E_k_m = E(K[1],E_k_m);
	std::cout << E_k_m << " = E " << 2 << std::endl;*/

	for (int i = 1; i < 13; i++)
	{
		K[i] = L(P(S(K[i-1] ^ TABLE_C[i-1])));
		std::cout << K[i] << " = K[" << i+1 << "] " << std::endl;
		if (i !=12)
			E_k_m = E(K[i],E_k_m);
		else
			E_k_m = E_k_m ^ K[i];
		std::cout << E_k_m << " = E " << i+1 << std::endl;
	}
	x = E_k_m ^ h ^ m;
	std::cout << x << " = E ^ h ^ m"  << std::endl;

	/*//2
	K[1] = L(P(S(K[0] ^ TABLE_C[0])));
	std::cout << K[1] << " = K[" << 2 << "] " << std::endl;
	E_k_m = E(K[1],E_k_m);
	std::cout << E_k_m << " = E " << 2 << std::endl;
	//3
	K[2] = L(P(S(K[1] ^ TABLE_C[1])));
	std::cout << K[2] << " = K[" << 3 << "] " << std::endl;
	E_k_m = E(K[2],E_k_m);
	std::cout << E_k_m << " = E " << 3 << std::endl;
	K[0] = L(P(S(h ^ N)));
	std::cout << K[0] << " = K[" << 1 << "] " << std::endl;
	E = S(K[0] ^ m);
	std::cout << E << " = E " << 1 << std::endl;
	//1
	K[0] = L(P(S(h ^ N)));
	std::cout << K[0] << " = K[" << 1 << "] " << std::endl;
	E = L(P(S(K[0] ^ m)));
	std::cout << E << " = E " << 1 << std::endl;
	//2
	K[1] = L(P(S(K[0] ^ TABLE_C[0])));
	std::cout << K[1] << " = K[" << 2 << "] " << std::endl;
	E = L(P(S(K[1]))) ^ E;
	std::cout << E << " = E " << 2 << std::endl;*/

	/*for (int i = 1; i < 13; i++)
	{

		K[i] = L(P(S(K[i-1] ^ TABLE_C[i-1])));
		std::cout << K[i] << " = K[" << i << "]" << std::endl;
		if (i!=11)
			E = L(P(S(K[i])))^E;
		else
			E = E ^ K[i];
		std::cout << E << " = E " << i << std::endl;
	}*/
	/*K[1] = L(P(S(K[0] ^ TABLE_C[0])));
	std::cout << K[1] << " = K[" << 2 << "]" << std::endl;
	E = L(P(S(K[1] ^ E)));
	std::cout << E << " = E " << 2 << std::endl;*/
	/*x = E ^ h ^ m;
	std::cout << x << " = E ^ h ^ m"  << std::endl;*/

}

void gost_34_11_hash_512()
{
	// 1 ????
	vec512_t h = {};
	vec512_t N = {};
	vec512_t sum = {};
	for (int i = 0; i < 8; i++)
	{
		h.u64[i]   = 0x00000000;
		N.u64[i]   = 0x00000000;
		sum.u64[i] = 0x00000000;
	}
	int mess_length = sizeof(message)/sizeof(uint8_t) ;
	int mess_length2 = mess_length * 8;


	std::cout << mess_length << " = mess_length " << mess_length2 << " = mess_length2" << std::endl;
	vec512_t m = {};
	int i_m = 0;
	/*for (; i_m < mess_length; i_m++)
	{
		m.u8[i_m] = message3[i_m];
	}*/
	// 2 ????
	while (mess_length2 >= 512)
	{
		std::cout << "mess_length2 >= 512" << std::endl;
		for (; i_m < 64; i_m++)
		{
				m.u8[i_m] = message[i_m];
		}
		std::cout << m << " = m hex2" << std::endl;

		gn(N,h,m,h);
		std::cout << h << " = h"  << std::endl;

		N += 512ULL;
		//std::cout << N.u8 << " = N"  << std::endl;

		sum +=m;
		//std::cout << sum.u8 << " = sum"  << std::endl;

		mess_length2 -=  512;

	}
	for (; i_m < mess_length; i_m++)
		{
			m.u8[i_m] = message[i_m];
		}

	std::cout << m << " = m hex" << std::endl;
	if (i_m < 64)
	{
		m.u8[i_m++] = 0x01;
		while (i_m < 64)
			m.u8[i_m++] = 0x00;
	}
	std::cout << m << " = m hex" << std::endl;
	//3 ????

	gn(N,h,m,h);
	std::cout << h << " = h gn after"  << std::endl;

	N += mess_length2;
	std::cout << N << " = N"  << std::endl;

	sum +=m;
	std::cout << sum << " = sum"  << std::endl;

	gn(0,h,N,h);
	std::cout << h << " = G0 N"  << std::endl;

	gn(0,h,sum,h);

	std::cout << h << " = G0 sum"  << std::endl;

}

}
}


