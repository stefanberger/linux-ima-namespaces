// SPDX-License-Identifier: Apache-2.0

/*----------------------------------------------------------------------
 *
 * Dilithium variants supported (K/L):
 *   round2
 *     Dil III   Dil-5/4
 *     Dil IV    Dil-6/5
 *     Dil V     Dil-8/7
 *   round3 (2021-02 update)
 *     Dil II    Dil-4/4
 *     Dil III   Dil-6/5
 *     Dil V     Dil-8/7
 *
 * define
 *    USE_STATIC_MLCA  -- make public functions static; suitable for
 *                     -- single-file distribution
 *
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <crypto/sha3.h>
#include <crypto/hash.h>

#include "keccak.h"
#include "mldsa_crypto.h"

#define UINT64_C(X) ((uint64_t)X)

#include "pqalgs.h" /* our own prototypes */
#if !defined(COMMON_BASE_H__)
#define COMMON_BASE_H__ 1

#if (__GNUC__ >= 3) /* note: pre-gcc3 support is basically irrelevant */
#define ATTR_PURE__ __attribute__((pure))
#define ATTR_CONST__ __attribute__((const))

#else
#define ATTR_PURE__ /**/
#define ATTR_CONST__ /**/
#endif /* gcc >= 3 */

/* NOP marker for possibly-sensitive stack structs */
#define CRS_SENSITIVE /**/

/*--------------------------------------
 * endianness-conversion 'macros'
 * assuming ntohl() etc. are real functions, not static-inline macros
 */

/*------------------------------------*/
static inline uint32_t MSBF3_READ(const void *p)
{
	const unsigned char *pb = (const unsigned char *)p;

	return ((((uint32_t)(pb)[2])) | (((uint32_t)((pb)[1])) << 8) |
		(((uint32_t)((pb)[0])) << 16));
}

/*------------------------------------*/
static inline uint32_t MSBF4_READ(const void *p)
{
	const unsigned char *pb = (const unsigned char *)p;

	return ((((uint32_t)(pb)[3])) | (((uint32_t)((pb)[2])) << 8) |
		(((uint32_t)((pb)[1])) << 16) | (((uint32_t)((pb)[0])) << 24));
}

/*------------------------------------*/
static inline uint32_t LSBF4_READ(const void *p)
{
	const unsigned char *pb = (const unsigned char *)p;

	return ((((uint32_t)(pb)[0])) | (((uint32_t)((pb)[1])) << 8) |
		(((uint32_t)((pb)[2])) << 16) | (((uint32_t)((pb)[3])) << 24));
}

/*--------------------------------------
 * assume this gets inlined, possibly through bswap() or equivalent
 * recent gcc/clang and some xlc's tend to do so
 */
static inline void MSBF4_WRITE(void *p, uint64_t v)
{
	unsigned char *pb = (unsigned char *)p;

	pb[3] = (unsigned char)v;
	pb[2] = (unsigned char)(v >> 8);
	pb[1] = (unsigned char)(v >> 16);
	pb[0] = (unsigned char)(v >> 24);
}

/*--------------------------------------
 * assume this gets inlined, possibly through bswap() or equivalent
 * recent gcc/clang and some xlc's tend to do so
 */

#endif /* !defined(COMMON_BASE_H__) */

#if defined(NO_CRYSTALS_SIG)
#if defined(NO_CRYSTALS_CIP) && defined(NO_CRYSTALS_KEX)
#error "error: both signature and key-transport/encryption has been prohibited"
#endif
#endif

/* conditionally keep top fns module-local */
#if defined(USE_STATIC_MLCA)
#define CRS_STATIC static
#else
#define CRS_STATIC /**/
#endif

#if 1 /*-----  delimiter: reduce  ------------------------------------*/
#define DIL_Q 8380417

/*
 * round3 equivalent, first with ref.impl-compatible signed units
 * unless otherwise noted, DIL_... constants are identical for r2 and r3
 */
#define DIL_SD 13
#define DIL_SMONT -4186625 /* 2^32 % DIL_Q, signed units */
#define DIL_SQINV 58728449 /* 1/DIL_Q mod 2^32, signed units */
/**/

#define DIL_SEEDBYTES ((unsigned int)256 / 8)
#define DIL_CRHBYTES ((unsigned int)384 / 8)
#define DIL_R3_CRHBYTES ((unsigned int)512 / 8)
/* max(r2, r3 CRH) */
#define DIL_MAX_CRHBYTES DIL_R3_CRHBYTES

#define DIL_R3_POLYT0_PACKEDBYTES ((unsigned int)416)
#define DIL_R3_POLYT1_PACKEDBYTES ((unsigned int)320)
/**/
/* r3 is param-dependent */
/**/
/* r3 is param-dependent, see dil_r3k2polyz_bytes() */

/* K/L-dependent values for (5,4), (6,5), (8,7) */
/**/
#define DIL_PUB_BYTES(k) (DIL_SEEDBYTES + (k) * DIL_R2_POLYT1_PACKEDBYTES)
#define DIL_PUB5x4_BYTES DIL_PUB_BYTES(5)
#define DIL_PUB6x5_BYTES DIL_PUB_BYTES(6)
#define DIL_PUB8x7_BYTES DIL_PUB_BYTES(8)
/* round3 and round3.0 are identical: */
#define DIL_R3_PUB4x4_BYTES ((size_t)1312)
#define DIL_R3_PUB6x5_BYTES ((size_t)1952)
#define DIL_R3_PUB8x7_BYTES ((size_t)2592)

#define DIL_BETA5x4 275
#define DIL_BETA6x5 175
#define DIL_BETA8x7 120

#define DIL_R3_BETA4x4 78
#define DIL_R3_BETA6x5 196
#define DIL_R3_BETA8x7 120

#define DIL_OMEGA5x4 96
#define DIL_OMEGA6x5 120
#define DIL_OMEGA8x7 140

#define DIL_R3_OMEGA4x4 80
#define DIL_R3_OMEGA6x5 55
#define DIL_R3_OMEGA8x7 75

#define DIL_SIGBYTES5x4 2701
#define DIL_SIGBYTES6x5 3366
#define DIL_SIGBYTES8x7 4668

#define DIL_R3_SIGBYTES4x4 2420
#define DIL_R3_SIGBYTES6x5 3293
#define DIL_R3_SIGBYTES8x7 4595

#define DIL_MLDSA_SIGBYTES4x4 2420
#define DIL_MLDSA_SIGBYTES6x5 3309
#define DIL_MLDSA_SIGBYTES8x7 4627

/*
 * raw bytecounts, excl. any ASN.1/BER framing or post-appended in-band type
 * hardwired since formula contains conditionals; do not expect
 * compiler constant expansion
 */
#define DIL_PRV5x4_BYTES ((size_t)3504)
#define DIL_PRV6x5_BYTES ((size_t)3856)
#define DIL_PRV8x7_BYTES ((size_t)5136)
/* see also dil_prv_wirebytes()
 */
/* was round3 v0:
#define  DIL_R3_PRV4x4_BYTES  ((size_t) 2544)   // r3.0
#define  DIL_R3_PRV6x5_BYTES  ((size_t) 4016)   // r3.0
#define  DIL_R3_PRV8x7_BYTES  ((size_t) 4880)   // r3.0
*/
#define DIL_R3_PRV4x4_BYTES ((size_t)2528)
#define DIL_R3_PRV6x5_BYTES ((size_t)4000)
#define DIL_R3_PRV8x7_BYTES ((size_t)4864)

#define DIL_MLDSA_PRV4x4_BYTES ((size_t)2560)
#define DIL_MLDSA_PRV6x5_BYTES ((size_t)4032)
#define DIL_MLDSA_PRV8x7_BYTES ((size_t)4896)

/* ETA <= 3 decides */
#define DIL_POLYETA5x4_PACKEDBYTES ((size_t)128)
#define DIL_POLYETA6x5_PACKEDBYTES ((size_t)96)
#define DIL_POLYETA8x7_PACKEDBYTES ((size_t)96)
/**/
#define DIL_R3_POLYETA4x4_PACKEDBYTES ((size_t)96)
#define DIL_R3_POLYETA6x5_PACKEDBYTES ((size_t)128)
#define DIL_R3_POLYETA8x7_PACKEDBYTES ((size_t)96)

#define DIL_MLDSA_44_CTILDEBYTES ((size_t)32)
#define DIL_MLDSA_65_CTILDEBYTES ((size_t)48)
#define DIL_MLDSA_87_CTILDEBYTES ((size_t)64)
#define DIL_MLDSA_MAX_CTILDEBYTES DIL_MLDSA_87_CTILDEBYTES

#define DIL_VECT_MAX ((unsigned int)8) /* MAX(K, L) for any config */

/* trailing bytes _after_ raw key material, storing type as BE unsigned value:
 */
#define CRS_WTYPE_BYTES ((size_t)4)

//--------------------------------------
typedef enum {
	CRS_ALG_FL_SIG = 1, // things related to signatures
	CRS_ALG_FL_KEX = 2, // ...related to key exchange...
	CRS_ALG_FL_CIP = 4 // ...related to encryption...
} CRS_AlgFlag_t;
#endif

#if 1 /*-----  delimiter: SHA-3 PRF  -------------------------------------*/
/* SHA-3 PRF only: */
#define DIL_STREAM128_BLOCKBYTES SHAKE128_RATE
typedef Keccak_state stream128_state;
/**/
#define stream128_init(STATE, SEED, NONCE) \
	shake128_stream_init(STATE, SEED, NONCE)
#define stream128_wipe(STATE) shake128_wipe(STATE)

#endif /*-----  /delimiter: SHA-3 PRF  ------------------------------------*/

/* /header constants from params.h */

/*--------------------------------------
 * signed (r3 ref.) counterpart of montgomery_reduce()
 */
ATTR_CONST__
/**/
static int32_t montgomery_s_reduce(int64_t a)
{
	int32_t t;

	t = (int64_t)a * DIL_SQINV;

	t = (a - (int64_t)t * DIL_Q) >> 32;

	return t;
}

/*************************************************
 * signed (r3 ref.impl.) counterpart of reduce32()
 *
 * Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *              compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
 * Arguments:   - int32_t: finite field element a
 * Returns r.
 **************************************************/
ATTR_CONST__
/**/
static int32_t s_reduce32(int32_t a)
{
	int32_t t;

	t = (a + (1 << 22)) >> 23;
	t = a - t * DIL_Q;

	return t;
}

/*************************************************
 * Description: Add Q if input coefficient is negative.
 * Arguments:   - int32_t: finite field element a
 */
static int32_t s_caddq(int32_t a)
{
	a += (a >> 31) & DIL_Q;

	return a;
}

volatile int32_t int32_t_blocker = 0;

#if 1 /*-----  delimiter: NTT  ---------------------------------------*/
/* Kyber and Dilithium primes, so NTT-internal reductions, differ */

#define DIL_N ((unsigned int)256)

static const uint8_t mldsa_ds_pure[2] = { 0x0, 0x0 };

/*-----  round3 NTT  -------------------------------------------------------*/

static const int32_t s_zetas[DIL_N] = {
	0,	  25847,    -2608894, -518909,	237124,	  -777960,  -876248,
	466468,	  1826347,  2353451,  -359251,	-2091905, 3119733,  -2884855,
	3111497,  2680103,  2725464,  1024112,	-1079900, 3585928,  -549488,
	-1119584, 2619752,  -2108549, -2118186, -3859737, -1399561, -3277672,
	1757237,  -19422,   4010497,  280005,	2706023,  95776,    3077325,
	3530437,  -1661693, -3592148, -2537516, 3915439,  -3861115, -3043716,
	3574422,  -2867647, 3539968,  -300467,	2348700,  -539299,  -1699267,
	-1643818, 3505694,  -3821735, 3507263,	-2140649, -1600420, 3699596,
	811944,	  531354,   954230,   3881043,	3900724,  -2556880, 2071892,
	-2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
	2176455,  -1585221, -1257611, 1939314,	-4083598, -1000202, -3190144,
	-3157330, -3632928, 126922,   3412210,	-983419,  2147896,  2715295,
	-2967645, -3693493, -411027,  -2477047, -671102,  -1228525, -22981,
	-1308169, -381987,  1349076,  1852771,	-1430430, -3343383, 264944,
	508951,	  3097992,  44288,    -1100098, 904516,	  3958618,  -3724342,
	-8578,	  1653064,  -3249728, 2389356,	-210977,  759969,   -1316856,
	189548,	  -3553272, 3159746,  -1851402, -2409325, -177440,  1315589,
	1341330,  1285669,  -1584928, -812732,	-1439742, -3019102, -3881060,
	-3628969, 3839961,  2091667,  3407706,	2316500,  3817976,  -3342478,
	2244091,  -2446433, -3562462, 266997,	2434439,  -1235728, 3513181,
	-3520352, -3759364, -1197226, -3193378, 900702,	  1859098,  909542,
	819034,	  495491,   -1613174, -43260,	-522500,  -655327,  -3122442,
	2031748,  3207046,  -3556995, -525098,	-768622,  -3595838, 342297,
	286988,	  -2437823, 4108315,  3437287,	-3342277, 1735879,  203044,
	2842341,  2691481,  -2590150, 1265009,	4055324,  1247620,  2486353,
	1595974,  -3767016, 1250494,  2635921,	-3548272, -2994039, 1869119,
	1903435,  -1050970, -1333058, 1237275,	-3318210, -1430225, -451100,
	1312455,  3306115,  -1962642, -1279661, 1917081,  -2546312, -1374803,
	1500165,  777191,   2235880,  3406031,	-542412,  -2831860, -1671176,
	-1846953, -2584293, -3724270, 594136,	-3776993, -2013608, 2432395,
	2454455,  -164721,  1957272,  3369112,	185531,	  -1207385, -3183426,
	162844,	  1616392,  3014001,  810149,	1652634,  -3694233, -1799107,
	-3038916, 3523897,  3866901,  269760,	2213111,  -975884,  1717735,
	472078,	  -426683,  1723600,  -1803090, 1910376,  -1667432, -1104333,
	-260646,  -3833893, -2939036, -2235985, -420899,  -2286327, 183443,
	-976891,  1612842,  -3545687, -554416,	3919660,  -48306,   -1362209,
	3937738,  1400424,  -846154,  1976782
};

/*************************************************
 * signed (r3 ref.) counterpart of ntt256()
 *
 * Description: Forward NTT, in-place. No modular reduction is performed after
 *              additions or subtractions. Output vector is in bitreversed order.
 * Arguments:   - uint32_t p[N]: input/output coefficient array
 **************************************************/
static void sntt256(int32_t a[DIL_N])
{
	unsigned int len, start, j, k = 0;
	int32_t zeta, t;

	for (len = 128; len > 0; len >>= 1) {
		for (start = 0; start < DIL_N; start = j + len) {
			zeta = s_zetas[++k];

			for (j = start; j < start + len; ++j) {
				t = montgomery_s_reduce((int64_t)zeta *
							a[j + len]);

				a[j + len] = a[j] - t;

				a[j] = a[j] + t;
			}
		}
	}
}

/*************************************************
 * signed (r3 ref.) counterpart of invntt_tomont256()
 *
 * Description: Inverse NTT and multiplication by Montgomery factor 2^32.
 *              In-place. No modular reductions after additions or
 *              subtractions; input coefficients need to be smaller than
 *              Q in absolute value. Output coefficient are smaller than Q in
 *              absolute value.
 * Arguments:   - uint32_t p[N]: input/output coefficient array
 **************************************************/
static void invntt_s_tomont256(int32_t a[DIL_N])
{
	int32_t f = 41978; /* mont^2/256 */
	unsigned int start, len, j, k;
	int32_t t, zeta;

	k = 256;

	for (len = 1; len < DIL_N; len <<= 1) {
		for (start = 0; start < DIL_N; start = j + len) {
			zeta = -s_zetas[--k];

			for (j = start; j < start + len; ++j) {
				t = a[j];

				a[j] = t + a[j + len];

				a[j + len] = t - a[j + len];

				a[j + len] = montgomery_s_reduce((int64_t)zeta *
								 a[j + len]);
			}
		}
	}

	for (j = 0; j < DIL_N; ++j) {
		a[j] = montgomery_s_reduce((int64_t)f * a[j]);
	}
}

#endif /*-----  /delimiter: NTT  --------------------------------------*/

#if 1 /*-----  delimiter: rounding  ----------------------------------*/

/*--------------------------------------
 * expanded form of GAMMA1, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 *
 * assume inlining/const-propagation on any reasonable platform
 */
ATTR_CONST__
/**/
static int32_t dil_r3k2gamma1(unsigned int k)
{
	switch (k) {
	case 4:
		return (1 << 17);

	case 6:
	case 8:
		return (1 << 19);

	default:
		return 0;
	}
}

/*--------------------------------------
 * expanded form of GAMMA2, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 *
 * assume inlining/const-propagation on any reasonable platform
 */
ATTR_CONST__
/**/
static int32_t dil_r3k2gamma2(unsigned int k)
{
	switch (k) {
	case 4:
		return 95232; /* (DIL_Q -1) /88 */

	case 6:
	case 8:
		return 261888; /* (DIL_Q -1) /32 */

	default:
		return 0;
	}
}

/*--------------------------------------
 * expanded form of POLYZ_PACKEDBYTES, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 *
 * assume inlining/const-propagation on any reasonable platform
 */
ATTR_CONST__
/**/
static size_t dil_r3k2polyz_bytes(unsigned int k)
{
	switch (k) {
	case 4:
		return 576;

	case 6:
	case 8:
		return 640;

	default:
		return 0;
	}
}

/*--------------------------------------
 * expanded form of POLYW1_PACKEDBYTES, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 *
 * assume inlining/const-propagation on any reasonable platform
 */
ATTR_CONST__
/**/
static size_t dil_r3k2polyw1_bytes(unsigned int k)
{
	switch (k) {
	case 4:
		return 192;
	case 6:
	case 8:
		return 128;

	default:
		return 0;
	}
}
/*
 * verification needs max(K * w1-bytes) as an upper limit, this is it:
 */
#define DIL__KxPOLYW1_MAX_BYTES ((size_t)1024)

/*--------------------------------------
 * expanded form of POLYETA_PACKEDBYTES, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 *
 * assume inlining/const-propagation on any reasonable platform
 */
ATTR_CONST__
/**/
static size_t dil_mldsa_ctilbytes(unsigned int k)
{
	switch (k) {
	case 4:
		return DIL_MLDSA_44_CTILDEBYTES;
	case 6:
		return DIL_MLDSA_65_CTILDEBYTES;
	case 8:
		return DIL_MLDSA_87_CTILDEBYTES;

	default:
		return 0;
	}
}

/*--------------------------------------
 * signed (r3 ref.) counterpart of decompose()
 */
static int32_t s_decompose(int32_t *a0, int32_t a, unsigned int dil_k)
{
	int32_t a1;

	a1 = (a + 127) >> 7;

	/* original condition: GAMMA2 == (DIL_Q-1) /32
     *   -> Dil3 (6x5), Dil5 (8x7)
     */
	if (dil_k != 4) {
		a1 = (a1 * 1025 + (1 << 21)) >> 22;
		a1 &= 15;

		/* original condition: GAMMA2 == (DIL_Q-1) /88
         *   -> Dil2 (4x4)
         */
	} else {
		a1 = (a1 * 11275 + (1 << 23)) >> 24;
		a1 ^= (((43 - a1) >> 31) ^ int32_t_blocker) & a1;
	}

	*a0 = a - a1 * 2 * dil_r3k2gamma2(dil_k); /* was: * GAMMA2; */

	*a0 -= (((DIL_Q - 1) / 2 - *a0) >> 31) & DIL_Q;

	return a1;
}

/*--------------------------------------
 * signed (r3 ref.) counterpart of use_hint()
 */
static int32_t use_s_hint(int32_t a, unsigned int hint, unsigned int dil_k)
{
	int32_t a0, a1;

	a1 = s_decompose(&a0, a, dil_k);

	if (hint == 0)
		return a1;

	/* original condition: GAMMA2 == (DIL_Q-1) /32
     *   -> Dil3 (6x5), Dil5 (8x7)
     */
	if (dil_k != 4) {
		if (a0 > 0) {
			return (a1 + 1) & 15;
		} else {
			return (a1 - 1) & 15;
		}

		/* original condition: GAMMA2 == (DIL_Q-1) /88
         *   -> Dil2 (4x4)
         */
	} else {
		if (a0 > 0) {
			return (a1 == 43) ? 0 : a1 + 1;
		} else {
			return (a1 == 0) ? 43 : a1 - 1;
		}
	}
}

#endif /*-----  /delimiter: rounding  ---------------------------------*/

static void shake128_stream_init(Keccak_state *state,
				 const uint8_t seed[DIL_SEEDBYTES],
				 uint16_t nonce)
{
	uint8_t t[2];

	t[0] = nonce;
	t[1] = nonce >> 8;

	shake128_init(state);
	shake128_absorb(state, seed, DIL_SEEDBYTES);
	shake128_absorb(state, t, 2);
	shake128_finalize(state);
}

/*----------------------------------*/
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)

#define stream256_wipe(STATE) shake256_wipe(STATE)

//--------------------------------------
static inline size_t dil_crh(unsigned char *res, size_t rbytes,
			     const unsigned char *seed, size_t sbytes)
{
	shake256(res, rbytes, seed, sbytes);

	return rbytes;
}

#if 1 /*-----  delimiter: poly  --------------------------------------*/

typedef struct {
	uint32_t coeffs[DIL_N]; /* round2 */
} poly;

typedef struct {
	int32_t coeffs[DIL_N]; /* round3 */
} spoly;

#if !defined(NO_CRYSTALS_SIG) /*-------------------------------------------*/

/*************************************************
 * Name:        poly_uniform
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [0,Q-1] by performing rejection sampling using the
 *              output stream of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
 *
 * Arguments:   - poly *a: pointer to output polynomial
 *              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
 *              - uint16_t nonce: 2-byte nonce
 **************************************************/
#define POLY_UNIFORM_NBLOCKS \
	((768 + DIL_STREAM128_BLOCKBYTES - 1) / DIL_STREAM128_BLOCKBYTES)

#if 1 /* delimiter: round3 */
/*************************************************
 * Description: Inplace reduction of all coefficients of polynomial to
 *              representative in [-6283009,6283007].
 * Arguments:   - spoly *a: pointer to input/output polynomial
 **************************************************/
static void spoly_reduce(spoly *a)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i)
		a->coeffs[i] = s_reduce32(a->coeffs[i]);
}

/*************************************************
 * Description: For all coefficients of in/out polynomial add Q if
 *              coefficient is negative.
 * Arguments:   - spoly *a: pointer to input/output polynomial
 **************************************************/
static void spoly_caddq(spoly *a)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i)
		a->coeffs[i] = s_caddq(a->coeffs[i]);
}

/*************************************************
 * Description: Add polynomials. No modular reduction is performed.
 * Arguments:   - spoly *c: pointer to output polynomial
 *              - const spoly *a: pointer to first summand
 *              - const spoly *b: pointer to second summand
 **************************************************/
static void spoly_add(spoly *c, const spoly *a, const spoly *b)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i)
		c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 * Arguments:   - spoly *c: pointer to output polynomial
 *              - const spoly *a: pointer to first input polynomial
 *              - const spoly *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 **************************************************/
static void spoly_sub(spoly *c, const spoly *a, const spoly *b)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i)
		c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************************************************
 * Description: Multiply polynomial by 2^D without modular reduction. Assumes
 *              input coefficients to be less than 2^{31-D} in absolute value.
 * Arguments:   - spoly *a: pointer to input/output polynomial
 **************************************************/
static void spoly_shiftl(spoly *a)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i)
		a->coeffs[i] <<= DIL_SD;
}

/*************************************************
 * Description: Inplace forward NTT. Coefficients can grow by
 *              8*Q in absolute value.
 * Arguments:   - spoly *a: pointer to input/output polynomial
 **************************************************/
static void spoly_ntt256(spoly *a)
{
	sntt256(a->coeffs);
}

/*************************************************
 * Description: Inplace inverse NTT and multiplication by 2^{32}.
 *              Input coefficients need to be less than Q in absolute
 *              value and output coefficients are again bounded by Q.
 *
 * Arguments:   - spoly *a: pointer to input/output polynomial
 **************************************************/
static void spoly_invntt_tomont(spoly *a)
{
	invntt_s_tomont256(a->coeffs);
}

/*************************************************
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting polynomial
 *              by 2^{-32}.
 * Arguments:   - spoly *c: pointer to output polynomial
 *              - const spoly *a: pointer to first input polynomial
 *              - const spoly *b: pointer to second input polynomial
 **************************************************/
static void spoly_pointwise_montgomery(spoly *c, const spoly *a, const spoly *b)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i) {
		c->coeffs[i] = montgomery_s_reduce((int64_t)a->coeffs[i] *
						   b->coeffs[i]);
	}
}

/*************************************************
 * Description: Use hint polynomial to correct the high bits of a polynomial.
 * Arguments:   - spoly *b: pointer to output polynomial with corrected high bits
 *              - const spoly *a: pointer to input polynomial
 *              - const spoly *h: pointer to input hint polynomial
 **************************************************/
static void spoly_use_hint(spoly *b, const spoly *a, const spoly *h,
			   unsigned int dil_k)
{
	unsigned int i;

	for (i = 0; i < DIL_N; ++i)
		b->coeffs[i] = use_s_hint(a->coeffs[i], h->coeffs[i], dil_k);
}

/*************************************************
 * Description: Check infinity norm of polynomial against given bound.
 *              Assumes input coefficients were reduced by reduce32().
 * Arguments:   - const spoly *a: pointer to polynomial
 *              - int32_t B: norm bound
 * Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 **************************************************/
static int spoly_chknorm(const spoly *a, int32_t B)
{
	unsigned int i;
	int32_t t;

	if (B > (DIL_Q - 1) / 8)
		return 1;

	/* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */

	for (i = 0; i < DIL_N; ++i) {
		/* Absolute value */
		t = a->coeffs[i] >> 31;

		t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

		if (t >= B) {
			return 1;
		}
	}

	return 0;
}

/*************************************************
 * Description: Sample uniformly random coefficients in [0, Q-1] by
 *              performing rejection sampling on array of random bytes.
 * Arguments:   - int32_t *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const uint8_t *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static unsigned int rej_s_uniform(int32_t *a, unsigned int len,
				  const uint8_t *buf, unsigned int buflen)
{
	unsigned int ctr, pos;
	uint32_t t;

	ctr = pos = 0;

	while ((ctr < len) && (pos + 3 <= buflen)) {
		t = buf[pos++];

		t |= (uint32_t)buf[pos++] << 8;

		t |= (uint32_t)buf[pos++] << 16;
		/* LSBF3_READ() */

		t &= 0x7FFFFF;

		if (t < DIL_Q)
			a[ctr++] = t;
	}

	return ctr;
}

/*************************************************
 * Description: Sample polynomial with uniformly random coefficients
 *              in [0,Q-1] by performing rejection sampling on the
 *              output stream of SHAKE256(seed|nonce)
 *
 * Arguments:   - spoly *a: pointer to output polynomial
 *              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
 *              - uint16_t nonce: 2-byte nonce
 **************************************************/
/* uses POLY_UNIFORM_NBLOCKS shared with round2 */

static void spoly_uniform(spoly *a, const uint8_t seed[DIL_SEEDBYTES],
			  uint16_t nonce)
{
	unsigned int buflen = POLY_UNIFORM_NBLOCKS * DIL_STREAM128_BLOCKBYTES;
	uint8_t buf[POLY_UNIFORM_NBLOCKS * DIL_STREAM128_BLOCKBYTES + 2];
	unsigned int i, ctr, off;
	stream128_state state;
	bool kern_hash = true;
	bool mlca_hash = false;

	struct crypto_shash *tfm_shake128 =
		crypto_alloc_shash("shake128", 0, 0);
	if (IS_ERR(tfm_shake128))
		printk(KERN_INFO
		       "-----------------------> BAD <--------------------\n");

	SHASH_DESC_ON_STACK(shash, tfm_shake128);
	shash->tfm = tfm_shake128;

	if (kern_hash) {
		uint8_t t[2];

		t[0] = nonce;
		t[1] = nonce >> 8;

		crypto_shash_init(shash);
		crypto_shash_update(shash, seed, DIL_SEEDBYTES);
		crypto_shash_update(shash, t, 2);

		crypto_shake_squeeze(shash, buf, sizeof(buf));

		printk(KERN_INFO
		       "sk128-1a.buf: %02x %02x %02x ... %02x %02x %02x\n",
		       buf[0], buf[1], buf[2], buf[POLY_UNIFORM_NBLOCKS - 3],
		       buf[POLY_UNIFORM_NBLOCKS - 2],
		       buf[POLY_UNIFORM_NBLOCKS - 1]);
	}

	if (mlca_hash) {
		stream128_init(&state, seed, nonce);
		stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);
		printk(KERN_INFO
		       "sk128-1b.buf: %02x %02x %02x ... %02x %02x %02x\n",
		       buf[0], buf[1], buf[2], buf[POLY_UNIFORM_NBLOCKS - 3],
		       buf[POLY_UNIFORM_NBLOCKS - 2],
		       buf[POLY_UNIFORM_NBLOCKS - 1]);
	}

	ctr = rej_s_uniform(a->coeffs, DIL_N, buf, buflen);

	while (ctr < DIL_N) {
		off = buflen % 3;

		for (i = 0; i < off; ++i)
			buf[i] = buf[buflen - off + i];

		if (kern_hash) {
			crypto_shake_squeeze(shash, buf,
					     DIL_STREAM128_BLOCKBYTES);
			printk(KERN_INFO
			       "sk128-2a.buf: %02x %02x %02x ... %02x %02x %02x\n",
			       buf[off + 0], buf[off + 1], buf[off + 2],
			       buf[off + DIL_STREAM128_BLOCKBYTES - 3],
			       buf[off + DIL_STREAM128_BLOCKBYTES - 2],
			       buf[off + DIL_STREAM128_BLOCKBYTES - 1]);
		}

		if (mlca_hash) {
			stream128_squeezeblocks(buf + off, 1, &state);
			printk(KERN_INFO
			       "sk128-2b.buf: %02x %02x %02x ... %02x %02x %02x\n",
			       buf[off + 0], buf[off + 1], buf[off + 2],
			       buf[off + DIL_STREAM128_BLOCKBYTES - 3],
			       buf[off + DIL_STREAM128_BLOCKBYTES - 2],
			       buf[off + DIL_STREAM128_BLOCKBYTES - 1]);
		}

		buflen = DIL_STREAM128_BLOCKBYTES + off;

		ctr += rej_s_uniform(a->coeffs + ctr, DIL_N - ctr, buf, buflen);
	}
	stream128_wipe(&state);
}

/*************************************************
 * Description: Unpack polynomial z with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 * Arguments:   - spoly *r: pointer to output polynomial
 *              - const uint8_t *a: byte array with bit-packed polynomial
 **************************************************/
static void spolyz_unpack(spoly *r, const uint8_t *a, unsigned int dil_k)
{
	unsigned int i, gamma1 = dil_r3k2gamma1(dil_k);

	if (gamma1 == (1 << 17)) { /* was: GAMMA1 == (1 << 17) */
		for (i = 0; i < DIL_N / 4; ++i) {
			r->coeffs[4 * i + 0] = a[9 * i + 0];
			r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 1] << 8;
			r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 2] << 16;
			r->coeffs[4 * i + 0] &= 0x3FFFF;

			r->coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
			r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 3] << 6;
			r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 4] << 14;
			r->coeffs[4 * i + 1] &= 0x3FFFF;

			r->coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
			r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 5] << 4;
			r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 6] << 12;
			r->coeffs[4 * i + 2] &= 0x3FFFF;

			r->coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
			r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 7] << 2;
			r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 8] << 10;
			r->coeffs[4 * i + 3] &= 0x3FFFF;

			r->coeffs[4 * i + 0] = gamma1 - r->coeffs[4 * i + 0];
			r->coeffs[4 * i + 1] = gamma1 - r->coeffs[4 * i + 1];
			r->coeffs[4 * i + 2] = gamma1 - r->coeffs[4 * i + 2];
			r->coeffs[4 * i + 3] = gamma1 - r->coeffs[4 * i + 3];
		}

	} else { /* (gamma1 == (1 << 19)) */
		for (i = 0; i < DIL_N / 2; ++i) {
			r->coeffs[2 * i + 0] = a[5 * i + 0];
			r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
			r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
			r->coeffs[2 * i + 0] &= 0xFFFFF;

			r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
			r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
			r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;
			r->coeffs[2 * i + 0] &= 0xFFFFF;

			r->coeffs[2 * i + 0] = gamma1 - r->coeffs[2 * i + 0];
			r->coeffs[2 * i + 1] = gamma1 - r->coeffs[2 * i + 1];
		}
	}
}

/*************************************************
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
 *              of SHAKE256(seed|nonce)
 * Arguments:   - spoly *a: pointer to output polynomial
 *              - const uint8_t seed[]: byte array with seed of length CRHBYTES
 *              - uint16_t nonce: 16-bit nonce
 **************************************************/

/* original constants: STREAM256_BLOCKBYTES == SHAKE256_RATE == 136
 * the values are coincidentally identical
 */
#if 0
// #if GAMMA1 == (1 << 17)                   /* 4x4 */
// #define POLY_UNIFORM_GAMMA1_NBLOCKS
//     ((576 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)  /* -> 5 */
//
// #elif GAMMA1 == (1 << 19)                 /* 6x5, 8x7 */
// #define POLY_UNIFORM_GAMMA1_NBLOCKS
//     ((640 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)  /* -> 5 */
// #endif
#endif
/**/
#define SPOLY_UNIFORM_GAMMA1_NBLOCKS ((unsigned int)5)

/*--------------------------------------
 * returns 0 for unknown param.sets, which should not happen
 */
ATTR_CONST__
/**/
static unsigned int dilr3_k2tau(unsigned int dil_k)
{
	switch (dil_k) {
	case 4:
		return 39;
	case 6:
		return 49;
	case 8:
		return 60;

	default:
		return 0; /* SNH */
	}
}

/*************************************************
 * Description: Implementation of H. Samples polynomial with TAU nonzero
 *              coefficients in {-1,1} using the output stream of
 *              SHAKE256(seed).
 * Arguments:   - spoly *c: pointer to output polynomial
 *              - const uint8_t seed[]: byte array containing seed of length ctildebytes
 **************************************************/
static void ml_spoly_challenge(spoly *c, const uint8_t *seed,
			       unsigned int dil_k,
			       struct crypto_shash *tfm_shake256)
{
	uint8_t buf[SHAKE256_RATE];
	unsigned int i, b, pos;
	Keccak_state state;
	uint64_t signs;
	size_t ctilbytes = dil_mldsa_ctilbytes(dil_k);

	SHASH_DESC_ON_STACK(shash, tfm_shake256);
	shash->tfm = tfm_shake256;

	bool kern_hash = true;
	bool mlca_hash = false;

	if (kern_hash) {
		crypto_shash_init(shash);
		crypto_shash_update(shash, seed, ctilbytes);
		crypto_shake_squeeze(shash, buf, sizeof(buf));
		printk(KERN_INFO "1a.buf: %02x %02x %02x ... %02x %02x %02x\n",
		       buf[0], buf[1], buf[2], buf[SHAKE256_RATE - 3],
		       buf[SHAKE256_RATE - 2], buf[SHAKE256_RATE - 1]);
	}

	if (mlca_hash) {
		shake256_init(&state);
		shake256_absorb(&state, seed, ctilbytes);
		shake256_finalize(&state);
		shake256_squeezeblocks(buf, 1, &state);
		printk(KERN_INFO "1b.buf: %02x %02x %02x ... %02x %02x %02x\n",
		       buf[0], buf[1], buf[2], buf[SHAKE256_RATE - 3],
		       buf[SHAKE256_RATE - 2], buf[SHAKE256_RATE - 1]);
	}

	signs = 0;
	for (i = 0; i < 8; ++i)
		signs |= (uint64_t)buf[i] << 8 * i;

	pos = 8;

	for (i = 0; i < DIL_N; ++i)
		c->coeffs[i] = 0;

	for (i = DIL_N - dilr3_k2tau(dil_k); i < DIL_N; ++i) {
		do {
			if (pos >= SHAKE256_RATE) {
				if (kern_hash) {
					crypto_shake_squeeze(shash, buf,
							     sizeof(buf));
					printk(KERN_INFO
					       "2a.buf: %02x %02x %02x ... %02x %02x %02x",
					       buf[0], buf[1], buf[2],
					       buf[SHAKE256_RATE - 3],
					       buf[SHAKE256_RATE - 2],
					       buf[SHAKE256_RATE - 1]);
				}
				if (mlca_hash) {
					shake256_squeezeblocks(buf, 1, &state);
					printk(KERN_INFO
					       "2b.buf: %02x %02x %02x ... %02x %02x %02x",
					       buf[0], buf[1], buf[2],
					       buf[SHAKE256_RATE - 3],
					       buf[SHAKE256_RATE - 2],
					       buf[SHAKE256_RATE - 1]);
				}
				pos = 0;
			}

			b = buf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (signs & 1);

		signs >>= 1;
	}
	stream256_wipe(&state);
}

/*************************************************
 * Description: Unpack polynomial t1 with 10-bit coefficients.
 *              Output coefficients are standard representatives.
 * Arguments:   - spoly *r: pointer to output polynomial
 *              - const uint8_t *a: byte array with bit-packed polynomial
 **************************************************/
static void spolyt1_unpack(spoly *r, const uint8_t *a)
{
	unsigned int i;

	for (i = 0; i < DIL_N / 4; ++i) {
		r->coeffs[4 * i + 0] =
			((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) &
			0x3FF;

		r->coeffs[4 * i + 1] =
			((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) &
			0x3FF;

		r->coeffs[4 * i + 2] =
			((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) &
			0x3FF;

		r->coeffs[4 * i + 3] =
			((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) &
			0x3FF;
	}
}

/*************************************************
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be standard representatives.
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYW1_PACKEDBYTES bytes
 *              - const spoly *a: pointer to input polynomial
 **************************************************/
static void spolyw1_pack(uint8_t *r, const spoly *a, unsigned int dil_k)
{
	unsigned int i, gamma2 = dil_r3k2gamma2(dil_k);

	if (gamma2 == (DIL_Q - 1) / 88) {
		for (i = 0; i < DIL_N / 4; ++i) {
			r[3 * i + 0] = a->coeffs[4 * i + 0];
			r[3 * i + 0] |= a->coeffs[4 * i + 1] << 6;
			r[3 * i + 1] = a->coeffs[4 * i + 1] >> 2;
			r[3 * i + 1] |= a->coeffs[4 * i + 2] << 4;
			r[3 * i + 2] = a->coeffs[4 * i + 2] >> 4;
			r[3 * i + 2] |= a->coeffs[4 * i + 3] << 2;
		}

	} else { /* gamma2 == (DIL_Q-1) /32 */
		for (i = 0; i < DIL_N / 2; ++i)
			r[i] = a->coeffs[2 * i + 0] |
			       (a->coeffs[2 * i + 1] << 4);
	}
}
#endif /* /delimiter: round3 */
#endif /* !NO_CRYSTALS_SIG */

#endif /*-----  /delimiter: poly  -------------------------------------*/

#if 1 /*-----  delimiter: polyvec, some of packing.c  ----------------*/
/* the largest polyvecl, polyveck possible
 * safe to cast to any valid, smaller size
 */
typedef struct {
	poly vec[DIL_VECT_MAX];
} polyvec_max;

/* round3, ref.impl-compatible signed math
 */
typedef struct {
	spoly vec[DIL_VECT_MAX];
} spolyvec_max;

#if !defined(NO_CRYSTALS_SIG)
//--------------------------------------
static unsigned int dil_omega(unsigned int k, unsigned int round)
{
	switch ((round << 4) | k) {
	case 0x25:
		return DIL_OMEGA5x4;
	case 0x26:
		return DIL_OMEGA6x5;
	case 0x28:
		return DIL_OMEGA8x7;

	case 0x34:
		return DIL_R3_OMEGA4x4;
	case 0x36:
		return DIL_R3_OMEGA6x5;
	case 0x38:
		return DIL_R3_OMEGA8x7;

	default:
		return 0;
	}
}

//--------------------------------------
//
static unsigned int dil_k2beta(unsigned int k, unsigned int round)
{
	switch ((round << 4) | k) {
	case 0x25:
		return DIL_BETA5x4;
	case 0x26:
		return DIL_BETA6x5;
	case 0x28:
		return DIL_BETA8x7;

	case 0x34:
		return DIL_R3_BETA4x4;
	case 0x36:
		return DIL_R3_BETA6x5;
	case 0x38:
		return DIL_R3_BETA8x7;

	default:
		return 0;
	}
}

//--------------------------------------
// raw bytecount, excluding ASN framing
// returns 0  if parameter choice is not supported
//
// ref.impl:
// CRYPTO_BYTES == (L*POLYZ_PACKEDBYTES + OMEGA + K + N/8 + 8)  [r2]
//
// see also: dil_sigbytes2type(), which is practically the inverse
//
static size_t dil_signature_bytes(unsigned int k, unsigned int l,
				  unsigned int round)
{
	switch ((round << 16) | (k << 4) | l) {
	case 0x20054:
		return DIL_SIGBYTES5x4; /* round 2 */
	case 0x20065:
		return DIL_SIGBYTES6x5;
	case 0x20087:
		return DIL_SIGBYTES8x7;

	case 0x30044:
		return DIL_R3_SIGBYTES4x4; /* round 3 */
	case 0x30065:
		return DIL_R3_SIGBYTES6x5;
	case 0x30087:
		return DIL_R3_SIGBYTES8x7;

	case 0x40044:
		return DIL_MLDSA_SIGBYTES4x4; /* mldsa */
	case 0x40065:
		return DIL_MLDSA_SIGBYTES6x5;
	case 0x40087:
		return DIL_MLDSA_SIGBYTES8x7;

	default:
		return 0;
	}
}

static unsigned int dil__pubbytes2type_mldsa(size_t pubbytes)
{
	switch (pubbytes) {
	case DIL_MLDSA_44_PUB_BYTES:
		return MLCA_ID_DIL_MLDSA_44;
	case DIL_MLDSA_65_PUB_BYTES:
		return MLCA_ID_DIL_MLDSA_65;
	case DIL_MLDSA_87_PUB_BYTES:
		return MLCA_ID_DIL_MLDSA_87;

	default:
		return 0;
	}
}

/*--------------------------------------
 * OID stubs for Dilithium
 *
 * highly regular:
 *     1.3.6.1.4.1.2.267 .X .Y.Z  ->  060b 2b0601040102820b <X> <Y> <Z>
 *
 * all valid X/Y/Z are single-byte, so sizeof(OID) == sizeof(...stub) +3
 */
static const unsigned char crs_oidstub[] = {
	0x06, 0x0b, // OID{
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, //     ...}
};

static const unsigned char crs_oidstub_csor[] = { 0x06, 0x09, 0x60, 0x86, 0x48,
						  0x01, 0x65, 0x03, 0x04 };
/**/
#define CRS_OIDTAIL_BYTES ((size_t)3)
#define CRS_OIDTAIL_CSOR_BYTES ((size_t)2)

/*--------------------------------------
 * returns  >0  if Crystals variant is a recognized one, see MLCA_ID_t
 *           0  not a recognized OID, incl. NULL/insufficient input
 *
 * OIDs are highly regular, so we just verify these stubs
 * see also crs_oid2wire(), the inverse
 */
static unsigned int crs_oid2type(const unsigned char *oid, size_t obytes)
{
	unsigned int rc = 0;

	if (oid && (obytes == sizeof(crs_oidstub) + CRS_OIDTAIL_BYTES) &&
	    !memcmp(oid, crs_oidstub, obytes - CRS_OIDTAIL_BYTES)) {
		switch (MSBF4_READ(oid + obytes - 4) & 0xffffff) {
			/* (.1) Dilithium round2 */
		case 0x010504:
			rc = MLCA_ID_DIL3_R2;
			break;
		case 0x010605:
			rc = MLCA_ID_DIL4_R2;
			break;
		case 0x010807:
			rc = MLCA_ID_DIL5_R2;
			break;

			/* (.6) Dilithium round2, 'raw' key objects */
		case 0x060504:
			rc = MLCA_ID_DIL3_R2_RAW;
			break;
		case 0x060605:
			rc = MLCA_ID_DIL4_R2_RAW;
			break;
		case 0x060807:
			rc = MLCA_ID_DIL5_R2_RAW;
			break;

			/* (.7) Dilithium round3, compressed signatures */
		case 0x070404:
			rc = MLCA_ID_DIL2_R3;
			break;
		case 0x070605:
			rc = MLCA_ID_DIL3_R3;
			break;
		case 0x070807:
			rc = MLCA_ID_DIL5_R3;
			break;

			/* Kyber OIDs are .N.N */

			/* (.5) Kyber round2 */
		case 0x050303:
			rc = MLCA_ID_KYB3_R2;
			break;
		case 0x050404:
			rc = MLCA_ID_KYB4_R2;
			break;

			/* (.8) Kyber round3 */
		case 0x080303:
			rc = MLCA_ID_KYB3_R3;
			break;
		case 0x080404:
			rc = MLCA_ID_KYB4_R3;
			break;

		default:
			break;
		}
	} else if (oid &&
		   (obytes ==
		    sizeof(crs_oidstub_csor) + CRS_OIDTAIL_CSOR_BYTES) &&
		   !memcmp(oid, crs_oidstub_csor,
			   obytes - CRS_OIDTAIL_CSOR_BYTES)) {
		switch (MSBF4_READ(oid + obytes - 4) & 0xffff) {
		/* ML-DSA */
		case 0x0311:
			rc = MLCA_ID_DIL_MLDSA_44;
			break;
		case 0x0312:
			rc = MLCA_ID_DIL_MLDSA_65;
			break;
		case 0x0313:
			rc = MLCA_ID_DIL_MLDSA_87;
			break;

		/* ML-KEM */
		case 0x0402:
			rc = MLCA_ID_KYB_MLKEM_768;
			break;
		case 0x0403:
			rc = MLCA_ID_KYB_MLKEM_1024;
			break;

		default:
			break;
		}
	}

	return rc;
}

#endif /* !NO_CRYSTALS_SIG */

/*--------------------------------------
 * does not check 'type' validity; call only after verification
 *
 * currently, type is either  <round> 0 <K>  or <round> <K> <L>
 *
 * expect this 'function' to be cheap, no need to cache etc.
 */
static unsigned int dil_type2k(unsigned int type)
{
	if (type & 0xf0) {
		return ((type >> 4) & 0x0f); /* <K> <L> */
	} else {
		return (type & 0x0f); /* 0 <K> */
	}
}

/*--------------------------------------
 * does not check 'type' validity; call only after verification
 *
 * currently, type is either  <round> 0 <K>  or <round> <K> <L>
 * K == L-1  for all variants of the first type
 *
 * expect this 'function' to be cheap, no need to cache etc.
 */
static unsigned int dil_type2l(unsigned int type)
{
	if (type & 0xf0) {
		return type & 0x0f; /* <K> <L> */
	} else {
		return ((type >> 4) & 0x0f) - 1; /* 0 <K> -> L == K-1 */
	}
}

/*--------------------------------------
 * does not check 'type' validity; call only after verification
 */
static unsigned int dil_type2round(unsigned int type)
{
	switch (type) {
	case MLCA_ID_DIL3_R2:
	case MLCA_ID_DIL4_R2:
	case MLCA_ID_DIL5_R2:
	case MLCA_ID_DIL3_R2_RAW:
	case MLCA_ID_DIL4_R2_RAW:
	case MLCA_ID_DIL5_R2_RAW:
		return 2;

	case MLCA_ID_DIL2_R3:
	case MLCA_ID_DIL3_R3:
	case MLCA_ID_DIL5_R3:
		return 3;

	case MLCA_ID_DIL_MLDSA_44:
	case MLCA_ID_DIL_MLDSA_65:
	case MLCA_ID_DIL_MLDSA_87:
		return 4;

	default:
		return 0;
	}
}

//--------------------------------------
#include "polyvec-include.h" /* size-specialized fn set */

/*------------------------------------
 * Unpack signature sig = (z, h, c); round3
 * Arguments:   - chash: challenge hash  [CTILBYTES]
 *              - polyvecl *z: pointer to output vector z
 *              - polyveck *h: pointer to output hint vector h
 *              - const uint8_t sig[]: byte array containing
 *                bit-packed signature
 *
 * Returns >0 in case of malformed signature; otherwise 0.
 *
 * accesses only necessary number of elements of z[] and h[],
 * 'sig' and 'chash' may be the same buffer; other overlap is undefined
 **************************************************/
static int mldsa_wire2sig(unsigned char *chash, /* CTILBYTES */
			  spolyvec_max *z, spolyvec_max *h, unsigned int dil_k,
			  unsigned int dil_l, const unsigned char *sig,
			  size_t sbytes)
{
	size_t sb = dil_signature_bytes(dil_k, dil_l, 4),
	       pzb = dil_r3k2polyz_bytes(dil_k);
	unsigned int i, j, k, omega = dil_omega(dil_k, 3);
	size_t ctilbytes = dil_mldsa_ctilbytes(dil_k);

	if (!sig || (sb != sbytes))
		return 1;
	if (!z || !h || !chash)
		return 2; /* should-not-happen */

	if ((const unsigned char *)chash != sig)
		memmove(chash, sig, ctilbytes);

	sig += ctilbytes;

	for (i = 0; i < dil_l; ++i) /* L */
		spolyz_unpack(&(z->vec[i]), sig + i * pzb, dil_k);

	sig += dil_l * pzb; /* L * ... */

	/* Decode h */
	k = 0;

	for (i = 0; i < dil_k; ++i) {
		for (j = 0; j < DIL_N; ++j)
			h->vec[i].coeffs[j] = 0;

		if ((sig[omega + i] < k) || (sig[omega + i] > omega))
			return 3;

		for (j = k; j < sig[omega + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */

			if ((j > k) && (sig[j] <= sig[j - 1]))
				return 4;

			h->vec[i].coeffs[sig[j]] = 1;
		}

		k = sig[omega + i];
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = k; j < omega; ++j) {
		if (sig[j])
			return 5;
	}

	sig += omega + dil_k;

	return 0;
}

#endif /*-----  /delimiter: polyvec, some of packing.c  ---------------*/

/*************************************************
 * Description: Verifies signature.
 * Arguments:   - uint8_t *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const uint8_t *m: pointer to message
 *              - size_t mlen: length of message
 *              - const uint8_t *pk: pointer to bit-packed public key
 * Returns >0 if signature could be verified correctly and 0 otherwise
 **************************************************/
static int mldsa_verify_internal(const uint8_t *sig, size_t siglen,
				 const uint8_t *m, size_t mlen,
				 const uint8_t *pk, size_t pkbytes,
				 const uint8_t *domsep, size_t domsepLen)
{
	unsigned char chash[DIL_MLDSA_MAX_CTILDEBYTES];
	unsigned char rho[DIL_MLDSA_MAX_CTILDEBYTES];
	unsigned char mu[DIL_R3_CRHBYTES];
	unsigned int K = 0, L, beta, type;
	// note: rho size is max(DIL_MLDSA_MAX_CTILDEBYTES, DIL_SEEDBYTES)
	int32_t gamma1, gamma2;
	size_t sigb, w1pb, i, ctilbytes;
	int rc = 1;

	struct ver_mat {
		spoly cp;
		spolyvec_max mat[DIL_VECT_MAX], z; /* L; LxK (mat) */
		spolyvec_max t1, h, w1; /* K */
		Keccak_state state;
		unsigned char w1pack[DIL__KxPOLYW1_MAX_BYTES];
	};

	struct ver_mat *pMat = kmalloc(sizeof(*pMat), GFP_KERNEL);
	if (!pMat)
		return -ENOMEM;

	struct crypto_shash *tfm_shake256 =
		crypto_alloc_shash("shake256", 0, 0);
	if (IS_ERR(tfm_shake256)) {
		rc = PTR_ERR(tfm_shake256);
		goto err_free_pmat;
	}

	type = dil__pubbytes2type_mldsa(pkbytes);
	K = dil_type2k(type);
	L = dil_type2l(type);
	ctilbytes = dil_mldsa_ctilbytes(K);
	gamma1 = dil_r3k2gamma1(K);
	gamma2 = dil_r3k2gamma2(K);
	w1pb = K * dil_r3k2polyw1_bytes(K);
	/**/
	if (!type || !K || !L || !gamma1 || !gamma2 || !w1pb ||
	    (w1pb > sizeof(pMat->w1pack)) || (dil_type2round(type) != 4)) {
		rc = MLCA_EKEYTYPE;
		goto err_free_shash;
	}

	sigb = dil_signature_bytes(K, L, 4);
	beta = dil_k2beta(K, 3);
	/**/
	if (!sig || !sigb || (siglen != sigb)) {
		rc = 0;
		goto err_free_shash;
	}

	switch (K) {
	case 4:
		sunpack_pk4(rho, (spolyvec4 *)&pMat->t1, pk);
		break;
	case 6:
		sunpack_pk6(rho, (spolyvec6 *)&pMat->t1, pk);
		break;
	case 8:
		sunpack_pk8(rho, (spolyvec8 *)&pMat->t1, pk);
		break;
	default:
		rc = -EINVAL;
		goto err_free_shash;
	}

	if (mldsa_wire2sig(chash, &pMat->z, &pMat->h, K, L, sig, siglen)) {
		rc = 0;
		goto err_free_shash;
	}

	unsigned int fail = 1;
	switch (K) {
	case 4:
		fail = !!spolyvec4_chknorm((const spolyvec4 *)&pMat->z,
					   gamma1 - beta);
		break;
	case 6:
		fail = !!spolyvec5_chknorm((const spolyvec5 *)&pMat->z,
					   gamma1 - beta);
		break;
	case 8:
		fail = !!spolyvec7_chknorm((const spolyvec7 *)&pMat->z,
					   gamma1 - beta);
		break;
	default:
		break;
	}
	if (fail) {
		rc = 0;
		goto err_free_shash;
	}

	bool kern_hash = true;
	bool mlca_hash = false;

	if (kern_hash) {
		SHASH_DESC_ON_STACK(shash, tfm_shake256);
		shash->tfm = tfm_shake256;

		crypto_shash_init(shash);
		crypto_shash_update(shash, pk, pkbytes);
		crypto_shake_squeeze(shash, mu, DIL_R3_CRHBYTES);
		printk(KERN_INFO "1a.mu: %02x %02x %02x ... %02x %02x %02x",
		       mu[0], mu[1], mu[2], mu[DIL_R3_CRHBYTES - 3],
		       mu[DIL_R3_CRHBYTES - 2], mu[DIL_R3_CRHBYTES - 1]);
	}

	if (mlca_hash) {
		shake256(mu, DIL_R3_CRHBYTES, pk, pkbytes);
		printk(KERN_INFO "1b.mu: %02x %02x %02x ... %02x %02x %02x",
		       mu[0], mu[1], mu[2], mu[DIL_R3_CRHBYTES - 3],
		       mu[DIL_R3_CRHBYTES - 2], mu[DIL_R3_CRHBYTES - 1]);
	}

	unsigned char mu2[DIL_R3_CRHBYTES];
	memcpy(mu2, mu, sizeof(mu2));

	/**/
	if (kern_hash) {
		SHASH_DESC_ON_STACK(shash, tfm_shake256);
		shash->tfm = tfm_shake256;

		crypto_shash_init(shash);
		crypto_shash_update(shash, mu2, DIL_R3_CRHBYTES);
		if (domsepLen)
			crypto_shash_update(shash, domsep, domsepLen);
		crypto_shash_update(shash, m, mlen);
		crypto_shake_squeeze(shash, mu, DIL_R3_CRHBYTES);
		printk(KERN_INFO "2a.mu: %02x %02x %02x ... %02x %02x %02x",
		       mu[0], mu[1], mu[2], mu[DIL_R3_CRHBYTES - 3],
		       mu[DIL_R3_CRHBYTES - 2], mu[DIL_R3_CRHBYTES - 1]);
	}

	if (mlca_hash) {
		shake256_init(&pMat->state);
		shake256_absorb(&pMat->state, mu2, DIL_R3_CRHBYTES);
		if (domsepLen)
			shake256_absorb(&pMat->state, domsep, domsepLen);
		shake256_absorb(&pMat->state, m, mlen);
		shake256_finalize(&pMat->state);
		shake256_squeeze(mu, DIL_R3_CRHBYTES, &pMat->state);
		printk(KERN_INFO "2b.mu: %02x %02x %02x ... %02x %02x %02x",
		       mu[0], mu[1], mu[2], mu[DIL_R3_CRHBYTES - 3],
		       mu[DIL_R3_CRHBYTES - 2], mu[DIL_R3_CRHBYTES - 1]);
	}

	ml_spoly_challenge(&pMat->cp, chash, K, tfm_shake256);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */

	switch (K) { /* NTT on L-sized vector */
	case 4:
		expand_smatrix_4x4(pMat->mat, rho);
		spolyvec4_ntt((spolyvec4 *)&pMat->z); /* L */
		spolyvec4x4_matrix_pointwise_montgomery(
			(spolyvec4 *)&pMat->w1, pMat->mat,
			(const spolyvec4 *)&pMat->z);
		break;

	case 6:
		expand_smatrix_6x5(pMat->mat, rho);
		spolyvec5_ntt((spolyvec5 *)&pMat->z); /* L */
		spolyvec6x5_matrix_pointwise_montgomery(
			(spolyvec6 *)&pMat->w1, pMat->mat,
			(const spolyvec5 *)&pMat->z);
		break;

	case 8:
		expand_smatrix_8x7(pMat->mat, rho);
		spolyvec7_ntt((spolyvec7 *)&pMat->z); /* L */
		spolyvec8x7_matrix_pointwise_montgomery(
			(spolyvec8 *)&pMat->w1, pMat->mat,
			(const spolyvec7 *)&pMat->z);
		break;
	}

	spoly_ntt256(&pMat->cp);

	switch (K) {
	case 4:
		spolyvec4_shiftl((spolyvec4 *)&pMat->t1);
		spolyvec4_ntt((spolyvec4 *)&pMat->t1);
		spolyvec4_pointwise_poly_montgomery(
			(spolyvec4 *)&pMat->t1, &pMat->cp,
			(const spolyvec4 *)&pMat->t1);
		spolyvec4_sub((spolyvec4 *)&pMat->w1,
			      (const spolyvec4 *)&pMat->w1,
			      (const spolyvec4 *)&pMat->t1);
		spolyvec4_reduce((spolyvec4 *)&pMat->w1);
		spolyvec4_invntt_tomont((spolyvec4 *)&pMat->w1);
		/* reconstruct W1 */
		spolyvec4_caddq((spolyvec4 *)&pMat->w1);
		spolyvec4_use_hint((spolyvec4 *)&pMat->w1,
				   (const spolyvec4 *)&pMat->w1,
				   (const spolyvec4 *)&pMat->h, K);
		spolyvec4_pack_w1(pMat->w1pack, (const spolyvec4 *)&pMat->w1);
		break;

	case 6:
		spolyvec6_shiftl((spolyvec6 *)&pMat->t1);
		spolyvec6_ntt((spolyvec6 *)&pMat->t1);
		spolyvec6_pointwise_poly_montgomery(
			(spolyvec6 *)&pMat->t1, &pMat->cp,
			(const spolyvec6 *)&pMat->t1);
		spolyvec6_sub((spolyvec6 *)&pMat->w1,
			      (const spolyvec6 *)&pMat->w1,
			      (const spolyvec6 *)&pMat->t1);
		spolyvec6_reduce((spolyvec6 *)&pMat->w1);
		spolyvec6_invntt_tomont((spolyvec6 *)&pMat->w1);
		/* reconstruct W1 */
		spolyvec6_caddq((spolyvec6 *)&pMat->w1);
		spolyvec6_use_hint((spolyvec6 *)&pMat->w1,
				   (const spolyvec6 *)&pMat->w1,
				   (const spolyvec6 *)&pMat->h, K);
		spolyvec6_pack_w1(pMat->w1pack, (const spolyvec6 *)&pMat->w1);
		break;

	case 8:
		spolyvec8_shiftl((spolyvec8 *)&pMat->t1);
		spolyvec8_ntt((spolyvec8 *)&pMat->t1);
		spolyvec8_pointwise_poly_montgomery(
			(spolyvec8 *)&pMat->t1, &pMat->cp,
			(const spolyvec8 *)&pMat->t1);
		spolyvec8_sub((spolyvec8 *)&pMat->w1,
			      (const spolyvec8 *)&pMat->w1,
			      (const spolyvec8 *)&pMat->t1);
		spolyvec8_reduce((spolyvec8 *)&pMat->w1);
		spolyvec8_invntt_tomont((spolyvec8 *)&pMat->w1);
		/* reconstruct W1 */
		spolyvec8_caddq((spolyvec8 *)&pMat->w1);
		spolyvec8_use_hint((spolyvec8 *)&pMat->w1,
				   (const spolyvec8 *)&pMat->w1,
				   (const spolyvec8 *)&pMat->h, K);
		spolyvec8_pack_w1(pMat->w1pack, (const spolyvec8 *)&pMat->w1);
		break;
	}

	/* rho[ DIL_SEEDBYTES ] := CRH(mu[ DIL_CRHBYTES ], w1pack[w1pb])
             * reusing already-idle rho[] which happens to share size
             */
	if (kern_hash) {
		SHASH_DESC_ON_STACK(shash, tfm_shake256);
		shash->tfm = tfm_shake256;

		crypto_shash_init(shash);
		crypto_shash_update(shash, mu, DIL_R3_CRHBYTES);
		crypto_shash_update(shash, pMat->w1pack, w1pb);
		crypto_shake_squeeze(shash, rho, ctilbytes);
		printk(KERN_INFO
		       "3a.rho[%zu]: %02x %02x %02x ... %02x %02x %02x",
		       ctilbytes, rho[0], rho[1], rho[2], rho[ctilbytes - 3],
		       mu[ctilbytes - 2], mu[ctilbytes - 1]);
	}
	if (mlca_hash) {
		shake256_init(&pMat->state);
		shake256_absorb(&pMat->state, mu, DIL_R3_CRHBYTES);
		shake256_absorb(&pMat->state, pMat->w1pack, w1pb);
		shake256_finalize(&pMat->state);
		shake256_squeeze(rho, ctilbytes, &pMat->state);
		printk(KERN_INFO "3b.mu: %02x %02x %02x ... %02x %02x %02x",
		       rho[0], rho[1], rho[2], rho[ctilbytes - 3],
		       mu[ctilbytes - 2], mu[ctilbytes - 1]);
	}

	sigb = 0;
	for (i = 0; i < ctilbytes; ++i)
		sigb += !!(chash[i] == rho[i]);

	rc = (sigb == ctilbytes);
	if (rc == 1)
		printk(KERN_INFO "SIGNATURE VERIFICATION SUCCESS!\n");

err_free_shash:
	crypto_free_shash(tfm_shake256);

err_free_pmat:
	memset(pMat, 0, sizeof(struct ver_mat));
	kfree(pMat);

	return rc;
}

static int mldsa_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
			size_t mlen, const uint8_t *pk, size_t pkbytes)
{
	return mldsa_verify_internal(sig, siglen, m, mlen, pk, pkbytes,
				     mldsa_ds_pure, 2);
}

/*-----  delimiter: mlca_verify ----------------------*/
static int __mlca_verify(const unsigned char *sig, size_t sbytes,
			 const unsigned char *msg, size_t mbytes,
			 const unsigned char *pub, size_t pbytes,
			 const unsigned char *algid, size_t ibytes)
{
	unsigned int round;
	unsigned int type;

	if (!sig || !sbytes || !msg || !mbytes || !pub || !pbytes)
		return 0;

	type = crs_oid2type(algid, ibytes);
	round = dil_type2round(type);
	if (round != 4)
		return 0;

	return mldsa_verify(sig, sbytes, msg, mbytes, pub, pbytes);
}

int mlca_verify(const unsigned char *sig, size_t sbytes,
		const unsigned char *msg, size_t mbytes,
		const unsigned char *pub, size_t pbytes,
		const unsigned char *algid, size_t ibytes)
{
	return __mlca_verify(sig, sbytes, msg, mbytes, pub, pbytes, algid,
			     ibytes);
}
