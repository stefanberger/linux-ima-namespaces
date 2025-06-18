// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 IBM Corporation
 *
 * Original sources: https://github.com/IBM/mlca/blob/main/KAT/
 *
 * Original Author: Basil Hess, bhe@zurich.ibm.com
 * Port to Linux  : Stefan Berger, stefanb@linux.ibm.com
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <crypto/sha3.h>

#include "mldsa_crypto.h"
#include "mldsa.h"

/* FIPS-204 parameter set */
#define MLDSA_Q 8380417
#define MLDSA_SQINV 58728449 /* 1/MLDSA_Q mod 2^32, signed units */

#define MLDSA_SD 13

#define MLDSA_TAU4x4 39
#define MLDSA_TAU6x5 49
#define MLDSA_TAU8x7 60

#define MLDSA_GAMMA1_4x4 (1 << 17)
#define MLDSA_GAMMA1_6x5 (1 << 19)
#define MLDSA_GAMMA1_8x7 (1 << 19)

#define MLDSA_GAMMA2_4x4 ((MLDSA_Q - 1) / 88)
#define MLDSA_GAMMA2_6x5 ((MLDSA_Q - 1) / 32)
#define MLDSA_GAMMA2_8x7 ((MLDSA_Q - 1) / 32)

#define MLDSA_BETA4x4 78
#define MLDSA_BETA6x5 196
#define MLDSA_BETA8x7 120

#define MLDSA_OMEGA4x4 80
#define MLDSA_OMEGA6x5 55
#define MLDSA_OMEGA8x7 75

/* other constants */
#define MLDSA_SEEDBYTES	(256 / 8)
#define MLDSA_CRHBYTES	(512 / 8)
#define MLDSA_TRBYTES   (512 / 8)

#define MLDSA_STREAM128_BLOCKBYTES SHAKE128_RATE

#define MLDSA_POLYT1_PACKEDBYTES 320

#define MLDSA_POLYZ_BYTES4x4 576
#define MLDSA_POLYZ_BYTES6x5 640
#define MLDSA_POLYZ_BYTES8x7 640

#define MLDSA_POLYW1_BYTES4x4 192
#define MLDSA_POLYW1_BYTES6x5 128
#define MLDSA_POLYW1_BYTES8x7 128

/* public key sizes */
#define MLDSA_PUB4x4_BYTES MLDSA_44_PUB_BYTES
#define MLDSA_PUB6x5_BYTES MLDSA_65_PUB_BYTES
#define MLDSA_PUB8x7_BYTES MLDSA_87_PUB_BYTES

/* signature sizes */
#define MLDSA_SIGBYTES4x4 2420
#define MLDSA_SIGBYTES6x5 3309
#define MLDSA_SIGBYTES8x7 4627

#define MLDSA_44_CTILDEBYTES ((size_t)32)
#define MLDSA_65_CTILDEBYTES ((size_t)48)
#define MLDSA_87_CTILDEBYTES ((size_t)64)
#define MLDSA_MAX_CTILDEBYTES MLDSA_87_CTILDEBYTES

#define MLDSA_VECT_MAX 8 /* MAX(K, L) for any config */

#define MLDSA_N 256

/*
 * verification needs max(K * w1-bytes) as an upper limit, this is it:
 */
#define MLDSA_KxPOLYW1_MAX_BYTES ((size_t)1024)

#define POLY_UNIFORM_NBLOCKS \
	((768 + MLDSA_STREAM128_BLOCKBYTES - 1) / MLDSA_STREAM128_BLOCKBYTES)

enum mldsa_id {
	MLDSA_44_ID = 0x44,
	MLDSA_65_ID = 0x65,
	MLDSA_87_ID = 0x87,
};

struct poly {
	uint32_t coeffs[MLDSA_N];
};

struct spoly {
	int32_t coeffs[MLDSA_N];
};

/* The largest spoly vector. Safe to cast to any valid, smaller size. */
struct spolyvec_max {
	struct spoly vec[MLDSA_VECT_MAX];
};

/* Signed counterpart of montgomery_reduce() */
static int32_t montgomery_s_reduce(int64_t a)
{
	int32_t t;

	t = (int64_t)(int32_t)a * MLDSA_SQINV;
	t = (a - (int64_t)t * MLDSA_Q) >> 32;

	return t;
}

/*
 * Signed (r3 ref.impl.) counterpart of reduce32()
 *
 * For finite field element a with a <= 2^{31} - 2^{22} - 1, compute
 * r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
 *
 * @a: finite field element a
 *
 * Returns r.
 */
static int32_t s_reduce32(int32_t a)
{
	int32_t t;

	t = (a + (1 << 22)) >> 23;
	t = a - t * MLDSA_Q;

	return t;
}

/*
 * Add Q if input coefficient is negative.
 *
 * @a: finite field element a
 */
static int32_t s_caddq(int32_t a)
{
	a += (a >> 31) & MLDSA_Q;

	return a;
}

static const int32_t s_zetas[MLDSA_N] = {
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

/*
 * Signed counterpart of ntt256()
 *
 * Forward NTT, in-place. No modular reduction is performed after additions or
 * subtractions. Output vector is in bitreversed order.
 *
 * @a: input/output coefficient array
 */
static void sntt256(int32_t a[MLDSA_N])
{
	unsigned int len, start, j, k = 0;
	int32_t zeta, t;

	for (len = 128; len > 0; len >>= 1) {
		for (start = 0; start < MLDSA_N; start = j + len) {
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

/*
 * Signed counterpart of invntt_tomont256()
 *
 * Inverse NTT and multiplication by Montgomery factor 2^32. In-place. No
 * modular reductions after additions or subtractions; input coefficients
 * need to be smaller than Q in absolute value. Output coefficient are smaller
 * than Q in absolute value.
 *
 * a: input/output coefficient array
 */
static void invntt_s_tomont256(int32_t a[MLDSA_N])
{
	unsigned int start, len, j, k;
	const int64_t f = 41978; /* mont^2/256 */
	int32_t t, zeta;

	k = 256;

	for (len = 1; len < MLDSA_N; len <<= 1) {
		for (start = 0; start < MLDSA_N; start = j + len) {
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

	for (j = 0; j < MLDSA_N; ++j)
		a[j] = montgomery_s_reduce(f * a[j]);
}

/*
 * Expanded form of GAMMA1, replacing ref.impl. #define
 * Returns 0 for unknown 'k' (which SNH).
 */
static int32_t mldsa_k2gamma1(unsigned int k)
{
	switch (k) {
	case 4:
		return MLDSA_GAMMA1_4x4;
	case 6:
		return MLDSA_GAMMA1_6x5;
	case 8:
		return MLDSA_GAMMA1_8x7;
	default:
		return 0;
	}
}

/*
 * Expanded form of GAMMA2, replacing ref.impl. #define
 * Returns 0 for unknown 'k' (which SNH).
 */
static int32_t mldsa_k2gamma2(unsigned int k)
{
	switch (k) {
	case 4:
		return MLDSA_GAMMA2_4x4;
	case 6:
		return MLDSA_GAMMA2_6x5;
	case 8:
		return MLDSA_GAMMA2_8x7;
	default:
		return 0;
	}
}

/*
 * Expanded form of POLYZ_PACKEDBYTES, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 */
static size_t mldsa_k2polyz_bytes(unsigned int k)
{
	switch (k) {
	case 4:
		return MLDSA_POLYZ_BYTES4x4;
	case 6:
		return MLDSA_POLYZ_BYTES6x5;
	case 8:
		return MLDSA_POLYZ_BYTES8x7;
	default:
		return 0;
	}
}

/*
 * Expanded form of POLYW1_PACKEDBYTES, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH)
 */
static size_t mldsa_k2polyw1_bytes(unsigned int k)
{
	switch (k) {
	case 4:
		return MLDSA_POLYW1_BYTES4x4;
	case 6:
		return MLDSA_POLYW1_BYTES6x5;
	case 8:
		return MLDSA_POLYW1_BYTES8x7;
	default:
		return 0;
	}
}

/*
 * Expanded form of POLYETA_PACKEDBYTES, replacing ref.impl. #define
 * returns 0 for unknown param sets (which SNH).
 */
static size_t mldsa_ctilbytes(unsigned int k)
{
	switch (k) {
	case 4:
		return MLDSA_44_CTILDEBYTES;
	case 6:
		return MLDSA_65_CTILDEBYTES;
	case 8:
		return MLDSA_87_CTILDEBYTES;
	default:
		return 0;
	}
}

/*
 * Signed (r3 ref.) counterpart of decompose()
 */
static int32_t s_decompose(int32_t *a0, int32_t a, unsigned int mldsa_k)
{
	int32_t a1;

	a1 = (a + 127) >> 7;

	/*
	 * Original condition: GAMMA2 == (MLDSA_Q-1) /32
	 *   -> Dil3 (6x5), Dil5 (8x7)
	 */
	if (mldsa_k != 4) {
		a1 = (a1 * 1025 + (1 << 21)) >> 22;
		a1 &= 15;

		/*
		 * Original condition: GAMMA2 == (MLDSA_Q-1) /88
		 *   -> Dil2 (4x4)
		 */
	} else {
		a1 = (a1 * 11275 + (1 << 23)) >> 24;
		a1 ^= ((43 - a1) >> 31) & a1;
	}

	*a0 = a - a1 * 2 * mldsa_k2gamma2(mldsa_k);

	*a0 -= (((MLDSA_Q - 1) / 2 - *a0) >> 31) & MLDSA_Q;

	return a1;
}

/*
 * signed (r3 ref.) counterpart of use_hint()
 */
static int32_t use_s_hint(int32_t a, unsigned int hint, unsigned int mldsa_k)
{
	int32_t a0, a1;

	a1 = s_decompose(&a0, a, mldsa_k);

	if (hint == 0)
		return a1;

	/*
	 * original condition: GAMMA2 == (MLDSA_Q-1) /32
	 *   -> Dil3 (6x5), Dil5 (8x7)
	 */
	if (mldsa_k != 4) {
		if (a0 > 0)
			return (a1 + 1) & 15;
		else
			return (a1 - 1) & 15;

	/*
	 * original condition: GAMMA2 == (MLDSA_Q-1) /88
	 *   -> Dil2 (4x4)
	 */
	} else {
		if (a0 > 0)
			return (a1 == 43) ? 0 : a1 + 1;
		else
			return (a1 == 0) ? 43 : a1 - 1;
	}
}

/*
 * Inplace reduction of all coefficients of polynomial t representative in
 * [-6283009,6283007].
 *
 * @a: pointer to input/output polynomial
 */
static void spoly_reduce(struct spoly *a)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		a->coeffs[i] = s_reduce32(a->coeffs[i]);
}

/*
 * For all coefficients of in/out polynomial add Q if coefficient is negative.
 *
 * @a: pointer to input/output polynomial
 */
static void spoly_caddq(struct spoly *a)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		a->coeffs[i] = s_caddq(a->coeffs[i]);
}

/*
 * Add polynomials. No modular reduction is performed.
 *
 * @c: pointer to output polynomial
 * @a: pointer to first summand
 * @b: pointer to second summand
 */
static void spoly_add(struct spoly *c,
		      const struct spoly *a,
		      const struct spoly *b)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*
 * Subtract polynomials. No modular reduction is performed.
 *
 * @c: pointer to output polynomial
 * @a: pointer to first input polynomial
 * @b: pointer to second input polynomial to be
 *     subtraced from first input polynomial
 */
static void spoly_sub(struct spoly *c,
		      const struct spoly *a,
		      const struct spoly *b)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*
 * Multiply polynomial by 2^D without modular reduction. Assumes input
 * coefficients to be less than 2^{31-D} in absolute value.
 *
 * @a: pointer to input/output polynomial
 */
static void spoly_shiftl(struct spoly *a)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		a->coeffs[i] <<= MLDSA_SD;
}

/*
 * Inplace forward NTT. Coefficients can grow by 8*Q in absolute value.
 *
 * @a: pointer to input/output polynomial
 */
static void spoly_ntt256(struct spoly *a)
{
	sntt256(a->coeffs);
}

/*
 * Inplace inverse NTT and multiplication by 2^{32}. Input coefficients need
 * to be less than Q in absolute value and output coefficients are again
 * bounded by Q.
 *
 * @a: pointer to input/output polynomial
 */
static void spoly_invntt_tomont(struct spoly *a)
{
	invntt_s_tomont256(a->coeffs);
}

/*
 * Pointwise multiplication of polynomials in NTT domain representation and
 * multiplication of resulting polynomial by 2^{-32}.
 *
 * @c: pointer to output polynomial
 * @a: pointer to first input polynomial
 * @b: pointer to second input polynomial
 */
static void spoly_pointwise_montgomery(struct spoly *c,
				       const struct spoly *a,
				       const struct spoly *b)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		c->coeffs[i] = montgomery_s_reduce((int64_t)a->coeffs[i] *
						   b->coeffs[i]);
}

/*
 * Use hint polynomial to correct the high bits of a polynomial.
 *
 * @b: pointer to output polynomial with corrected high bits
 * @a: pointer to input polynomial
 * @h: pointer to input hint polynomial
 * @mldsa_k: K parameter
 */
static void spoly_use_hint(struct spoly *b,
			   const struct spoly *a,
			   const struct spoly *h,
			   unsigned int mldsa_k)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N; ++i)
		b->coeffs[i] = use_s_hint(a->coeffs[i], h->coeffs[i], mldsa_k);
}

/*
 * Check infinity norm of polynomial against given bound.
 * Assumes input coefficients were reduced by reduce32().
 *
 * @a: pointer to polynomial
 * @B: norm bound
 *
 * Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 */
static int spoly_chknorm(const struct spoly *a, int32_t B)
{
	unsigned int i;
	int32_t t;

	if (B > (MLDSA_Q - 1) / 8)
		return 1;

	/*
	 * It is ok to leak which coefficient violates the bound since
	 * the probability for each coefficient is independent of secret
	 * data but we must not leak the sign of the centralized representative.
	 */

	for (i = 0; i < MLDSA_N; ++i) {
		/* Absolute value */
		t = a->coeffs[i] >> 31;

		t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

		if (t >= B)
			return 1;
	}

	return 0;
}

/*
 * Sample uniformly random coefficients in [0, Q-1] by performing rejection
 * sampling on array of random bytes.
 *
 * @a: pointer to output array (allocated)
 * @len: number of coefficients to be sampled
 * @buf: array of random bytes
 * @buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 */
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

		t &= 0x7FFFFF;

		if (t < MLDSA_Q)
			a[ctr++] = t;
	}

	return ctr;
}

/*
 * Sample polynomial with uniformly random coefficients in [0,Q-1] by
 * performing rejection sampling on the output stream of SHAKE256(seed|nonce)
 *
 * @a: pointer to output polynomial
 * @seed[]: byte array with seed of length SEEDBYTES
 * @nonce: 2-byte nonce
 */
static void spoly_uniform(struct spoly *a,
			  const uint8_t seed[MLDSA_SEEDBYTES],
			  uint16_t nonce)
{
	unsigned int buflen = POLY_UNIFORM_NBLOCKS * MLDSA_STREAM128_BLOCKBYTES;
	uint8_t buf[POLY_UNIFORM_NBLOCKS * MLDSA_STREAM128_BLOCKBYTES + 2];
	SHASH_DESC_ON_STACK(shash, crypto_mldsa_shake128);
	uint8_t t[2] = { nonce, nonce >> 8 };
	unsigned int ctr;
	unsigned int off;
	unsigned int i;

	shash->tfm = crypto_mldsa_shake128;

	crypto_shash_init(shash);
	crypto_shash_update(shash, seed, MLDSA_SEEDBYTES);
	crypto_shash_update(shash, t, 2);
	crypto_shash_squeeze(shash, buf, sizeof(buf), false);

	ctr = rej_s_uniform(a->coeffs, MLDSA_N, buf, buflen);

	while (ctr < MLDSA_N) {
		// FIXME: simplify loop: https://ibm-research.slack.com/archives/D08BUJ8CKEY/p1758187493346489
		off = buflen % 3;
		printk(KERN_INFO "off=%u\n", off);

		for (i = 0; i < off; ++i)
			buf[i] = buf[buflen - off + i];

		crypto_shash_squeeze(shash, buf + off,
				     MLDSA_STREAM128_BLOCKBYTES, false);

		buflen = MLDSA_STREAM128_BLOCKBYTES + off;

		ctr += rej_s_uniform(a->coeffs + ctr, MLDSA_N - ctr,
				     buf, buflen);
	}
	crypto_shash_squeeze(shash, NULL, 0, true);
}

/*
 * Unpack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1].
 *
 * @r: pointer to output polynomial
 * @a: byte array with bit-packed polynomial
 * @mldsa_k: K parameter
 */
static void spolyz_unpack(struct spoly *r, const uint8_t *a,
			  unsigned int mldsa_k)
{
	unsigned int i, gamma1;

	gamma1 = mldsa_k2gamma1(mldsa_k);

	if (gamma1 == (1 << 17)) { /* was: GAMMA1 == (1 << 17) */
		for (i = 0; i < MLDSA_N / 4; ++i) {
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
		for (i = 0; i < MLDSA_N / 2; ++i) {
			r->coeffs[2 * i + 0] = a[5 * i + 0];
			r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
			r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
			r->coeffs[2 * i + 0] &= 0xFFFFF;

			r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
			r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
			r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;

			r->coeffs[2 * i + 0] = gamma1 - r->coeffs[2 * i + 0];
			r->coeffs[2 * i + 1] = gamma1 - r->coeffs[2 * i + 1];
		}
	}
}


/*
 * returns 0 for unknown param.sets, which should not happen
 */
static unsigned int mldsa_k2tau(unsigned int mldsa_k)
{
	switch (mldsa_k) {
	case 4:
		return MLDSA_TAU4x4;
	case 6:
		return MLDSA_TAU6x5;
	case 8:
		return MLDSA_TAU8x7;
	default:
		return 0; /* SNH */
	}
}

/*
 * Implementation of H. Samples polynomial with TAU nonzero
 * coefficients in {-1,1} using the output stream of SHAKE256(seed).
 *
 * @c: pointer to output polynomial
 * @seed: byte array containing seed of length ctildebytes
 * @mldsa_k: K parameter
 */
static void ml_spoly_challenge(struct spoly *c, const uint8_t *seed,
			       unsigned int mldsa_k)
{
	SHASH_DESC_ON_STACK(shash, crypto_mldsa_shake256);
	size_t ctilbytes = mldsa_ctilbytes(mldsa_k);
	uint8_t buf[SHAKE256_RATE];
	unsigned int pos;
	unsigned int i;
	unsigned int b;
	uint64_t signs;

	shash->tfm = crypto_mldsa_shake256;

	crypto_shash_init(shash);
	crypto_shash_update(shash, seed, ctilbytes);
	crypto_shash_squeeze(shash, buf, sizeof(buf), false);

	signs = 0;
	for (i = 0; i < 8; ++i)
		signs |= (uint64_t)buf[i] << 8 * i;

	pos = 8;

	for (i = 0; i < MLDSA_N; ++i)
		c->coeffs[i] = 0;

	for (i = MLDSA_N - mldsa_k2tau(mldsa_k); i < MLDSA_N; ++i) {
		do {
			if (pos >= SHAKE256_RATE) {
				crypto_shash_squeeze(shash, buf,
						     sizeof(buf), false);
				pos = 0;
			}

			b = buf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (signs & 1);

		signs >>= 1;
	}
	crypto_shash_squeeze(shash, NULL, 0, true);
}

/*
 * Unpack polynomial t1 with 10-bit coefficients.
 * Output coefficients are standard representatives.
 *
 * @r: pointer to output polynomial
 * @a: byte array with bit-packed polynomial
 */
static void spolyt1_unpack(struct spoly *r, const uint8_t *a)
{
	unsigned int i;

	for (i = 0; i < MLDSA_N / 4; ++i) {
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

/*
 * spolyw1_pack
 *
 * Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 * Input coefficients are assumed to be standard representatives.
 *
 * @r: pointer to output byte array with at least
 *     POLYW1_PACKEDBYTES bytes
 * @a: pointer to input polynomial
 * @mldsa_k: K parameter
 */
static void spolyw1_pack(uint8_t *r, const struct spoly *a,
			 unsigned int mldsa_k)
{
	unsigned int i, gamma2;

	gamma2 = mldsa_k2gamma2(mldsa_k);

	if (gamma2 == (MLDSA_Q - 1) / 88) {
		for (i = 0; i < MLDSA_N / 4; ++i) {
			r[3 * i + 0] = a->coeffs[4 * i + 0];
			r[3 * i + 0] |= a->coeffs[4 * i + 1] << 6;
			r[3 * i + 1] = a->coeffs[4 * i + 1] >> 2;
			r[3 * i + 1] |= a->coeffs[4 * i + 2] << 4;
			r[3 * i + 2] = a->coeffs[4 * i + 2] >> 4;
			r[3 * i + 2] |= a->coeffs[4 * i + 3] << 2;
		}

	} else { /* gamma2 == (MLDSA_Q-1) /32 */
		for (i = 0; i < MLDSA_N / 2; ++i)
			r[i] = a->coeffs[2 * i + 0] |
				(a->coeffs[2 * i + 1] << 4);
	}
}


static unsigned int mldsa_omega(unsigned int k)
{
	switch (k) {
	case 0x4:
		return MLDSA_OMEGA4x4;
	case 0x6:
		return MLDSA_OMEGA6x5;
	case 0x8:
		return MLDSA_OMEGA8x7;
	default:
		return 0;
	}
}

static unsigned int mldsa_k2beta(unsigned int k)
{
	switch (k) {
	case 0x4:
		return MLDSA_BETA4x4;
	case 0x6:
		return MLDSA_BETA6x5;
	case 0x8:
		return MLDSA_BETA8x7;
	default:
		return 0;
	}
}

/*
 * Raw bytecount, excluding ASN framing
 * Returns 0 if parameter choice is not supported.
 *
 * ref.impl:
 * CRYPTO_BYTES == (L*POLYZ_PACKEDBYTES + OMEGA + K + N/8 + 8)  [r2]
 *
 */
static size_t mldsa_signature_bytes(unsigned int k, unsigned int l)
{
	switch ((k << 4) | l) {
	case 0x44:
		return MLDSA_SIGBYTES4x4;
	case 0x65:
		return MLDSA_SIGBYTES6x5;
	case 0x87:
		return MLDSA_SIGBYTES8x7;
	default:
		return 0;
	}
}

static enum mldsa_id mldsa_pubbytes2type(size_t pubbytes)
{
	switch (pubbytes) {
	case MLDSA_44_PUB_BYTES:
		return MLDSA_44_ID;
	case MLDSA_65_PUB_BYTES:
		return MLDSA_65_ID;
	case MLDSA_87_PUB_BYTES:
		return MLDSA_87_ID;
	default:
		return 0;
	}
}

/*
 * does not check 'type' validity; call only after verification
 *
 * Type is <K> <L>
 */
static unsigned int mldsa_type2k(enum mldsa_id type)
{
	return ((type >> 4) & 0x0f); /* <K> <L> */
}

/*
 * does not check 'type' validity; call only after verification
 *
 * Type is <K> <L>
 */
static unsigned int mldsa_type2l(enum mldsa_id type)
{
	return type & 0x0f; /* <K> <L> */
}

#include "polyvec-include.h" /* size-specialized fn set */

/*
 * mldsa_wire2sig - Unpack signature sig = (z, h, c)
 *
 * @z: pointer to output vector z
 * @h: pointer to output hint vector h
 * @mldsa_k: K parameter
 * @mldsa_l: L parameter
 * @sig: pointer to bit-packed signature; its size must have been checked
 *       by caller
 *
 * Returns >0 in case of malformed signature; otherwise 0.
 *
 * accesses only necessary number of elements of z[] and h[],
 * 'sig' and 'chash' may be the same buffer; other overlap is undefined
 */
static int mldsa_wire2sig(unsigned char chash[MLDSA_MAX_CTILDEBYTES],
                          struct spolyvec_max *z, struct spolyvec_max *h,
			  unsigned int mldsa_k, unsigned int mldsa_l,
			  const unsigned char *sig)
{
	size_t ctilbytes = mldsa_ctilbytes(mldsa_k);
	size_t pzb = mldsa_k2polyz_bytes(mldsa_k);
	unsigned int omega = mldsa_omega(mldsa_k);
	unsigned int i, j, k;

	memmove(chash, sig, ctilbytes);

	sig += ctilbytes;

	for (i = 0; i < mldsa_l; ++i) /* L */
		spolyz_unpack(&(z->vec[i]), sig + i * pzb, mldsa_k);

	sig += mldsa_l * pzb; /* L * ... */

	/* Decode h */
	k = 0;

	for (i = 0; i < mldsa_k; ++i) {
		for (j = 0; j < MLDSA_N; ++j)
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

	return 0;
}

/*
 * mldsa_verify_internal - Verifies signature
 *
 * @sig: pointer to input signature
 * @siglen: length of signature
 * @m: pointer to message
 * @mlen: length of message
 * @pk: pointer to bit-packed public key
 * @pkbytes: length of @pk
 * @domsep: byte for domain separation; 0 or 1
 * @domseplen: length of domain separator; if 0 then domain separator
 *             and context will not be added to hash
 * @ctx: optional context
 * @cbytes: length of context; must be <= 255
 *
 * Returns 1 if signature could be verified correctly, 0 or a negative errno
 * otherwise.
 */
int mldsa_verify_internal(const uint8_t *sig, size_t siglen,
			  const uint8_t *m, size_t mlen,
			  const uint8_t *pk, size_t pkbytes,
			  const uint8_t *domsep, size_t domseplen,
			  const uint8_t *ctx, size_t cbytes)
{
	struct ver_mat {
		struct spoly cp;
		struct spolyvec_max mat[MLDSA_VECT_MAX], z; /* L; LxK (mat) */
		struct spolyvec_max t1, h, w1; /* K */
		unsigned char w1pack[MLDSA_KxPOLYW1_MAX_BYTES];
	} *pMat;
	SHASH_DESC_ON_STACK(shash, crypto_mldsa_shake256);
	unsigned char chash[MLDSA_MAX_CTILDEBYTES];
	/* note: rho size is max(MLDSA_MAX_CTILDEBYTES, MLDSA_SEEDBYTES) */
	unsigned char rho[MLDSA_MAX_CTILDEBYTES];
	unsigned char mu[MLDSA_CRHBYTES];
	size_t ctilbytes, sigb, w1pb, i;
	unsigned int beta, fail, K, L;
	int32_t gamma1, gamma2;
	enum mldsa_id type;
	unsigned char clen;
	int ret = -EINVAL;

	if (cbytes > 255)
		return -EINVAL;

	type = mldsa_pubbytes2type(pkbytes);
	K = mldsa_type2k(type);
	L = mldsa_type2l(type);
	ctilbytes = mldsa_ctilbytes(K);
	gamma1 = mldsa_k2gamma1(K);
	gamma2 = mldsa_k2gamma2(K);
	w1pb = K * mldsa_k2polyw1_bytes(K);

	if (!type || !K || !L || !gamma1 || !gamma2 || !w1pb ||
	    (w1pb > sizeof(pMat->w1pack)))
		return -EKEYREJECTED;

	sigb = mldsa_signature_bytes(K, L);
	beta = mldsa_k2beta(K);

	if (!sig || !sigb || (siglen != sigb))
		return -EINVAL;

	pMat = kmalloc(sizeof(*pMat), GFP_KERNEL);
	if (!pMat)
		return -ENOMEM;

	switch (K) {
	case 4:
		sunpack_pk4(rho, (struct spolyvec4 *)&pMat->t1, pk);
		break;
	case 6:
		sunpack_pk6(rho, (struct spolyvec6 *)&pMat->t1, pk);
		break;
	case 8:
		sunpack_pk8(rho, (struct spolyvec8 *)&pMat->t1, pk);
		break;
	default:
		ret = -EINVAL;
		goto err_free_pmat;
	}

	if (mldsa_wire2sig(chash, &pMat->z, &pMat->h, K, L, sig)) {
		ret = -EINVAL;
		goto err_free_pmat;
	}

	switch (K) {
	case 4:
		fail = !!spolyvec4_chknorm((const struct spolyvec4 *)&pMat->z,
					   gamma1 - beta);
		break;
	case 6:
		fail = !!spolyvec5_chknorm((const struct spolyvec5 *)&pMat->z,
					   gamma1 - beta);
		break;
	case 8:
		fail = !!spolyvec7_chknorm((const struct spolyvec7 *)&pMat->z,
					   gamma1 - beta);
		break;
	default:
		fail = 1;
		break;
	}
	if (fail) {
		ret = -EINVAL;
		goto err_free_pmat;
	}

	shash->tfm = crypto_mldsa_shake256;

	crypto_shash_init(shash);
	crypto_shash_update(shash, pk, pkbytes);
	crypto_shash_squeeze(shash, mu, MLDSA_CRHBYTES, true);

	crypto_shash_init(shash);
	crypto_shash_update(shash, mu, MLDSA_TRBYTES);
	if (domseplen > 0) {
		clen = cbytes;
		crypto_shash_update(shash, domsep, domseplen);
		crypto_shash_update(shash, &clen, 1);
		if (ctx)
			crypto_shash_update(shash, ctx, cbytes);
	}
	crypto_shash_update(shash, m, mlen);
	crypto_shash_squeeze(shash, mu, MLDSA_TRBYTES, true);

	ml_spoly_challenge(&pMat->cp, chash, K);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */

	switch (K) { /* NTT on L-sized vector */
	case 4:
		expand_smatrix_4x4(pMat->mat, rho);
		spolyvec4_ntt((struct spolyvec4 *)&pMat->z); /* L */
		spolyvec4x4_matrix_pointwise_montgomery(
			(struct spolyvec4 *)&pMat->w1, pMat->mat,
			(const struct spolyvec4 *)&pMat->z);
		break;

	case 6:
		expand_smatrix_6x5(pMat->mat, rho);
		spolyvec5_ntt((struct spolyvec5 *)&pMat->z); /* L */
		spolyvec6x5_matrix_pointwise_montgomery(
			(struct spolyvec6 *)&pMat->w1, pMat->mat,
			(const struct spolyvec5 *)&pMat->z);
		break;

	case 8:
		expand_smatrix_8x7(pMat->mat, rho);
		spolyvec7_ntt((struct spolyvec7 *)&pMat->z); /* L */
		spolyvec8x7_matrix_pointwise_montgomery(
			(struct spolyvec8 *)&pMat->w1, pMat->mat,
			(const struct spolyvec7 *)&pMat->z);
		break;
	}

	spoly_ntt256(&pMat->cp);

	switch (K) {
	case 4:
		spolyvec4_shiftl((struct spolyvec4 *)&pMat->t1);
		spolyvec4_ntt((struct spolyvec4 *)&pMat->t1);
		spolyvec4_pointwise_poly_montgomery(
			(struct spolyvec4 *)&pMat->t1, &pMat->cp,
			(const struct spolyvec4 *)&pMat->t1);
		spolyvec4_sub((struct spolyvec4 *)&pMat->w1,
			      (const struct spolyvec4 *)&pMat->w1,
			      (const struct spolyvec4 *)&pMat->t1);
		spolyvec4_reduce((struct spolyvec4 *)&pMat->w1);
		spolyvec4_invntt_tomont((struct spolyvec4 *)&pMat->w1);
		/* reconstruct W1 */
		spolyvec4_caddq((struct spolyvec4 *)&pMat->w1);
		spolyvec4_use_hint((struct spolyvec4 *)&pMat->w1,
				   (const struct spolyvec4 *)&pMat->w1,
				   (const struct spolyvec4 *)&pMat->h, K);
		spolyvec4_pack_w1(pMat->w1pack,
				  (const struct spolyvec4 *)&pMat->w1);
		break;

	case 6:
		spolyvec6_shiftl((struct spolyvec6 *)&pMat->t1);
		spolyvec6_ntt((struct spolyvec6 *)&pMat->t1);
		spolyvec6_pointwise_poly_montgomery(
			(struct spolyvec6 *)&pMat->t1, &pMat->cp,
			(const struct spolyvec6 *)&pMat->t1);
		spolyvec6_sub((struct spolyvec6 *)&pMat->w1,
			      (const struct spolyvec6 *)&pMat->w1,
			      (const struct spolyvec6 *)&pMat->t1);
		spolyvec6_reduce((struct spolyvec6 *)&pMat->w1);
		spolyvec6_invntt_tomont((struct spolyvec6 *)&pMat->w1);
		/* reconstruct W1 */
		spolyvec6_caddq((struct spolyvec6 *)&pMat->w1);
		spolyvec6_use_hint((struct spolyvec6 *)&pMat->w1,
				   (const struct spolyvec6 *)&pMat->w1,
				   (const struct spolyvec6 *)&pMat->h, K);
		spolyvec6_pack_w1(pMat->w1pack,
				  (const struct spolyvec6 *)&pMat->w1);
		break;

	case 8:
		spolyvec8_shiftl((struct spolyvec8 *)&pMat->t1);
		spolyvec8_ntt((struct spolyvec8 *)&pMat->t1);
		spolyvec8_pointwise_poly_montgomery(
			(struct spolyvec8 *)&pMat->t1, &pMat->cp,
			(const struct spolyvec8 *)&pMat->t1);
		spolyvec8_sub((struct spolyvec8 *)&pMat->w1,
			      (const struct spolyvec8 *)&pMat->w1,
			      (const struct spolyvec8 *)&pMat->t1);
		spolyvec8_reduce((struct spolyvec8 *)&pMat->w1);
		spolyvec8_invntt_tomont((struct spolyvec8 *)&pMat->w1);
		/* reconstruct W1 */
		spolyvec8_caddq((struct spolyvec8 *)&pMat->w1);
		spolyvec8_use_hint((struct spolyvec8 *)&pMat->w1,
				   (const struct spolyvec8 *)&pMat->w1,
				   (const struct spolyvec8 *)&pMat->h, K);
		spolyvec8_pack_w1(pMat->w1pack,
				  (const struct spolyvec8 *)&pMat->w1);
		break;
	}

	/*
	 * rho[ MLDSA_SEEDBYTES ] := CRH(mu[ DIL_CRHBYTES ], w1pack[w1pb])
	 * reusing already-idle rho[] which happens to share size
	 */
	crypto_shash_init(shash);
	crypto_shash_update(shash, mu, MLDSA_CRHBYTES);
	crypto_shash_update(shash, pMat->w1pack, w1pb);
	crypto_shash_squeeze(shash, rho, ctilbytes, true);

	sigb = 0;
	for (i = 0; i < ctilbytes; ++i)
		sigb += (chash[i] == rho[i]);

	ret = (sigb == ctilbytes);

err_free_pmat:
	memzero_explicit(pMat, sizeof(struct ver_mat));
	kfree(pMat);

	return ret;
}
