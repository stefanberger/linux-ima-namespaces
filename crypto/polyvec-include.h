// SPDX-License-Identifier: Apache-2.0
#ifndef _CRYPTO_POLYVEC_INCLUDE_H
#define _CRYPTO_POLYVEC_INCLUDE_H

typedef struct {
	spoly vec[4];
} spolyvec4;

typedef struct {
	spoly vec[5];
} spolyvec5;

typedef struct {
	spoly vec[6];
} spolyvec6;

typedef struct {
	spoly vec[7];
} spolyvec7;

typedef struct {
	spoly vec[8];
} spolyvec8;

static inline void spolyvec4_ntt(spolyvec4 *v)
{
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		spoly_ntt256(&(v->vec[i]));
	}
}

static inline unsigned int spolyvec4_chknorm(const spolyvec4 *v,
					     int32_t bound)
{
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		if (spoly_chknorm(&(v->vec[i]), bound))
			return 1;
	}

	return 0;
}

static inline void spolyvec4_reduce(spolyvec4 *v)
{
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		spoly_reduce(&(v->vec[i]));
	}
}

static inline void spolyvec4_invntt_tomont(spolyvec4 *v)
{
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		spoly_invntt_tomont(&(v->vec[i]));
	}
}

static inline void spolyvec4_pointwise_poly_montgomery(spolyvec4 *r,
						       const spoly *a,
						       const spolyvec4 *v)
{
	unsigned int n;

	for (n = 0; n < 4; ++n) {
		spoly_pointwise_montgomery(&(r->vec[n]), a, &(v->vec[n]));
	}
}

static inline void spolyvec4_pointwise_acc_montgomery(spoly *w,
						      const spolyvec4 *u,
						      const spolyvec4 *v)
{
	unsigned int i;
	spoly tmp;

	spoly_pointwise_montgomery(w, &(u->vec[0]), &(v->vec[0]));

	for (i = 1; i < 4; ++i) {
		spoly_pointwise_montgomery(&tmp, &(u->vec[i]), &(v->vec[i]));
		spoly_add(w, w, &tmp);
	}
}

static inline void spolyvec5_ntt(spolyvec5 *v)
{
	unsigned int i;

	for (i = 0; i < 5; ++i) {
		spoly_ntt256(&(v->vec[i]));
	}
}

static inline unsigned int spolyvec5_chknorm(const spolyvec5 *v,
					     int32_t bound)
{
	unsigned int i;

	for (i = 0; i < 5; ++i) {
		if (spoly_chknorm(&(v->vec[i]), bound))
			return 1;
	}

	return 0;
}

static inline void spolyvec5_pointwise_acc_montgomery(spoly *w,
						      const spolyvec5 *u,
						      const spolyvec5 *v)
{
	unsigned int i;
	spoly tmp;

	spoly_pointwise_montgomery(w, &(u->vec[0]), &(v->vec[0]));

	for (i = 1; i < 5; ++i) {
		spoly_pointwise_montgomery(&tmp, &(u->vec[i]), &(v->vec[i]));
		spoly_add(w, w, &tmp);
	}
}

static inline void spolyvec6_ntt(spolyvec6 *v)
{
	unsigned int i;

	for (i = 0; i < 6; ++i) {
		spoly_ntt256(&(v->vec[i]));
	}
}

static inline void spolyvec6_reduce(spolyvec6 *v)
{
	unsigned int i;

	for (i = 0; i < 6; ++i) {
		spoly_reduce(&(v->vec[i]));
	}
}

static inline void spolyvec6_invntt_tomont(spolyvec6 *v)
{
	unsigned int i;

	for (i = 0; i < 6; ++i) {
		spoly_invntt_tomont(&(v->vec[i]));
	}
}

static inline void spolyvec6_pointwise_poly_montgomery(spolyvec6 *r,
						       const spoly *a,
						       const spolyvec6 *v)
{
	unsigned int n;

	for (n = 0; n < 6; ++n) {
		spoly_pointwise_montgomery(&(r->vec[n]), a, &(v->vec[n]));
	}
}

static inline void spolyvec7_ntt(spolyvec7 *v)
{
	unsigned int i;

	for (i = 0; i < 7; ++i) {
		spoly_ntt256(&(v->vec[i]));
	}
}

static inline unsigned int spolyvec7_chknorm(const spolyvec7 *v,
					     int32_t bound)
{
	unsigned int i;

	for (i = 0; i < 7; ++i) {
		if (spoly_chknorm(&(v->vec[i]), bound))
			return 1;
	}

	return 0;
}

static inline void spolyvec7_pointwise_acc_montgomery(spoly *w,
						      const spolyvec7 *u,
						      const spolyvec7 *v)
{
	unsigned int i;
	spoly tmp;

	spoly_pointwise_montgomery(w, &(u->vec[0]), &(v->vec[0]));

	for (i = 1; i < 7; ++i) {
		spoly_pointwise_montgomery(&tmp, &(u->vec[i]), &(v->vec[i]));
		spoly_add(w, w, &tmp);
	}
}

static inline void spolyvec8_ntt(spolyvec8 *v)
{
	unsigned int i;

	for (i = 0; i < 8; ++i) {
		spoly_ntt256(&(v->vec[i]));
	}
}

static inline void spolyvec8_reduce(spolyvec8 *v)
{
	unsigned int i;

	for (i = 0; i < 8; ++i) {
		spoly_reduce(&(v->vec[i]));
	}
}

static inline void spolyvec8_invntt_tomont(spolyvec8 *v)
{
	unsigned int i;

	for (i = 0; i < 8; ++i) {
		spoly_invntt_tomont(&(v->vec[i]));
	}
}

static inline void spolyvec8_pointwise_poly_montgomery(spolyvec8 *r,
						       const spoly *a,
						       const spolyvec8 *v)
{
	unsigned int n;

	for (n = 0; n < 8; ++n) {
		spoly_pointwise_montgomery(&(r->vec[n]), a, &(v->vec[n]));
	}
}

static inline void expand_smatrix_4x4(spolyvec_max mat[4],
				      const unsigned char rho[DIL_SEEDBYTES])
{
	unsigned int k, l;

	for (k = 0; k < 4; ++k) {
		for (l = 0; l < 4; ++l) {
			spoly_uniform(&(mat[k].vec[l]), rho, (k << 8) + l);
		}
	}
}

static inline void
spolyvec4x4_matrix_pointwise_montgomery(spolyvec4 *t,
					const spolyvec_max *mat, /* use x4 */
					const spolyvec4 *v)
{
	unsigned int k;

	for (k = 0; k < 4; ++k) {
		spolyvec4_pointwise_acc_montgomery(
			&(t->vec[k]), (const spolyvec4 *)&(mat[k]), v);
	}
}

static inline void expand_smatrix_6x5(spolyvec_max mat[6],
				      const unsigned char rho[DIL_SEEDBYTES])
{
	unsigned int k, l;

	for (k = 0; k < 6; ++k) {
		for (l = 0; l < 5; ++l) {
			spoly_uniform(&(mat[k].vec[l]), rho, (k << 8) + l);
		}
	}
}

static inline void
spolyvec6x5_matrix_pointwise_montgomery(spolyvec6 *t,
					const spolyvec_max *mat, /* use x6 */
					const spolyvec5 *v)
{
	unsigned int k;

	for (k = 0; k < 6; ++k) {
		spolyvec5_pointwise_acc_montgomery(
			&(t->vec[k]), (const spolyvec5 *)&(mat[k]), v);
	}
}

static inline void expand_smatrix_8x7(spolyvec_max mat[8],
				      const unsigned char rho[DIL_SEEDBYTES])
{
	unsigned int k, l;

	for (k = 0; k < 8; ++k) {
		for (l = 0; l < 7; ++l) {
			spoly_uniform(&(mat[k].vec[l]), rho, (k << 8) + l);
		}
	}
}

static inline void
spolyvec8x7_matrix_pointwise_montgomery(spolyvec8 *t,
					const spolyvec_max *mat, /* use x8 */
					const spolyvec7 *v)
{
	unsigned int k;

	for (k = 0; k < 8; ++k) {
		spolyvec7_pointwise_acc_montgomery(
			&(t->vec[k]), (const spolyvec7 *)&(mat[k]), v);
	}
}

static inline void spolyvec4_caddq(spolyvec4 *v)
{
	unsigned int k;

	for (k = 0; k < 4; ++k) {
		spoly_caddq(&(v->vec[k]));
	}
}

static inline void spolyvec4_sub(spolyvec4 *r, const spolyvec4 *u,
				 const spolyvec4 *v)
{
	unsigned int k;

	for (k = 0; k < 4; ++k) {
		spoly_sub(&(r->vec[k]), &(u->vec[k]), &(v->vec[k]));
	}
}

static inline void spolyvec4_shiftl(spolyvec4 *v)
{
	unsigned int k;

	for (k = 0; k < 4; ++k) {
		spoly_shiftl(&(v->vec[k]));
	}
}

static inline void spolyvec4_use_hint(spolyvec4 *r, const spolyvec4 *u,
				      const spolyvec4 *v, unsigned int dil_k)
{
	unsigned int k;

	for (k = 0; k < 4; ++k) {
		spoly_use_hint(&(r->vec[k]), &(u->vec[k]), &(v->vec[k]), dil_k);
	}
}

static inline void spolyvec4_pack_w1(unsigned char r[768], const spolyvec4 *w1)
{
	unsigned int k;

	for (k = 0; k < 4; ++k) {
		spolyw1_pack(&(r[k * 192]), &(w1->vec[k]), 4 /*K*/);
	}
}

static inline void sunpack_pk4(unsigned char rho[DIL_SEEDBYTES], spolyvec4 *t1,
			       const unsigned char pk[DIL_R3_PUB4x4_BYTES])
{
	unsigned int k;

	memmove(rho, pk, DIL_SEEDBYTES);
	pk += DIL_SEEDBYTES;

	for (k = 0; k < 4; ++k) {
		spolyt1_unpack(&(t1->vec[k]),
			       pk + k * DIL_R3_POLYT1_PACKEDBYTES);
	}
}

static inline void spolyvec6_caddq(spolyvec6 *v)
{
	unsigned int k;

	for (k = 0; k < 6; ++k) {
		spoly_caddq(&(v->vec[k]));
	}
}

static inline void spolyvec6_sub(spolyvec6 *r, const spolyvec6 *u,
				 const spolyvec6 *v)
{
	unsigned int k;

	for (k = 0; k < 6; ++k) {
		spoly_sub(&(r->vec[k]), &(u->vec[k]), &(v->vec[k]));
	}
}

static inline void spolyvec6_shiftl(spolyvec6 *v)
{
	unsigned int k;

	for (k = 0; k < 6; ++k) {
		spoly_shiftl(&(v->vec[k]));
	}
}

static inline void spolyvec6_use_hint(spolyvec6 *r, const spolyvec6 *u,
				      const spolyvec6 *v, unsigned int dil_k)
{
	unsigned int k;

	for (k = 0; k < 6; ++k) {
		spoly_use_hint(&(r->vec[k]), &(u->vec[k]), &(v->vec[k]), dil_k);
	}
}

static inline void spolyvec6_pack_w1(unsigned char r[768], const spolyvec6 *w1)
{
	unsigned int k;

	for (k = 0; k < 6; ++k) {
		spolyw1_pack(&(r[k * 128]), &(w1->vec[k]), 6 /*K*/);
	}
}

static inline void sunpack_pk6(unsigned char rho[DIL_SEEDBYTES], spolyvec6 *t1,
			       const unsigned char pk[DIL_R3_PUB6x5_BYTES])
{
	unsigned int k;

	memmove(rho, pk, DIL_SEEDBYTES);
	pk += DIL_SEEDBYTES;

	for (k = 0; k < 6; ++k) {
		spolyt1_unpack(&(t1->vec[k]),
			       pk + k * DIL_R3_POLYT1_PACKEDBYTES);
	}
}

static inline void spolyvec8_caddq(spolyvec8 *v)
{
	unsigned int k;

	for (k = 0; k < 8; ++k) {
		spoly_caddq(&(v->vec[k]));
	}
}

static inline void spolyvec8_sub(spolyvec8 *r, const spolyvec8 *u,
				 const spolyvec8 *v)
{
	unsigned int k;

	for (k = 0; k < 8; ++k) {
		spoly_sub(&(r->vec[k]), &(u->vec[k]), &(v->vec[k]));
	}
}

static inline void spolyvec8_shiftl(spolyvec8 *v)
{
	unsigned int k;

	for (k = 0; k < 8; ++k) {
		spoly_shiftl(&(v->vec[k]));
	}
}

static inline void spolyvec8_use_hint(spolyvec8 *r, const spolyvec8 *u,
				      const spolyvec8 *v, unsigned int dil_k)
{
	unsigned int k;

	for (k = 0; k < 8; ++k) {
		spoly_use_hint(&(r->vec[k]), &(u->vec[k]), &(v->vec[k]), dil_k);
	}
}

static inline void spolyvec8_pack_w1(unsigned char r[1024], const spolyvec8 *w1)
{
	unsigned int k;

	for (k = 0; k < 8; ++k) {
		spolyw1_pack(&(r[k * 128]), &(w1->vec[k]), 8 /*K*/);
	}
}

static inline void sunpack_pk8(unsigned char rho[DIL_SEEDBYTES], spolyvec8 *t1,
			       const unsigned char pk[DIL_R3_PUB8x7_BYTES])
{
	unsigned int k;

	memmove(rho, pk, DIL_SEEDBYTES);
	pk += DIL_SEEDBYTES;

	for (k = 0; k < 8; ++k) {
		spolyt1_unpack(&(t1->vec[k]),
			       pk + k * DIL_R3_POLYT1_PACKEDBYTES);
	}
}

#endif
