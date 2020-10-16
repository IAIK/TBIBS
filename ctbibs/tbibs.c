/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#include "tbibs.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/sha.h>
#include <relic/relic.h>

struct tbibs_public_params_s {
  bn_t order;
  ep_t g_2, g_3;
  size_t L;
  ep_t h[];
};

struct tbibs_public_key_s {
  tbibs_public_params_t* pp;
  ep2_t public_key;
};

struct tbibs_public_key_with_precomp_s {
  tbibs_public_key_t* pk;
  ep_t precomp;
};

struct tbibs_secret_key_s {
  tbibs_public_params_t* pp;
  ep_t secret_key;
};

struct tbibs_delegated_key_s {
  tbibs_public_params_t* pp;
  ep_t s_1;
  ep2_t s_2;
  ep_t precomp;
  ep_t s_3[];
};

struct tbibs_signature_s {
  ep_t s_1;
  ep2_t s_2;
};

/* helper functions */

static void hash_order(bn_t v, bn_t order, size_t num, ...) {
  uint8_t digest[RLC_MD_LEN_SH512];
  SHA512_CTX ctx;
  SHA512_Init(&ctx);

  va_list ap;
  va_start(ap, num);
  while (num--) {
    const uint8_t* data = va_arg(ap, const uint8_t*);
    const size_t len    = va_arg(ap, const size_t);
    SHA512_Update(&ctx, data, len);
  }
  va_end(ap);

  SHA512_Final(digest, &ctx);

  bn_read_bin(v, digest, RLC_MD_LEN_SH512);
  bn_mod(v, v, order);
}

/* relic init/deinit */

static fp12_t fp12_one;

int tbibs_init(void) {
  if (core_init() != RLC_OK) {
    return 1;
  }

  int ret = 0;

  ep_param_set_any_pairf();
  fp12_null(fp12_one);

  TRY {
    fp12_new(fp12_one);
    fp12_zero(fp12_one);
    fp12_set_dig(fp12_one, 1);
  } CATCH_ANY {
    ret = 1;
  }

  return ret;
}

void tbibs_deinit(void) {
  fp12_free(fp12_one);

  core_clean();
}

/* public parameter handling */

void tbibs_public_params_free(tbibs_public_params_t* pp) {
  if (pp) {
    for (unsigned int i = pp->L; i; --i) {
      ep_free(pp->h[i - 1]);
    }
    ep_free(pp->g_3);
    ep_free(pp->g_2);
    bn_free(pp->order);
    free(pp);
  }
}

tbibs_public_params_t* tbibs_public_params_new(unsigned int L) {
  if (!L) {
    return NULL;
  }
  /* add a level for the message */
  L += 1;

  tbibs_public_params_t* pp = malloc(sizeof(tbibs_public_params_t) + L * sizeof(ep_t));
  if (!pp) {
    return NULL;
  }

  /* initialize to NULL */
  bn_null(pp->order);
  ep_null(pp->g_2);
  ep_null(pp->g_3);
  pp->L = L;
  for (unsigned int i = 0; i < L; ++i) {
    ep_null(pp->h[i]);
  }

  char buffer[128];
  TRY {
    bn_new(pp->order);
    ep_curve_get_ord(pp->order);

    snprintf(buffer, sizeof(buffer), "TBIBS|g_2|%" PRIx64, (uint64_t)L);
    ep_new(pp->g_2);
    ep_map(pp->g_2, (const uint8_t*)buffer, strlen(buffer));

    snprintf(buffer, sizeof(buffer), "TBIBS|g_3|%" PRIx64, (uint64_t)L);
    ep_new(pp->g_3);
    ep_map(pp->g_3, (const uint8_t*)buffer, strlen(buffer));

    for (unsigned int i = 0; i < L; ++i) {
      snprintf(buffer, sizeof(buffer), "TBIBS|g|%" PRIx64 "|%" PRIx64, (uint64_t)L, (uint64_t)i);
      ep_new(pp->h[i]);
      ep_map(pp->h[i], (const uint8_t*)buffer, strlen(buffer));
    }
  } CATCH_ANY {
    tbibs_public_params_free(pp);
    pp = NULL;
  }

  return pp;
}

/* key handling */

void tbibs_public_key_free(tbibs_public_key_t* pk) {
  if (pk) {
    ep2_free(pk->public_key);
    free(pk);
  }
}

tbibs_public_key_t* tbibs_public_key_new(tbibs_public_params_t* pp) {
  if (!pp) {
    return NULL;
  }

  tbibs_public_key_t* pk = malloc(sizeof(tbibs_public_key_t));
  if (!pk) {
    return NULL;
  }

  pk->pp = pp;
  /* initialize to NULL */
  ep2_null(pk->public_key);

  TRY {
    ep2_new(pk->public_key);
  } CATCH_ANY {
    tbibs_public_key_free(pk);
    pk = NULL;
  }

  return pk;
}

void tbibs_public_key_with_precomp_free(tbibs_public_key_with_precomp_t* pk) {
  if (pk) {
    ep_free(pk->precomp);
    free(pk);
  }
}

tbibs_public_key_with_precomp_t* tbibs_public_key_with_precomp_new(tbibs_public_key_t* pk) {
  if (!pk) {
    return NULL;
  }

  tbibs_public_key_with_precomp_t* pkprecomp = malloc(sizeof(tbibs_public_key_with_precomp_t));
  if (!pkprecomp) {
    return NULL;
  }

  pkprecomp->pk = pk;
  /* initialize to NULL */
  ep_null(pkprecomp->precomp);

  TRY {
    ep_new(pkprecomp->precomp);
  } CATCH_ANY {
    tbibs_public_key_with_precomp_free(pkprecomp);
    pkprecomp = NULL;
  }

  return pkprecomp;
}

void tbibs_secret_key_free(tbibs_secret_key_t* sk) {
  if (sk) {
    ep_free(sk->secret_key);
    free(sk);
  }
}

tbibs_secret_key_t* tbibs_secret_key_new(tbibs_public_params_t* pp) {
  if (!pp) {
    return NULL;
  }

  tbibs_secret_key_t* sk = malloc(sizeof(tbibs_secret_key_t));
  if (!sk) {
    return NULL;
  }

  sk->pp = pp;
  /* initialize to NULL */
  ep_null(sk->secret_key);

  TRY {
    ep_new(sk->secret_key);
  } CATCH_ANY {
    tbibs_secret_key_free(sk);
    sk = NULL;
  }

  return sk;
}

void tbibs_delegated_key_free(tbibs_delegated_key_t* dk) {
  if (dk) {
    for (unsigned int i = 1; i; --i) {
      ep_free(dk->s_3[i - 1]);
    }
    ep_free(dk->precomp);
    ep2_free(dk->s_2);
    ep_free(dk->s_1);
    free(dk);
  }
}

tbibs_delegated_key_t* tbibs_delegated_key_new(tbibs_public_params_t* pp) {
  if (!pp) {
    return NULL;
  }

  tbibs_delegated_key_t* dk = malloc(sizeof(tbibs_delegated_key_t) + sizeof(ep_t));
  if (!dk) {
    return NULL;
  }

  dk->pp = pp;
  /* initialize to NULL */
  ep_null(dk->s_1);
  ep2_null(dk->s_2);
  ep_null(dk->precomp);
  for (unsigned int i = 0; i < 1; ++i) {
    ep_null(dk->s_3[i]);
  }

  TRY {
    ep_new(dk->s_1);
    ep2_new(dk->s_2);
    ep_new(dk->precomp);
    for (unsigned int i = 0; i < 1; ++i) {
      ep_new(dk->s_3[i]);
    }
  } CATCH_ANY {
    tbibs_delegated_key_free(dk);
    dk = NULL;
  }

  return dk;
}

int tbibs_generate_key(tbibs_secret_key_t* sk, tbibs_public_key_t* pk) {
  if (!sk || !pk || sk->pp != pk->pp) {
    return -1;
  }

  int ret = 0;
  bn_t secret_key;
  bn_null(secret_key);

  TRY {
    bn_new(secret_key);
    bn_rand_mod(secret_key, sk->pp->order);
    ep_mul(sk->secret_key, sk->pp->g_2, secret_key);
    ep2_mul_gen(pk->public_key, secret_key);
  } CATCH_ANY {
    ret = 1;
  } FINALLY {
    bn_free(secret_key);
  }

  return ret;
}

int tbibs_delegate_key(tbibs_delegated_key_t* dk, tbibs_secret_key_t* sk, uint64_t epoch, ...) {
  if (!dk || !sk || dk->pp != sk->pp) {
    return -1;
  }

  tbibs_public_params_t* pp = sk->pp;
  int ret                   = 0;

  bn_t v;
  bn_null(v);

  ep_t tmp;
  ep_null(tmp);
  TRY {
    bn_new(v);
    ep_new(tmp);

    va_list ap;
    va_start(ap, epoch);

    // h_1^H(epoch | id_1)
    const uint8_t* id = va_arg(ap, const uint8_t*);
    size_t len        = va_arg(ap, size_t);

    hash_order(v, pp->order, 2, &epoch, sizeof(epoch), id, len);
    ep_mul(dk->s_1, pp->h[0], v);

    for (unsigned int i = 1; i < pp->L - 1; ++i) {
      // h_i^H(id_i)
      id  = va_arg(ap, const uint8_t*);
      len = va_arg(ap, size_t);

      hash_order(v, pp->order, 1, id, len);
      ep_mul(tmp, pp->h[i], v);
      ep_add(dk->s_1, dk->s_1, tmp);
    }
    va_end(ap);
    // * g_3
    ep_add(dk->precomp, dk->s_1, pp->g_3);
    // ^v
    bn_rand_mod(v, pp->order);
    ep_mul(dk->s_1, dk->precomp, v);
    // * sk_1
    ep_add(dk->s_1, dk->s_1, sk->secret_key);

    // ghat^v
    ep2_mul_gen(dk->s_2, v);
    // h_3^v
    ep_mul(dk->s_3[0], pp->h[sk->pp->L - 1], v);
  } CATCH_ANY {
    ret = 1;
  } FINALLY {
    ep_free(tmp);
    bn_free(v);
  }

  return ret;
}

static int tbibs_public_key_precompute_va(tbibs_public_key_with_precomp_t* pkprecomp,
                                          uint64_t epoch, va_list ap) {
  tbibs_public_key_t* pk    = pkprecomp->pk;
  tbibs_public_params_t* pp = pk->pp;
  int ret                   = 0;

  bn_t v;
  bn_null(v);

  ep_t tmp;
  ep_null(tmp);
  TRY {
    bn_new(v);
    ep_new(tmp);

    // h_1^H(epoch | id)
    const uint8_t* id = va_arg(ap, const uint8_t*);
    size_t len        = va_arg(ap, size_t);
    hash_order(v, pp->order, 2, &epoch, sizeof(epoch), id, len);
    ep_mul(pkprecomp->precomp, pp->h[0], v);

    for (unsigned int i = 1; i < pp->L - 1; ++i) {
      // h_i^H(id_i)
      id  = va_arg(ap, const uint8_t*);
      len = va_arg(ap, const size_t);

      hash_order(v, pp->order, 1, id, len);
      ep_mul(tmp, pp->h[i], v);
      ep_add(pkprecomp->precomp, pkprecomp->precomp, tmp);
    }
    // * g_3
    ep_add(pkprecomp->precomp, pkprecomp->precomp, pp->g_3);
  } CATCH_ANY {
    ret = 1;
  }

  return ret;
}

int tbibs_public_key_precompute(tbibs_public_key_with_precomp_t* pkprecomp, uint64_t epoch, ...) {
  if (!pkprecomp) {
    return -1;
  }

  va_list va;
  va_start(va, epoch);
  int ret = tbibs_public_key_precompute_va(pkprecomp, epoch, va);
  va_end(va);

  return ret;
}

/* signature handling */

void tbibs_signature_free(tbibs_signature_t* sig) {
  if (sig) {
    ep2_free(sig->s_2);
    ep_free(sig->s_1);
    free(sig);
  }
}

tbibs_signature_t* tbibs_signature_new(void) {
  tbibs_signature_t* sig = malloc(sizeof(tbibs_signature_t));
  if (!sig) {
    return NULL;
  }

  /* initialize to NULL */
  ep_null(sig->s_1);
  ep2_null(sig->s_2);

  TRY {
    ep_new(sig->s_1);
    ep2_new(sig->s_2);
  } CATCH_ANY {
    tbibs_signature_free(sig);
    sig = NULL;
  }

  return sig;
}

int tbibs_sign(tbibs_signature_t* sig, tbibs_delegated_key_t* dk, const uint8_t* message,
               size_t message_len) {
  if (!sig || !dk) {
    return -1;
  }

  tbibs_public_params_t* pp = dk->pp;
  int status                = 0;

  bn_t v, h;
  bn_null(v);
  bn_null(h);

  TRY {
    bn_new(v);
    bn_new(h);

    // h^H(id_1)
    // hash_order(h, id_1, id_1_len);
    // ep_mul(sig->s_1, dk->pk->h[0], h);
    // h^H(id_2)
    // hash_order(h, id_2, id_2_len);
    // ep_mul(tmp, dk->pk->h[1], h);
    // ep_add(sig->s_1, sig->s_1, tmp);
    // h^H(id_3)
    hash_order(h, pp->order, 1, message, message_len);
    ep_mul(sig->s_1, pp->h[pp->L - 1], h);
    ep_add(sig->s_1, dk->precomp, sig->s_1);
    // * g_3
    // ep_add(sig->s_1, sig->s_1, dk->pk->g_3);
    // ^v
    bn_rand_mod(v, pp->order);
    // ep_mul(sig->s_1, sig->s_1, v);
    // * b_3^H(id_3)
    // ep_mul(tmp, dk->s_3[0], h);
    // ep_add(sig->s_1, sig->s_1, tmp);
    ep_mul_sim(sig->s_1, sig->s_1, v, dk->s_3[0], h);
    // * a_0
    ep_add(sig->s_1, sig->s_1, dk->s_1);

    // ghat^v
    ep2_mul_gen(sig->s_2, v);
    // * a_1
    ep2_add(sig->s_2, sig->s_2, dk->s_2);
  } CATCH_ANY {
    status = 1;
  } FINALLY {
    bn_free(h);
    bn_free(v);
  }

  return status;
}

/* verification */

int tbibs_verify_with_precomp(tbibs_signature_t* sig, tbibs_public_key_with_precomp_t* pkprecomp,
                              const uint8_t* message, size_t message_len) {
  if (!sig || !pkprecomp) {
    return -1;
  }

  int status = 0;

  tbibs_public_key_t* pk    = pkprecomp->pk;
  tbibs_public_params_t* pp = pk->pp;

  ep_t lhs[3];
  ep_null(lhs[0]);
  ep_null(lhs[1]);
  ep_null(lhs[2]);

  ep2_t rhs[3];
  ep2_null(rhs[0]);
  ep2_null(rhs[1]);
  ep2_null(rhs[2]);

  fp12_t val;
  fp12_null(val);

  bn_t h;
  bn_null(h);

  TRY {
    ep_new(lhs[0]);
    ep_new(lhs[1]);
    ep_new(lhs[2]);

    ep2_new(rhs[0]);
    ep2_new(rhs[1]);
    ep2_new(rhs[2]);

    fp_new(val);
    bn_new(h);

    // h_1^H(id_1)
    // hash_order(h, id_1, id_1_len);
    // ep_mul(lhs[0], pk->h[0], h);
    // h_2^H(id_2)
    // hash_order(h, id_2, id_2_len);
    // ep_mul(tmp, pk->h[1], h);
    // ep_add(lhs[0], lhs[0], tmp);
    // h_3^H(id_3)
    hash_order(h, pp->order, 1, message, message_len);
    ep_mul(lhs[0], pp->h[pp->L - 1], h);
    ep_add(lhs[0], pkprecomp->precomp, lhs[0]);
    // * g_3
    // ep_add(lhs[0], lhs[0], pk->g_3);

    // e(h_1^H(id_1) ..., sk_2)
    ep2_copy(rhs[0], sig->s_2);

    // e(g_2, pk)
    ep_copy(lhs[1], pp->g_2);
    ep2_copy(rhs[1], pk->public_key);

    // e(sk_1, ghat)
    ep_neg(lhs[2], sig->s_1);
    ep2_curve_get_gen(rhs[2]);

    pp_map_sim_k12(val, lhs, rhs, 3);
    //  status = fp12_cmp(val, fp12_one) == RLC_EQ ? 0 : 1;
    fp12_sub(val, val, fp12_one);
    status = !fp12_is_zero(val);
  } CATCH_ANY {
    status = 1;
  } FINALLY {
    bn_free(h);
    fp12_free(val);
    ep2_free(rhs[2]);
    ep2_free(rhs[1]);
    ep2_free(rhs[0]);
    ep_free(lhs[2]);
    ep_free(lhs[1]);
    ep_free(lhs[0]);
  }

  return status;
}

int tbibs_verify(tbibs_signature_t* sig, tbibs_public_key_t* pk, const uint8_t* message,
                 size_t message_len, uint64_t epoch, ...) {
  if (!sig || !pk) {
    return -1;
  }

  tbibs_public_key_with_precomp_t* pkprecomp = tbibs_public_key_with_precomp_new(pk);
  if (!pkprecomp) {
    return -1;
  }

  va_list va;
  va_start(va, epoch);
  int status = tbibs_public_key_precompute_va(pkprecomp, epoch, va);
  va_end(va);

  if (!status) {
    status = tbibs_verify_with_precomp(sig, pkprecomp, message, message_len);
  }
  tbibs_public_key_with_precomp_free(pkprecomp);

  return status;
}
