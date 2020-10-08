/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#include <relic/relic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <openssl/sha.h>

#define L 3

typedef struct {
  ep_t g_2, g_3;
  ep_t h[L];

  ep2_t public_key;
} hibe_public_key_t;

typedef struct {
  hibe_public_key_t pk;
  ep_t secret_key;
} hibe_secret_key_t;

typedef struct {
  hibe_public_key_t* pk;
  ep_t s_1;
  ep2_t s_2;
  ep_t s_3[L - 2];
  ep_t precomp;
} hibe_delegated_key_t;

typedef struct {
  ep_t s_1;
  ep2_t s_2;
} signature_t;

static bn_t order;
static fp12_t fp12_one;

static void sk_free(hibe_secret_key_t* sk) {
  if (sk) {
    ep_free(sk->secret_key);
    ep2_free(sk->pk.public_key);
    for (unsigned int i = 0; i < L; ++i) {
      ep_free(sk->pk.h[i]);
    }
    ep_free(sk->pk.g_3);
    ep_free(sk->pk.g_2);
  }
}

static void dk_free(hibe_delegated_key_t* dk) {
  if (dk) {
    ep_free(dk->s_1);
    ep2_free(dk->s_2);
    for (unsigned int i = 0; i < L - 2; ++i) {
      ep_free(dk->s_3[i]);
    }
    ep_free(dk->precomp);
  }
}

static void signature_init(signature_t* sig) {
  ep_null(sig->s_1);
  ep2_null(sig->s_2);

  ep_new(sig->s_1);
  ep2_new(sig->s_2);
}

static void signature_free(signature_t* sig) {
  if (sig) {
    ep2_free(sig->s_2);
    ep_free(sig->s_1);
  }
}

static int keygen(hibe_secret_key_t* sk) {
  int status = 0;

  ep_null(sk->pk.g_2);
  ep_null(sk->pk.g_3);
  for (unsigned int i = 0; i < L; ++i) {
    ep_null(sk->pk.h[i]);
  }
  ep2_null(sk->pk.public_key);
  ep_null(sk->secret_key);

  bn_t secret_key;
  bn_null(secret_key);
  TRY {
    bn_new(secret_key);

    ep_new(sk->pk.g_2);
    ep_new(sk->pk.g_3);
    for (unsigned int i = 0; i < L; ++i) {
      ep_new(sk->pk.h[i]);
    }
    ep2_new(sk->pk.public_key);
    ep_new(sk->secret_key);

    ep_rand(sk->pk.g_2);
    ep_rand(sk->pk.g_3);
    for (unsigned int i = 0; i < L; ++i) {
      ep_rand(sk->pk.h[i]);
    }

    bn_rand_mod(secret_key, order);
    ep_mul(sk->secret_key, sk->pk.g_2, secret_key);
    ep2_mul_gen(sk->pk.public_key, secret_key);
  }
  CATCH_ANY {
    status = -1;
    sk_free(sk);
  }
  FINALLY {
    bn_free(secret_key);
  }

  return status;
}

static void hash_order(bn_t v, const uint8_t* data, size_t len) {
  uint8_t digest[RLC_MD_LEN_SH512];
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, data, len);
  SHA512_Final(digest, &ctx);

  bn_read_bin(v, digest, RLC_MD_LEN_SH512);
  bn_mod(v, v, order);
}

static int delegate(hibe_delegated_key_t* dk, hibe_secret_key_t* sk, const uint8_t* id_1,
                    size_t id_1_len, const uint8_t* id_2, size_t id_2_len) {
  int status = 0;

  dk->pk = &sk->pk;
  ep_null(dk->s_1);
  ep2_null(dk->s_2);
  for (unsigned int i = 0; i < L - 2; ++i) {
    ep_null(dk->s_3[i]);
  }
  ep_null(dk->precomp);

  bn_t v;
  bn_null(v);

  ep_t tmp;
  ep_null(tmp);
  TRY {
    bn_new(v);
    ep_new(tmp);

    ep_new(dk->s_1);
    ep2_new(dk->s_2);
    for (unsigned int i = 0; i < L - 2; ++i) {
      ep_new(dk->s_3[i]);
    }
    ep_new(dk->precomp);

    // h_1^H(id_1)
    hash_order(v, id_1, id_1_len);
    ep_mul(dk->s_1, sk->pk.h[0], v);
    // h_2^H(id_2)
    hash_order(v, id_2, id_2_len);
    ep_mul(tmp, sk->pk.h[1], v);
    ep_add(dk->s_1, dk->s_1, tmp);
    // * g_3
    ep_add(dk->precomp, dk->s_1, sk->pk.g_3);
    // ^v
    bn_rand_mod(v, order);
    ep_mul(dk->s_1, dk->precomp, v);
    // * sk_1
    ep_add(dk->s_1, dk->s_1, sk->secret_key);

    // ghat^v
    ep2_mul_gen(dk->s_2, v);
    // h_3^v
    ep_mul(dk->s_3[0], sk->pk.h[2], v);
  }
  CATCH_ANY {
    status = -1;
    dk_free(dk);
  }
  FINALLY {
    bn_free(tmp);
    bn_free(v);
  }

  return status;
}

static int sign(signature_t* sig, hibe_delegated_key_t* dk, const uint8_t* id_1, size_t id_1_len,
                const uint8_t* id_2, size_t id_2_len, const uint8_t* message, size_t message_len) {
  int status = 0;

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
    hash_order(h, message, message_len);
    ep_mul(sig->s_1, dk->pk->h[2], h);
    ep_add(sig->s_1, dk->precomp, sig->s_1);
    // * g_3
    // ep_add(sig->s_1, sig->s_1, dk->pk->g_3);
    // ^v
    bn_rand_mod(v, order);
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
  }
  CATCH_ANY {
    status = -1;
  }
  FINALLY {
    bn_free(h);
    bn_free(v);
  }

  return status;
}

static int verify(signature_t* sig, hibe_public_key_t* pk, ep_t precomp, const uint8_t* id_1,
                  size_t id_1_len, const uint8_t* id_2, size_t id_2_len, const uint8_t* message,
                  size_t message_len) {
  int status = 0;

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
    bn_new(h);

    ep_new(lhs[0]);
    ep_new(lhs[1]);
    ep_new(lhs[2]);

    ep2_new(rhs[0]);
    ep2_new(rhs[1]);
    ep2_new(rhs[2]);

    fp12_new(val);

    // h_1^H(id_1)
    // hash_order(h, id_1, id_1_len);
    // ep_mul(lhs[0], pk->h[0], h);
    // h_2^H(id_2)
    // hash_order(h, id_2, id_2_len);
    // ep_mul(tmp, pk->h[1], h);
    // ep_add(lhs[0], lhs[0], tmp);
    // h_3^H(id_3)
    hash_order(h, message, message_len);
    ep_mul(lhs[0], pk->h[2], h);
    ep_add(lhs[0], precomp, lhs[0]);
    // * g_3
    // ep_add(lhs[0], lhs[0], pk->g_3);

    // e(h_1^H(id_1) ..., sk_2)
    ep2_copy(rhs[0], sig->s_2);

    // e(g_2, pk)
    ep_copy(lhs[1], pk->g_2);
    ep2_copy(rhs[1], pk->public_key);

    // e(sk_1, ghat)
    ep_neg(lhs[2], sig->s_1);
    ep2_curve_get_gen(rhs[2]);

    pp_map_sim_k12(val, lhs, rhs, 3);
    //  status = fp12_cmp(val, fp12_one) == RLC_EQ ? 0 : 1;
    fp12_sub(val, val, fp12_one);
    status = !fp12_is_zero(val);
  }
  CATCH_ANY {
    status = -1;
  }
  FINALLY {
    fp12_free(val);
    ep2_free(rhs[2]);
    ep2_free(rhs[1]);
    ep2_free(rhs[0]);
    ep_free(lhs[2]);
    ep_free(lhs[1]);
    ep_free(lhs[0]);
    bn_free(h);
  }

  return status;
}

int main() {
  if (core_init() != RLC_OK) {
    core_clean();
    return -1;
  }

  int status = 0;
  ep_param_set_any_pairf();

  bn_new(order);
  ep_curve_get_ord(order);
  fp12_new(fp12_one);
  fp12_zero(fp12_one);
  fp12_set_dig(fp12_one, 1);

  printf("generting keys\n");
  hibe_secret_key_t sk;
  hibe_delegated_key_t dk;
  signature_t sig;
  signature_init(&sig);

  if (keygen(&sk)) {
    status = -1;
    goto exit;
  }

  static const uint8_t id_1[]    = {0x12, 0x13};
  static const uint8_t id_2[]    = {0x14, 0x15, 0x16, 0x17, 0x18};
  static const uint8_t message[] = {0xad, 0xac, 0xab, 0xaa, 0xa9};

  printf("delegating key\n");
  if (delegate(&dk, &sk, id_1, sizeof(id_1), id_2, sizeof(id_2))) {
    status = -1;
    goto exit;
  }

  printf("signing\n");
  if (sign(&sig, &dk, id_1, sizeof(id_1), id_2, sizeof(id_2), message, sizeof(message))) {
    status = -1;
    goto exit;
  }

  printf("verifying\n");
  if (verify(&sig, dk.pk, dk.precomp, id_1, sizeof(id_1), id_2, sizeof(id_2), message,
             sizeof(message))) {
    status = -1;
    goto exit;
  }
  printf("done\n");

  static const unsigned int REPS = 100000;
  uint64_t time_sign_s           = 0;
  uint64_t time_sign_ns          = 0;
  uint64_t time_verify_s         = 0;
  uint64_t time_verify_ns        = 0;

  for (unsigned int i = 0; i < REPS; ++i) {
    struct timespec start, mid, end;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    sign(&sig, &dk, id_1, sizeof(id_1), id_2, sizeof(id_2), message, sizeof(message));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mid);
    verify(&sig, dk.pk, dk.precomp, id_1, sizeof(id_1), id_2, sizeof(id_2), message,
           sizeof(message));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    const uint64_t delta_sign =
        (mid.tv_sec * 1000000000 + mid.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    const uint64_t delta_verify =
        (end.tv_sec * 1000000000.0 + end.tv_nsec) - (mid.tv_sec * 1000000000.0 + mid.tv_nsec);

    time_sign_s += delta_sign / 1000000000;
    if (__builtin_add_overflow(time_sign_ns, delta_sign % 1000000000, &time_sign_ns)) {
      ++time_sign_s;
    }
    time_verify_s += delta_verify / 1000000000;
    if (__builtin_add_overflow(time_verify_ns, delta_verify % 1000000000, &time_verify_ns)) {
      ++time_verify_s;
    }
  }

  printf("sign: %lf ms\n", (time_sign_s * 1000000000.0 + time_sign_ns) / REPS / 1000000);
  printf("verify: %lf ms\n", (time_verify_s * 1000000000.0 + time_verify_ns) / REPS / 1000000);

exit:
  signature_free(&sig);
  dk_free(&dk);
  sk_free(&sk);
  fp12_free(fp12_one);
  bn_free(order);

  return status;
}
