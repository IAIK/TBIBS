/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#include <stdio.h>
#include <time.h>

#include "tbibs.h"

#define L 2

int main() {
  if (tbibs_init()) {
    return -1;
  }

  int status = 0;

  tbibs_public_params_t* pp = NULL;
  tbibs_public_key_t* pk = NULL;
  tbibs_secret_key_t* sk = NULL;
  tbibs_delegated_key_t* dk = NULL;
  tbibs_signature_t* sig = NULL;

  printf("generting public parameters\n");
  pp = tbibs_public_params_new(L);
  if (!pp) {
    status = -1;
    goto exit;
  }

  printf("generting keys\n");
  pk = tbibs_public_key_new(pp);
  sk = tbibs_secret_key_new(pp);
  if (!pk || !sk) {
    status = -1;
    goto exit;
  }

  if (tbibs_generate_key(sk, pk)) {
    status = -1;
    goto exit;
  }

  static const uint8_t id_1[]    = {0x12, 0x13};
  static const uint8_t id_2[]    = {0x14, 0x15, 0x16, 0x17, 0x18};
  static const uint8_t message[] = {0xad, 0xac, 0xab, 0xaa, 0xa9};

  printf("delegating key\n");
  dk = tbibs_delegated_key_new(pp);
  if (tbibs_delegate_key(dk, sk, id_1, sizeof(id_1), id_2, sizeof(id_2))) {
    status = -1;
    goto exit;
  }

  printf("signing\n");
  sig = tbibs_signature_new();
  if (tbibs_sign(sig, dk, message, sizeof(message))) {
    status = -1;
    goto exit;
  }

  printf("verifying\n");
  if (tbibs_verify_precompute(pk, id_1, sizeof(id_1), id_2, sizeof(id_2))) {
    status = -1;
    goto exit;
  }

  if (tbibs_verify(sig, pk, message, sizeof(message))) {
    status = -1;
    goto exit;
  }
  printf("done\n");

  static const unsigned int REPS = 10000;
  uint64_t time_sign_s           = 0;
  uint64_t time_sign_ns          = 0;
  uint64_t time_verify_s         = 0;
  uint64_t time_verify_ns        = 0;

  for (unsigned int i = 0; i < REPS; ++i) {
    struct timespec start, mid, end;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    tbibs_sign(sig, dk, message, sizeof(message));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mid);
    tbibs_verify(sig, pk, message, sizeof(message));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    const uint64_t delta_sign =
        (mid.tv_sec * 1000000000 + mid.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    const uint64_t delta_verify =
        (end.tv_sec * 1000000000 + end.tv_nsec) - (mid.tv_sec * 1000000000 + mid.tv_nsec);

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
  tbibs_signature_free(sig);
  tbibs_delegated_key_free(dk);
  tbibs_secret_key_free(sk);
  tbibs_public_key_free(pk);
  tbibs_public_params_free(pp);
  tbibs_deinit();

  return status;
}
