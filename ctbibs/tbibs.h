/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#ifndef TBIBS_H
#define TBIBS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tbibs_public_params_s tbibs_public_params_t;
typedef struct tbibs_public_key_s tbibs_public_key_t;
typedef struct tbibs_public_key_with_precomp_s tbibs_public_key_with_precomp_t;
typedef struct tbibs_secret_key_s tbibs_secret_key_t;
typedef struct tbibs_delegated_key_s tbibs_delegated_key_t;
typedef struct tbibs_signature_s tbibs_signature_t;

int tbibs_init(void);
void tbibs_deinit(void);

void tbibs_public_params_free(tbibs_public_params_t* pp);
tbibs_public_params_t* tbibs_public_params_new(unsigned int L);

void tbibs_public_key_free(tbibs_public_key_t* pk);
tbibs_public_key_t* tbibs_public_key_new(tbibs_public_params_t* pp);
void tbibs_public_key_with_precomp_free(tbibs_public_key_with_precomp_t* pk);
tbibs_public_key_with_precomp_t* tbibs_public_key_with_precomp_new(tbibs_public_key_t* pk);
int tbibs_public_key_precompute(tbibs_public_key_with_precomp_t* pkprecomp, uint64_t epoch, ...);

void tbibs_secret_key_free(tbibs_secret_key_t* sk);
tbibs_secret_key_t* tbibs_secret_key_new(tbibs_public_params_t* pp);
void tbibs_delegated_key_free(tbibs_delegated_key_t* dk);
tbibs_delegated_key_t* tbibs_delegated_key_new(tbibs_public_params_t* pp);
int tbibs_generate_key(tbibs_secret_key_t* sk, tbibs_public_key_t* pk);
int tbibs_delegate_key(tbibs_delegated_key_t* dk, tbibs_secret_key_t* sk, uint64_t epoch, ...);

void tbibs_signature_free(tbibs_signature_t* sig);
tbibs_signature_t* tbibs_signature_new(void);
int tbibs_sign(tbibs_signature_t* sig, tbibs_delegated_key_t* dk, const uint8_t* message,
               size_t message_len);
int tbibs_verify_with_precomp(tbibs_signature_t* sig, tbibs_public_key_with_precomp_t* pk,
                              const uint8_t* message, size_t message_len);
int tbibs_verify(tbibs_signature_t* sig, tbibs_public_key_t* pk, const uint8_t* message,
                 size_t message_len, uint64_t epoch, ...);

#ifdef __cplusplus
}
#endif
#endif
