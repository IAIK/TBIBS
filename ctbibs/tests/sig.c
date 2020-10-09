/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#include "../tbibs.h"
#include <cgreen/cgreen.h>

#define L 2
static tbibs_public_params_t* pp = NULL;
static tbibs_public_key_t* pk    = NULL;
static tbibs_secret_key_t* sk    = NULL;
static tbibs_delegated_key_t* dk = NULL;

static const uint64_t epoch    = 0x123;
static const uint8_t id_1[]    = {0x12, 0x13};
static const uint8_t id_2[]    = {0x14, 0x15, 0x16, 0x17, 0x18};
static const uint8_t message[] = {0xad, 0xac, 0xab, 0xaa, 0xa9};

Describe(TBIBS_SIG);
BeforeEach(TBIBS_SIG) {
  pp = tbibs_public_params_new(L);
  assert_that(pp, is_non_null);
  pk = tbibs_public_key_new(pp);
  sk = tbibs_secret_key_new(pp);
  dk = tbibs_delegated_key_new(pp);
  assert_that(pk, is_non_null);
  assert_that(sk, is_non_null);
  assert_that(dk, is_non_null);

  assert_that(tbibs_generate_key(sk, pk), is_equal_to(0));
  assert_that(tbibs_delegate_key(dk, sk, epoch, id_1, sizeof(id_1), id_2, sizeof(id_2)),
              is_equal_to(0));
}
AfterEach(TBIBS_SIG) {
  tbibs_delegated_key_free(dk);
  tbibs_secret_key_free(sk);
  tbibs_public_key_free(pk);
  tbibs_public_params_free(pp);
  dk = NULL;
  sk = NULL;
  pk = NULL;
  pp = NULL;
}

Ensure(TBIBS_SIG, sig_new) {
  tbibs_signature_t* sig = tbibs_signature_new();
  assert_that(sig, is_non_null);
  tbibs_signature_free(sig);
}

Ensure(TBIBS_SIG, sign) {
  tbibs_signature_t* sig = tbibs_signature_new();
  assert_that(sig, is_non_null);

  assert_that(tbibs_sign(sig, dk, message, sizeof(message)), is_equal_to(0));

  tbibs_signature_free(sig);
}

Ensure(TBIBS_SIG, sign_and_verify) {
  tbibs_signature_t* sig = tbibs_signature_new();
  assert_that(sig, is_non_null);

  assert_that(tbibs_sign(sig, dk, message, sizeof(message)), is_equal_to(0));
  assert_that(tbibs_verify_precompute(pk, epoch, id_1, sizeof(id_1), id_2, sizeof(id_2)),
              is_equal_to(0));
  assert_that(tbibs_verify(sig, pk, message, sizeof(message)), is_equal_to(0));

  tbibs_signature_free(sig);
}

void add_tbibs_sig_tests(TestSuite* suite) {
  add_test_with_context(suite, TBIBS_SIG, sig_new);
  add_test_with_context(suite, TBIBS_SIG, sign);
  add_test_with_context(suite, TBIBS_SIG, sign_and_verify);
}
