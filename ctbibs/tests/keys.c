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

static const uint64_t epoch = 0x123;
static const uint8_t id_1[] = {0x12, 0x13};
static const uint8_t id_2[] = {0x14, 0x15, 0x16, 0x17, 0x18};

Describe(TBIBS_KEYS);
BeforeEach(TBIBS_KEYS) {
  pp = tbibs_public_params_new(L);
  assert_that(pp, is_non_null);
}
AfterEach(TBIBS_KEYS) {
  tbibs_public_params_free(pp);
  pp = NULL;
}

Ensure(TBIBS_KEYS, pk_new) {
  tbibs_public_key_t* pk = tbibs_public_key_new(pp);
  assert_that(pk, is_non_null);
  tbibs_public_key_free(pk);
}

Ensure(TBIBS_KEYS, sk_new) {
  tbibs_secret_key_t* sk = tbibs_secret_key_new(pp);
  assert_that(sk, is_non_null);
  tbibs_secret_key_free(sk);
}

Ensure(TBIBS_KEYS, dk_new) {
  tbibs_delegated_key_t* dk = tbibs_delegated_key_new(pp);
  assert_that(dk, is_non_null);
  tbibs_delegated_key_free(dk);
}

Ensure(TBIBS_KEYS, key_gen) {
  tbibs_public_key_t* pk = tbibs_public_key_new(pp);
  tbibs_secret_key_t* sk = tbibs_secret_key_new(pp);
  assert_that(pk, is_non_null);
  assert_that(sk, is_non_null);

  assert_that(tbibs_generate_key(sk, pk), is_equal_to(0));

  tbibs_secret_key_free(sk);
  tbibs_public_key_free(pk);
}

Ensure(TBIBS_KEYS, delegate) {
  tbibs_public_key_t* pk    = tbibs_public_key_new(pp);
  tbibs_secret_key_t* sk    = tbibs_secret_key_new(pp);
  tbibs_delegated_key_t* dk = tbibs_delegated_key_new(pp);
  assert_that(pk, is_non_null);
  assert_that(sk, is_non_null);
  assert_that(dk, is_non_null);

  assert_that(tbibs_generate_key(sk, pk), is_equal_to(0));
  assert_that(tbibs_delegate_key(dk, sk, epoch, id_1, sizeof(id_1), id_2, sizeof(id_2)),
              is_equal_to(0));

  tbibs_delegated_key_free(dk);
  tbibs_secret_key_free(sk);
  tbibs_public_key_free(pk);
}

void add_tbibs_keys_tests(TestSuite* suite) {
  add_test_with_context(suite, TBIBS_KEYS, pk_new);
  add_test_with_context(suite, TBIBS_KEYS, sk_new);
  add_test_with_context(suite, TBIBS_KEYS, dk_new);
  add_test_with_context(suite, TBIBS_KEYS, key_gen);
  add_test_with_context(suite, TBIBS_KEYS, delegate);
}
