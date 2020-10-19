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
static tbibs_signature_t* sig    = NULL;
static char* buffer              = NULL;
static size_t bufferlen          = 0;
static FILE* file                = NULL;

static const uint64_t epoch    = 0x12;
static const uint8_t id_1[]    = {0x12};
static const uint8_t id_2[]    = {0x14};
static const uint8_t message[] = {0xad};

Describe(TBIBS_IO);
BeforeEach(TBIBS_IO) {
  pp = tbibs_public_params_new(L);
  assert_that(pp, is_non_null);
  pk  = tbibs_public_key_new(pp);
  sk  = tbibs_secret_key_new(pp);
  dk  = tbibs_delegated_key_new(pp);
  sig = tbibs_signature_new();
  assert_that(pk, is_non_null);
  assert_that(sk, is_non_null);
  assert_that(dk, is_non_null);
  assert_that(sk, is_non_null);

  assert_that(tbibs_generate_key(sk, pk), is_equal_to(0));
  assert_that(tbibs_delegate_key(dk, sk, epoch, id_1, sizeof(id_1), id_2, sizeof(id_2)),
              is_equal_to(0));
  assert_that(tbibs_sign(sig, dk, message, sizeof(message)), is_equal_to(0));

  file = open_memstream(&buffer, &bufferlen);
  assert_that(file, is_non_null);
}
AfterEach(TBIBS_IO) {
  fclose(file);
  free(buffer);
  tbibs_signature_free(sig);
  tbibs_delegated_key_free(dk);
  tbibs_secret_key_free(sk);
  tbibs_public_key_free(pk);
  tbibs_public_params_free(pp);
  file      = NULL;
  bufferlen = 0;
  buffer    = NULL;
  sig       = NULL;
  dk        = NULL;
  sk        = NULL;
  pk        = NULL;
  pp        = NULL;
}

Ensure(TBIBS_IO, all) {
  assert_that(tbibs_public_params_write(file, pp), is_not_equal_to(0));
  assert_that(fseek(file, 0, SEEK_SET), is_not_equal_to(-1));
  tbibs_public_params_t* pp2 = tbibs_public_params_read(file);
  assert_that(pp2, is_not_null);
  assert_that(fseek(file, 0, SEEK_SET), is_not_equal_to(-1));

  tbibs_secret_key_t* sk2    = tbibs_secret_key_new(pp2);
  tbibs_public_key_t* pk2    = tbibs_public_key_new(pp2);
  tbibs_delegated_key_t* dk2 = tbibs_delegated_key_new(pp2);
  tbibs_signature_t* sig2    = tbibs_signature_new();

  assert_that(sk2, is_not_null);
  assert_that(pk2, is_not_null);
  assert_that(dk2, is_not_null);
  assert_that(sig2, is_not_null);

  assert_that(tbibs_secret_key_write(file, sk), is_not_equal_to(0));
  assert_that(tbibs_public_key_write(file, pk), is_not_equal_to(0));
  assert_that(tbibs_delegated_key_write(file, dk), is_not_equal_to(0));
  assert_that(tbibs_signature_write(file, sig), is_not_equal_to(0));
  assert_that(fseek(file, 0, SEEK_SET), is_not_equal_to(-1));

  assert_that(tbibs_secret_key_read(sk2, file), is_not_equal_to(0));
  assert_that(tbibs_public_key_read(pk2, file), is_not_equal_to(0));
  assert_that(tbibs_delegated_key_read(dk2, file), is_not_equal_to(0));
  assert_that(tbibs_signature_read(sig2, file), is_not_equal_to(0));
  assert_that(fseek(file, 0, SEEK_SET), is_not_equal_to(-1));

  assert_that(tbibs_verify(sig2, pk, message, sizeof(message), epoch, id_1, sizeof(id_1), id_2,
                           sizeof(id_2)),
              is_equal_to(0));
  assert_that(tbibs_verify(sig, pk2, message, sizeof(message), epoch, id_1, sizeof(id_1), id_2,
                           sizeof(id_2)),
              is_equal_to(0));
  assert_that(tbibs_verify(sig2, pk2, message, sizeof(message), epoch, id_1, sizeof(id_1), id_2,
                           sizeof(id_2)),
              is_equal_to(0));

  assert_that(tbibs_sign(sig, dk2, message, sizeof(message)), is_equal_to(0));
  assert_that(tbibs_verify(sig, pk, message, sizeof(message), epoch, id_1, sizeof(id_1), id_2,
                           sizeof(id_2)),
              is_equal_to(0));

  assert_that(tbibs_delegate_key(dk, sk2, epoch, id_1, sizeof(id_1), id_2, sizeof(id_2)),
              is_equal_to(0));
  assert_that(tbibs_sign(sig, dk, message, sizeof(message)), is_equal_to(0));
  assert_that(tbibs_verify(sig, pk, message, sizeof(message), epoch, id_1, sizeof(id_1), id_2,
                           sizeof(id_2)),
              is_equal_to(0));

  tbibs_signature_free(sig2);
  tbibs_delegated_key_free(dk2);
  tbibs_public_key_free(pk2);
  tbibs_secret_key_free(sk2);
  tbibs_public_params_free(pp2);
}

void add_tbibs_io_tests(TestSuite* suite) {
  add_test_with_context(suite, TBIBS_IO, all);
}
