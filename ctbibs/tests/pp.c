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

Describe(TBIBS_PP);
BeforeEach(TBIBS_PP) {}
AfterEach(TBIBS_PP) {}

Ensure(TBIBS_PP, pp_gen) {
  tbibs_public_params_t* pp = tbibs_public_params_new(L);
  assert_that(pp, is_non_null);
  tbibs_public_params_free(pp);
}

Ensure(TBIBS_PP, pp_gen_0) {
  tbibs_public_params_t* pp = tbibs_public_params_new(0);
  assert_that(pp, is_null);
}

void add_tbibs_pp_tests(TestSuite* suite) {
  add_test_with_context(suite, TBIBS_PP, pp_gen);
  add_test_with_context(suite, TBIBS_PP, pp_gen_0);
}
