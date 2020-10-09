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

void add_tbibs_pp_tests(TestSuite* suite);
void add_tbibs_keys_tests(TestSuite* suite);
void add_tbibs_sig_tests(TestSuite* suite);

int main() {
  tbibs_init();

  TestSuite* suite = create_test_suite();
  add_tbibs_pp_tests(suite);
  add_tbibs_keys_tests(suite);
  add_tbibs_sig_tests(suite);

  const int ret = run_test_suite(suite, create_text_reporter());

  tbibs_deinit();
  return ret;
}
