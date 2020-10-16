/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#include <algorithm>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <boost/timer/timer.hpp>

#include "tbibs.hpp"

namespace {
  constexpr unsigned int L    = 2;
  constexpr unsigned int REPS = 10000;
} // namespace

int main() try {
  tbibs_instance tbibs;

  std::cout << "generting public parameters" << std::endl;
  std::shared_ptr<tbibs_public_params_t> pp{tbibs_public_params_new(L), tbibs_public_params_free};

  std::cout << "generting keys" << std::endl;
  std::shared_ptr<tbibs_public_key_t> pk{tbibs_public_key_new(pp.get()), tbibs_public_key_free};
  std::shared_ptr<tbibs_secret_key_t> sk{tbibs_secret_key_new(pp.get()), tbibs_secret_key_free};

  if (tbibs_generate_key(sk.get(), pk.get())) {
    return -1;
  }

  std::random_device rd;
  std::uniform_int_distribution<unsigned int> dist(0, 255);

  auto rand = [&dist, &rd]() { return static_cast<uint8_t>(dist(rd)); };

  const uint64_t epoch = 0x123;
  uint8_t id_1[4];
  uint8_t id_2[8];
  uint8_t message[16];

  std::generate_n(id_1, sizeof(id_1), rand);
  std::generate_n(id_2, sizeof(id_2), rand);

  std::cout << "delegating key" << std::endl;
  std::shared_ptr<tbibs_delegated_key_t> dk{tbibs_delegated_key_new(pp.get()),
                                            tbibs_delegated_key_free};
  if (tbibs_delegate_key(dk.get(), sk.get(), epoch, id_1, sizeof(id_1), id_2, sizeof(id_2))) {
    return -1;
  }

  std::cout << "precomputing public key" << std::endl;
  std::shared_ptr<tbibs_public_key_with_precomp_t> pkprecomp{
      tbibs_public_key_with_precomp_new(pk.get()), tbibs_public_key_with_precomp_free};
  if (tbibs_public_key_precompute(pkprecomp.get(), epoch, id_1, sizeof(id_1), id_2, sizeof(id_2))) {
    return -1;
  }

  std::shared_ptr<tbibs_signature_t> sig{tbibs_signature_new(), tbibs_signature_free};

  std::cout << "benchmarking ..." << std::endl;
  boost::timer::cpu_timer sign_timer;
  sign_timer.stop();
  boost::timer::cpu_timer verify_timer;
  verify_timer.stop();

  unsigned int sign_failures = 0;
  unsigned int verify_failures = 0;

  for (unsigned int i = 0; i < REPS; ++i) {
    std::generate_n(message, sizeof(message), rand);

    sign_timer.resume();
    if (tbibs_sign(sig.get(), dk.get(), message, sizeof(message))) {
      ++sign_failures;
    }
    sign_timer.stop();

    verify_timer.resume();
    if (tbibs_verify_with_precomp(sig.get(), pkprecomp.get(), message, sizeof(message))) {
      ++verify_failures;
    }
    verify_timer.stop();
  }

  std::cout << "sign failures: " << sign_failures << " verify failures: " << verify_failures << "\n";
  std::cout << "sign x " << REPS << ": " << sign_timer.format(9, "%ws wall, %ts CPU") << "\n";
  std::cout << "verify x " << REPS << ": " << verify_timer.format(9, "%ws wall, %ts CPU") << std::endl;

  return 0;
} catch (const std::exception& e) {
  std::cerr << "E: " << e.what() << std::endl;
}
