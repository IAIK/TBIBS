/*
  Written in 2020 by Sebastian Ramacher <sebastian.ramacher@ait.ac.at>

  To the extent possible under law, the author(s) have dedicated all copyright and related and
  neighboring rights to this software to the public domain worldwide. This software is distributed
  without any warranty.

  You should have received a copy of the CC0 1.0 Universial along with this software. If not, see
  <https://creativecommons.org/publicdomain/zero/1.0/>.

  SPDX-License-Identifier: CC0-1.0
*/

#ifndef TBIBS_HPP
#define TBIBS_HPP

#include "tbibs.h"

struct tbibs_instance {
  tbibs_instance();
  ~tbibs_instance() noexcept;

  tbibs_instance(const tbibs_instance&) = delete;
  tbibs_instance& operator=(const tbibs_instance&) = delete;
};

#endif
