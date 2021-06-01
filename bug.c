// SPDX-License-Identifier: GPL-2.0-only
/*
 * Various uses of BUG, to see if these are detectable.
 *
 * (C) 2021 David Malcolm, Red Hat
 * Written by David Malcolm <dmalcolm@redhat.com>
 */

#include <linux/bug.h>
#include "antipatterns.h"

/*
 * Unconditional usage of BUG.
 */

int bug_always(void)
{
  BUG();
  return 0;
}

/*
 * Conditional usage of BUG.
 */

int bug_guarded(int flag)
{
  if (flag)
    BUG();
  return 0;
}
