// SPDX-License-Identifier: GPL-2.0-only
/*
 * Various uses of BUG, to see if these are detectable.
 * TODO: expose these (e.g. as ioctls) so they can actually be triggered
 * at run-time.
 *
 * (C) 2021 David Malcolm, Red Hat
 * Written by David Malcolm <dmalcolm@redhat.com>
 */

#include <linux/bug.h>

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
