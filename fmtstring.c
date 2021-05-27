// SPDX-License-Identifier: GPL-2.0-only
/*
 * Various bogus uses of format strings (CWE-134), to see if these are
 * detectable.
 * TODO: expose these (e.g. as ioctls) so they can actually be triggered
 * at run-time.
 *
 * (C) 2021 David Malcolm, Red Hat
 * Written by David Malcolm <dmalcolm@redhat.com>
 */

#include <linux/printk.h>
#include <linux/uaccess.h>

int user_controlled_printk (void __user *src)
{
  char buf[256];
  if (copy_from_user(buf, src, sizeof(buf)))
    return -EFAULT;

  /* "buf" is under user control and could contain '%' */

  printk (buf);
  return 0;
}
