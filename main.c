// SPDX-License-Identifier: GPL-2.0-only
/*
 * The world's worst kernel module?
 * This contains numerous vulnerabilities.
 * It is intended purely as a testbed for vulnerability detection tools.
 * DO NOT USE THIS MODULE.
 *
 * (C) 2021 David Malcolm, Red Hat
 * Written by David Malcolm <dmalcolm@redhat.com>
 */

#include <linux/init.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");

static int antipatterns_init(void)
{
  printk(KERN_ALERT "antipatterns.ko started; DO NOT USE; DANGER DANGER\n");

  /*
   * TODO: wire up the entrypoints in the other files so that they can be
   * actually run, and detected by dynamic analysis.
   */

  return 0;
}

static void antipatterns_exit(void)
{
  printk(KERN_ALERT "antipatterns.ko exited; DANGER DANGER\n");
}

module_init(antipatterns_init);
module_exit(antipatterns_exit);
