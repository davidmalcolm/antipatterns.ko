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
#include <linux/cdev.h>
#include "antipatterns.h"

MODULE_LICENSE("GPL");

static dev_t ap_dev;
static struct cdev *ap_cdev;

static int devno;
static int major;
static int minor;

static long ap_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
{
  switch (cmd) {
    /* Implemented in bug.c  */
    case AP_IOC_BUG_ALWAYS:
      return bug_always();
    case AP_IOC_BUG_GUARDED:
      return bug_guarded(arg);

    /* Implemented in fmtstring.c */
    case AP_IOC_USER_CONTROLLED_PRINTK:
      return user_controlled_printk ((void __user *)arg);

    /* Implemented in infoleaks.c */
    case AP_IOC_INFOLEAK_STACK_NO_INIT:
      return infoleak_stack_no_init((void __user *)arg);
    case AP_IOC_INFOLEAK_HEAP_NO_INIT:
      return infoleak_heap_no_init((void __user *)arg);
    case AP_IOC_INFOLEAK_STACK_MISSING_A_FIELD:
      return infoleak_stack_missing_a_field((void __user *)arg, 42);
    case AP_IOC_INFOLEAK_HEAP_MISSING_A_FIELD:
      return infoleak_heap_missing_a_field((void __user *)arg, 42);
    case AP_IOC_INFOLEAK_STACK_PADDING:
      return infoleak_stack_padding((void __user *)arg, 42, 1776);
    case AP_IOC_INFOLEAK_STACK_UNCHECKED_ERR:
      return infoleak_stack_unchecked_err((void __user *)arg,
					  (void __user *)arg);
    case AP_IOC_INFOLEAK_STACK_UNION:
      return infoleak_stack_union((void __user *)arg, 42);
    case AP_IOC_INFOLEAK_STACK_KERNEL_PTR:
      return infoleak_stack_kernel_ptr((void __user *)arg, ap_ioctl);

    /* Implemented in taint.c */
    case AP_IOC_TAINT_ARRAY_ACCESS:
      return taint_array_access((void __user *)arg);
    case AP_IOC_TAINT_SIGNED_ARRAY_ACCESS:
      return taint_signed_array_access((void __user *)arg);
    case AP_IOC_TAINT_DIVIDE_BY_ZERO_DIRECT:
      return taint_divide_by_zero_direct((void __user *)arg);
    case AP_IOC_TAINT_DIVIDE_BY_ZERO_COMPOUND:
      return taint_divide_by_zero_compound((void __user *)arg);
    case AP_IOC_TAINT_MOD_BY_ZERO_DIRECT:
      return taint_mod_by_zero_direct((void __user *)arg);
    case AP_IOC_TAINT_MOD_BY_ZERO_COMPOUND:
      return taint_mod_by_zero_compound((void __user *)arg);
  }
  return -ENOTTY;
}

static struct file_operations ap_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ap_ioctl
};

static int antipatterns_init(void)
{
  int result;
  printk(KERN_ALERT "antipatterns.ko started; DO NOT USE; DANGER DANGER\n");

  result = alloc_chrdev_region(&ap_dev, 0, 1, "antipatterns");
  if (result < 0) {
    printk(KERN_WARNING "antipatterns.ko: can't allocate chrdev");
    return result;
  }
  major = MAJOR(ap_dev);

  devno = MKDEV(major, minor);
  ap_cdev = cdev_alloc ();
  ap_cdev->owner = THIS_MODULE;
  ap_cdev->ops = &ap_fops;
  result = cdev_add(ap_cdev, devno, 1);
  if (result)
    printk(KERN_NOTICE "error %d adding antipatterns device", result);

  return 0;
}

static void antipatterns_exit(void)
{
  printk(KERN_ALERT "antipatterns.ko exited; DANGER DANGER\n");
  /* TODO: unregister device.  */
  unregister_chrdev_region(ap_dev, 0);
}

module_init(antipatterns_init);
module_exit(antipatterns_exit);
