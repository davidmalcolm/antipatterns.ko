// SPDX-License-Identifier: GPL-2.0-only
/*
 * Various infoleaks (CWE-200).
 * TODO: expose these (e.g. as ioctls) so they can actually be triggered
 * at run-time.
 *
 * (C) 2021 David Malcolm, Red Hat
 * Written by David Malcolm <dmalcolm@redhat.com>
 */

#include <linux/uaccess.h>
#include <linux/slab.h>

struct infoleak_buf
{
  char buf[256];
};

int infoleak_stack_no_init(void __user *dst)
{
  struct infoleak_buf st;
  /* No initialization of "st" at all.  */
  if (copy_to_user(dst, &st, sizeof(st)))
    return -EFAULT;
  return 0;
}

int infoleak_heap_no_init(void __user *dst)
{
  struct infoleak_buf *heapbuf = kmalloc(sizeof(*heapbuf), GFP_KERNEL);
  /* No initialization of "heapbuf" at all.  */

  if (copy_to_user(dst, heapbuf, sizeof(*heapbuf)))
    return -EFAULT; /* Also a leak.  */

  kfree(heapbuf);
  return 0;
}

struct infoleak_2
{
  u32 a;
  u32 b;
};

int infoleak_stack_missing_a_field(void __user *dst, u32 v)
{
  struct infoleak_2 st;
  st.a = v;
  /* No initialization of "st.b".  */
  if (copy_to_user(dst, &st, sizeof(st)))
    return -EFAULT;
  return 0;
}

int infoleak_heap_missing_a_field(void __user *dst, u32 v)
{
  struct infoleak_2 *heapbuf = kmalloc(sizeof(*heapbuf), GFP_KERNEL);
  heapbuf->a = v;
  /* No initialization of "heapbuf->b".  */
  if (copy_to_user(dst, heapbuf, sizeof(*heapbuf)))
    {
      kfree(heapbuf);
      return -EFAULT;
    }
  kfree(heapbuf);
  return 0;
}

struct infoleak_3
{
  u8 a;
  /* padding here */
  u32 b;
};

int infoleak_stack_padding(void __user *dst, u8 p, u32 q)
{
  struct infoleak_3 st;
  st.a = p;
  st.b = q;
  /* No initialization of padding.  */
  if (copy_to_user(dst, &st, sizeof(st)))
    return -EFAULT;
  return 0;
}

int infoleak_stack_unchecked_err(void __user *dst, void __user *src)
{
  struct infoleak_buf st;
  /*
   * If the copy_from_user call fails, then st is still uninitialized,
   * and if the copy_to_user call succeds, we have an infoleak.
   */
  int err = copy_from_user (&st, src, sizeof(st));
  err |= copy_to_user (dst, &st, sizeof(st));
  if (err)
    return -EFAULT;
  return 0;
}

struct infoleak_4
{
  union {
    u8 f1;
    u32 f2;
  } u;
};

int infoleak_stack_union(void __user *dst, u8 v)
{
  struct infoleak_4 st;
  /*
   * This write only initializes the u8 within the union "u",
   * leaving the remaining 3 bytes uninitialized.
   */
  st.u.f1 = v;
  if (copy_to_user(dst, &st, sizeof(st)))
    return -EFAULT;
  return 0;
}

struct infoleak_5
{
  void *ptr;
};

int infoleak_stack_kernel_ptr(void __user *dst, void *kp)
{
  struct infoleak_5 st;
  /* This writes a kernel-space pointer into a user space buffer.  */
  st.ptr = kp;
  if (copy_to_user(dst, &st, sizeof(st)))
    return -EFAULT;
  return 0;
}
