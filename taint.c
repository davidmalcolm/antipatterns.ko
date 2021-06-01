// SPDX-License-Identifier: GPL-2.0-only
/*
 * Various blithe uses of attacker-controlled values.
 * TODO: expose these (e.g. as ioctls) so they can actually be triggered
 * at run-time.
 *
 * (C) 2021 David Malcolm, Red Hat
 * Written by David Malcolm <dmalcolm@redhat.com>
 */

#include <linux/uaccess.h>

struct cmd_1
{
  u32 idx;
  u32 val;
};

int taint_array_access(void __user *src, u32 *arr)
{
  struct cmd_1 cmd;
  if (copy_from_user(&cmd, src, sizeof(cmd)))
    return -EFAULT;
  /*
   * cmd.idx is an unsanitized value from user-space, hence
   * this is an arbitrary kernel memory access.
   */
  arr[cmd.idx] = cmd.val;
  return 0;
}

struct cmd_2
{
  s32 idx;
  u32 val;
};

int taint_signed_array_access(void __user *src, u32 *arr)
{
  struct cmd_2 cmd;
  if (copy_from_user(&cmd, src, sizeof(cmd)))
    return -EFAULT;
  if (cmd.idx >= 16)
    return -EFAULT;

  /*
   * cmd.idx hasn't been checked for being negative, hence
   * this is an arbitrary kernel memory access.
   */
  arr[cmd.idx] = cmd.val;
  return 0;
}

struct cmd_s32_binop
{
  s32 a;
  s32 b;
  s32 result;
};

int taint_divide_by_zero_direct(void __user *uptr)
{
  struct cmd_s32_binop cmd;
  if (copy_from_user(&cmd, uptr, sizeof(cmd)))
    return -EFAULT;

  /* cmd.b is attacker-controlled and could be zero */
  cmd.result = cmd.a / cmd.b;

  if (copy_to_user (uptr, &cmd, sizeof(cmd)))
    return -EFAULT;
  return 0;
}

int taint_divide_by_zero_compound(void __user *uptr)
{
  struct cmd_s32_binop cmd;
  if (copy_from_user(&cmd, uptr, sizeof(cmd)))
    return -EFAULT;

  /*
   * cmd.b is attacker-controlled and could be -1, hence
   * the divisor could be zero
   */
  cmd.result = cmd.a / (cmd.b + 1);

  if (copy_to_user (uptr, &cmd, sizeof(cmd)))
    return -EFAULT;
  return 0;
}

int taint_mod_by_zero_direct(void __user *uptr)
{
  struct cmd_s32_binop cmd;
  if (copy_from_user(&cmd, uptr, sizeof(cmd)))
    return -EFAULT;

  /* cmd.b is attacker-controlled and could be zero */
  cmd.result = cmd.a % cmd.b;

  if (copy_to_user (uptr, &cmd, sizeof(cmd)))
    return -EFAULT;
  return 0;
}

int taint_mod_by_zero_compound(void __user *uptr)
{
  struct cmd_s32_binop cmd;
  if (copy_from_user(&cmd, uptr, sizeof(cmd)))
    return -EFAULT;

  /*
   * cmd.b is attacker-controlled and could be -1, hence
   * the divisor could be zero
   */
  cmd.result = cmd.a % (cmd.b + 1);

  if (copy_to_user (uptr, &cmd, sizeof(cmd)))
    return -EFAULT;
  return 0;
}

/* TODO: etc.  */
