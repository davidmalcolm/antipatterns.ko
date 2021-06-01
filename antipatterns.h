// SPDX-License-Identifier: GPL-2.0-only

#ifndef __ANTIPATTERNS_H__
#define __ANTIPATTERNS_H__

#include <linux/fs.h>

extern struct file_operations bug_fops;
extern struct file_operations fmtstring_fops;
extern struct file_operations infoleak_fops;
extern struct file_operations taint_fops;

#define AP_IOC_MAGIC 0xf0

enum ioctl_codes {
	/* Implemented in bug.c  */
	BUG_ALWAYS = 1,
	BUG_GUARDED,

	/* Implemented in fmtstring.c  */
	USER_CONTROLLED_PRINTK,

	/* Implemented in infoleaks.c */
	INFOLEAK_STACK_NO_INIT,
	INFOLEAK_HEAP_NO_INIT,
	INFOLEAK_STACK_MISSING_A_FIELD,
	INFOLEAK_HEAP_MISSING_A_FIELD,
	INFOLEAK_STACK_PADDING,
	INFOLEAK_STACK_UNCHECKED_ERR,
	INFOLEAK_STACK_UNION,
	INFOLEAK_STACK_KERNEL_PTR,

	/* Implemented in taint.c */
	TAINT_ARRAY_ACCESS,
	TAINT_SIGNED_ARRAY_ACCESS,
	TAINT_DIVIDE_BY_ZERO_DIRECT,
	TAINT_DIVIDE_BY_ZERO_COMPOUND,
	TAINT_MOD_BY_ZERO_DIRECT,
	TAINT_MOD_BY_ZERO_COMPOUND
};

/* Implemented in bug.c  */

extern int bug_always(void);
extern int bug_guarded(int flag);

#define AP_IOC_BUG_ALWAYS _IO(AP_IOC_MAGIC, BUG_ALWAYS)
#define AP_IOC_BUG_GUARDED _IOW(AP_IOC_MAGIC, BUG_GUARDED, int)

/* Implemented in fmtstring.c  */

extern int user_controlled_printk (void __user *src);

#define AP_IOC_USER_CONTROLLED_PRINTK _IOW(AP_IOC_MAGIC, USER_CONTROLLED_PRINTK, void *)

/* Implemented in infoleaks.c */

extern int infoleak_stack_no_init(void __user *dst);
extern int infoleak_heap_no_init(void __user *dst);
extern int infoleak_stack_missing_a_field(void __user *dst, u32 v);
extern int infoleak_heap_missing_a_field(void __user *dst, u32 v);
extern int infoleak_stack_padding(void __user *dst, u8 p, u32 q);
extern int infoleak_stack_unchecked_err(void __user *dst, void __user *src);
extern int infoleak_stack_union(void __user *dst, u8 v);
extern int infoleak_stack_kernel_ptr(void __user *dst, void *kp);

#define AP_IOC_INFOLEAK_STACK_NO_INIT _IOR(AP_IOC_MAGIC, INFOLEAK_STACK_NO_INIT, void *)
#define AP_IOC_INFOLEAK_HEAP_NO_INIT _IOR(AP_IOC_MAGIC, INFOLEAK_HEAP_NO_INIT, void *)
#define AP_IOC_INFOLEAK_STACK_MISSING_A_FIELD _IOW(AP_IOC_MAGIC, INFOLEAK_STACK_MISSING_A_FIELD, void *)
#define AP_IOC_INFOLEAK_HEAP_MISSING_A_FIELD _IOW(AP_IOC_MAGIC, INFOLEAK_HEAP_MISSING_A_FIELD, void *)
#define AP_IOC_INFOLEAK_STACK_PADDING _IOW(AP_IOC_MAGIC, INFOLEAK_STACK_PADDING, void *)
#define AP_IOC_INFOLEAK_STACK_UNCHECKED_ERR _IOW(AP_IOC_MAGIC, INFOLEAK_STACK_UNCHECKED_ERR, void *)
#define AP_IOC_INFOLEAK_STACK_UNION _IOW(AP_IOC_MAGIC, INFOLEAK_STACK_UNION, void *)
#define AP_IOC_INFOLEAK_STACK_KERNEL_PTR _IOW(AP_IOC_MAGIC, INFOLEAK_STACK_KERNEL_PTR, void *)

/* Implemented in taint.c */

extern int taint_array_access(void __user *src);
extern int taint_signed_array_access(void __user *src);
extern int taint_divide_by_zero_direct(void __user *uptr);
extern int taint_divide_by_zero_compound(void __user *uptr);
extern int taint_mod_by_zero_direct(void __user *uptr);
extern int taint_mod_by_zero_compound(void __user *uptr);

#define AP_IOC_TAINT_ARRAY_ACCESS _IOR(AP_IOC_MAGIC, TAINT_ARRAY_ACCESS, void *)
#define AP_IOC_TAINT_SIGNED_ARRAY_ACCESS _IOR(AP_IOC_MAGIC, TAINT_SIGNED_ARRAY_ACCESS, void *)
#define AP_IOC_TAINT_DIVIDE_BY_ZERO_DIRECT _IOWR(AP_IOC_MAGIC, TAINT_DIVIDE_BY_ZERO_DIRECT, void *)
#define AP_IOC_TAINT_DIVIDE_BY_ZERO_COMPOUND _IOWR(AP_IOC_MAGIC, TAINT_DIVIDE_BY_ZERO_COMPOUND, void *)
#define AP_IOC_TAINT_MOD_BY_ZERO_DIRECT _IOWR(AP_IOC_MAGIC, TAINT_MOD_BY_ZERO_DIRECT, void *)
#define AP_IOC_TAINT_MOD_BY_ZERO_COMPOUND _IOWR(AP_IOC_MAGIC, TAINT_MOD_BY_ZERO_COMPOUND, void *)

#endif		/* __ANTIPATTERNS_H__ */
