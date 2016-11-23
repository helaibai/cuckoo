#ifndef HOOK_H_INCLUDED
#define HOOK_H_INCLUDED

#include <linux/security.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/kallsyms.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <net/inet_sock.h>

#include <asm/uaccess.h>
#include <asm/insn.h>


#define MODULE_NAME "ktrace"
#define PKPRE "[" MODULE_NAME "] "
#define MAX_FILE_LEN 256


#define OP_JMP_SIZE 5

#define IN_ERR(x) (x < 0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#define hook_d_path(file, buf, len) d_path(file->f_dentry, file->f_vfsmnt, buf, len)
#else
#define hook_d_path(file, buf, len) d_path(&file->f_path, buf, len)
#endif


struct kernsym {
	void *addr; // orig addr
	void *end_addr;
	unsigned long size;
	char *name;
	bool name_alloc; // whether or not we alloc'd memory for char *name
	u8 orig_start_bytes[OP_JMP_SIZE];
	void *new_addr;
	unsigned long new_size;
	bool found;
	bool hijacked;
	void *run;
};

extern long ktrace_pid;

int symbol_hijack(struct kernsym *, const char *, unsigned long *);
void symbol_restore(struct kernsym *);

void hook_syscalls(void);
void undo_hook_syscalls(void);

void symbol_info(struct kernsym *);

int find_symbol_address(struct kernsym *, const char *);

int kernfunc_init(void);

void hook_insn_init(struct insn *, const void *);
void hook_insn_get_length(struct insn *insn);
int hook_insn_rip_relative(struct insn *insn);

void *malloc(unsigned long size);
void malloc_free(void *buf);

#endif
