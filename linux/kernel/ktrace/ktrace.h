#ifndef HOOK_H_INCLUDED
#define HOOK_H_INCLUDED


#include <linux/security.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <net/inet_sock.h>

#include <asm/uaccess.h>
#include <asm/insn.h>

extern long ktracepid;

#define PREFIX "[KTRACE]"
#define KERROR "[KERROR]"
#define KDEBUG "[KDEBUG]"

int register_api(void);

void unregister_api(void);

#define kt_info printk
#define kt_err  printk
#define kt_dbg  printk

#endif
