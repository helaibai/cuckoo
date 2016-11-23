#include "naudit.h"


struct kernsym sym_security_bprm_check;
struct kernsym sym_do_fork;

extern long ktrace_pid; 
char *hook_file_path(struct file *file, char *buf, int len)
{
    char *p = NULL;
    char *realp = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    if(file->f_dentry == NULL || file->f_vfsmnt == NULL){
        return NULL;
    }
    p = d_path(file->f_dentry, file->f_vfsmnt, buf, len);
#else
    p = d_path(&(file->f_path), buf, len);
#endif
    if(IS_ERR(p)){
        return NULL;
    }
    realp = strchr(p, ' ');
    if(realp){
    	*realp = 0x00;
    }
    return p;
}
/*
 * Get full path by struct task_struct in <linux/sched.h>
 * Author:Shenjunwei
 */
char *hook_task_path(struct task_struct *task, char *buf, int len)
{
	char *p = NULL;
	struct mm_struct *mm = task->mm;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
	/*
	 * For Less than 2.6.18
	 */
	struct vm_area_struct *vma = NULL;
	if(!mm){
		goto out;
	}
	down_read(&(mm->mmap_sem));
	vma = mm->mmap;
	while(vma){
		if((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file){
			p = sec_file_path(vma->vm_file, buf, len);
			break;
		}
		vma = vma->vm_next;
	}
	up_read(&(mm->mmap_sem));
out:
	return p;
#else
	/*
	 * For great than 2.6.18 
	 */
	if(mm == NULL)
		return NULL;
	down_read(&(mm->mmap_sem));
	if(mm->exe_file != NULL){
		p = hook_file_path(mm->exe_file, buf, len);
	}
	up_read(&(mm->mmap_sem));
	return p;
#endif
}
int hook_security_bprm_check(struct linux_binprm *bprm) {

	int (*run)(struct linux_binprm *) = sym_security_bprm_check.run;
	char buffer[128];
	char *task_buffer = NULL, *tp = NULL;
	if(current->pid != ktrace_pid){
		goto out;
	}
	task_buffer = kmalloc(1024, GFP_KERNEL);
	if(task_buffer == NULL){
		tp = current->comm;
	}
	tp = hook_task_path(current, task_buffer, 1024);
	if (bprm->file) {
		printk("current [%s]->[%s]\n",tp,hook_d_path(bprm->file,buffer, sizeof(buffer)));
	}
	if(task_buffer){
		kfree(task_buffer);
	}
out:
	return run(bprm);
}
long hook_do_fork(unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size, int __user * parent_tidptr
, int __user * child_tidptr)
{
	long ret;
	long (*run)(unsigned long, unsigned long, unsigned long, int __user *, int __user *) = sym_do_fork.run;
	ret = run(clone_flags, stack_start, stack_size, parent_tidptr, child_tidptr); 
	if(current->pid != ktrace_pid){
		goto out;
	}
	printk("[KTRACE]""do_fork(%08lx,%08lx,%08lx,%p, %p) = %ld\n", 
			clone_flags, stack_start, stack_size, parent_tidptr, child_tidptr,ret);
out:
	return ret;
}
struct symhook {
	char *name;
	struct kernsym *sym;
	unsigned long *func;
};

struct symhook hooks[] = {
	{"security_bprm_check", &sym_security_bprm_check, (unsigned long *)hook_security_bprm_check},
	{"do_fork", &sym_do_fork, (unsigned long *)hook_do_fork},
};

void hook_syscalls(void) {
	int ret, i;
	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		ret = symbol_hijack(hooks[i].sym, hooks[i].name, hooks[i].func);
		if (IN_ERR(ret))
			printk("hook %s faile\n",hooks[i].name);
	}
}
void undo_hook_syscalls(void) {
	int i;
	for (i = 0; i < ARRAY_SIZE(hooks); i++)
		symbol_restore(hooks[i].sym);
}
