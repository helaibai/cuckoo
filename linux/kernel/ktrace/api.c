#include "ktrace.h"

long analyzer = 0;

module_param(analyzer,long,0644);

struct proc_dir_entry *ktracelist = NULL;

struct ktrace_list {
	struct list_head head;
	spinlock_t lock;
	int number;
} ktrace_head;

struct ktrace_node {
	struct list_head list;
	long pid;
};
static int ktrace_process_check(long pid)
{
	struct list_head *pos, *head = &(ktrace_head.head);
	struct ktrace_node *node;

	spin_lock(&(ktrace_head.lock));
	list_for_each(pos, head){
		node = list_entry(pos, struct ktrace_node, list);
		if(node->pid == pid){
			spin_unlock(&(ktrace_head.lock));
			return 0;
		}
	}
	spin_unlock(&(ktrace_head.lock));
	return 1;
}
static int ktrace_process_add(long pid)
{
	struct ktrace_node *node;
	node = kmalloc(sizeof(struct ktrace_node), GFP_KERNEL);
	if(node == NULL){
		printk(KERROR"No memory\n");
		return -ENOMEM;
	}
	node->pid = pid;
	spin_lock(&(ktrace_head.lock));
	list_add(&(node->list), &(ktrace_head.head));
	ktrace_head.number ++;
	spin_unlock(&(ktrace_head.lock));
	return 0;
}
static void ktrace_process_del(long exit_pid)
{
	struct list_head *tmp,*pos;
	struct ktrace_node *node;
	struct list_head *head = &(ktrace_head.head);
	spin_lock(&(ktrace_head.lock));
	list_for_each_safe(pos, tmp, head){
		node = list_entry(pos, struct ktrace_node, list);
		if(node->pid == exit_pid){
			list_del(pos);
			ktrace_head.number --;
			spin_unlock(&(ktrace_head.lock));
			kfree(node);
			return ;
		}
	}
	spin_unlock(&(ktrace_head.lock));
}
static int ktracelist_proc_show(struct seq_file *m, void *v) 
{
	struct list_head *pos, *head = &(ktrace_head.head);
	struct ktrace_node *node;

	spin_lock(&(ktrace_head.lock));
	list_for_each(pos, head){
		node = list_entry(pos, struct ktrace_node, list);
		seq_printf(m,"%ld\n",node->pid); 
	}
	spin_unlock(&(ktrace_head.lock));
	return 0;
}

static int ktracelist_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, ktracelist_proc_show, NULL);
}

static const struct file_operations ktracelist_proc_fops = { 
	.open           = ktracelist_proc_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};
static int ktrace_process_init(long pid)
{
	INIT_LIST_HEAD(&(ktrace_head.head));
	spin_lock_init(&(ktrace_head.lock));
	ktrace_head.number = 0;
	if(pid == 0){
		printk(KERROR"we wanted a ktrace pid\n");
		return -EINVAL;
	}
	if(ktrace_process_add(pid) != 0){
		printk(KERROR"ktrace_process_add(%ld)\n",pid);
		return -EINVAL;
	}

	return 0;
}
static void ktrace_process_free(void)
{
	struct list_head *tmp,*pos;
	struct ktrace_node *node;
	struct list_head *head = &(ktrace_head.head);
	printk("ktrace.number %d \n",ktrace_head.number);
	list_for_each_safe(pos, tmp, head){
		node = list_entry(pos, struct ktrace_node, list);
		printk("leave:%ld\n",node->pid);
		ktrace_head.number --;
		list_del(pos);
		kfree(node);
	}
}

long realtime(void)
{
	struct timeval val;
	do_gettimeofday(&val);
	return (val.tv_sec);
}

struct ktrace_struct {
	char buffer[1024];
	size_t size;
	void *private;
};
static int entry_handler(struct kretprobe_instance *kri, struct pt_regs *regs)
{
	struct ktrace_struct *ks;
	const char *function;
	size_t size = 0;
	long current_pid = 0;
	int ret = 1;
	if(current->mm == NULL){
		return ret;
	}

	current_pid = current->pid;

	if(ktrace_process_check(current_pid)){
		return ret;
	}
	ks = (struct ktrace_struct *)kri->data;
	if(ks == NULL){
		goto out;
	}

	ks->size = 0;

	function = kri->rp->kp.symbol_name;
	ret = 0;	
	size = sprintf(ks->buffer,"%s:%ld:%ld:%s(",PREFIX,current_pid,realtime(),function);
	if(strcmp(function, "do_fork") == 0){
		unsigned long clone_flags = regs->di;
		unsigned long stack_start = regs->si;
		unsigned long stack_size = regs->dx;
		int *parent_tidptr = (int *)regs->cx;
		int *child_tidptr = (int *)regs->ax;
		ks->private = parent_tidptr;
		size += sprintf(ks->buffer+size, "%08lx,%08lx,%08lx,%p,%p",clone_flags,stack_start, stack_size, parent_tidptr, child_tidptr);
		goto out;
	}

	if(strcmp(function, "sys_execve") == 0){
		char *path = (char *)(regs->di);
		size += sprintf(ks->buffer+size, "%s,0x%08lx,0x%08lx",path,regs->si,regs->dx);
		goto out;
	}
	if(strcmp(function, "sys_access") == 0){
		char *filename = (char *)regs->di;
		int mode = (int)(regs->si);
		size += sprintf(ks->buffer+size, "%s,0x%08x",filename,mode);
	}
	if(strcmp(function, "sys_creat") == 0){
		char *pathname = (char *)(regs->di);
		unsigned long mode = regs->si;
		size += sprintf(ks->buffer+size, "%s,0x%08lx",pathname,mode);
		goto out;
	}
	if(strcmp(function, "sys_open") == 0){
		char *path = (char *)(regs->di);
		size += sprintf(ks->buffer+size, "%s,0x%08lx,0x%08lx",path,regs->si,regs->dx);
		goto out;
	}
	if(strcmp(function, "sys_unlink") == 0){
		char *path = (char *)(regs->di);
		size += sprintf(ks->buffer+size, "%s",path);
		goto out;
	}
	if(strcmp(function, "sys_truncate") == 0){
		char *path = (char *)regs->di;
		long length = (long)regs->si;
		size += sprintf(ks->buffer+size, "%s,%ld",path,length);
	}
	if(strcmp(function, "sys_rename") == 0){
		char *old = (char *)(regs->di);
		char *new = (char *)(regs->si);
		size += sprintf(ks->buffer+size, "%s,%s",old,new);
		goto out;
	}
	if(strcmp(function, "sys_mkdir") == 0){
		char *filename = (char *)regs->di;
		unsigned long mode = regs->si;
		size += sprintf(ks->buffer+size, "%s,%lu",filename,mode);
	}
	if(strcmp(function, "sys_rmdir") == 0){
		char *filename = (char *)regs->di;
		size += sprintf(ks->buffer+size, "%s",filename);
	}
	if(strcmp(function, "sys_chmod") == 0){
		char *filename = (char *)regs->di;
		unsigned int mode = regs->si;
		size += sprintf(ks->buffer+size, "%s,%u",filename,mode);
	}
	if(strcmp(function, "sys_ptrace") == 0){
		long request = regs->di;
		long pid = regs->si;
		unsigned long addr = (unsigned long)regs->dx;
		unsigned long data = (unsigned long)regs->cx;
		size += sprintf(ks->buffer+size, "%ld,%ld,%08lx,%08lx",request,pid,addr,data);
	}
	if(strcmp(function, "sys_getuid") == 0){
		size += sprintf(ks->buffer+size, "void");
	}
	if(strcmp(function, "sys_setuid") == 0){
		long uid = regs->di;
		size += sprintf(ks->buffer+size, "%ld",uid);
	}
	if(strcmp(function, "sys_kill") == 0){
		long pid = regs->di;
		long sig = regs->si;
		size += sprintf(ks->buffer+size, "%ld,%ld",pid,sig);
	}
	if(strcmp(function, "sys_nanosleep") == 0){
		struct timespec { long tv_sec; long tv_nsec;} *ts;
		ts = (struct timespec *)regs->di;
		size += sprintf(ks->buffer+size, "%ld,%ld",ts->tv_sec, ts->tv_nsec);
	}
	if(strcmp(function, "sys_brk") == 0){
		unsigned long brk = regs->di;
		size += sprintf(ks->buffer+size, "%lu",brk);
	}
	if(strcmp(function, "sys_chroot") == 0){
		char *filename = (char *)regs->di;
		size += sprintf(ks->buffer+size, "%s",filename);
	}
	if(strcmp(function, "sys_sysctl") == 0){
		size += sprintf(ks->buffer+size, "{}");
	}
	if(strcmp(function, "sys_socket") == 0){
		int domain = regs->di;
		int type = regs->si;
		int protocol = regs->dx;
		size += sprintf(ks->buffer+size, "%d,%d,%d",domain, type, protocol);
	}
	if(strcmp(function, "sys_listen") == 0){
		int fd = regs->di;
		int backlog = regs->si;
		size += sprintf(ks->buffer+size, "%d,%d",fd, backlog);
	}
	if(strcmp(function, "do_exit") == 0){
		int code = (int)regs->di;
		size += sprintf(ks->buffer+size, "%d) = %d\n",code, code);
		ktrace_process_del(current_pid);
		printk("%s",ks->buffer);
		ret = 1;
	}
	if(strcmp(function, "sys_nice") == 0){
		int increment = (int)regs->di;
		size += sprintf(ks->buffer+size, "%d",increment);
	}
	if(strcmp(function, "load_module") == 0){
		void *load_info = (void*)regs->di;
		unsigned long len = regs->si;
		const char *uargs = (char *)regs->dx;
		size += sprintf(ks->buffer+size, "%p,%lu,%s",load_info,len,uargs);
	}
	if(strcmp(function, "sys_delete_module") == 0){
		char *name_user = (char *)regs->di;
		unsigned int flags = (unsigned int)regs->si;
		size += sprintf(ks->buffer+size, "%s,%08x",name_user,flags);
	}
	if(strcmp(function, "sys_stat") == 0){
		char *filename = (char *)regs->di;
		void *stat_buffer = (void *)(regs->si);
		size += sprintf(ks->buffer+size, "%s,%p",filename,stat_buffer);
	}
	if(strcmp(function, "sys_newstat") == 0){
		char *filename = (char *)regs->di;
		void *stat_buffer = (void *)(regs->si);
		size += sprintf(ks->buffer+size, "%s,%p",filename,stat_buffer);
	}
	if(strcmp(function, "sys_fstat") == 0){
		int fd = (int)regs->di;
		void *stat_buffer = (void*)(regs->di);
		size += sprintf(ks->buffer+size, "%d,%p",fd,stat_buffer);
	}
	if(strcmp(function, "sys_newfstat") == 0){
		int fd = (int)regs->di;
		void *stat_buffer = (void*)(regs->di);
		size += sprintf(ks->buffer+size, "%d,%p",fd,stat_buffer);
	}
	if(strcmp(function, "sys_reboot") == 0){
		int magic1 = (int)regs->di;
		int magic2 = (int)regs->si;
		unsigned int cmd = (unsigned int)regs->dx;
		void *arg = (void *)regs->cx;
		size += sprintf(ks->buffer+size, "%d,%d, %u,%p",magic1, magic2, cmd, arg);
		printk("%s",function);
	}
	ks->size = size;
out:
	return ret;
}
static int ktrace_ret_handler(struct kretprobe_instance *kri, struct pt_regs *regs)
{
	long retval = regs_return_value(regs);
	struct ktrace_struct *ks;
	const char *function = NULL; 
	ks = (struct ktrace_struct *)kri->data;
	printk("%s) = %ld\n",ks->buffer, retval);
	function = kri->rp->kp.symbol_name;
	if(strcmp(function, "do_fork") == 0){
		if(ks->private == NULL && ktrace_process_add(retval) != 0){
			printk(KERROR"ktrace_process_add(%ld)\n",retval);
		}
	}
	return 0;
}
static struct kretprobe apis[] = {
	{.kp = { .symbol_name = "do_fork",},},
	{.kp = { .symbol_name = "sys_execve",},},
	{.kp = { .symbol_name = "sys_access",},},
	{.kp = { .symbol_name = "sys_creat",},},
	{.kp = { .symbol_name = "sys_open",},},
	{.kp = { .symbol_name = "sys_unlink",},},
	{.kp = { .symbol_name = "sys_truncate",},},
	{.kp = { .symbol_name = "sys_rename",},},
	{.kp = { .symbol_name = "sys_mkdir",},},
	{.kp = { .symbol_name = "sys_rmdir",},},
	{.kp = { .symbol_name = "sys_chmod",},},
	{.kp = { .symbol_name = "sys_ptrace",},},
	{.kp = { .symbol_name = "sys_getuid",},},
	{.kp = { .symbol_name = "sys_setuid",},},
	{.kp = { .symbol_name = "sys_kill",},},
	{.kp = { .symbol_name = "sys_nanosleep",},},
	{.kp = { .symbol_name = "sys_chroot",},},
	{.kp = { .symbol_name = "sys_sysctl",},},
	{.kp = { .symbol_name = "sys_socket",},},
	{.kp = { .symbol_name = "sys_listen",},},
	{.kp = { .symbol_name = "do_exit",},},
	{.kp = { .symbol_name = "sys_nice",},},
	{.kp = { .symbol_name = "load_module",},},
	{.kp = { .symbol_name = "sys_delete_module",},},
	{.kp = { .symbol_name = "sys_stat",},},
	{.kp = { .symbol_name = "sys_newstat",},},
	{.kp = { .symbol_name = "sys_fstat",},},
	{.kp = { .symbol_name = "sys_newfstat",},},
	{.kp = { .symbol_name = "sys_reboot",},},
};
int register_api(void)
{
	int ret = 0;
	int i = 0;
	ret = ktrace_process_init(analyzer);
	if(ret){
		return ret;
	}
	ktracelist = proc_create("ktracelist", 0, NULL, &ktracelist_proc_fops);
	if(ktracelist == NULL){
		goto out;
	}
	for(i=0; i<sizeof(apis)/sizeof(apis[0]); ++i){
		apis[i].entry_handler = entry_handler;
		apis[i].handler = ktrace_ret_handler;
		apis[i].data_size = sizeof(struct ktrace_struct); 
		apis[i].maxactive = 10; 
		ret = register_kretprobe(&apis[i]);
		if(ret < 0){
			printk("kprobe '%s' error\n",apis[i].kp.symbol_name);
			goto out;
		}
	}
	return 0;
out:
	for(; i>=0; i--){
		unregister_kretprobe(&apis[i]);
	}
	if(ktracelist){
		proc_remove(ktracelist);
	}
	ktrace_process_free();
	return ret;
}
void unregister_api(void)
{
	int i = 0;
	for(i=0; i<sizeof(apis)/sizeof(apis[0]); ++i){
		unregister_kretprobe(&apis[i]);
	}
	if(ktracelist){
		proc_remove(ktracelist);
	}
	ktrace_process_free();
}
