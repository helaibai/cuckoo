#include "naudit.h"

long ktrace_pid = 0;
module_param(ktrace_pid, long, 0644);

int init_naudit(void) {
	int ret;
	ret = kernfunc_init();
	if (IN_ERR(ret))
		return ret;
	hook_syscalls();
	printk("added --->>>\n");
	return ret;
}
static void exit_naudit(void) {
	undo_hook_syscalls();
	printk("removed <<<---\n");
	return;
}
module_init(init_naudit);
module_exit(exit_naudit);
MODULE_AUTHOR("Hackboy");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Yahasu");
MODULE_VERSION("0.2.0");

