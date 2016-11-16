#include "ktrace.h"
int init_naudit(void) {
	printk("added --->>>\n");
	return 0;
}
static void exit_naudit(void) {
	printk("removed <<<---\n");
	return;
}
module_init(init_naudit);
module_exit(exit_naudit);
MODULE_AUTHOR("Hackboy");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Yahasu");
MODULE_VERSION("0.2.0");

