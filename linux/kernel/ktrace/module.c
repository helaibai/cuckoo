#include "ktrace.h"


int init_naudit(void) {
	int ret = 0;
	ret = register_api();
	if(ret){
		kt_err("register kprobe api error\n");
	}
	kt_info("========== Start =========\n");
	return 0;
}
static void exit_naudit(void) {
	kt_info("==========  End  =========\n");
	unregister_api();
	return;
}
module_init(init_naudit);
module_exit(exit_naudit);
MODULE_AUTHOR("Hackboy");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Yahasu");
MODULE_VERSION("0.2.0");

