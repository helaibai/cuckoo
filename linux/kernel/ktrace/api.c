#include "ktrace.h"
#define KPROBE_PRE
#ifdef KPROBE_PRE
int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk("{\"current\":\"%s\",\"api\":\"%s\"}\n",current->comm, p->symbol_name);
    return 0;
}
#endif
#ifdef KPROBE_FAULT
handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
}
#endif
void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) 
{
    printk("{\"current\":\"%s\",\"api\":\"%s\"}\n",current->comm, p->symbol_name);
}

struct kprobe apis[] = {
    {
        .symbol_name = "sys_open",
        #ifdef KPROBE_PRE
        .pre_handler = handler_pre,
        #endif
        .post_handler = handler_post,
        #ifdef KPROBE_FAULT
        .fault_handler = handler_fault,
        #endif
    },
};

int register_api(void)
{
    int ret = 0;
    int i = 0;
    for(i=0; i<sizeof(apis)/sizeof(apis[0]); ++i){
        ret = register_kprobe(&apis[i]);
        if(ret < 0){
            printk("kprobe '%s' error\n",apis[i].symbol_name);
            break;
        }
    }
    for(; i>=0; i--){
        unregister_kprobe(&apis[i]);
    }
    return ret;
}
void unregister_api(void)
{
    int i = 0;
    for(i=0; i<sizeof(apis)/sizeof(apis[0]); ++i){
        unregister_kprobe(&apis[i]);
    }
}
