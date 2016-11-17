#include "naudit.h"

static struct kernsym sym_module_alloc;
static struct kernsym sym_module_free;

static struct kernsym sym_insn_init;
static struct kernsym sym_insn_get_length;
static struct kernsym sym_insn_rip_relative;

int kernfunc_init(void) {
	int ret;
	ret = find_symbol_address(&sym_module_alloc, "module_alloc");
	if (IN_ERR(ret))
		return ret;
	ret = find_symbol_address(&sym_module_free, "module_free");
	if (IN_ERR(ret))
		return ret;
	ret = find_symbol_address(&sym_insn_init, "insn_init");

	if (IN_ERR(ret))
		return ret;
	ret = find_symbol_address(&sym_insn_get_length, "insn_get_length");
	if (IN_ERR(ret))
		return ret;
	ret = find_symbol_address(&sym_insn_rip_relative, "insn_rip_relative");
	if (IN_ERR(ret))
		return ret;
	return 0;
}
void *malloc(unsigned long size) {
	void *(*run)(unsigned long) = sym_module_alloc.run;
	return run(size);
}
void malloc_free(void *buf) {
	void (*run)(struct module *, void *) = sym_module_free.run;
	if (buf != NULL)
		run(NULL, buf);
}

void hook_insn_init(struct insn *insn, const void *kaddr) {
	void (*run)(struct insn *, const void *, int) = sym_insn_init.run;
	run(insn, kaddr,
#ifdef CONFIG_X86_64
		1
#else // CONFIG_X86_32
		0
#endif
		);
}

void hook_insn_get_length(struct insn *insn) {
	void (*run)(struct insn *) = sym_insn_get_length.run;
	run(insn);
}

int hook_insn_rip_relative(struct insn *insn) {
	int (*run)(struct insn *) = sym_insn_rip_relative.run;
	return run(insn);
}
