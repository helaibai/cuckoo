#include "ktrace.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)

static int find_symbol_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		sym->end_addr = (unsigned long *)addr;
		return 1;
	}
	if (name && sym->name && !strcmp(name, sym->name)) {
		sym->addr = (unsigned long *)addr;
		sym->found = true;
	}

	return 0;
}
int find_symbol_address(struct kernsym *sym, const char *symbol_name) {
	int ret;
	sym->name = (char *)symbol_name;
	sym->found = 0;
	ret = kallsyms_on_each_symbol((void *)find_symbol_callback, sym);

	if (!ret)
		return -EFAULT;

	sym->size = sym->end_addr - sym->addr;
	sym->new_size = sym->size;
	sym->run = sym->addr;

	return 0;
}
static int find_address_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		sym->end_addr = (unsigned long *)addr;
		return 1;
	}
	if (addr && (unsigned long) sym->addr == addr) {
		sym->name = malloc(strlen(name)+1);
		strncpy(sym->name, name, strlen(name)+1);
		sym->name_alloc = true;
		sym->found = true;
	}

	return 0;
}

int find_address_symbol(struct kernsym *sym, unsigned long addr) {

	int ret;

	sym->found = 0;
	sym->addr = (unsigned long *)addr;

	ret = kallsyms_on_each_symbol((void *)find_address_callback, sym);

	if (!ret)
		return -EFAULT;

	sym->size = sym->end_addr - sym->addr;
	sym->new_size = sym->size;
	sym->run = sym->addr;

	return 0;
}

#else
#define SYSTEM_MAP_PATH "/boot/System.map-"
unsigned long str2long(const char *cp, char **endp, unsigned int base) {
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);
	return simple_strtoull(cp, endp, base);
}
int find_symbol_address_from_file(struct kernsym *sym, const char *filename) {

	char buf[MAX_FILE_LEN];
	int i = 0;
	int ret = -EFAULT;
	char *p, *substr;
	struct file *f;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs (KERNEL_DS);

	f = filp_open(filename, O_RDONLY, 0);

	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		printk(PKPRE "Unable to open file %s\n", filename);
		goto out_nofilp;
	}

	memset(buf, 0x0, MAX_FILE_LEN);

	p = buf;

	while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {

		if (p[i] == '\n' || i == (MAX_FILE_LEN-1)) {

			char *sys_string;
			if (sym->found) {

				sys_string = kmalloc(MAX_FILE_LEN, GFP_KERNEL);

				if (sys_string == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_FILE_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_FILE_LEN);

				sym->end_addr = (unsigned long *) str2long(sys_string, NULL, 16);

				kfree(sys_string);

				sym->size = sym->end_addr - sym->addr;
				sym->new_size = sym->size;

				ret = 0;

				goto out;
			}

			i = 0;

			substr = strstr(p, sym->name);

			if (!sym->found && substr != NULL && substr[-1] == ' ' && substr[strlen(sym->name)+1] == '\0') {

				sys_string = kmalloc(MAX_FILE_LEN, GFP_KERNEL);	

				if (sys_string == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_FILE_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_FILE_LEN);

				sym->addr = (unsigned long *) str2long(sys_string, NULL, 16);
				kfree(sys_string);
				sym->found = true;
			}
			memset(buf, 0x0, MAX_FILE_LEN);
			continue;
		}
		i++;

	}
	out:

	filp_close(f, 0);

	out_nofilp:

	set_fs(oldfs);

	return ret;
}

int find_symbol_address(struct kernsym *sym, const char *symbol_name) {

	char *filename;
	int ret;

	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct new_utsname *uts = init_utsname();
	#else
	struct new_utsname *uts = utsname();
	#endif

	sym->name = symbol_name;

	ret = find_symbol_address_from_file(sym, "/proc/kallsyms");

	if (IN_ERR(ret)) {

		filename = kmalloc(strlen(uts->release)+strlen(SYSTEM_MAP_PATH)+1, GFP_KERNEL);

		if (filename == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		memset(filename, 0, strlen(SYSTEM_MAP_PATH)+strlen(uts->release)+1);

		strncpy(filename, SYSTEM_MAP_PATH, strlen(SYSTEM_MAP_PATH));
		strncat(filename, uts->release, strlen(uts->release));

		ret = find_symbol_address_from_file(sym, filename);

		kfree(filename);
	}
	sym->run = sym->addr;
	out:
	return ret;
}

#endif

