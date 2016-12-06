#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/ptrace.h>

void dump_memory_region(FILE *fmemory, unsigned long start_address, long length, FILE *out)
{
    unsigned long address;
    size_t page_size = 4096;
    size_t readlen = 0;
    unsigned char page[4096] = {0};
    fseeko(fmemory, start_address, SEEK_SET);
    for(address = start_address; address < start_address + length; address += page_size){
        readlen = fread(page, sizeof(char), page_size, fmemory);
        if(readlen == 0){
            fprintf(stderr, "fread zero\n");
            break;
        }
        fwrite(page, sizeof(char), page_size, out);
    }
}
int main(int argc, const char **argv)
{
	const char *output = NULL;
	pid_t pid = -1;
	int i;
	long pret;
    int ret = -1;
    char maps_path[1024] = {0};
    char mem_path[1024] = {0};
    FILE *fmaps = NULL, *fmem = NULL, *fout = NULL;
    char line[512] = {0};
	if(argc != 5){
        fprintf(stderr, "procmem --pid $$ --output path\n");
		return -EINVAL;
	}
	for(i=1; i<argc; ++i){
		if(strcmp(argv[i], "--pid") == 0){
			i++;
			pid = atoi(argv[i]);
			continue;	
		}
		if(strcmp(argv[i], "--output") == 0){
			i++;
			output = argv[i];
			continue;	
		}
	}
	if(pid <= 0 || output == NULL){
		return -EINVAL;
	}

    sprintf(maps_path, "/proc/%d/maps", pid);
    sprintf(mem_path, "/proc/%d/mem", pid);

	pret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if(pret < 0){
            printf("Unable to attach to the pid specified\n");
            return pret;
    }
    fmaps = fopen(maps_path, "r");
    if(fmaps == NULL){
        goto out;
    }
    fmem = fopen(mem_path, "r");
    if(fmem == NULL){
        goto out;
    }
    fout = fopen(output, "w+");
    if(fout == NULL){
        goto out;
    }
    while (fgets(line, sizeof(line), fmaps) != NULL)
    {
            unsigned long start_address;
            unsigned long end_address;
            //fprintf(stderr, "sscanf [%s]",line);
            sscanf(line, "%08lx-%08lx\n", &start_address, &end_address);
            dump_memory_region(fmem, start_address, end_address - start_address, fout);
    }
    ret = 0;
out:
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if(fout){
            fclose(fout);
    }
    if(fmaps){
            fclose(fmaps);
    }
    if(fmem){
            fclose(fmem);
    }
    return ret;
}

