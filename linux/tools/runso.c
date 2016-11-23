#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>


int main(int argc, char **argv)
{
    void *handler = NULL;
    char *path,*fname;
    int (*function)(void) = NULL;
    int ret = 0;
    if(argc != 3){
        fprintf(stderr, "runso library function\n");
        return -EINVAL;
    }
    path = argv[1];
    fname = argv[2];
    handler = dlopen(path, RTLD_LAZY);
    if(handler == NULL){
        fprintf(stderr, "load library %s error:%s\n",path, dlerror());
        return -1;
    }
    dlerror();
    function = dlsym(handler, fname);
    function();
    dlclose(handler);
    return ret;
}
