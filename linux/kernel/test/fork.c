#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int pid;
    pid = fork();
    if(pid == 0){
        return 0;
    }
    return pid;
}
