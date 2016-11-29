#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
void *run(void *arg)
{
	sleep(3);
	return NULL;
}
int main(int argc, char **argv)
{
	int i,ret;
	int pid;
	pthread_t tid;
	for(i=0; i< 10; ++i)
	{
		pid = fork();
		if(pid == 0){
			sleep(3);
			exit(0);
		}
	}
	for(i=0; i< 10; ++i){
		ret = pthread_create(&tid, NULL,  run, NULL);
	}
	return 0;

}
