#include <stdio.h>
#include <unistd.h>



int main(int argc, char **argv)
{
	fprintf(stderr, "stand error infomation\n");
	while(1)
		sleep(30);
	return 0;
}
