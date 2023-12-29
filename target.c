#include <stdio.h>
#include <unistd.h>

//call this function
int target(void)
{
	printf("hello world!\n");
	return 42;
}

int main(void)
{
	printf("target\n");

	while(1) {
		printf("doot\n");
		sleep(1);
	}

	return 0;
}
