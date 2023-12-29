#include <stdio.h>

extern int __attribute__((constructor)) callme(void)
{
	printf("callme\n");
	return 42;
}

extern void sleep(int time)
{
	printf("xd\n");

	//exit(-1);

	/* or trigger a GPF */

	*(void **) NULL = NULL;
}
