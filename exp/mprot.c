#include <stdio.h>

#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

static const char payload[] =
	"\x55\x48\x89\xe5\x48\x83\xec\x10"
	"\x48\xc7\xc0\x01\x00\x00\x00\x48"
	"\xc7\xc7\x01\x00\x00\x00\x48\xbe"
	"\x48\x65\x6c\x6c\x6f\x0a\x00\x00"
	"\x48\x89\x75\xf8\x48\x8d\x75\xf8"
	"\x48\xc7\xc2\x06\x00\x00\x00\x0f"
	"\x05\x48\x89\xec\x5d\xc3";

int main(void)
{
	void (*test)(void);
	void *ptr;

	ptr = sbrk(sizeof(payload));

	mprotect(ptr, sizeof(payload), PROT_READ | PROT_WRITE | PROT_EXEC);

	memcpy(ptr, payload, sizeof(payload));

	test = ptr;
	test();

	return 0;
}
