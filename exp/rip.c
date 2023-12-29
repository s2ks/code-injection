#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#define jump_if(__condition__, __label__) if(__condition__) goto __label__

#define debugf(__fmt__, ...) 	do { if(DEBUG) printf(__fmt__, __VA_ARGS__); } while(0)
#define derror(__str__) 	do { if(DEBUG) perror(__str__); } while(0)
#define debugchar(__char__) 	do { if(DEBUG) putchar(__char__); } while(0)

#define DEBUG 		1
#define NOINJECT 	0

size_t align(size_t size)
{
	if(size % sizeof(long) == 0)
		return size;
	else
		return size + sizeof(long) - (size % sizeof(long));
}

int poke(pid_t pid, unsigned char *payload, uint8_t *rip, size_t len)
{
	uint64_t	padded = align(len);

	unsigned long 	data;
	unsigned char 	buf[padded];

	memset(buf, 0, sizeof(buf));
	memcpy(buf, payload, len);

	debugf("orig %lu\n", len);
	debugf("padded %lu\n", padded);

	for(size_t i = 0; i < len; i += sizeof(data)) {
		data = *(unsigned long *) (buf + i);
		ptrace(PTRACE_POKETEXT, pid, rip + i, data);
	}

	derror("PTRACE_POKETEXT");
	debugchar('\n');

	return errno;
}

int back(pid_t pid, unsigned char *store, uint8_t *rip, size_t len)
{
	unsigned long	data;

	for(size_t i = 0; i < len; i += sizeof(data)) {
		data = ptrace(PTRACE_PEEKTEXT, pid, rip + i, NULL);
		*(long *) (store + i) = data;
	}

	return errno;
}

int peek(pid_t pid, uint8_t *rip, size_t count)
{
	long data;

	for(size_t i = 0; i < count; i += sizeof(data)) {
		data = ptrace(PTRACE_PEEKTEXT, pid, rip + i, NULL);

		debugf("%p:", rip + i);

		for(size_t x = 0; x < sizeof(data) * 8; x += 8) {
			debugf(" %02lx", (data >> x) & 0xff);
		}
		debugchar('\n');
	}
	derror("PTRACE_PEEKTEXT");
	debugchar('\n');

	return errno;
}

int main(void)
{
	unsigned char payload[] =
		"\x55\x48\x89\xe5\x48\x83\xec\x10"
		"\x48\xc7\xc0\x01\x00\x00\x00\x48"
		"\xc7\xc7\x01\x00\x00\x00\x48\xbe"
		"\x48\x65\x6c\x6c\x6f\x0a\x00\x00"
		"\x48\x89\x75\xf8\x48\x8d\x75\xf8"
		"\x48\xc7\xc2\x06\x00\x00\x00\x0f"
		"\x05\x48\x89\xec\x5d\xcc";

	unsigned char store[align(sizeof(payload) - 1)]; // original bytes storage

	pid_t 	pid;
	void 	*rip;
	struct 	user_regs_struct regs;

	pid = fork();

	if(pid == 0) {
		for(int i = 0; i < 15; i++) {
			sleep(1);
			puts("sleeping...");
		}
	} else {
		if(NOINJECT)
			return 0;

		sleep(5);

		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		derror("PTRACE_ATTACH");

		waitpid(pid, NULL, 0);

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		derror("PTRACE_GETREGS");
		debugchar('\n');

		rip = (void*) regs.rip;

		debugf("pid %d rip %p\n", pid, rip);

		back(pid, store, rip, sizeof(store));

		peek(pid, rip, sizeof(payload));
		poke(pid, payload, rip, sizeof(payload) - 1);
		peek(pid, rip, sizeof(payload));

		ptrace(PTRACE_CONT, pid, NULL, NULL);
		derror("SIGCONT");

		waitpid(pid, NULL, 0);

		poke(pid, store, rip, sizeof(store));
		peek(pid, rip, sizeof(payload));

		ptrace(PTRACE_SETREGS, pid, NULL, &regs);

		ptrace(PTRACE_CONT, pid, NULL, NULL);
		derror("SIGCONT");

		waitpid(pid, NULL, 0);

	}

	return 0;
}
