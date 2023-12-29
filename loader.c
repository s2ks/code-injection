#define _GNU_SOURCE //for environ declaration

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <assert.h>
#include <errno.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <unistd.h>

#define jump_if(__cond__, __label__) if(__cond__) goto __label__
#define jump_unless(__cond__, __label__) if(!(__cond__)) goto __label__

#define derror(__str__) if(DEBUG) perror(__str__)
#define	debugf(...) 	if(DEBUG) printf(__VA_ARGS__)

#define DEBUG	1

size_t align(size_t size);

static const unsigned char payload[] =
	"\x55\x48\x89\xe5\x48\x83\xec\x10"
	"\x48\xc7\xc0\x01\x00\x00\x00\x48"
	"\xc7\xc7\x01\x00\x00\x00\x48\xbe"
	"\x48\x65\x6c\x6c\x6f\x0a\x00\x00"
	"\x48\x89\x75\xf8\x48\x8d\x75\xf8"
	"\x48\xc7\xc2\x06\x00\x00\x00\x0f"
	"\x05\x48\x89\xec\x5d\xcc";


size_t align(size_t size)
{
	if(size % sizeof(long) == 0)
		return size;
	else
		return size + sizeof(long) - (size % sizeof(long));
}

int poke(pid_t pid, uint8_t *rip, const unsigned char *payload, size_t len)
{
	uint64_t	padded = align(len);

	unsigned long	data;
	unsigned char	buf[padded];

	memset(buf, 0, sizeof(buf));
	memcpy(buf, payload, len);

	for(size_t i = 0; i < len; i += sizeof(data)) {
		data = *(unsigned long *) (buf + i);
		ptrace(PTRACE_POKETEXT, pid, rip + i, data);
	}

	return errno;
}

int peek(pid_t pid, uint8_t *rip, size_t len)
{
	if(DEBUG)
		return 0;

	long data;

	for(size_t i = 0; i < len; i += sizeof(long)) {
		data = ptrace(PTRACE_PEEKTEXT, pid, rip + i, NULL);

		printf("%p:", rip + i);

		for(size_t x = 0; x < sizeof(data) * 8; x += 8)
			printf(" %02lx", (data >> x) & 0xff);

		printf("\n");
	}

	return errno;
}

/* NOTE: this function *HAS* to set errno to 0 to check for errors
 * blame ptrace for this feature */
int back(pid_t pid, uint8_t *rip, unsigned char *store, size_t size)
{
	int 	stat = 0;
	long 	data;

	jump_unless(size % sizeof(long) == 0, alignerr);

	for(size_t i = 0; i < size; i += sizeof(long)) {
		errno = 0;
		data = ptrace(PTRACE_PEEKTEXT, pid, rip + i, NULL);
		jump_if(errno != 0, err);

		*(long *) (store + i) = data;
	}

	goto ret;

alignerr:
	debugf("store needs to be properly aligned\n");
	return -1;
err:
	stat = -1;
ret:
	return stat;
}

int main(void)
{
	int pid;
	int stat = 0;
	int fds[2];

	unsigned char store[align(sizeof(payload) - 1)];
	struct user_regs_struct regs;

	char *cmd = "./target";

	char *const args[] = {cmd, NULL};

	stat = pipe(fds);
	jump_unless(stat == 0, err);

	pid = fork();
	jump_if(pid == -1, err);

	if(pid == 0) {
		/* close pipe on exec */
		stat = fcntl(fds[1], F_GETFD);
		stat |= FD_CLOEXEC;
		stat = fcntl(fds[1], F_SETFD, stat);

		jump_if(stat == -1, err);

		close(fds[0]);

		/* does not return on success */
		execve(cmd, args, environ);

		/* write errno to parent */
		write(fds[1], &errno, sizeof(errno));
	} else {
		close(fds[1]);
		/* If the pipe closed we get 0 otherwise we get errno */
		read(fds[0], &errno, sizeof(errno));
		derror("execve");
		jump_unless(errno == 0, err);

		/* attach and interrupt */
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		derror("PTRACE_ATTACH");

		waitpid(pid, NULL, 0);

		/* save GPRs */
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		derror("PTRACE_GETREGS");
		debugf("\n");

		/* display original code */
		stat = peek(pid, (void *) regs.rip, sizeof(payload) - 1);
		jump_if(stat != 0, err);
		putchar('\n');

		/* save code */
		stat = back(pid, (void *) regs.rip, store, sizeof(store));
		jump_if(stat != 0, err);

		/* inject */
		stat = poke(pid, (void *) regs.rip, payload, sizeof(payload));
		derror("INJECT");
		jump_if(stat != 0, err);

		/* execute */
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		derror("SIGCONT");

		/* wait for interrupt */
		stat = waitpid(pid, NULL, 0);
		derror("WAIT");
		jump_unless(stat == pid, err);

		/* restore */
		stat = poke(pid, (void *) regs.rip, store, sizeof(store));
		derror("RESTORE CODE");

		/* restore GPRs */
		ptrace(PTRACE_SETREGS, pid, NULL, &regs);
		derror("RESTORE GPRs");

		/* resume tracee */
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		derror("DETACH");


	}

	goto ret;

err:
	stat = -1;
ret:
	perror("loader");

	//Is this necessary?
	if(pid == 0)
		close(fds[1]);
	else if(pid > 0)
		close(fds[0]);
	else {
		close(fds[0]);
		close(fds[1]);
	}

	perror("close");

	return stat;
}
