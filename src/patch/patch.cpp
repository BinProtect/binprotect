#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>

/* TEST */
#include <link.h>
/* TEST END */

using namespace std;

#define NAME_LIBC_SO			"libc.so"
#define GLIBC_CANARY_DISTANCE	12

static char libc[255];
static int dyninstSegmSize = 0;

/* printf related */
int (*orig_printf)(__const char *__restrict __format, ...);
int (*orig_fprintf)(FILE *__restrict __stream, __const char *__restrict __format, ...);
int (*orig_puts)(__const char *__s);
int (*orig_fputs)(__const char *__restrict __s, FILE *__restrict __stream);

/* strcpy related */
char (*orig_strcpy)(char *dest, const char *src);


inline void die(const char* msg)
{
	orig_printf("[BINPROTECT] .:: %s: Aborting execution ::.\n", msg);
	exit(EXIT_FAILURE);
}

#if 0
//int orig_puts(__const char *__s) { return 0; }
int bp_puts(__const char *__s)
{
	int ret;

	ret = orig_puts(__s);
	/*orig_*/puts("[PATCHED PRINT] congratulations, you have been successfully patched (puts)!!\n");

	return ret;
}

//int orig_fputs(__const char *__restrict __s, FILE *__restrict __stream) { return 0; }
int bp_fputs (__const char *__restrict __s, FILE *__restrict __stream)
{
	int ret;

	ret = orig_fputs(__s, __stream);
	orig_fputs("[PATCHED PRINT] congratulations, you have been successfully patched (fputs)!!\n", __stream);

	return ret;
}

//int orig_printf(__const char *__restrict __format, ...) { return 0; }
int bp_printf(__const char *__restrict __format, ...)
{
	va_list arg;
	int ret;

	va_start(arg, __format);

	ret = vprintf(__format, arg);
	orig_printf(__format, arg);
	orig_printf("[PATCHED PRINT] congratulations, you have been successfully patched (printf)!!\n");
	puts("HELLO \n");
	va_end(arg);

	return ret;
}

//int orig_fprintf (FILE *__restrict __stream, __const char *__restrict __format, ...) { return 0; }
int bp_fprintf (FILE *__restrict __stream, __const char *__restrict __format, ...)
{
	va_list arg;
	int ret;

	va_start(arg, __format);

	ret = vprintf(__format, arg);
	orig_fprintf(__stream, __format, arg);
	orig_printf("[PATCHED PRINT] congratulations, you have been successfully patched (fprintf)!!\n");

	va_end(arg);

	return ret;
}
#endif

/******************************************************************************
 ** printf related functions
 */

int printf(__const char *__restrict __format, ...)
{
	va_list arg;
	int ret;

	va_start(arg, __format);

	ret = vprintf(__format, arg);
	orig_printf("[INTERCEPT PRINTF] congratulations, you have been successfully patched!!\n");

	va_end(arg);

	return ret;
}

int fprintf(FILE *__restrict __stream, __const char *__restrict __format, ...)
{
	va_list arg;
	int ret;

	va_start(arg, __format);

	ret = vfprintf(__stream, __format, arg);
	orig_fprintf(__stream, "[PATCHED FPRINT] congratulations, you have been successfully patched!!\n");

	va_end(arg);

	return ret;
}

int puts(__const char *__s)
{
	int ret;

	ret = orig_puts(__s);
	orig_printf("[INTERCEPT PUTS] congratulations, you have been successfully patched!!\n");

	return ret;
}

int fputs(__const char *__restrict __s, FILE *__restrict __stream)
{
	int ret;

	ret = orig_fputs(__s, __stream);
	orig_fputs("[PATCHED FPUTS] congratulations, you have been successfully patched!!\n", __stream);

	return ret;
}

/******************************************************************************
 ** strcpy related functions
 */

//char *bp_strcpy(char *dest, const char *src) {
//	return strcpy(dest, src);
//}
char *strcpy(char *dest, const char *src)
{
	size_t maxLen = 0;
	size_t srcLen = 0;
	volatile long *reg_ebp;

	__asm__ volatile ("movl %%ebp, %[reg_ebp]" : /* output */ [reg_ebp] "=r" (reg_ebp));
	orig_printf("[INTERCEPT STRCPY] Address of EBP is %p\n", reg_ebp);

sleep(15);
	/* strcpy() to stack: address of dest buffer _must_ be smaller than the address of the
	 * base pointer of the associated stack frame. If this is not the case
	 * unroll the stack frames to find the appropriate stack frame and
	 * subsequently determine the maximum allowed buffer size */
	srcLen = strlen(src);
	while ((long)dest > (long)reg_ebp) {
		orig_printf("[INTERCEPT STRCPY] Address of EBP is %p -> %p\n", reg_ebp, *reg_ebp);
		reg_ebp = (long*)(*reg_ebp);

		if (reg_ebp == NULL) {
			/* address on the heap? */
			orig_printf("heap\n");

			memcpy((void*)dest, (void*)src, srcLen);
			dest[srcLen-1] = '\0';

			return dest;
		}
	}
//	orig_printf("[INTERCEPT STRCPY] Address of EBP is %p\n", reg_ebp);

//	srcLen = strlen(src);
	maxLen = (size_t)((size_t)reg_ebp - (size_t)dest);
	maxLen -= GLIBC_CANARY_DISTANCE; // optional: stack space required for canary is fixed atm

//	maxLen = (maxLen < srcLen) ? maxLen : srcLen;

	if (maxLen < srcLen) {
		die("Overflow in strcpy()");
	}

	orig_printf("[INTERCEPT STRCPY] max buffer size (maxlen=%lu): %lu\n", (unsigned long)maxLen, (unsigned long)maxLen);

	memcpy((void*)dest, (void*)src, srcLen/*maxLen*/);

	/* if srcLen > maxLen, then the last byte needs to be terminated */
//	dest[srcLen/*maxLen*/-1] = '\0';
orig_printf("stack\n");
	return dest;
}

/******************************************************************************
 ** __init and __fini related functions
 */

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;

	/* find the name of the used libc version */
	for (j = 0; j < info->dlpi_phnum; j++) {
		string libName(info->dlpi_name);

		if (libName.find(NAME_LIBC_SO, 1) != string::npos) {
			strncpy(libc, info->dlpi_name, strlen(info->dlpi_name));
//			break;
		}

		if (info->dlpi_phdr[j].p_vaddr == 0x08100000) {
			dyninstSegmSize = info->dlpi_phdr[j].p_memsz;
		}
	}

	return 0;
}

/**
 * _init/_fini functions are part of ELF files. The code within these functions
 * is executed by the loader or dynamic-linker. In contrast, .ctors/.dtors
 * that means code that is declared with the appropriate ctors/dtors attribute
 * (__attribute__((constructor))/((destructor))), requires support by the utilized
 * linker/loader. So, one cannot be sure that code with the ctors/dtors attribute
 * will be actually executed before main -- embedded systems may lack support for
 * ctors/dtors.
 */
void orig__init() {}
void bp__init()
{
	void *handle;
	char *error;

	dl_iterate_phdr(callback, NULL);

	/* resolve the original printf */
	handle = dlopen(libc, /*RTLD_LAZY*/RTLD_NOW);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	dlerror();

	*(void**)(&orig_printf) = dlsym(handle, "printf");
	*(void**)(&orig_fprintf) = dlsym(handle, "fprintf");
	*(void**)(&orig_puts) = dlsym(handle, "puts");
	*(void**)(&orig_fputs) = dlsym(handle, "fputs");
	*(void**)(&orig_strcpy) = dlsym(handle, "strcpy");

	if ((error = dlerror()) != NULL)  {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	orig_printf("[PATCHED INIT  ] symbols resolved.\n");

	int size = sysconf(_SC_PAGE_SIZE);

	/* BinProtect allocates PAGESIZE bytes for the shadow stack:
	 * we mark this region as RW. 
	 *
	 * TODO: we do not yet consider the size of the remaining part of
	 * this segment, which should be remapped as RE */
	if (mprotect((void*)0x08100000, size, PROT_READ|PROT_WRITE)) {
		perror("[PATCHED INIT  ] cannot remap memory at 0x08100000.");
	} else {
//		int *remDyninstSegmSize = (int*)0x08100000;
		if (dyninstSegmSize) { //  *remDyninstSegmSize != (int)0xDeadD00D) {
			int numPages = (dyninstSegmSize / sysconf(_SC_PAGE_SIZE)) + 1;
			size = (numPages-1) * sysconf(_SC_PAGE_SIZE);

			/* mark the remaining size of the segment provided by Dyninst as RE */
			if (mprotect((void*)0x08101000, size, PROT_READ|PROT_EXEC)) {
				perror("[PATCHED INIT  ] cannot remap memory at 0x08101000.");
			}
		}
	}

	/* BinProtect relocated the section .got.plt to the address 0x08200000,
	 * we mark this region as RE */
	size = sysconf(_SC_PAGE_SIZE);
	if (mprotect((void*)0x08200000, size, PROT_READ|PROT_EXEC)) {
		perror("[PATCHED INIT  ] cannot remap memory at 0x08200000.");
	}

	orig_printf("[PATCHED INIT  ] remapping memory.\n");

	dlclose(handle);
}

void orig__fini() {}
void bp__fini()
{
	orig_printf("[PATCHED FINI    ] done.\n");
	orig__fini();
}
