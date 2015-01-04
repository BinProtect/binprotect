/*
 * ElfInject.h
 *
 *  Created on: Dec 17, 2014
 *      Author: sergej
 */

#ifndef ELFINJECT_H_
#define ELFINJECT_H_

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <iostream>

#include <Logging.h>

#define LABEL_ELFINJECT   	"ELFINJECT"
#define SH_NAME_DYNSTR		".dynstr"
#define SH_NAME_STRTAB		".strtab"
#define SH_NAME_SHSTRTAB	".shstrtab"
#define SH_NAME_GOTPLT		".got.plt"
#define SH_NAME_GOT			".got"
#define SH_NAME_PLT			".plt"
#define SH_NAME_RELPLT		".rel.plt"
#define SH_NAME_RELDYN		".rel.dyn"

#define PAGESIZE			0x1000
#define INVALID_PH			0xBadD00D
#define INVALID_SH			0xBadD00D

#define PH_LOAD_ADDR		0x08200000

using namespace std;

static inline void hexdump(unsigned char *mem, size_t size)
{
	printf("Hexdump: @mem  = %p\n", mem);
	printf("Hexdump: @size = 0x%x\n", size);

	for (size_t i=0; i<size; i++) {
		if ((i%0x10) == 0) {
			if (i) {
				printf("\n  %04x ", i);
			} else {
				printf("  %04x ", i);
			}
		}
		printf("%02X ", (unsigned char)(mem[i]));
	}
	printf("\n");
}

class ElfInject {
private:
	typedef struct elfBin_str {
	    int fd;
	    string name;
	    struct stat stats;
	    char *basePtr;

	    Elf *elf;
	    Elf *elfMem;
	    GElf_Ehdr *elfHdr;

	    size_t shSymtabIndex;		/* symtab */
	    size_t shStrtabIndex;		/* section header symtab */

	    size_t shDynamicIndex;
	    size_t shDynsymIndex; 		/* dynamic symtab */
	    size_t shDynstrIndex;		/* dynamic strtab */

	    size_t shGotPltIndex;
	    size_t shGotIndex;

	    size_t shRelPltIndex;
	    size_t shRelDynIndex;
	    size_t shPltIndex;

	    /* program header information */
	    size_t phPhdrIndex;
	    size_t phDynamicIndex;
	    size_t phGnuStackIndex;
	    size_t phGnuRelroIndex;
	    size_t phLoadTextIndex;
		size_t phLoadDataIndex;

	    size_t sizeGotPlt;
	    size_t sizeGot;
	} elfBin_t;

	elfBin_t bin;

    /* signalize that the ELF file has been resized */
    bool elfRemapped;

public:

private:
    /* initialization */
	int prepareElfBin();
	int collectPHInfo();
	int collectSHInfo();

	/* stack */
	void injectGNUStackPH();
	void modifyGNUStackPH();

	/* relro */
	void injectGNURelroPH();
	void modifyGNURelroPH(Elf *elf);

	/* misc */
	void remapElf();
	Elf* resizeElf(Elf64_Half resizeOffset);
	void updateEHOffset(Elf *elf, Elf64_Half resizeOffset);
	void updatePHOffset(Elf *elf, Elf64_Half resizeOffset);
	void updatePHOffset_DataSegment(Elf *elf, Elf64_Half resizeOffset);
	void updateSHOffset(Elf *elf, Elf64_Half resizeOffset);

	Elf32_Shdr* mem_getAddrSH(Elf *elf, size_t shIndex);
	void mem_moveElf(char *dest, char *src, size_t size);
	char *mem_getSymName(Elf *elf, size_t index);
	Elf32_Shdr* mem_newSH(Elf32_Addr addr);

/* TEST */
	void deleteGotPltSym();
	void relocateGOT();
	void relocatePLT(size_t relCount, size_t relOffset);
	void injectLoadPH(Elf32_Off fileOff, Elf32_Addr virtAddr, size_t size);
	void modifyDynamicPH();

	void sortLoadPH(Elf *elf);
	Elf32_Shdr* sortSHTable(Elf *elf, Elf32_Addr addr);
	void reorderPH(Elf* elf, size_t fromIndex, size_t toIndex);
/* TEST END */

	/* debugging */
	void inspectDynsymSection(Elf *elf);
	void inspectSectionDynamic(Elf *elf);
	void inspectSectionHeaders(Elf *elf);
	void inspectProgramHeaders(Elf *elf);
	void disableGnuStack(Elf *elf);

public:
	ElfInject() =  delete;
	ElfInject(string binName);
	~ElfInject();

	/* initialization */
	void init();
	void finish();

	/* fortify source */
	void reorderDynLibraries();
	void removeDyninstLib();

	/* stack */
	void fortifyStack();

	/* relro */
	void fortifyGOT();

};

#endif /* ELFINJECT_H_ */
