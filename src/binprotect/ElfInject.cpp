/*
 * ElfInject.cpp
 *
 *  Created on: Dec 17, 2014
 *      Author: sergej
 */

#include "ElfInject.h"



ElfInject::ElfInject(string binName)
{
	bin.name = binName;
	bin.basePtr = NULL;

	bin.phGnuRelroIndex = INVALID_PH;
	bin.phGnuStackIndex = INVALID_PH;
	bin.phDynamicIndex = INVALID_PH;

	bin.shDynamicIndex = INVALID_SH;
	bin.shDynstrIndex = INVALID_SH;
	bin.shDynsymIndex = INVALID_SH;
	bin.shGotIndex = INVALID_SH;
	bin.shGotPltIndex = INVALID_SH;
	bin.shStrtabIndex = INVALID_SH;
	bin.shSymtabIndex = INVALID_SH;
	bin.shRelPltIndex = INVALID_SH;
	bin.shRelDynIndex = INVALID_SH;
	bin.shPltIndex = INVALID_SH;

	bin.sizeGotPlt = 0;
	bin.sizeGot = 0;

	elfRemapped = false;
}



ElfInject::~ElfInject()
{
	/* close elf descriptor */
	elf_end(bin.elf);

	if (bin.basePtr != NULL) {
		/* close elf memory descriptor */
		elf_end(bin.elfMem);

		/* write ELF file back to file */
		if (lseek(bin.fd, 0, SEEK_SET) != 0) {
			error("error lseek");
			return;
		}

		if (write(bin.fd, bin.basePtr, bin.stats.st_size) != bin.stats.st_size) {
			error("error write");
			return;
		}
	}

	close(bin.fd);

	if (bin.basePtr) {
		free(bin.basePtr);
	}
}


/******************************************************************************
 **  initialization
 */

void
ElfInject::init()
{
	info(" ");
	info(".:: initialize ElfInject ::.");
	info(" ");

    prepareElfBin();
    collectPHInfo();
    collectSHInfo();
}

void
ElfInject::finish()
{
	info("finish ELF transformation");

	if (bin.elfMem) {
		sortLoadPH(bin.elfMem);
	}
}

/**
 * perform checks on the initial ELF binary and create an ELF descriptor
 * to perform direct manipulations within the file.
 */
int
ElfInject::prepareElfBin()
{
	info("prepare ELF binary: %s", bin.name.c_str());

	/* open binary file */
	bin.fd = open(bin.name.c_str(), O_RDWR, S_IRWXU);
	if (bin.fd < 0) {
		error("cannot open %s", bin.name.c_str());
		return -1;
	}

	/* fstat binary */
	if (fstat(bin.fd, &bin.stats)) {
		error("cannot fstat %s", bin.name.c_str());
		return -1;
	}

	/* initialize ELF library */
	if(elf_version(EV_CURRENT) == EV_NONE ) {
		error("ELF library initialization failed");
		return -1;
	}

	/* create elf descriptor */
	if ((bin.elf = elf_begin(bin.fd, ELF_C_RDWR_MMAP, NULL)) == NULL) {
		error("cannot initialize elf");
		return -1;
	}

	/* check, whether the file is an ELF-file */
	if (elf_kind(bin.elf) != ELF_K_ELF) {
		error("%s is not an ELF file", bin.name.c_str());
		return -1;
	}
	debug("° correct ELF type");

	if (gelf_getclass(bin.elf) != ELFCLASS32) {
		error("%s is not a 32-bit binary", bin.name.c_str());
		return -1;
	}
	debug("° compiled for 32-bit systems");

	/* allocate space for binary */
//	if ((bin.basePtr = (char*)malloc(bin.stats.st_size)) == NULL) {
//		error("cannot allocate enough memory" << lend ;
//	}

	/* create elf descriptor for mem region */
//	if ((bin.elfMem = elf_memory(bin.basePtr, bin.stats.st_size)) == NULL) {;
//		error("cannot initialize elfMem");
//	}

	return 0;
}


/**
 * parse initial ELF file and collect essential program header information
 */
int
ElfInject::collectPHInfo() {
	size_t phCount;
	GElf_Phdr phdr;

	info("collect program header information");

	if (elf_getphdrnum(bin.elf, &phCount) != 0) {
		error("cannot extract program header information");
		return -1;
	}

	for (size_t i=0; i<phCount; i++) {
		if (gelf_getphdr(bin.elf, i, &phdr) != &phdr) {
			error("cannot extract program header nr %d", i);
			return -1;
		}

		switch (phdr.p_type) {
		case PT_PHDR:
			bin.phPhdrIndex = i;
			debug("° program header PHDR: %d", i);
			break;
		case PT_DYNAMIC:
			bin.phDynamicIndex = i;
			debug("° program header DYNAMIC: %d", i);
			break;
		case PT_LOAD:
			if (!phdr.p_offset) {
				/* text segment */
				bin.phLoadTextIndex = i;
				debug("° program header LOAD (.text): %d", i);
			} else if (!(phdr.p_flags & PF_X)) {
				/* data segment */
				bin.phLoadDataIndex = i;
				debug("° program header LOAD (.data): %d", i);
			}
			break;
		case PT_GNU_STACK:
			bin.phGnuStackIndex = i;
			debug("° program header GNU_STACK: %d", i);
			break;
		case PT_GNU_RELRO:
			bin.phGnuRelroIndex = i;
			debug("° program header GNU_RELRO: %d", i);
			break;
		default:
			/* do nothing */
			break;
		}
	}

	return 0;
}

/**
 * parse initial ELF file and collect essential section header information
 */
int
ElfInject::collectSHInfo() {
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	GElf_Shdr tmpShdr;
	char *symName = NULL;

	info("collect section header information");

	/* initialize important sections */

	elf_getshdrstrndx(bin.elf, &bin.shStrtabIndex);
	debug("° section .shstrtab: %d", bin.shStrtabIndex);

	while((scn = elf_nextscn(bin.elf, scn)) != NULL) {
		/* get section header */
		gelf_getshdr(scn, &shdr);

		switch(shdr.sh_type) {
		case SHT_SYMTAB:
			bin.shSymtabIndex = elf_ndxscn(scn);
			debug("° section .symtab: %d", bin.shSymtabIndex);
			break;
		case SHT_DYNAMIC:
			bin.shDynamicIndex = elf_ndxscn(scn);
			debug("° section .dyntab: %d", bin.shDynamicIndex);
			break;
		case SHT_STRTAB:
			gelf_getshdr(scn, &tmpShdr);
			symName = elf_strptr(bin.elf, bin.shStrtabIndex, tmpShdr.sh_name);

			if (!strcmp(symName, SH_NAME_DYNSTR)) {
				bin.shDynstrIndex = elf_ndxscn(scn);
				debug("° section .dynstr: %d", bin.shDynstrIndex);
			} else if (!strcmp(symName, SH_NAME_STRTAB)) {
				bin.shStrtabIndex = elf_ndxscn(scn);
				debug("° section .strtab: %d", bin.shStrtabIndex);
			}
			break;
		case SHT_DYNSYM:
			bin.shDynsymIndex = elf_ndxscn(scn);
			debug("° section .dynsym: %d", bin.shDynsymIndex);
			break;
		case SHT_PROGBITS:
			gelf_getshdr(scn, &tmpShdr);
			symName = elf_strptr(bin.elf, bin.shStrtabIndex, tmpShdr.sh_name);

			if (!strcmp(symName, SH_NAME_PLT)) {
				bin.shPltIndex = elf_ndxscn(scn);
				debug("° section .plt: %d", bin.shPltIndex);
			} else if (!strcmp(symName, SH_NAME_GOTPLT)) {
				bin.shGotPltIndex = elf_ndxscn(scn);
				bin.sizeGotPlt = tmpShdr.sh_size;
				debug("° section .got.plt: %d (size: %d)", bin.shGotPltIndex, bin.sizeGotPlt);
			} else if (!strcmp(symName, SH_NAME_GOT)) {
				bin.shGotIndex = elf_ndxscn(scn);
				bin.sizeGot = tmpShdr.sh_size;
				debug("° section .got: %d (size: %d)", bin.shGotIndex, bin.sizeGot);
			}
			break;
		case SHT_REL:
			gelf_getshdr(scn, &tmpShdr);
			symName = elf_strptr(bin.elf, bin.shStrtabIndex, tmpShdr.sh_name);

			if (!strcmp(symName, SH_NAME_RELPLT)) {
				bin.shRelPltIndex = elf_ndxscn(scn);
				debug("° section .rel.plt: %d", bin.shRelPltIndex);
			} else if (!strcmp(symName, SH_NAME_RELDYN)) {
				bin.shRelDynIndex = elf_ndxscn(scn);
				debug("° section .rel.dyn: %d", bin.shRelDynIndex);
			}
			break;
		default:
			/* do nothing */
			break;
		}
	}

	if(!bin.shSymtabIndex) {
		error("cannot find section .symtab");
		return -1;
	}

	return 0;
}



/******************************************************************************
 ** fortify GOT
 */

void
ElfInject::fortifyGOT()
{
	info("fortify GOT");

	/* perform GOT related transformation in memory -- not on the file */
	remapElf();

	/* NOTE: the current implementation assumes 'partial RELRO' to transform
	 * into 'full RELRO'. To be able to transform no RELRO to full RELRO the
	 * .dynamic section needs to be moved addresses inside of the .text segment
	 * need to be adopted. */
	if (bin.phGnuRelroIndex == INVALID_PH) {
#if 0
		injectGNURelroPH();
#endif

		error("no partial RELRO: abort fortifying GOT");
		return;
	}

	modifyGNURelroPH(bin.elfMem);
}


void
ElfInject::modifyGNURelroPH(Elf *elf)
{
	Elf32_Shdr *shdr;
	size_t resizeOffset;


	info("° modify PT_GNU_RELRO program header");

	/* NOTE: here, we _do not_ make use of libelf - so the following is
	 * architecture dependent
	 *
	 *  -> cannot explain why libelf' cannot be used after copying elf file
	 *  into memory */

	/* we need two additional entries of type Elf32_Dyn */
	resizeOffset = 2 * sizeof(Elf32_Dyn);

	/* locate memory address of .dynamic section in memory and adopt its size*/
	shdr = mem_getAddrSH(elf, bin.shDynamicIndex);
	shdr->sh_size += resizeOffset;


	info("° resize ELF binary in memory by %d bytes", resizeOffset);

	/* determine appropriate position for our dyn entry: include a dynamic symbol
	 * either before any of the flags containing a tag of the form 0x6fxxxxxx or
	 * at the end of the list*/

	/* .dynamic section start address in mem */
	Elf32_Dyn *dyn = (Elf32_Dyn*)(bin.basePtr + shdr->sh_offset);
	for ( ; (void*)dyn->d_tag != NULL; dyn++) {
		if (dyn->d_tag >= 0x6ffffffc) {
			/* found it */
			break;
		}
/* TEST */
#if 0
		/* TODO: .dynamic section entry: change to start of .got */
		if (dyn->d_tag == DT_PLTGOT) {
			log << "PLTGOT HERE");
			dyn->d_un.d_ptr = PH_LOAD_ADDR; // 0x08049fe0; // 0x08049fdc;
		}
		if (dyn->d_tag == DT_INIT_ARRAY) {
			dyn->d_un.d_ptr -= 0x30;
		}
		if (dyn->d_tag == DT_FINI_ARRAY) {
			dyn->d_un.d_ptr -= 0x30;
		}
#endif
/* TEST END */
	}

	/* determine offsets for ELF transformation */
	char *memOffsetFrom = (char*)dyn;
	char *memOffsetTo = (char*)((long)(dyn) + resizeOffset);
	size_t memCopySize = bin.stats.st_size - ((long)memOffsetFrom - (long)bin.basePtr);

	/* move parts of the ELF file in memory */
	mem_moveElf(memOffsetTo, memOffsetFrom, memCopySize);

	/* TODO: we have allocated more space than needed, introduce a check for remaining mem */
	bin.stats.st_size += resizeOffset;
	elf = elf_memory(bin.basePtr, bin.stats.st_size);

	info("° insert dynamic symbols 'DT_BIND_NOW' and 'DT_FLAGS_1'");

	/* insert new dynamic section entries */

	dyn->d_tag = DT_BIND_NOW;
	dyn->d_un.d_val = DF_BIND_NOW;

	dyn++;
	dyn->d_tag = DT_FLAGS_1;
	dyn->d_un.d_val = DF_1_NOW;

	/* update ELF header and affected program headers */

	updateEHOffset(elf, resizeOffset);
	updatePHOffset_DataSegment(elf, resizeOffset);

	/* update affected shdr offsets (after section .dynamic) */

	size_t shCount;
	elf_getshdrnum(elf, &shCount);

	shdr = mem_getAddrSH(elf, bin.shDynamicIndex);
	shdr++;

	for (size_t i=bin.shDynamicIndex+1; i<shCount; i++, shdr++) {
		if (shdr->sh_offset) {
			shdr->sh_offset += resizeOffset;
		}
	}

	/* update GOT related parts of ELF fo enalbe full RELRO */
#if 0
	/* update size of .got section: therefore, we simply add the size of the .plt.got section */
	shdr = mem_getAddrSH(elf, bin.shGotIndex);
	shdr->sh_size += bin.sizeGotPlt;

debug("NEW RELRO SIZE: " << shdr->sh_size);
#endif
	/* enable relocation read-only (full RELRO) of dynamically linked libraries */
	if (bin.shGotPltIndex) {
		relocateGOT();
	}
}

/**
 * we need to update the file and memory size of the affected program headers
 * after inserting flags (DT_BIND_NOW and DT_FLAGS_1) into the dynamic section.
 *
 * The affected program headers are PT_DYNAMIC and PT_LOAD, where the .dynamic
 * section is mapped to.
 */
void
ElfInject::updatePHOffset_DataSegment(Elf *elf, Elf64_Half resizeOffset)
{
	size_t phCount;
	GElf_Phdr dynamic;
	GElf_Phdr phdr;

	long oldLBorder_Dynamic;
	long oldRBorder_Dynamic;
	long lBorder;
	long rBorder;

	/* update offset in program headers */

	info("° update offset of the data segment");

    if (elf_getphdrnum(elf, &phCount) != 0) {
        error("update offset of the data segment");
    }

    /* adopt dynamic program header */

    if (gelf_getphdr(elf, bin.phDynamicIndex, &dynamic) != &dynamic) {
		error("cannot extract program header nr %d", bin.phDynamicIndex);
	}

    oldLBorder_Dynamic = dynamic.p_offset;
    oldRBorder_Dynamic = oldLBorder_Dynamic + dynamic.p_filesz;

    debug("° increase size (file/mem) of DYNAMIC segment: %llu -> %llu",dynamic.p_filesz, (dynamic.p_filesz + resizeOffset));


    dynamic.p_filesz += resizeOffset;
    dynamic.p_memsz += resizeOffset;

	if (!gelf_update_phdr(elf, bin.phDynamicIndex, &dynamic)) {
		error("cannot insert program header");
	}

    /* find and adopt the file and memory size of the LOAD segment, where the dynamic
     * section is mapped to */

    for (size_t i=0; i<phCount; i++) {
		if (gelf_getphdr(elf, i, &phdr) != &phdr) {
			error("cannot extract program header nr %d", i);
		}

		switch (phdr.p_type) {
		case PT_LOAD:
//			if (phdr.p_offset != 0) {
			lBorder = phdr.p_offset;
			rBorder = lBorder + phdr.p_filesz;

			/* is dynamic section inside of this LOAD sement? */
			if ((lBorder <= oldLBorder_Dynamic) && (rBorder >= oldRBorder_Dynamic)) {
				/* data segment */
				debug("° increase size (file/mem) of LOAD segment: %llu -> %llu", phdr.p_filesz, (phdr.p_filesz + resizeOffset));

				phdr.p_filesz += resizeOffset;
				phdr.p_memsz += resizeOffset;
			}

			/* update only the modified program header */
			if (!gelf_update_phdr(elf, i, &phdr)) {
				error("cannot insert program header");
			}
			break;

//		case PT_DYNAMIC:
//			phdr.p_filesz += resizeOffset;
//			phdr.p_memsz += resizeOffset;
//			break;
//		case PT_GNU_RELRO:
//			phdr.p_filesz += resizeOffset; // + bin.sizeGotPlt;
//			phdr.p_memsz += resizeOffset; // + bin.sizeGotPlt;
//			break;

		default:
			/* do nothing */
			break;
		}
    }
}

void ElfInject::relocateGOT()
{
//	Elf32_Shdr *shGot = NULL;
	Elf32_Shdr *shGotPlt = NULL;
	Elf32_Shdr *shRelPlt = NULL;
//	Elf32_Shdr *shRelDyn = NULL;
	Elf32_Shdr *shSymtab = NULL;
	Elf32_Shdr *shDynamic = NULL;
	Elf32_Rel *rel = NULL;
	Elf32_Sym* sym = NULL;

	size_t phLoadSize = 0;
//	size_t oldAddrGot = 0;
	size_t oldAddrGotPlt = 0;

#if GOT
	/* section header .got */
	shGoit = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shGotIndex);
	phLoadSize = shGot->sh_size;
#endif
	if (bin.shGotPltIndex != INVALID_SH) {
		/* section header .got.plt */
		shGotPlt = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shGotPltIndex);
		phLoadSize += shGotPlt->sh_size;
	}
#if GOT
	injectLoadPH(shGot->sh_offset, phLoadSize);
#endif

	injectLoadPH(shGotPlt->sh_offset, PH_LOAD_ADDR, phLoadSize);

#if GOT
	/* relocate original .got */
	oldAddrGot = shGot->sh_addr;
	shGot->sh_addr = PH_LOAD_ADDR;
#endif

	if (shGotPlt) {
		/* relocate original .got.plt */
		oldAddrGotPlt = shGotPlt->sh_addr;
#if GOT
		shGotPlt->sh_addr = PH_LOAD_ADDR + shGot->sh_size;
#endif
		shGotPlt->sh_addr = PH_LOAD_ADDR;
	}

	/* relocate relocation entries in .rel.plt */
	shRelPlt = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shRelPltIndex);
	size_t relCount = (size_t)(shRelPlt->sh_size / shRelPlt->sh_entsize);

	size_t relPltOffset = 0x0c;
	rel = (Elf32_Rel*)(bin.basePtr + shRelPlt->sh_offset);

	for (size_t i=0; i<relCount; i++, rel++) {
		rel->r_offset = shGotPlt->sh_addr + relPltOffset + (i * 0x04);
	}
	relocatePLT(relCount, (shGotPlt->sh_addr - oldAddrGotPlt));

#if GOT
	/* TODO: relocate rel entries in .rel.dyn */

	/* relocate relocation entries in rel.dyn */
	shRelDyn = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shRelDynIndex);
	relCount = (size_t)(shRelDyn->sh_size / shRelDyn->sh_entsize);

	rel = (Elf32_Rel*)(bin.basePtr + shRelDyn->sh_offset);
	for (size_t i=0; i<relCount; i++, rel++) {
		rel->r_offset = shGot->sh_addr + (i * 0x04);
	}
#endif

	/* update symbols accordingly */

#if GOT
	/* symbol .got */
	sym = (Elf32_Sym*)(bin.basePtr + shSymtab->sh_offset + (22 * shSymtab->sh_entsize));
	debug("GOT SYM: " << sym->st_name;
	sym->st_value = shGot->sh_addr;
#endif

	/* adopt symbols .got.plt and .got */
	if (bin.shSymtabIndex != INVALID_SH) {
		/* symbol .got.plt */

		shSymtab = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shSymtabIndex);

		char *name = mem_getSymName(bin.elfMem, shGotPlt->sh_name);
		debug("° adopt value of symbol: %s", name);

		sym = (Elf32_Sym*)(bin.basePtr + shSymtab->sh_offset);
		size_t symCount = shSymtab->sh_size / shSymtab->sh_entsize;

		for (size_t i=0; i<symCount; i++, sym++) {

			if (sym->st_name == shGotPlt->sh_name) {
				debug("° adopt value of symbol [%zd]: %p -> %p", i, (void*)sym->st_value, (void*)shGotPlt->sh_addr);
				sym->st_value = shGotPlt->sh_addr;
			}
		}

		/* TODO: same for .got */
	}

	/* adopt dynamic table symbol DT_PLTGOT */
	shDynamic = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shDynamicIndex);
	Elf32_Dyn *dyn = (Elf32_Dyn*)(bin.basePtr + shDynamic->sh_offset);
	for ( ; (void*)dyn->d_tag != NULL; dyn++) {
		/* TODO: .dynamic section entry: change to start of .got */
		if (dyn->d_tag == DT_PLTGOT) {
			debug("° adopt value of dynamic symbol DT_PLTGOT: %p -> %p", (void*)dyn->d_un.d_ptr, (void*)PH_LOAD_ADDR);
			dyn->d_un.d_ptr = PH_LOAD_ADDR;
		}
	}
}

void ElfInject::relocatePLT(size_t relCount, size_t relOffset)
{
	/* rewrite code in section .plt */
	Elf32_Shdr *shPlt = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shPltIndex);
	unsigned char *plt = NULL;

	plt = (unsigned char*)(bin.basePtr + shPlt->sh_offset);
	debug("° PLT start addr (in binary): %p", (void*)((long)plt - (long)bin.basePtr));

	hexdump(plt, shPlt->sh_size);

	/* first two addresses of .plt are special */

	debug("° relocate entry in PLT: %p -> %p", (void*)(*(long*)(&plt[2])), (void*)(*(long*)(&plt[2]) + (long)relOffset));
	debug("° relocate entry in PLT: %p -> %p", (void*)(*(long*)(&plt[8])), (void*)(*(long*)(&plt[8]) + (long)relOffset));

	*(long*)(&plt[2]) += (long)relOffset;
	*(long*)(&plt[8]) += (long)relOffset;

	/* first plt relocation entry */
	size_t padOffset = 0x12;

	/* adopt relocation addresses of the section .plt */
	for (size_t i=0; i<relCount; i++) {
		size_t index = padOffset + (i*0x10);

		debug("° relocate entry in PLT: %p -> %p", (void*)(*(long*)(&plt[index])), (void*)(*(long*)(&plt[index]) + (long)relOffset));

		*(long*)(&plt[index]) += relOffset;
	}

//	hexdump(plt, shPlt->sh_size);
}


#if 0
/**
 * NOTE: at the moment, we do not inject a new RELRO header if it is not present.
 *
 * right now, we do not insert a new RELRO header, since it would require to adopt
 * not only the .dynamic section, but as well the addresses within the .data segment.
 *
 * TODO: check, whether we can do this with help of Dyninst
 * TODO: check size of RELRO stuff
 **/
void ElfInject::injectGNURelroPH()
{
	GElf_Ehdr ehdr;

	info("injecting PT_GNU_RELRO program header");

    /* adopt number of program headers in elf header */
	gelf_getehdr(bin.elfMem, &ehdr);

	ehdr.e_phnum += 1;

	if (!gelf_update_ehdr(bin.elfMem, &ehdr)) {
		error("cannot update elf header");
	}

    /* create a PT_GNU_RELRO program header */
	int phdrIndex = ehdr.e_phnum - 1;

	GElf_Phdr phdr;
	gelf_getphdr(bin.elfMem, phdrIndex, &phdr);

	GElf_Phdr phdrData;
	gelf_getphdr(bin.elfMem, bin.phLoadDataIndex, &phdrData);

	Elf32_Shdr *got = mem_getAddrSH(bin.elfMem, bin.shGotIndex);

	memset((void*)(&phdr), 0, sizeof(phdr));
	phdr.p_type = PT_GNU_RELRO;
	phdr.p_flags = PF_R;
	phdr.p_align = 0x1;
	phdr.p_offset = phdrData.p_offset;
	phdr.p_vaddr = phdrData.p_vaddr;
	phdr.p_paddr = phdrData.p_paddr;
	phdr.p_filesz = got->sh_addr + got->sh_size - phdrData.p_vaddr;
	phdr.p_memsz = phdr.p_filesz;

//	debug("TEST RELRO size (inject): " << hex << phdr.p_filesz);

	if (!gelf_update_phdr(bin.elfMem, phdrIndex, &phdr)) {
		error("cannot insert program header of type PT_GNU_STACK");
	}

	/* update offset in the program header of type PHDR */

	if (gelf_getphdr(bin.elfMem, bin.phPhdrIndex, &phdr) != &phdr) {
		error("cannot extract program header nr " << bin.phPhdrIndex);
	}

	phdr.p_filesz += ehdr.e_phentsize;
	phdr.p_memsz += ehdr.e_phentsize;

	if (!gelf_update_phdr(bin.elfMem, bin.phPhdrIndex, &phdr)) {
		error("cannot insert program header");
	}
}
#endif

#if 0
Elf32_Shdr* ElfInject::mem_newSH(Elf32_Addr addr)
{
	GElf_Ehdr ehdr;
	Elf32_Shdr *shdr;

	gelf_getehdr(bin.elfMem, &ehdr);

	bin.stats.st_size += ehdr.e_shentsize;
	ehdr.e_shnum += 1;

	if (!gelf_update_ehdr(bin.elfMem, &ehdr)) {
		error("cannot update elf header");
	}

	shdr = sortSHTable(bin.elfMem, addr);

	return shdr;
}


Elf32_Shdr* ElfInject::sortSHTable(Elf *elf, Elf32_Addr addr)
{
	GElf_Ehdr ehdr;
	Elf32_Shdr *shdr;
//	Elf32_Shdr *nextShdr;
	size_t countShdr;
	size_t shIndex = INVALID_SH;

	gelf_getehdr(elf, &ehdr);
	elf_getshdrnum(elf, &countShdr);

	shdr = mem_getAddrSH(bin.elfMem, 0);

	for (size_t i=0; i<countShdr; i++, shdr++) {
		if (shdr->sh_offset > addr) {
			debug("new section header at index: %d (of %d)", i, countShdr);
			shIndex = i;
			break;
		}
	}

/* TEST */
	shIndex = 26;
/* TEST END */

	if (shIndex != INVALID_SH) {
//		Elf32_Shdr sh;
//		char sh[sizeof(Elf32_Shdr)];
//
//		/* temporary store the next shdr */
//		shdr = mem_getAddrSH(bin.elfMem, shIndex+1);
//		memset((void*)&sh, 0, sizeof(Elf32_Shdr));
//		memcpy((void*)&sh, shdr, sizeof(Elf32_Shdr));
//
//		/* get address of current shdr */
//		shdr = mem_getAddrSH(bin.elfMem, shIndex);

		/* sort section headers */
//		for (size_t i=shIndex+1; i<=countShdr; i++, shdr++) {
		for (size_t i=countShdr-1; i>=shIndex; i--, shdr--) {
			debug("update sections: %d -> %d", i, (i + 1));

			shdr = mem_getAddrSH(elf, i);


//			debug("strtab section: " << hex << shdr->sh_name);
			if (shdr->sh_type == SHT_STRTAB) {
				debug("strtab section: %p (%d)", shdr->sh_name, ehdr.e_shstrndx);

				if (i == ehdr.e_shstrndx) {
					/* .shstrtab */
					ehdr.e_shstrndx = i+1;
					gelf_update_ehdr(elf, &ehdr);
				}
			}

			/* overwrite next shdr with temporary shdr */
//			nextShdr = mem_getAddrSH(bin.elfMem, i);
			memcpy((void*)(shdr+1), (void*)shdr, sizeof(Elf32_Shdr));




//
//			/* temporary store the next shdr */
//			shdr = mem_getAddrSH(bin.elfMem, i+1);
//			memset((void*)&sh, 0, sizeof(Elf32_Shdr));
//			memcpy((void*)&sh, shdr, sizeof(Elf32_Shdr));
//
//			/* get address of current shdr */
//			shdr = mem_getAddrSH(bin.elfMem, i);
		}
	}

	return mem_getAddrSH(bin.elfMem, shIndex);

	/* TODO: update ehdr strndx */
//#endif


//	gelf_getehdr(bin.elfMem, &ehdr);
//
//	bin.stats.st_size += ehdr.e_shentsize;
//	ehdr.e_shnum += 1;
//
//	if (!gelf_update_ehdr(bin.elfMem, &ehdr)) {
//		error("cannot update elf header");
//	}
//
//	shdr = mem_getAddrSH(bin.elfMem, ehdr.e_shnum-1);
//
//	return shdr;
}
#endif

#if 0
void ElfInject::modifyDynamicPH()
{
	GElf_Ehdr ehdr;
	GElf_Phdr phDynamic;
	Elf32_Shdr *shDynamic;
	Elf32_Shdr *shSymtab;

	gelf_getehdr(bin.elfMem, &ehdr);








	Elf32_Shdr *shdr = mem_getAddrSH(bin.elfMem, 26);

	mem_moveElf((char*)(bin.basePtr + 0x1000), (char*)(bin.basePtr + shdr->sh_offset), shdr->sh_size);

	shdr->sh_addr = 0x08046000;
	shdr->sh_offset = 0x1000;

	return;













	shDynamic = mem_getAddrSH(bin.elfMem, bin.shDynamicIndex);

	/* copy dynamic section to another place in ELF memory */

	/* first, move section headers by the offset of one sh entry and .dynamic section*/
	size_t memCopyOffset = shDynamic->sh_size /*+ ehdr.e_shentsize*/;
/* TEST */
Elf32_Shdr *sh = mem_getAddrSH(bin.elfMem, 26);
/* TEST END */
	char *memOffsetFrom = (char*)((long)bin.basePtr + (long)sh->sh_offset); //(char*)((long)bin.basePtr + ehdr.e_shoff);
	char *memOffsetTo = (char*)((long)memOffsetFrom + sh->sh_size); // (char*)((long)memOffsetFrom + memCopyOffset);
	size_t memCopySize =  (size_t)(bin.basePtr + bin.stats.st_size - (long)memOffsetFrom); //(ehdr.e_shentsize * ehdr.e_shnum);

	debug("1. offset: " << hex << (long)memCopyOffset);
	debug("1. size: " << hex << (long)memCopySize);
	debug("1. from: " << hex << (long)(memOffsetFrom-bin.basePtr));
	debug("1. to: " << hex << (long)(memOffsetTo-bin.basePtr));

	/* move section headers */
	mem_moveElf(memOffsetTo, memOffsetFrom, memCopySize);
	bin.stats.st_size += memCopyOffset;
	ehdr.e_shoff += memCopyOffset;

gelf_update_ehdr(bin.elfMem, &ehdr);
return;

	/* determine offset and size of the new .dynamic section */
	memOffsetTo = memOffsetFrom;
	memOffsetFrom = (char*)((long)bin.basePtr + shDynamic->sh_offset);
	memCopySize = memCopyOffset;

	debug("2. from: " << hex << (long)memOffsetFrom);
	debug("2. to: " << hex << (long)memOffsetTo);
	debug("2. size: " << hex << (long)memCopySize);

	/* move parts of the ELF file in memory */
	mem_moveElf(memOffsetTo, memOffsetFrom, memCopySize);
//	bin.stats.st_size += memCopySize;
	gelf_update_ehdr(bin.elfMem, &ehdr);

	/* include a new .dynamic section header */

	/* section header positions changed, read old dynamic sh again */
	shDynamic = mem_getAddrSH(bin.elfMem, bin.shDynamicIndex);

//	Elf32_Shdr *newSHDynamic = mem_newSH((Elf32_Addr)(memOffsetTo - bin.basePtr));
	Elf32_Shdr *newSHDynamic = mem_newSH((Elf32_Addr)(shDynamic->sh_offset));

	memset((void*)newSHDynamic, 0, ehdr.e_shentsize);
	memcpy((void*)newSHDynamic, (void*)shDynamic, ehdr.e_shentsize);

	/* only one DYNAMIC segment allowed */
//	shDynamic->sh_type = SHT_PROGBITS;
	shDynamic->sh_name++;

//	newSHDynamic->sh_type = SHT_PROGBITS;
	newSHDynamic->sh_addr = PH_LOAD_ADDR/* + PAGESIZE*/;
//	newSHDynamic->sh_offset = (long)(memOffsetTo - bin.basePtr);
	newSHDynamic->sh_offset = (long)(shDynamic->sh_offset);

	/* adjust the program header DYNAMIC */
//	shDynamic->sh_offset = (long)((long)memOffsetTo - (long)bin.basePtr);
	if (gelf_getphdr(bin.elfMem, bin.phDynamicIndex, &phDynamic) != &phDynamic) {
		error("cannot extract program header nr " << bin.phPhdrIndex);
	}

	debug("3. off: " << hex << (long)phDynamic.p_offset);
	debug("3. vaddr: " << hex << (long)phDynamic.p_vaddr);
	debug("3. paddr: " << hex << (long)phDynamic.p_paddr);

//	phDynamic.p_offset = newSHDynamic->sh_offset;
//	phDynamic.p_vaddr = newSHDynamic->sh_addr;
//	phDynamic.p_paddr = newSHDynamic->sh_addr;

	if (!gelf_update_phdr(bin.elfMem, bin.phDynamicIndex, &phDynamic)) {
		error("cannot insert program header");
	}

//	injectLoadPH(newSHDynamic->sh_offset, newSHDynamic->sh_addr, phDynamic.p_memsz);


#if 0
//#if 0
	info(" ["<<bin.shDynamicIndex<<"] sh .dynamic address: " << hex << shDynamic->sh_addr << " -> " << hex <<  (PH_LOAD_ADDR + PAGESIZE));

	shDynamic->sh_addr = 0x08100000; //PH_LOAD_ADDR + PAGESIZE;

	info("modify PT_DYNAMIC program header");

	gelf_getphdr(bin.elfMem, bin.phDynamicIndex, &phDynamic);

/* TEST */
	/* determine offsets for ELF transformation */
	char *memOffsetFrom = (char*)(shDynamic->sh_offset + (long)bin.basePtr);
	char *memOffsetTo = (char*)((long)bin.basePtr + bin.stats.st_size);
	size_t memCopySize = (long)phDynamic.p_filesz;

	debug("from: " << hex << (long)memOffsetFrom);
	debug("to: " << hex << (long)memOffsetTo);
	debug("size: " << hex << (long)memCopySize);

	/* move parts of the ELF file in memory */
	mem_moveElf(memOffsetTo, memOffsetFrom, memCopySize);
	bin.stats.st_size += memCopySize;
	shDynamic->sh_offset = (long)((long)memOffsetTo - (long)bin.basePtr);
	phDynamic.p_offset = (long)((long)memOffsetTo - (long)bin.basePtr);


/* TEST END */

//	memset((void*)(&phdr), 0, sizeof(phdr));
//	phdr.p_type = PT_LOAD;
	phDynamic.p_flags = PF_R | PF_W;
//	phDynamic.p_align = 0x1000;
//	phDynamic.p_filesz = size;
//	phDynamic.p_memsz = size;
//	phDynamic.p_offset = (long)memOffsetTo;
	phDynamic.p_paddr = 0x08100000; //PH_LOAD_ADDR + PAGESIZE;
	phDynamic.p_vaddr = 0x08100000; //PH_LOAD_ADDR + PAGESIZE;

	if (!gelf_update_phdr(bin.elfMem, bin.phDynamicIndex, &phDynamic)) {
		error("cannot insert program header of type PT_GNU_STACK");
	}

	/* adopt symbols .dynamic */
	if (bin.shSymtabIndex != INVALID_SH) {
		shSymtab = (Elf32_Shdr*)mem_getAddrSH(bin.elfMem, bin.shSymtabIndex);

		char *name = mem_getSymName(bin.elfMem, shDynamic->sh_name);
		debug("adopt value of symbol: " << name);

		Elf32_Sym *sym = (Elf32_Sym*)(bin.basePtr + shSymtab->sh_offset);
		size_t symCount = shSymtab->sh_size / shSymtab->sh_entsize;

		for (size_t i=0; i<symCount; i++, sym++) {
//			debug("value of symbol ["<<i<<"]: " << sym->st_value  << " name: " << sym->st_shndx << "("<<shDynamic->sh_name<<")"<< lend;
			if (sym->st_shndx == bin.shDynamicIndex) {
				debug("adopt value of symbol ["<<i<<"]: " << sym->st_value <<" -> "<<  shDynamic->sh_addr);
				sym->st_value = shDynamic->sh_addr;
			}
			else if (sym->st_value == 0x0804a090) {
				sym->st_value = 0x08101000;
			}
		}
	}
//#endif
	injectLoadPH(phDynamic.p_offset, 0x08100000 /*(PH_LOAD_ADDR + PAGESIZE)*/, phDynamic.p_filesz);
//#if 0

/* TEST*/
	/* first .got.plt entry is the address of the dynamic section */
	Elf32_Shdr *shGotPlt = mem_getAddrSH(bin.elfMem, bin.shGotPltIndex);

	long *gotPlt = (long*)((long)shGotPlt->sh_offset + (long)bin.basePtr);
//	*gotPlt = 0x08100000; //PH_LOAD_ADDR + PAGESIZE;


/*
	GElf_Phdr phdr;
	gelf_getphdr(bin.elfMem, 4, &phdr);
	phdr.p_filesz -= 0x1c0;
	phdr.p_memsz -= 0x1c0;
	gelf_update_phdr(bin.elfMem, 4, &phdr);
*/
/* TEST END */
//#endif
#endif
}
#endif

void ElfInject::injectLoadPH(Elf32_Off fileOff, Elf32_Addr virtAddr, size_t size)
{
	GElf_Ehdr ehdr;

	info("° injecting PT_LOAD program header");

    /* adopt number of program headers in elf header */
	gelf_getehdr(bin.elfMem, &ehdr);

	ehdr.e_phnum += 1;

	if (!gelf_update_ehdr(bin.elfMem, &ehdr)) {
		error("cannot update elf header");
	}

	/* create a PT_LOAD program header (RW) */

	int phdrIndex = ehdr.e_phnum  - 1;

	GElf_Phdr phdr;
	gelf_getphdr(bin.elfMem, phdrIndex, &phdr);

	memset((void*)(&phdr), 0, sizeof(phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_R | PF_W;
	phdr.p_align = 0x1000;
	phdr.p_filesz = size;
	phdr.p_memsz = size;
	phdr.p_offset = fileOff;
	phdr.p_paddr = virtAddr; // PH_LOAD_ADDR;
	phdr.p_vaddr = virtAddr; // PH_LOAD_ADDR;

	if (!gelf_update_phdr(bin.elfMem, phdrIndex, &phdr)) {
		error("cannot insert program header of type PT_GNU_STACK");
	}

	/* update offset in the program header of type PHDR */

	if (gelf_getphdr(bin.elfMem, bin.phPhdrIndex, &phdr) != &phdr) {
		error("cannot extract program header nr %d", bin.phPhdrIndex);
	}

	phdr.p_filesz += ehdr.e_phentsize;
	phdr.p_memsz += ehdr.e_phentsize;

	if (!gelf_update_phdr(bin.elfMem, bin.phPhdrIndex, &phdr)) {
		error("cannot insert program header");
	}

//	sortLoadPH(bin.elfMem);
}

void ElfInject::sortLoadPH(Elf *elf)
{
	GElf_Phdr phdr;
	size_t phCount;
	size_t lastLoadPHIndex = 0;
	size_t secondLastLoadPHIndex = 0;

	debug("° sorting program headers");

	if (elf_getphdrnum(elf, &phCount) != 0) {
		error("cannot extract program header information");
	}

	for (size_t i=0; i<phCount; i++) {
		if (gelf_getphdr(elf, i, &phdr) != &phdr) {
			error("cannot extract program header nr %d", bin.phDynamicIndex);
		}

		if (phdr.p_type == PT_LOAD) {
			secondLastLoadPHIndex = lastLoadPHIndex;
			lastLoadPHIndex = i;

			size_t phDistance = lastLoadPHIndex - secondLastLoadPHIndex;
			if (phDistance != 1 && secondLastLoadPHIndex) {
				reorderPH(elf, lastLoadPHIndex, (secondLastLoadPHIndex+1));
			}
		}
	}
}

void ElfInject::reorderPH(Elf* elf, size_t fromIndex, size_t toIndex)
{
	GElf_Phdr phdr;
	GElf_Phdr tmpPhdr;

	debug("° move program header index: %d -> %d", fromIndex, toIndex);

	if (gelf_getphdr(elf, fromIndex, &tmpPhdr) != &tmpPhdr) {
		error("cannot extract program header nr %d", fromIndex);
	}

	for (size_t i=fromIndex-1; i>=toIndex; i--) {
		if (gelf_getphdr(elf, i, &phdr) != &phdr) {
			error("cannot extract program header nr %d", i);
		}

		if (!gelf_update_phdr(elf, i+1, &phdr)) {
			error("cannot update program header nr %d", i);
		}
	}

	if (!gelf_update_phdr(elf, toIndex, &tmpPhdr)) {
		error("cannot update program header nr %d", toIndex);
	}
}

/* TODO: reorder libs _only_ if the ELF file is dynamically linked
 * NOTE that it is important to follow the order of operations atm.
 * -> this means that reorderDynLibraries must be called before
 *    the ELF file is mapped to memory. */
void
ElfInject::reorderDynLibraries()
{
	Elf_Scn *scn;
	Elf_Data *edata;
	GElf_Shdr shdr;
	GElf_Dyn dyn;
	GElf_Dyn dynTmp;
	int entries;
	char *dynName;

	info("° reorder dynamically linked libraries");

	scn = elf_getscn(bin.elf, bin.shDynamicIndex);
	if (scn == NULL) {
		error("cannot access .dynamic");
	}
	gelf_getshdr(scn, &shdr);
	edata = elf_getdata(scn, NULL);

	/* look for the index of our library dependency within the section .dynamic */
	entries = shdr.sh_size / shdr.sh_entsize;
	for (int symIndex=0; symIndex<entries; symIndex++) {
		gelf_getdyn(edata, symIndex, &dyn);

		if (dyn.d_tag == DT_NEEDED) {
			dynName = elf_strptr(bin.elf, bin.shDynstrIndex, dyn.d_un.d_val);

			/* reorder dynamically linked library precedence */
			if (!strcmp(dynName, "libbinprotect.so")) {
				gelf_getdyn(edata, 0, &dynTmp);
				gelf_update_dyn(edata, 0, &dyn);
				gelf_update_dyn(edata, symIndex, &dynTmp);

				/* finished */
				return;
			}
		}
	}

	warn("could not reorder library precedence");
}

void
ElfInject::removeDyninstLib()
{
	Elf_Scn *scn;
	Elf_Data *edata;
	GElf_Shdr shdr;
	GElf_Dyn dyn;
	GElf_Dyn dynTmp;
	int entries;
	char *dynName;

	info("° remove libdyninstAPI_RT.so library dependency");

	scn = elf_getscn(bin.elf, bin.shDynamicIndex);
	if (scn == NULL) {
		error("cannot access .dynamic");
	}
	gelf_getshdr(scn, &shdr);
	edata = elf_getdata(scn, NULL);

	/* look for the index of our library dependency within the section .dynamic */
	entries = shdr.sh_size / shdr.sh_entsize;
	for (int symIndex=0; symIndex<entries; symIndex++) {
		gelf_getdyn(edata, symIndex, &dyn);

		if (dyn.d_tag == DT_NEEDED) {
			dynName = elf_strptr(bin.elf, bin.shDynstrIndex, dyn.d_un.d_val);

			/* replace the library dependency introduced by Dyninst:
			 * otherwise the stack cannot be made non-executable */
			if (!strcmp(dynName, "libdyninstAPI_RT.so.8.2")) {
				gelf_getdyn(edata, 0, &dynTmp);
				gelf_update_dyn(edata, symIndex, &dynTmp);
			}
			/* TODO: fix this!! */
			if (!strcmp(dynName, "/usr/local/lib/libdyninstAPI_RT.so.8.2")) {
				gelf_getdyn(edata, 0, &dynTmp);
				gelf_update_dyn(edata, symIndex, &dynTmp);
			}
		}
	}
}

void ElfInject::fortifyStack()
{
	info("fortify stack");

	if (bin.phGnuStackIndex == INVALID_PH) {
		remapElf();
		injectGNUStackPH();
	} else {
		remapElf();
		modifyGNUStackPH();
	}
}

void ElfInject::remapElf()
{
	/* we resize the file exactly by one page (4096 bytes):
	 * one page eliminates later alignment issues of the ELF segments */
	Elf *elf;
	Elf64_Half resizeOffset = 2*PAGESIZE;

	info("° map ELF to memory ");

	/* check whether the ELF file has already been mapped */
	if (elfRemapped) {
		return;
	}

	elfRemapped = true;

	elf = resizeElf(resizeOffset);
	updateEHOffset(elf, resizeOffset);
    updatePHOffset(elf, resizeOffset);
    updateSHOffset(elf, resizeOffset);

    bin.elfMem = elf;
}


Elf* ElfInject::resizeElf(Elf64_Half resizeOffset)
{
	info("° resize ELF by %d bytes", resizeOffset);

	Elf *elf;
	GElf_Ehdr ehdr;

	gelf_getehdr(bin.elf, &ehdr);

	/* read current elf binary into memory */

	/* determine offsets */
	long elfOffset = ehdr.e_phoff + ((ehdr.e_phnum) * ehdr.e_phentsize);
	long memOffset = elfOffset + resizeOffset;
	long memCopySize = bin.stats.st_size - elfOffset;

	/* allocate space for binary */
	if (bin.basePtr == NULL) {
		/* allocate new space for binary (NOTE that we allocate more space than needed) */
		bin.basePtr = (char*)malloc(bin.stats.st_size + resizeOffset + PAGESIZE);
		if(bin.basePtr == NULL) {
			error("cannot allocate enough memory");
		}
	} else {
		/* increase elf size (NOTE that we allocate more space than needed) */
		bin.basePtr = (char*)realloc(bin.basePtr, (size_t)(bin.stats.st_size + resizeOffset + PAGESIZE));
		if(bin.basePtr == NULL) {
			error("cannot allocate enough memory");
		}
	}

	/* update fstat */
	bin.stats.st_size += resizeOffset;

	/* clear memory */
	memset((void*)bin.basePtr, 0, bin.stats.st_size + PAGESIZE);

	/* copy original ELF content incl ELF and program header table to memory */
	if (read(bin.fd, (void*)(bin.basePtr), elfOffset) != elfOffset) {
		error("error read");
	}

	/* move original ELF remaining content to memory, by resizeOffset */
	if (lseek(bin.fd, elfOffset, SEEK_SET) != elfOffset) {
		error("error lseek");
	}

    if (read(bin.fd, (void*)(bin.basePtr + memOffset), memCopySize) < memCopySize) {
        error("cannot read file %s", bin.name.c_str());
    }

    /* reset elf_errno */
    elf_errno();

	/* create fd for mem region */
	elf = elf_memory(bin.basePtr, bin.stats.st_size);
	if(elf == NULL) {
		error("cannot initialize elfMem");
	}

	return elf;
}



void ElfInject::updateEHOffset(Elf *elf, Elf64_Half resizeOffset)
{
	GElf_Ehdr ehdr;

	/* update offset within the elf header */

	info("° update offsets in ELF header");
	gelf_getehdr(elf, &ehdr);

	ehdr.e_shoff += resizeOffset;

	if (!gelf_update_ehdr(elf, &ehdr)) {
		error("cannot update elf header");
	}
}

/**
 * after the ELF file has been resized, updatePHOffset() updates offset
 * of all affected Program Headers.
 */
void ElfInject::updatePHOffset(Elf *elf, Elf64_Half resizeOffset)
{
	size_t phCount;
	GElf_Phdr phdr;

	/* update offset in program headers */

	info("° update offset in program headers");

    if (elf_getphdrnum(elf, &phCount) != 0) {
        error("cannot extract program header information");
    }

    for (size_t i=0; i<phCount; i++) {
		if (gelf_getphdr(elf, i, &phdr) != &phdr) {
			error("cannot extract program header nr %d", i);
		}

		switch (phdr.p_type) {
		case PT_PHDR:
			/* phdr */
			phdr.p_vaddr -= resizeOffset;
			phdr.p_paddr -= resizeOffset;
			break;
		case PT_LOAD:
			if (phdr.p_offset == 0) {
				/* text segment */
				phdr.p_filesz += resizeOffset;
				phdr.p_memsz += resizeOffset;
				phdr.p_vaddr -= resizeOffset;
				phdr.p_paddr -= resizeOffset;
			} else {
				phdr.p_offset += resizeOffset;
			}
			break;
		default:
			if (phdr.p_offset) {
				/* everything else */
				phdr.p_offset += resizeOffset;
			}
			break;
		}

		if (!gelf_update_phdr(elf, i, &phdr)) {
			error("cannot insert program header");
		}
    }
}

/**
 * after the ELF file has been resized, updateSHOffset() updates the file offset
 * of the section headers.
 */
void ElfInject::updateSHOffset(Elf *elf, Elf64_Half resizeOffset)
{
	size_t shCount;
	GElf_Ehdr ehdr;

	/* update offset in section headers */

	info("° update offset in section headers");

	elf_getshdrnum(elf, &shCount);
	gelf_getehdr(elf, &ehdr);

	/* NOTE: here we do not make use of libelf - so the following is architecture dependent
	 *  -> cannot explain why libelf' elf_nextscn() does not return valid results
	 *     even after invoking elf_update(elf, ELF_C_NULL) */

	Elf32_Shdr *shdr;
	shdr = (Elf32_Shdr*)(bin.basePtr + ehdr.e_shoff);

	for (unsigned int i=0; i<shCount; i++, shdr++) {
		if (shdr->sh_offset) {
			shdr->sh_offset += resizeOffset;
		}
	}
}

/**
 * in case a PT_GNU_STACK program header is not present in the file,
 * the function injectGNUStackPH() injects the PT_GNU_STACK program header
 * into the binary file. It additionally, adopts all required information
 * within the program header table PHDR.
 */
void ElfInject::injectGNUStackPH()
{
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	int phdrIndex;

	info("° injecting PT_GNU_STACK program header");

    /* adopt number of program headers in elf header */
	gelf_getehdr(bin.elfMem, &ehdr);

	phdrIndex = ehdr.e_phnum;
	ehdr.e_phnum += 1;

	if (!gelf_update_ehdr(bin.elfMem, &ehdr)) {
		error("cannot update elf header");
	}

    /* create a PT_GNU_STACK program header (RW) */
//	int phdrIndex = ehdr.e_phnum - 1;

	gelf_getphdr(bin.elfMem, phdrIndex, &phdr);

	memset((void*)(&phdr), 0, sizeof(phdr));
	phdr.p_type = PT_GNU_STACK;
	phdr.p_flags = PF_R | PF_W;
	phdr.p_align = 0x10;

	if (!gelf_update_phdr(bin.elfMem, phdrIndex, &phdr)) {
		error("cannot insert program header of type PT_GNU_STACK");
	}

	/* update offset in the program header of type PHDR */

	if (gelf_getphdr(bin.elfMem, bin.phPhdrIndex, &phdr) != &phdr) {
		error("cannot extract program header nr %d", bin.phPhdrIndex);
	}

	phdr.p_filesz += ehdr.e_phentsize;
	phdr.p_memsz += ehdr.e_phentsize;

	if (!gelf_update_phdr(bin.elfMem, bin.phPhdrIndex, &phdr)) {
		error("cannot insert program header");
	}
}

void ElfInject::modifyGNUStackPH()
{
	GElf_Phdr phdr;
	Elf *elf;

	if (bin.elfMem) {
		/* memory elf descriptor */
		elf = bin.elfMem;
	} else {
		/* file elf descriptor */
		elf = bin.elf;
	}

	info("° modify PT_GNU_STACK program header");

	if (!gelf_getphdr(elf, bin.phGnuStackIndex, &phdr)) {
		error("cannot extract program header");
	}

	/* mark stack as non executable (NX) */
	phdr.p_flags = PF_R | PF_W;

	if (!gelf_update_phdr(elf, bin.phGnuStackIndex, &phdr)){
		error("cannot insert program header");
	}
}


/******************************************************************************
 ** Helpers: ELF editing in memory
 */

void ElfInject::mem_moveElf(char *dest, char *src, size_t size)
{
	/* allocate space for intermediate storage */
	char *tmpStorage = (char*)malloc(size);

	/* copy part of the ELF file to intermediate storage */
	memcpy((void*)tmpStorage, (void*)src, size);

	/* copy content from intermediate storage to memory, by resizeOffset */
	memcpy((void*)dest, (void*)tmpStorage, size);
}

Elf32_Shdr* ElfInject::mem_getAddrSH(Elf *elf, size_t shIndex)
{
	GElf_Ehdr ehdr;
	gelf_getehdr(elf, &ehdr);

	Elf32_Shdr *shdr = (Elf32_Shdr*)(bin.basePtr + ehdr.e_shoff + (shIndex * sizeof(Elf32_Shdr)));

	return shdr;
}

char* ElfInject::mem_getSymName(Elf *elf, size_t index) {
	char *name = NULL;
	Elf32_Shdr *shStrtab = mem_getAddrSH(elf, bin.shStrtabIndex);

	name = (char*)(bin.basePtr + shStrtab->sh_offset + index);

	return name;
}

/******************************************************************************
 **  debugging
 */

void ElfInject::disableGnuStack(Elf *elf) {
	GElf_Phdr phdr;
	size_t phCount;

	debug("disable program header of type GNU_STACK");

	elf_getphdrnum(elf, &phCount);

	for (unsigned int i=0; i<phCount; i++) {
		if (gelf_getphdr(bin.elf, i, &phdr) != &phdr) {
			error("cannot extract program header nr %d", i);
		}

		if (phdr.p_type == PT_GNU_STACK) {
			phdr.p_type = PT_NULL;
//			phdr.p_flags = 0;
		}

		if (phdr.p_type == PT_GNU_RELRO) {
			phdr.p_type = PT_NULL;
		}

		gelf_update_phdr(elf, i, &phdr);
	}
}

void ElfInject::inspectDynsymSection(Elf *elf)
{
	Elf_Scn *scn;
	Elf_Data *edata;
	GElf_Shdr shdr;
	GElf_Sym sym;
	int entries;
	char *dynName;

	debug("inspect dynamic section");

	scn = elf_getscn(elf, bin.shDynsymIndex);
	if (scn == NULL) {
		error("cannot access .dynsym");
	}
	gelf_getshdr(scn, &shdr);
	edata = elf_getdata(scn, NULL);

	entries = shdr.sh_size / shdr.sh_entsize;
	for (int symIndex=0; symIndex<entries; symIndex++) {
		gelf_getsym(edata, symIndex, &sym);
		dynName = elf_strptr(elf, bin.shDynstrIndex, sym.st_name);
		debug("DYN: %s", dynName);
	}
}

void ElfInject::inspectProgramHeaders(Elf *elf)
{
    GElf_Phdr phdr;
//    GElf_Phdr tpmPhdr;
    size_t phCount;

    debug("inspect program headers");

    if (elf_getphdrnum(elf, &phCount) != 0) {
        error("cannot extract program header information");
    }

    info("found %zd program headers", phCount);

    for (size_t i=0; i<phCount; i++) {
        if(gelf_getphdr(elf, i, &phdr) != &phdr) {
        	error("cannot extract program header nr %d", i);
        }

        printf("program header nr %d\n", i);
        printf("%-20s 0x%jx\n", "p_type", (uintmax_t)phdr.p_type);
        printf("%-20s 0x%jx\n", "p_offset", (uintmax_t)phdr.p_offset);
        printf("%-20s 0x%jx\n", "p_vaddr", (uintmax_t)phdr.p_vaddr);
        printf("%-20s 0x%jx\n", "p_paddr", (uintmax_t)phdr.p_paddr);
        printf("%-20s 0x%jx\n", "p_filesz", (uintmax_t)phdr.p_filesz);
        printf("%-20s 0x%jx\n", "p_memsz", (uintmax_t)phdr.p_memsz);
        printf("%-20s 0x%jx\n", "p_flags", (uintmax_t)phdr.p_flags);
        printf("%-20s 0x%jx\n", "p_align", (uintmax_t)phdr.p_align);
    }
}

void ElfInject::inspectSectionHeaders(Elf *elf)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
//	GElf_Shdr tmpShdr;
	char *secName = NULL;

    debug("inspect section headers");

	while((scn = elf_nextscn(elf, scn)) != NULL) {
		/* get section header */
		gelf_getshdr(scn, &shdr);

		secName = elf_strptr(elf, bin.shStrtabIndex, shdr.sh_name);

		if (secName) {
			debug("name: %s", secName);
		} else {
			debug("addr: %llu", shdr.sh_addr);
		}
	}
}

void ElfInject::inspectSectionDynamic(Elf *elf)
{
	Elf_Scn *scn;
	Elf_Data *edata;
	GElf_Shdr shdr;
	GElf_Dyn dyn;
//	GElf_Dyn dynTmp;
	int entries;
	char *dynName;

	info("reorder dynamically linked libraries");

	scn = elf_getscn(elf, bin.shDynamicIndex);
	if (scn == NULL) {
		error("cannot access .dynamic");
	}
	gelf_getshdr(scn, &shdr);
	edata = elf_getdata(scn, NULL);

	/* look for the index of our library dependency within the section .dynamic */
	entries = shdr.sh_size / shdr.sh_entsize;
	for (int symIndex=0; symIndex<entries; symIndex++) {
		gelf_getdyn(edata, symIndex, &dyn);

		dynName = elf_strptr(elf, bin.shDynstrIndex, dyn.d_un.d_val);
		if (dynName) {
			debug(" ° dyn: %s - tag: %llu - val: %p", dynName, dyn.d_tag, (void*)dyn.d_un.d_val);
		} else {
			debug(" ° dyn: NONAME - tag: %llu - val: %p", dyn.d_tag, (void*)dyn.d_un.d_val);
		}
	}
}



