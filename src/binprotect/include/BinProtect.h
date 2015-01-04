/*
 * MyClass.h
 *
 *  Created on: Dec 13, 2014
 *      Author: sergej
 */

#ifndef BINPROTECT_H_
#define BINPROTECT_H_

#include <stdlib.h>
#include <iostream>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h"

#include "PatchObject.h"
#include "PatchMgr.h"
#include "PatchModifier.h"
#include "Point.h"
#include "PatchCFG.h"
#include "AddrLookup.h"
#include "AddrSpace.h"
#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_image.h"
#include "BPatch_function.h"
#include "BPatch_Vector.h"

using namespace std;
using namespace Dyninst;
using namespace Dyninst::ParseAPI;
using namespace Dyninst::PatchAPI;
using namespace Dyninst::SymtabAPI;
using namespace Dyninst::InstructionAPI;

#include <Logging.h>
#include <ElfInject.h>

#define PROLOG_SIZE			33 // 30
#define EPILOG_SIZE 		50 // 46

//#define LABEL_BINPROTECT 	"BINPROTECT"

typedef enum {
	at_create,
	at_attach,
	at_open,
	at_invalid
} accessType_t;

class BinProtect {

public:

private:
	string mutatee;
	string patch;
	BPatch bp;
	BPatch_addressSpace* bp_as;
	PatchMgrPtr p_mgr;
	BPatch_object *bp_lib;

	/* profiling information */
	size_t totalFuncs;
	size_t omittedFuncs;

	/* shadow stack for return address protection */
	BPatch_variableExpr* shadow;

	/* shadow stack supports protection of 256 nested function calls */
	typedef struct {
		int counter;
		int* rad[256];
	} rad_t;

	/* shellcode: prolog */
	unsigned char prolog[PROLOG_SIZE] = {
		0x60,										// pusha
		0x8b, 0x15, 0x00, 0x00, 0x10, 0x08,			// mov edx, ($0x08100000)
		0x83, 0x05, 0x00, 0x00, 0x10, 0x08, 0x01,	// add 0x08100000, $1
		0xd1, 0xe2,									// shl edx, 1
		0xd1, 0xe2,									// shl edx, 1
		0x8d, 0x0d, 0x00, 0x00, 0x10, 0x08,			// lea ecx, 0x08100000
		0x01, 0xca,									// add edx, ecx
		0x8b, 0x4c/*0x4d*/, 0x24, 0x24,				// mov ecx, [esp+0x24]
		0x89, 0x0a,									// mov (edx), ecx
		0x61,										// popa
	};

	/* shellcode: epilog */
	unsigned char epilog[EPILOG_SIZE] = {
		0x60,										// pusha
		0x83, 0x2d, 0x00, 0x00, 0x10, 0x08, 0x01,	// sub    DWORD PTR ds:0x8100000,0x1
		0x8b, 0x15, 0x00, 0x00, 0x10, 0x08,			// mov    edx, ($0x08100000)
		0xd1, 0xe2,									// shl    edx,1
		0xd1, 0xe2,									// shl    edx,1
		0x8d, 0x0d, 0x00, 0x00, 0x10, 0x08,			// lea    ecx,ds:0x8100000
		0x01, 0xca,									// add    edx,ecx
		0x8b, 0x12,									// mov    edx,DWORD PTR [edx]
		0x8b, 0x4c, 0x24, 0x20,						// mov    ecx,DWORD PTR [esp+0x20]
		0x39, 0xca,									// cmp    edx,ecx
		0x0f, 0x84, 0x08, 0x00, 0x00, 0x00,			// je     85 <_new_epilog+0x2f>
		0x31, 0xdb,									// xor    ebx,ebx
		0x89, 0xd8,									// mov    eax,ebx
		0x40,										// inc    eax
		0x4b,										// dec    ebx
		0xcd, 0x80,									// int    0x80
		0x61,										// popa
		0xc3,										// ret
	};

public:
	BinProtect() = delete;
	explicit BinProtect(string newMutatee, string newPatch);
	~BinProtect();

	/* delete copy constructor and copy assignment operator */
	BinProtect(const BinProtect&) = delete;
	BinProtect& operator=(const BinProtect&) = delete;

	/* delete move constructor and move assignment operator */
	BinProtect(BinProtect&&) = delete;
	BinProtect& operator=(BinProtect&&) = delete;

	bool init(accessType_t accessType, int pid, const char *argv[]);
	bool finish();

	void replaceFuncCall(string oldFuncName, string newFuncName);
	void wrapFunc(string funcName);

	void protectStack();

	/* debugging */
	void listFunctions();

private:
	/* initialization based functions */
	bool loadLibrary();
	bool allocShadowStack();

	void protectFunc(BPatch_function *func);

	size_t getPrologInfo(PatchBlock *block, Offset *addr/*, unsigned char *bytes*/);
	size_t getEpilogInfo(PatchBlock *block, Offset *addr/*, unsigned char *bytes*/);

	int instrumentProlog(void* addr, unsigned char *bytes, size_t new_nbytes, size_t nbytes, PatchBlock *block);
	int instrumentEpilog(void* addr, unsigned char *bytes, size_t new_nbytes, size_t nbytes, PatchBlock *block);

	/* debugging */
	void listBasicBlocks(BPatch_function *func);
};

#endif /* BINPROTECT_H_ */
