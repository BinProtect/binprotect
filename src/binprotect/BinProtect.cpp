/*
 * MyClass.cpp
 *
 *  Created on: Dec 13, 2014
 *      Author: sergej
 */

#include "BinProtect.h"

BinProtect::BinProtect(std::string newMutatee, string newPatch)
			: mutatee(newMutatee), patch(newPatch)
{
	/* initialize profiling information */
	totalFuncs = 0;
	omittedFuncs = 0;

	/* initialze binary editing related information */
	bp_as = NULL;
	bp_lib = NULL;

	/* initialize shadow stack */
	shadow = NULL;
}

BinProtect::~BinProtect() {}

/**
 * load provided patch in form of a .so library
 */
bool
BinProtect::loadLibrary()
{
	debug("° loading library: %s", patch.c_str());

	bp_lib = ((BPatch_binaryEdit*)bp_as)->loadLibrary(patch.c_str(), true);
	if(bp_lib == NULL) {
		error("cannot load library %s", patch.c_str());
		return false;
	}

	return true;
}

/**
 * defines the instrumentation type and loads the provided patch and
 * initializes the shadow stack
 */
bool
BinProtect::init(
		accessType_t accessType,
		int pid,
		const char *argv[])
{
	bool res = true;

	info(" ");
	info(".:: initialize BinProtect ::.");
	info(" ");

	switch(accessType) {
	case at_create:
		/* create a new process to perform dynamic instrumentation */
		info("° create process: %s", mutatee.c_str());

		bp_as = bp.processCreate(mutatee.c_str(), argv);
		if(!bp_as) {
			error("cannot create the process %s", mutatee.c_str());
			return false;
		}
		break;

	case at_attach:
		/* attach to an already running process to perform dynamic instrumentation */

		/* TODO: note that the function attach was implemented only in form of
		 * a stub: it was never tested. This way, it remains the task of the future
		 * developer to extend this functionality */
		info("° attach to process with pid: %d", pid);

		/* always return false: no use for this functionality, yet */
		warn("uups!! not gonna happen, bro!");
		return false;

		bp_as = bp.processAttach(mutatee.c_str(), pid);
		if(!bp_as) {
			error("cannot attach to process %s", mutatee.c_str());
			return false;
		}
		break;

	case at_open:
		/* open a mutatee binary to perform static binary modification */

		info("° open binary: %s", mutatee.c_str());

		bp_as = bp.openBinary(mutatee.c_str(), true);
		if(!bp_as) {
			error("cannot open binary %s", mutatee.c_str());
			return false;
		}
		break;

	default:
		/* should not happen */
		error("invalid program access type");
		return false;
	}

	/* load the patch, dependent on whether it was provided with the constructor */
	if(!patch.empty()) {
		res = loadLibrary();
		if(!res) {
			return false;
		}
	}

//	/* allocate space for the shadow stack - RAD (return address defence) */
//	res = allocShadowStack();

	return res;
}

/* allocates space and initializes a shadow stack to store control flow
 * affecting registers of the mutatee, such as %EBP
 *
 * TODO: future implementations may easily extend this concept by introducing
 * the storage of %EBP register, as well.
 */
bool
BinProtect::allocShadowStack()
{
	shadow = bp_as->malloc(sizeof(rad_t));
	if(shadow == NULL) {
		error("cannot allocate memory for shadow stack");
		return false;
	}

	/* initialize the return address protection counter with 1 */
	int counter = 1;
	if(!shadow->writeValue((void *)(&counter), sizeof(int), false)) {
		error("cannot write shadow stack into allocated memory");
		return false;
	}

	debug("° shadow stack at address: %p", (long*)shadow->getBaseAddr());

	return true;
}

/**
 * terminates instrumentation of the associated binary or process
 */
bool
BinProtect::finish()
{
	bool res;
	BPatch_process *appProc = dynamic_cast<BPatch_process *>(bp_as);
	BPatch_binaryEdit *appBin = dynamic_cast<BPatch_binaryEdit *>(bp_as);

	info("finish binary instrumentation");

	/* distinguish between a running process (hotpatching) and a binary
	 * to be written into a new binary file */
	if (appProc) {
		info(" ");
		info("execution of mutatee");
		info("=============================");
		info("===== Program Execution =====");

		appProc->continueExecution();

		while (!appProc->isTerminated()) {
			bp.waitForStatusChange();
		}

		info("=============================");
		info(" ");
	}

	if (appBin) {
		string newBin = mutatee + "_new";

		info("° write instrumented binary to file: %s", newBin.c_str());

		res = appBin->writeFile(newBin.c_str());
		if(!res) {
			error("cannot write instrumented binary to file: %s", newBin.c_str());
			return false;
		}
	}

	info("° done");

	if(totalFuncs) {
		info("° cannot protect %d of %d total activation records", omittedFuncs, totalFuncs);
	}

	return true;
}

/* lists all functions */
void
BinProtect::listFunctions()
{
#define MODNAME_SIZE	50

	BPatch_image* bp_img;
	vector<BPatch_function *> bp_funcs;
	vector<BPatch_module *> bp_modules;
	char modname[MODNAME_SIZE] = {0};

	info("functions:");

	bp_img = bp_as->getImage();
	bp_img->getModules(bp_modules);

	for (auto mod=bp_modules.begin(); mod!=bp_modules.end(); mod++) {
		if((*mod)->isSharedLib()) {
			continue;
		}

		(*mod)->getName(modname, MODNAME_SIZE);
		info("° modname: %s", modname);

		/* meaning of false in 'getProcedures(bool)': returns only
		 * _instrumentable_ procedures */
		(*mod)->getProcedures(bp_funcs, false);

		for (auto func=bp_funcs.begin(); func!=bp_funcs.end(); func++) {
		   info("  [+] %s", (*func)->getName().c_str());
		   /* debug */
//		   listBasicBlocks(*func);
		}
	}
}

void
BinProtect::listBasicBlocks(BPatch_function *func)
{
	BPatch_flowGraph *cfg;
	set<BPatch_basicBlock*> blocks;

	info("basic blocks in function %s:", func->getName().c_str());

	cfg = func->getCFG();
	cfg->getAllBasicBlocks(blocks);

	for(auto b=blocks.begin(); b!=blocks.end(); b++) {
		PatchBlock *block = PatchAPI::convert(*b);

		info("° block->format:");
		info("%s", block->disassemble().c_str());
	}
}

void
BinProtect::replaceFuncCall(string oldFuncName, string newFuncName)
{
	BPatch_image* img;
	BPatch_Vector<BPatch_point*> entryPoints;
	BPatch_Vector<BPatch_function *> funcs;
	BPatch_function *funcOld;
	BPatch_function *funcNew;

	info("replace function call: %s with %s", oldFuncName.c_str(), newFuncName.c_str());

	img = bp_as->getImage();

	/* find original function to be patched */
	img->findFunction(oldFuncName.c_str(), funcs);
	if(!funcs.size()) {
		warn("cannot find function to be instrumented: %s", oldFuncName.c_str());
		return;
	}
	funcOld = funcs[0];

	/* find patch function in library to be instrumented */
	funcs.clear();
	img->findFunction(newFuncName.c_str(), funcs);
	if(!funcs.size()) {
		warn("cannot find function to be instrumented: %s", newFuncName.c_str());
		return;
	}
	funcNew = funcs[0];

	funcOld->getCallPoints(entryPoints);
	if(!entryPoints.size()) {
		warn("cannot find function to be instrumented: %s", "myusage");
		return;
	}
	BPatch_point *p = entryPoints[0];

	/* NOTE: persistent replacing of function calls works only on statically defined functions; or at runtime!! */
	bp_as->replaceFunctionCall(*p, *funcNew);
}

void
BinProtect::wrapFunc(string funcName)
{
	BPatch_image* img = bp_as->getImage();
	BPatch_Vector<BPatch_point*> entryPoints;
	BPatch_Vector<BPatch_function *> funcs;
	BPatch_function *oldFunc;
	BPatch_function *newFunc;

	string newFuncName = "bp_" + funcName;
	string origFuncName = "orig_" + funcName;

	info("wrap function: %s", funcName.c_str());

	/* find original function to be patched */
	img->findFunction(funcName.c_str(), funcs);
	if(!funcs.size()) {
		warn("cannot find function to be instrumented: %s", funcName.c_str());
		return;
	}
	oldFunc = funcs[0];

	/* find patch function in library to be instrumented */
	funcs.clear();
	img->findFunction(newFuncName.c_str(), funcs);
	if(!funcs.size()) {
		warn("cannot find function to be instrumented: %s", "myusage");
		return;
	}
	newFunc = funcs[0];

	Module *mod = SymtabAPI::convert(newFunc->getModule());
	if (mod == NULL) {
		warn("cannot convert BPatch_object* into BPatch_module*");
		return;
	}

	vector<Symbol *> symbols;
	mod->getAllSymbols(symbols);

//	mod->findSymbol(symbols, origFuncName, Symbol::ST_FUNCTION, SymtabAPI::NameType::prettyName, false, false);
	for (auto s=symbols.begin(); s!=symbols.end(); s++) {
//		log << ll_info << "sym: "<< (*s)->getMangledName() << " vs " << (*s)->getPrettyName() << lend;
		if (!(*s)->getPrettyName().compare(origFuncName)) {
//			if ((*s)->isInDynSymtab()) {
				bp_as->wrapFunction(oldFunc, newFunc, (*s));
//				(*s)->set
//			}
		}
	}
}

void
BinProtect::protectStack()
{
#define MAX_SIZE_SHLIB_NAME 	50

	BPatch_image* img;
	vector<BPatch_function *> *funcs;
	std::vector<BPatch_module *>* modules;

	info("initiate stack protection");

	/* allocate space for the shadow stack - RAD (return address defence) */
	allocShadowStack();

	img = bp_as->getImage();
	modules = img->getModules();

	for(auto m=modules->begin(); m!=modules->end(); m++) {
		/* do not need to look into shared libraries */
		if((*m)->isSharedLib()) {
			char name[MAX_SIZE_SHLIB_NAME];
			(*m)->getName(name, MAX_SIZE_SHLIB_NAME);

			info("° skipping shared lib: %s", name);

			continue;
		}

		/* returns only instrumentable functions */
		funcs = (*m)->getProcedures(false);
		for(size_t i=0; i<funcs->size(); i++) {
			BPatch_function *f = funcs->at(i);

			info("° function: %s", f->getName().c_str());

			/* look only at user defined functions, which normally do not start with '_'
			 * and also we omit frame_dummy function
			 *
			 * TODO: we need to chck whether the EBP has a valid value -- otherwise
			 * we must not protect the stack frame */
			if(f->getName().c_str()[0] != '_'
					&& strcmp(f->getName().c_str(), "frame_dummy")) {
				protectFunc(f);
			}
		}
	}
}

/* performs prolog and epilog protection of the provided function */
void
BinProtect::protectFunc(BPatch_function *func)
{
#define RAW_BYTE_SIZE		50

	std::vector<BPatch_basicBlock*> bpBlocksProlog;
	std::vector<BPatch_basicBlock*> bpBlocksEpilog;
	BPatch_flowGraph *cfg = NULL;
	PatchBlock *pBlockProlog = NULL;
	PatchBlock *pBlockEpilog = NULL;
	Offset addrProlog;
	Offset addrEpilog;
	size_t nbytesProlog = 0;
	size_t nbytesEpilog = 0;
	int index = 0;
//	unsigned char rawBytesProlog[RAW_BYTE_SIZE] = {0};
//	unsigned char rawBytesEpilog[RAW_BYTE_SIZE] = {0};

	info("protect stack frame of the function: %s", func->getName().c_str());

	/* profiling information: count total functions to be protected */
	totalFuncs++;

	bpBlocksProlog.clear();
	bpBlocksEpilog.clear();
	cfg = func->getCFG();
	cfg->getEntryBasicBlock(bpBlocksProlog);
	cfg->getExitBasicBlock(bpBlocksEpilog);

	pBlockProlog = PatchAPI::convert(bpBlocksProlog[0]);
	nbytesProlog = getPrologInfo(pBlockProlog, &addrProlog/*, rawBytesProlog*/);
	if (nbytesProlog == 0) {
		warn("insufficient prolog information: abort protection of %s", func->getName().c_str());
		omittedFuncs++;
		return;
	}

	/* NOTE: we are able to protect functions that create a stack frame.
	 * To be more sepcific, we protect functions, whose prolog _and_ epililog
	 * information can be found by our program. In case a functions' epilog
	 * cannot be located (although its prolog has been located), we must
	 * abort protection of this particular function; Otherwise
	 * the binary would crash at runtime. */
	for (auto b=bpBlocksEpilog.begin(); b!=bpBlocksEpilog.end(); b++) {
		PatchBlock *pb = PatchAPI::convert(*b);

		nbytesEpilog = 0;
		nbytesEpilog = getEpilogInfo(pb, &addrEpilog/*, rawBytesEpilog*/);

		/* NOTE: if a function has been protected by gcc, a call to
		 * __stack_chk_fail() is considered as an exit basic block.
		 * The same applies if a function calls exit(): look for an
		 * appropriate exit basic block (ending with the instruction 'ret') */
		if ((nbytesEpilog == 0) && (&addrEpilog == NULL)) {
			/* an exit cannot not be patched: look for another basic block */
			break;
		}
	}

	/* check whether sufficient prolog and epilog information could be extracted */
	if ((nbytesProlog != 0) && (nbytesEpilog != 0)) {
		for (auto b=bpBlocksEpilog.begin(); b!=bpBlocksEpilog.end(); b++) {
			pBlockEpilog = PatchAPI::convert(*b);
			nbytesEpilog = 0;

			/* nbytes represents the number of bytes of the instruction, which
			 * is about to be replaced */
			nbytesEpilog = getEpilogInfo(pBlockEpilog, &addrEpilog/*, rawBytesEpilog*/);

			if ((nbytesEpilog == 0) || ((long*)addrEpilog == NULL)) {
//				warn("insufficient epilog information");
				continue;
			}

			/* count Nr of performed epilog modifications */
			index++;

			if (instrumentEpilog((void*)addrEpilog, epilog, EPILOG_SIZE, nbytesEpilog, pBlockEpilog)) {
				warn("° index [-] = %d", index);
				index--;
			}
		}
		/* perform prolog modification only if at least one epilog modification has been performed */
		if(index > 0) {
			/* inject the new prolog into the original function */
			instrumentProlog((void*)addrProlog, prolog/*rawBytesProlog*/, (PROLOG_SIZE/*+nbytesProlog*/), nbytesProlog, pBlockProlog);
		} else {
			warn("insufficient epilog information: abort protection of %s", func->getName().c_str());
			omittedFuncs++;
		}
	}
//	else {
//		warn("insufficient prolog/epilog information: abort protection of %s", func->getName().c_str());
//		omittedFuncs++;
//	}
}

/**
 * extracts prolog related part of the function and provides the caller with:
 *
 * ° the address, where the prolog extension should be inserted
 * ° the size of the instruction to be replaced with the prolog extension
 *   -> which is "push	%ebp"
 * ° raw bytes of the instruction to be replaced
 */
size_t
BinProtect::getPrologInfo(
		PatchBlock *block,
		Offset *addr/*,
		unsigned char *bytes*/)
{
	Instruction::Ptr iptr;
	PatchBlock::Insns insns;
	Offset tmpAddr;
	size_t nbytes;
	string operand0, operand1;

	debug("° find address for prolog basic block injection");

	block->getInsns(insns);

	for(auto i=insns.rbegin(); i!=insns.rend(); i++) {
		/* work with raw instructions */
		tmpAddr = (*i).first;
		iptr = (*i).second;
		nbytes = iptr->size();

		entryID instrID = iptr->getOperation().getID();
		operand0 = iptr->getOperand(0).format(iptr->getArch(), tmpAddr).c_str();

		/* to find an appropriate address within the functions' prolog, we look for
		 * the instruction sequence:
		 *  ...
		 *  push ebp
		 *  sub esp, $Nr
		 *  ...
		 * the current presentation, injects code at right after 'push ebp'
		 * -> it is not possible to redirect indirect calls to functions, which
		 *    is the reason for our choise -- otherwise we would have placed our
		 *    prolog extention right before the first instruction of the function. */
//		if((instrID == entryID::e_sub) && !operand0.compare("ESP")) {
		if((instrID == entryID::e_push) && !operand0.compare("EBP")) {
			*addr = tmpAddr;

#if 0
			/* TODO: stack size becomes important when performing stack protection
			 * using a canary, since the stack and the stack access by the %EBP
			 * register needs to be modified */
			stack_size = atoi(iptr->getOperand(1).format(iptr->getArch(), tmpAddr).c_str());
#endif

#if 0
			/* NOTE: the following has been used to extract raw bytes of the demanded
			 * prolog instructions. This part is however not used at the moment. */

			/* store raw bytes of the instruction in question into the provided buffer */
			debug("° prolog: instruction at %p of size %d: %s", *addr, nbytes, iptr->format().c_str());
			for(size_t j=0; j<nbytes; j++) {
				bytes[j] = iptr->rawByte(j);
//				debug("0x%x", (int)bytes[j]);
			}
#endif

			return nbytes;
		}
	}

	/* prolog information has not been found */
	addr = NULL;
	return 0;
}

/**
 * extracts epilog related part of the function and provides the caller with:
 *
 * - the address -- where the prolog extension should be inserted
 * - the size of the instruction to be replaced with the prolog extension
 *   -> which is "leave; ret"
 *   -> NOTE: it is important to understand that -- depending on the compiler --
 *      the representative _last_ part of the function presenting the epilog can
 *      vary. Another possibility, which could potentially be a part of the epilog
 *      is: "add   %esp, ...; ret". This functionality is, however, not yet implemented
 *      and left to the future developer.
 * - raw bytes of the instruction to be replaced
 */
size_t
BinProtect::getEpilogInfo(
		PatchBlock *block,
		Offset *addr/*,
		unsigned char *bytes*/)
{
	Instruction::Ptr iptr;
	PatchBlock::Insns insns;
	Offset tmp_addr;
	size_t nbytes;
	string reg;

	debug("° find address for epilog basic block injection");

	block->getInsns(insns);

	for(auto i=insns.rbegin(); i!=insns.rend(); i++) {
		/* work with raw instructions */
		tmp_addr = (*i).first;
		iptr = (*i).second;
		nbytes = iptr->size();

		reg = iptr->getOperand(0).format(iptr->getArch(), tmp_addr);
		entryID instrID = iptr->getOperation().getID();

		switch (instrID) {
		case entryID::e_ret_near/*e_leave*/:
			/* 'normal' function exit */
			*addr = tmp_addr;

#if 0
			/* NOTE: the following has been used to extract raw bytes of the demanded
			 * prolog instructions. This part is however not used at the moment. */

			debug("° epilog: instruction at %p of size %d: %s", *addr, nbytes, iptr->format().c_str());
			for(size_t j=0; j<nbytes; j++) {
				bytes[j] = iptr->rawByte(j);
//				debug("0x%x", (int)bytes[j]);
			}
#endif

			return nbytes;
#if 0
		case entryID::e_call:
			/* function ends with a call to exit(), __stack_chk_fail, or similar.
			 * -> signalize the caller that the function ends with a call instruction
			 *    by returning a non-NULL address */
			*addr = tmp_addr;
			return 0;
#endif
		default:
			/* do nothing */
			break;
		}
	}

	/* did not find an appropriate epilog point to extend */
	addr = NULL;
	return 0;
}


/* instrument the basic block including prolog information at the address _addr_
 * - addr represents the address of the instruction, where to split the block
 * - bytes include new prolog instructions to be injected into the function
 * - newBBSize represent the size in bytes of the new prolog
 * - oldBBSize represent the size of the instruction to be replaced with new prolog
 * - block is the block to be modified
 */
int
BinProtect::instrumentProlog(
		void* addr,
		unsigned char *bytes,
		size_t newBBSize,
		size_t oldBBSize,
		PatchBlock *block)
{
	PatchBlock *oldBlock;
	void *insStartAddr;
	void *insEndAddr;

	info("instrument basic block (prolog): %s", block->format().c_str());

	oldBlock = block;
	insStartAddr = addr;
	insEndAddr = (void*)((unsigned long)insStartAddr + oldBBSize);

	debug("° insStartAddr = 0x%x", (int)insStartAddr);
	debug("° insEndAddr = 0x%x", (int)insEndAddr);
	debug("° oldBlock fmt: %s", oldBlock->format().c_str());


	/* first, the CFG needs to be adjusted, so that additional blocks of
	 * instructions may be included */

	/* split before instruction block to be created */

	/*
	 *                   +----------+                       +----------+
	 *                   | oldBlock |                       |   ...    |
	 *   insStartAddr -> +          +       insStartAddr -> +----------+
	 *                   |          |  =>                   | oldBlock |
	 *     insEndAddr -> +          +         insEndAddr -> +          +
	 *                   |          |                       |          |
	 *                   +----------+                       +----------+
	 */
	if((unsigned int)insStartAddr > (unsigned int)oldBlock->start()) {
		debug("° splitting block (pre) %s at: 0x%x", oldBlock->format().c_str(), (int)insStartAddr);
		oldBlock = PatchModifier::split(oldBlock, (Address)insStartAddr);
		if(!oldBlock) {
			error("cannot split oldBlock %s at: 0x%x", oldBlock->format().c_str(), (int)insStartAddr);
			return -1;
		}
	} else {
		/* no need for splitting block before the instruction: instruction block is already
		 * at the beginning of the initial block */
		debug("° no need for splitting block: instruction at the beginning of the block");
	}

	/* split after instruction block to be created */

	/*
	 *                   +----------+                       +-----------+
	 *                   |   ...    |                       |    ...    |
	 *   insStartAddr -> +----------+       insStartAddr -> +-----------+
	 *                   | oldBlock |  =>                   | oldBlock  |
	 *     insEndAddr -> +          +         insEndAddr -> +-----------+
	 *                   |          |                       | postBlock |
	 *                   +----------+                       +-----------+
	 */
	PatchBlock *postBlock = NULL;
	if((unsigned int)insEndAddr < (unsigned int)oldBlock->end()) {
		debug("° splitting block (post) %s at: 0x%x", oldBlock->format().c_str(), (int)insEndAddr);

		postBlock = PatchModifier::split(oldBlock, (Address)insEndAddr);
		if(!postBlock) {
			error("cannot split block %s at: 0x%x", oldBlock->format().c_str(), (int)insEndAddr);
			return -1;
		}
	} else {
		/* no need for splitting block after the instructions: instruction block is already
		 * at the end of the initial block */
		debug("° no need for splitting block: instruction at the end of the block");
		if(/*old_*/block->targets().size() != 1) {
			error("no target edges in old block");
			return -1;
		}

		PatchEdge *postEdge = *(oldBlock->targets().begin());
		if(postEdge->type() != ParseAPI::FALLTHROUGH) {
			error("Target edge in old block of type '%s'", ParseAPI::format(postEdge->type()).c_str());
			return -1;
		}

		/* define post_block as the next block reachable from old_block */
		postBlock = postEdge->trg();
	}

	debug("° resulted block: %s", oldBlock->format().c_str());

	/* after adjustment of the CFG, we should insert the provided code in form of the raw instruction
	 * bytes into a new instruction block, between 'old_block' and 'post_block' */

	/* insert new code */

	/*
	 *                   +-----------+
	 *                   |    ...    |
	 *   insStartAddr -> +-----------+      +-----------+
	 *                   | oldBlock  |      | newBlock  | <= includes prolog extension
	 *      insEndAddr-> +-----------+      +-----------+
	 *                   | postBlock |
	 *                   +-----------+
	 */

	InsertedCode::Ptr icode = PatchModifier::insert(postBlock->object(), bytes, newBBSize);
	if(icode->blocks().size() < 1) {
		error("cannot insert snippet into block");
		return -1;
	}

	/* create new block including the code snippet */
	PatchBlock *newBlock = icode->entry();
	if(newBlock == NULL) {
		error("cannot create new block");
		return -1;
	}

	/* debug */
//	debug(" * new block constellation:");
//	debug(" * ------------------------");
//	debug(" * pre block:      %s", block->format().c_str());
//	debug(" * affected block: %s", oldBlock->format().c_str());
//	debug(" * post block:     %s", postBlock->format().c_str());
//	debug(" * ------------------------");
//	debug(" * new block:      %s (replaces 'affected block')", newBlock->format().c_str());
//
//	debug("%s", block->disassemble().c_str());
//	debug("%s", oldBlock->disassemble().c_str());
//	debug("%s", newBlock->disassemble().c_str());
//	debug("%s", postBlock->disassemble().c_str());

	/* At this point, we are able to reverse all edges to and from the newly created
	 * instruction block 'newBlock' - this way, we connect the block to the remaining
	 * CFG and hence actually include the code block into the program */

	/*
	 *                   +-----------+
	 *                   |    ...    |-------------+
	 *                   +-----------+             |
	 *                                             v
	 *   insStartAddr -> +-----------+      +-----------+
	 *                   | oldBlock  |      | newBlock  | <= includes prolog extension
	 *                   +-----------+      +-----------+
	 *                                             |
	 *      insEndAddr-> +-----------+             |
	 *                   | postBlock |<------------+
	 *                   +-----------+
	 */

	/* edirect in-edges of 'oldBlock' to the newly created block 'new_block' */
	for (auto e=oldBlock->targets().begin(); e!=oldBlock->targets().end(); e++) {
		debug(" * redirecting: incomming edge %s -> %s (of type '%s') to %s",
				(*e)->src()->format().c_str(), (*e)->trg()->format().c_str(),
				ParseAPI::format((*e)->type()).c_str(), newBlock->format().c_str());

	    bool res = PatchModifier::redirect(*e, newBlock);
	    if(!res){
	    	error("cannot redirect edges");
	    	return -1;
	    }
	}

	/* redirect icode's exit (new_block's exit) to post_block (should be only one exit) */
	if(icode->exits().size() != 1) {
		error("icode has != 1 exit (%d)", icode->exits().size());

		/* show exit edges - for debugging purposes */
		for(auto e=icode->exits().begin(); e!=icode->exits().end(); e++) {
			debug("Exit Edge: %s", (*e)->format().c_str());
		}

		return -1;
	}

	/* normal way: new_block has only one exit */
	debug(" * redirecting: outgoing edge %s -> %s (of type %s) to %s",
			(*icode->exits().begin())->src()->format().c_str(),
			(*icode->exits().begin())->trg()->format().c_str(),
			ParseAPI::format((*icode->exits().begin())->type()).c_str(),
			postBlock->format().c_str());

	if (!PatchModifier::redirect(*icode->exits().begin(), postBlock)) {
		error("cannot redirect edge");
		return -1;
	}

	return 0;
}

/* instrument the basic block including epilog information at the address _addr_
 * - addr represents the address of the instruction, where to split the block
 * - bytes include new prolog instructions to be injected into the function
 * - newBBSize represent the size in bytes of the new prolog
 * - oldBBSize represent the size of the instruction to be replaced with new prolog
 * - block is the block to be modified
 *
 * NOTE: this function is almost (not completely!!) identical to instrument_prolog.
 *       however, we kept this function to be able to test smaller changes within
 *       both implementations in a fast way.
 */
int
BinProtect::instrumentEpilog(
		void* addr,
		unsigned char *bytes,
		size_t newBBSize,
		size_t oldBBSize,
		PatchBlock *block)
{
	/* 'old_block' is a block with initially implemented instructions - without any modifications
	 * except for splitting to the right block size within the process of instrumentation */
	PatchBlock *oldBlock;
	void *insStartAddr;
	void *insEndAddr;

	info("instrument basic block (epilog): %s", block->format().c_str());

	oldBlock = block;
	insStartAddr = addr;
	insEndAddr = (void*)((unsigned int)insStartAddr + oldBBSize);

	debug("° pre_split_addr = %p", (long*)insStartAddr);
	debug("° post_split_addr = %p", (long*)insEndAddr);
	debug("° old_block fmt: %s", oldBlock->format().c_str());

	/* first, the CFG needs to be adjusted, so that additional blocks of
	 * instructions may be included */

	/* split before instruction block to be created */
	if((unsigned int)insStartAddr > (unsigned int)oldBlock->start()) {
		debug("° splitting block %s (pre) at: %p", oldBlock->format().c_str(), (long*)insStartAddr);
		oldBlock = PatchModifier::split(oldBlock, (Address)insStartAddr);
		if(!oldBlock) {
			error("cannot split block %s at: %p", oldBlock->format().c_str(), (long*)insStartAddr);
			return -1;
		}
	} else {
		/* no need for splitting block before the instruction: instruction block is already
		 * at the beginning of the initial block */
		debug("° no need for splitting block: instruction at the beginning of the block");
	}

	/* split after instruction block to be created */
	PatchBlock *postBlock = NULL;
	if((unsigned int)insEndAddr <= (unsigned int)oldBlock->end()) {
		/* TODO: is this needed for epilog? */
		postBlock = oldBlock;
	} else {
		/* no need for splitting block after the instructions: instruction block is already
		 * at the end of the initial block */
		info(" * no need for splitting block (post): instruction at the end of the block");
		if(block->targets().size() != 1) {
			error("No target edges in old block");
			return -1;
		}

		PatchEdge *postEdge = *(oldBlock->targets().begin());
		if(postEdge->type() != ParseAPI::FALLTHROUGH) {
			error("Target edge in old block of type '%s'", ParseAPI::format(postEdge->type()).c_str());
			return -1;
		}

		postBlock = postEdge->trg();
	}

	debug("° resulted block: \n%s", oldBlock->format().c_str());

	/* after adjustment of the CFG, we should insert the provided code in form of the raw instruction
	 * bytes into a new instruction block, between 'old_block' and 'post_block' */
	InsertedCode::Ptr icode = PatchModifier::insert(postBlock->object(), bytes, newBBSize);

	if(icode->blocks().size() < 1) {
		error("cannot insert snippet into block");
		return -1;
	}

	/* create new block including the code snippet */
	PatchBlock *newBlock = icode->entry();
	if(newBlock == NULL) {
		error("cannot create new block");
		return -1;
	}

	/* debugging */
//	debug(" * new block constellation:");
//	debug(" * ------------------------");
//	debug(" * pre block:      %s", block->format().c_str());
//	debug(" * affected block: %s", oldBlock->format().c_str());
//	debug(" * post block:     %s", postBlock->format().c_str());
//	debug(" * ------------------------");
//	debug(" * new block:      %s (replaces 'affected block')", newBlock->format().c_str());
//
//	debug("%s", block->disassemble().c_str());
//	debug("%s", oldBlock->disassemble().c_str());
//	debug("%s", newBlock->disassemble().c_str());
//	debug("%s", postBlock->disassemble().c_str());

	/* At this point, we are able to reverse all edges to and from the newly created
	 * instruction block 'new_block' - this way, we connect the block to the remaining
	 * CFG and hence actually include the code block into the program */

	/* reverse all edges to 'block', right before newly created block 'new_block',
	 * since it is rewritten as well - PatchAPI rewrites the complete initial block
	 * so that every newly created or modified block requires edge redirections */
//	for(auto e=block->sources().begin(); e!=block->sources().end(); e++) {
//		bool res = PatchModifier::redirect(*e, block);
//		if(!res){
//			error("cannot redirect edges of type: %s", (*e)->format().c_str());
//		}
//	}

	/* we need to temporary store the edges in the vector */
	vector<PatchEdge*> edges;
	for(auto i = oldBlock->sources().begin(); i != oldBlock->sources().end(); i++) {
		edges.push_back(*i);
	}

	/* redirect edges from 'pre-block' (or source!!) to the newly created block 'new_block' */
	for(auto e=edges.begin(); e!=edges.end(); e++) {
		debug("° redirecting: incomming edge %s -> %s (of type '%s') to %s",
				(*e)->src()->format().c_str(), (*e)->trg()->format().c_str(),
				ParseAPI::format((*e)->type()).c_str(), newBlock->format().c_str());

		bool res = PatchModifier::redirect(*e, newBlock);
		if(!res){
			error("cannot redirect edges");
			return -1;
		}
	}

	/* redirection of outgoing edges */
	for(auto e=icode->exits().begin(); e!=icode->exits().end(); e++) {
		PatchEdge *out_edge = *e;

		info(" * INFO: outgoing edge %s -> %s (of type %s) to %s",
				out_edge->src()->format().c_str(),
				out_edge->trg()->format().c_str(),
				ParseAPI::format(out_edge->type()).c_str(),
				postBlock->format().c_str());

		if(out_edge->type() == EdgeTypeEnum::COND_TAKEN) {
			debug(" * redirecting: outgoing edge %s -> %s (of type %s) to %s",
					out_edge->src()->format().c_str(),
					out_edge->trg()->format().c_str(),
					ParseAPI::format(out_edge->type()).c_str(),
					postBlock->format().c_str());

			if (!PatchModifier::redirect(out_edge, postBlock)) {
				error("cannot redirect edge");
			}
		}
	}

	return 0;
}
