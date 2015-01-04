#include <unistd.h>
#include <getopt.h>

#include <BinProtect.h>
#include <ElfInject.h>
#include <Logging.h>

#define MAX_ARGUMENTS   				10
#define MAX_LEN_NAME   					256
#define INIT_FUNC_NAME					"_init"


/* operation bits */
#define OPERATION_NONE						0
#define OPERATION_BIN_LIST_FUNCS 			1
#define OPERATION_BIN_PROTECT_STACK			2
#define OPERATION_BIN_WRAP_INIT				4
#define OPERATION_ELF_FORTIFY_SOURCE		16
#define OPERATION_ELF_NX_STACK				32
#define OPERATION_ELF_RELRO					64

/* check, whether any binary operation are required */
#define _requiresBinOp(x)					((unsigned char)x & 0x0F)
/* check, whether any ELF operation are required */
#define _requiresElfOp(x)					((unsigned char)(x >> 4))

typedef struct taskOps {
	string mutatee;
	string patch;
	accessType_t type;
	char* progArgv[MAX_ARGUMENTS] = {NULL};

	/* operation flags */
	unsigned char ops;

	/* instances of relevant classes */
	BinProtect *bp;
	ElfInject *elf;
} taskOps_t;
static taskOps_t task;


void
usage(char* progName)
{
	info(" ");
	info("[Usage] %s --binary <bin> [--options <opts>]", progName);
	info("--------------------------------------------------------------------");
	info("[Usage] ...");
}

void
freeRessources()
{
	/* free dynamically allocated memory */
	for(int i=0; i<MAX_ARGUMENTS; i++) {
		if(task.progArgv[i] != NULL) {
			free(task.progArgv[i]);
		}
	}

	if (task.bp) {
		delete(task.bp);
	}

	if (task.elf) {
		delete(task.elf);
	}
}

void
performOperation(unsigned int op)
{
	switch(op) {
	case OPERATION_NONE:
//		debug("operation: none");
		break;

	case OPERATION_BIN_LIST_FUNCS:
		info("operation: list functions");
		task.bp->listFunctions();
		break;

	case OPERATION_BIN_WRAP_INIT:
		info("operation: wrap function %s()", INIT_FUNC_NAME);
		task.bp->wrapFunc(INIT_FUNC_NAME);
		break;

	case OPERATION_BIN_PROTECT_STACK:
		info("operation: protect stack");
		task.bp->protectStack();
		break;

	case OPERATION_ELF_FORTIFY_SOURCE:
		info("operation: fortify source");
		task.elf->reorderDynLibraries();
		break;

	case OPERATION_ELF_NX_STACK:
		info("operation: create NX stack");
		if (_requiresBinOp(task.ops)) {
			task.elf->removeDyninstLib();
		}
		task.elf->fortifyStack();
		break;

	case OPERATION_ELF_RELRO:
		info("operation: create NX stack");
		task.elf->fortifyGOT();
		break;

	default:
		/* not supported: do nothing */
		break;
	}
}

void parseArgv(int argc, char* argv[])
{
	int c = 0;
	task.ops = OPERATION_NONE;
	task.type = at_invalid;

	while (1) {
	    int optionIndex = 0;

	    static struct option longOptions[] = {
	        {"binary",   required_argument, NULL, 'b' },
	        {"patch",	 required_argument, NULL, 'l' },
	        /* type of binary processing */
	        {"type",	 required_argument, NULL, 't' },
	        /* operations */
			{"display",     no_argument,    NULL, 'd' },
			{"nx",       no_argument,       NULL, 'x' },
			{"fortify",  no_argument,       NULL, 'f' },
			{"relro",    no_argument,       NULL, 'r' },
			{"protect",  no_argument,       NULL, 'p' },
	        {0, 0, 0, 0}
	    };

	    c = getopt_long(argc, argv, "b:l:t:dxfrp", longOptions, &optionIndex);
	    if (c == -1)
	        break;

	    switch (c) {

	    /* binary name */
	    case 'b':
	    	task.mutatee = optarg;
	    	task.progArgv[0] = (char*)malloc(MAX_LEN_NAME);
			memset(task.progArgv[0], 0, MAX_LEN_NAME);
			memcpy(task.progArgv[0], task.mutatee.c_str(), task.mutatee.size());
	    	break;

	    /* custom library name */
	    case 'l':
	    	task.patch = optarg;
	    	break;

	    /* type of binary processing: open, create, attach */
	    case 't':
	    	if(!strcmp(optarg, "open")) {
	    		task.type = at_open;
	    	} else if(!strcmp(optarg, "create")) {
	    		task.type = at_create;
	    	} else if(!strcmp(optarg, "at_attach")) {
	    		task.type = at_attach;
	    	}
	        break;

	    /* collect operations in a bit array */
	    case 'd':
	    	task.ops |= OPERATION_BIN_LIST_FUNCS;
	    	break;
	    case 'p':
	    	task.ops |= OPERATION_BIN_PROTECT_STACK;
	    	break;
	    case 'f':
	    	task.ops |= OPERATION_ELF_FORTIFY_SOURCE;
	    	task.ops |= OPERATION_BIN_WRAP_INIT;
	    	break;
	    case 'r':
	    	task.ops |= OPERATION_ELF_RELRO;
	    	task.ops |= OPERATION_BIN_WRAP_INIT;
	    	break;
	    case 'x':
	    	task.ops |= OPERATION_ELF_NX_STACK;
	    	break;


	    /* no arguments provided */
	    default:
	    	usage(argv[0]);
	    	freeRessources();
	    	exit(EXIT_FAILURE);
	    }
	}

	if (task.mutatee.empty()) {
		error("binary is not specified");
		usage(argv[0]);
		freeRessources();
		exit(EXIT_FAILURE);
	}

	if (task.type == at_invalid) {
		debug("type not specified: default 'open'");
		task.type = at_open;
	}
}

int main(int argc, char* argv[])
{
	info(" ");
	info(".:: BinProtect ::.");
	info(" ");

	parseArgv(argc, argv);

	/* first, perform binary-level modifications */

	if (_requiresBinOp(task.ops)) {
		task.bp = new BinProtect(task.mutatee, task.patch);
		task.bp->init(task.type, 0, const_cast<const char**>(task.progArgv));

		performOperation(task.ops & OPERATION_BIN_LIST_FUNCS);
		performOperation(task.ops & OPERATION_BIN_WRAP_INIT);
		performOperation(task.ops & OPERATION_BIN_PROTECT_STACK);

		/* write back changes before further modifications */
		task.bp->finish();
	}

	/* then, perform ELF-level modifications */

	if (_requiresElfOp(task.ops)) {
		if (_requiresBinOp(task.ops)) {
			task.elf = new ElfInject(task.mutatee + "_new");
		} else {
			task.elf = new ElfInject(task.mutatee);
		}
		task.elf->init();

		performOperation(task.ops & OPERATION_ELF_FORTIFY_SOURCE);
		performOperation(task.ops & OPERATION_ELF_NX_STACK);
		performOperation(task.ops & OPERATION_ELF_RELRO);

		task.elf->finish();
	}

	info(" ");
	info(".:: Done ::.");
	info(" ");

	freeRessources();
	return EXIT_SUCCESS;
}
