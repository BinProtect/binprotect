/*
 * Logging.h
 *
 *  Created on: 01.01.2015
 *      Author: sergej
 */

#ifndef BINPROTECT_INCLUDE_LOGGING_H_
#define BINPROTECT_INCLUDE_LOGGING_H_

#define DEBUG		1

#define error(fmt, ...)							\
	do { 										\
		fprintf(stderr, "[BinProtect] <<ERR>> | %s (line %d):  ", __FILE__, __LINE__); \
		fprintf(stderr, fmt, ##__VA_ARGS__); 	\
		fprintf(stderr, "\n"); 					\
		/*exit(-1);*/							\
	} while (0)

#define warn(fmt, ...)							\
	do { 										\
		fprintf(stderr, "[BinProtect] <<WRN>> | %s (line %d):  ", __FILE__, __LINE__); \
		fprintf(stderr, fmt, ##__VA_ARGS__); 	\
		fprintf(stderr, "\n"); 					\
		/*exit(-1);*/ 							\
	} while (0)

#define info(fmt, ...)							\
	do { 										\
		fprintf(stdout, "[BinProtect] <<INF>> | "); 	\
		fprintf(stdout, fmt, ##__VA_ARGS__); 	\
		fprintf(stdout, "\n"); 					\
	} while (0)

#if DEBUG
#define debug(fmt, ...)							\
	do { 										\
		fprintf(stdout, "[BinProtect] <<DBG>> | "); \
		fprintf(stdout, fmt, ##__VA_ARGS__); 	\
		fprintf(stdout, "\n"); 					\
	} while (0)
#else
#define debug(fmt, ...) ((void)0)
#endif

#endif /* BINPROTECT_INCLUDE_LOGGING_H_ */
