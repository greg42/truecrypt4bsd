/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#include <stdio.h>

void hexdump(void* b, unsigned int buflen) {
	unsigned int i;
        unsigned char* buf = (unsigned char*)b;

	for (i = 0; i < buflen; i++) {
		fprintf(stderr, "%.2x ", (unsigned char)buf[i]);
		if ((i+1) % 20 == 0) {
			fprintf(stderr, "\n");
		}
	}
	fprintf(stderr, "\n");
}
