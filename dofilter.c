#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

extern inline uint32_t ld8(const void *pkt, int len, int off)
{
	if (off + 1 <= len) {
		const uint8_t *p = ((const uint8_t *)pkt) + off;
		uint8_t v = *((const uint8_t *)p);

		return v;
	}

	return 0xff;
}

extern inline uint32_t ld16(const void *pkt, int len, int off)
{
	if (off + 2 <= len) {
		const uint8_t *p = ((const uint8_t *)pkt) + off;
		uint16_t v = *((const uint16_t *)p);

//		return ntohs(v);
		return ((v >> 8) & 0xff) | ((v << 8) & 0xff00);
//		return v;
	}

	return 0xffff;
}

extern inline uint32_t ld32(const void *pkt, int len, int off)
{
	if (off + 4 <= len) {
		const uint8_t *p = ((const uint8_t *)pkt) + off;

		if ((off & 3) == 2) {
			uint32_t v = *((const uint32_t *)p);

			if (1) {
				v = (v >> 24) | ((v >> 8) & 0xff00) |
				    ((v << 8) & 0xff0000) | (v << 24);
			}

			return v;
		}

		return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	}

	return 0xffffffff;
}


uint32_t filter(const void *pkt, int off);

int main(int argc, char *argv[])
{
	return filter(argv[0], 128);
}
