#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define MIN(A, B) ((A) < (B) ? (A) : (B))

int
xmemcmp(void *s1, size_t l1, void *s2, size_t l2)
{
	return memcmp(s1, s2, MIN(l1, l2));
}

unsigned char*
readfile(char *fp)
{
	FILE *fd;
	struct stat st;
	size_t len, read;
	unsigned char *fc;

	if (stat(fp, &st))
		return NULL;
	len = st.st_size;

	fc = malloc(len + 1);
	if (!fc)
		return NULL;
	if (!(fd = fopen(fp, "r")))
		return NULL;

	read = fread(fc, sizeof(unsigned char), len, fd);
	if (ferror(fd))
		return NULL;
	if (fclose(fd))
		return NULL;

	fc[read] = '\0';
	return fc;
}
