int usock(char*, char*, sockop);
dtls_context_t* dsock(char*, char*, unsigned char*,
	unsigned char*, int, sockop);

unsigned char* readfile(char*);
int xmemcmp(void*, size_t, void*, size_t);
