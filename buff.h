#ifndef BUFF_H
#define BUFF_H

#include <stddef.h>

typedef struct buff {
	char *data;
	size_t write_index;
	size_t read_index;
	size_t cap;
} buff_t;

buff_t* buff_create(size_t cap);
void buff_release(buff_t *buff);
int buff_readfd(buff_t *buff, int fd);
int buff_writefd(buff_t *buff, int fd);
void* buff_read(buff_t *buff, void *dst, size_t size);
void buff_skip(buff_t *buff, size_t size);
int buff_write(buff_t *buff, void *src, size_t size);
int buff_concat(buff_t *front, buff_t *rear);
size_t buff_readable(buff_t *buff);
void buff_clear(buff_t *buff);

#endif // BUFF_H
