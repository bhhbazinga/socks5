#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <assert.h>

#include "buff.h"

/*   +-------------+------------------+------------------+
 *   | prependable |     readable     |     writable     |
 *   +-------------+------------------+------------------+
 *             read_index       writable_index          cap
 */

buff_t* buff_create(size_t cap)
{
	buff_t *buff = (buff_t*)malloc(sizeof(*buff));
	if (buff == NULL) return NULL;
	memset(buff, 0, sizeof(*buff));
	
	char *data = (char*)malloc(cap);
	if (data == NULL) {
		free(buff);
		return NULL;
	}

	buff->write_index = 0;
	buff->read_index = 0;
	buff->cap = cap;
	buff->data = data;

	return buff;
}

void buff_release(buff_t *buff)
{
	free(buff->data);
	free(buff);
}

size_t buff_readable(buff_t *buff)
{
	return buff->write_index - buff->read_index;
}

static size_t buff_prependable(buff_t* buff)
{
	return buff->read_index;
}


static size_t buff_writable(buff_t *buff)
{
	return buff->cap - buff->write_index;
}

static int buff_expand(buff_t *buff)
{
	int newcap = buff->cap * 2;
	char *newdata = realloc(buff->data, newcap);
	if (newdata == NULL) return -1;

	buff->cap = newcap;
	buff->data = newdata;
	return 0;
}

int buff_readfd(buff_t *buff, int fd)
{
	int writable = buff_writable(buff);
	if (writable <= 0) {
		assert(writable == 0);

		if (buff_expand(buff) < 0) return -1;
		writable = buff_writable(buff);
	}

	int n = read(fd, buff->data + buff->write_index, writable);
	if (n <= 0) return n;

	buff->write_index += n;
	return n;
}

int buff_writefd(buff_t *buff, int fd)
{
	int readable = buff_readable(buff);
	int n = write(fd, buff->data + buff->read_index, readable);
	if (n <= 0)	return n;

	buff->read_index += n;
	return n;
}

void* buff_read(buff_t *buff, void *dst, size_t size)
{
	size_t readable = buff_readable(buff);
	assert(size <= readable);

	memcpy(dst, buff->data + buff->read_index, size);
	buff->read_index += size;
	return dst;
}

void buff_skip(buff_t *buff, size_t size)
{
	size_t readable = buff_readable(buff);
	assert(size <= readable);

	buff->read_index += size;
}

/*
 * 1. If writable >= size then append to buff
 * 2. If prepandable + writable >= size then move readable content to 0
 * 3. Otherwise, expand buff
 * 
 * repeat until 1 or 2 satisfied
 */
int buff_write(buff_t *buff, void *src, size_t size)
{
	for(;;) {
		size_t writable = buff_writable(buff);
		if (writable >= size) break;

		size_t prependable = buff_prependable(buff);
		if (prependable + writable >= size) { // move readable content to 0
			int readable = buff_readable(buff);
			memmove(buff->data, buff->data + buff->read_index, readable);
			buff->read_index = 0;
			buff->write_index -= prependable;
			break;
		}

		if (buff_expand(buff) < 0) return -1;
	}

	memcpy(buff->data + buff->write_index, src, size);
	buff->write_index += size;
	return 0;
}

int buff_concat(buff_t *front, buff_t *rear)
{
	return buff_write(front, rear->data + rear->read_index, buff_readable(rear));
}

void buff_clear(buff_t *buff)
{
	buff->write_index = 0;
	buff->read_index = 0;
}
