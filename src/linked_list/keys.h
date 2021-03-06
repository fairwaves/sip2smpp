#ifndef KEYS_MAP_H
#define KEYS_MAP_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void free_uli(void **data);
void* copy_uli(const void *data);
long int compare_uli(const void *data1, const void *data2);

///////////////////////
// uint16 (unsigned short)
/////

#define new_uint16()    (uint16_t*)calloc(1,sizeof(uint16_t))

void free_uint16(void **data);
void* copy_uint16(const void *data);
int compare_uint16(const void *data1, const void *data2);

///////////////////////
///////////////////////
// uint32 (unsigned int)
/////

#define new_uint32()    (unsigned int*)calloc(1,sizeof(unsigned int))

void free_uint32(void **data);
void* copy_uint32(const void *data);
int compare_uint32(const void *data1, const void *data2);

///////////////////////
// char* (string)
/////

#define new_string(len)    (unsigned char*)calloc(len+1,sizeof(unsigned char))

void  free_string(void **s);
void* copy_string(const void *s);
int   compare_string(const void *a, const void *b);

///////////////////////
// Key char** (tab string)
/////

void free_tab_string(void **data);

#endif /*KEYS_MAP_H*/
