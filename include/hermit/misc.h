/****************************************************************************************
 *
 * Author: Stefan Lankes
 *         Chair for Operating Systems, RWTH Aachen University
 * Date:   24/03/2011
 *
 ****************************************************************************************
 * 
 * Written by the Chair for Operating Systems, RWTH Aachen University
 * 
 * NO Copyright (C) 2010, Stefan Lankes,
 * consider these trivial functions to be public domain.
 * 
 * These functions are distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */ 

/** 
 * @author Stefan Lankes
 * @file include/hermit/ctype.h
 * @brief Functions related to alphanumerical character values
 *
 * This file contains functions helping to determine 
 * the type of alphanumerical character values.
 */

#ifndef __MISC_H_
#define __MISC_H_

#include <stddef.h>

extern volatile int libc_sd;
static int soc;
static char** cargv = NULL;
static char **cenviron = NULL;
static int just_a_flag = -1;

int reinitd();
int hermit_lwip_write(int s, const void *data, size_t size);
int hermit_lwip_read(int s, void *mem, size_t len);

#endif
