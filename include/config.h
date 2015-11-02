#ifndef _WIREPLAY_CONFIG_H
#define _WIREPLAY_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

//#define WIREPLAY_LIBPATH   "lib"

static inline void w_get_lib_path(char **path)
{
#ifdef WIREPLAY_LIBPATH
   char *p = malloc(strlen(WIREPLAY_LIBPATH) + 1);
   assert(p != NULL);
   
   strcpy(p, WIREPLAY_LIBPATH, strlen(WIREPLAY_LIBPATH));
   *path = p;
#else
   char* buf = malloc(1024 * sizeof(char));

   char *cwd = getcwd(buf, 1024);
   char *p = NULL;

   assert(cwd != NULL);
   
   p = malloc(strlen(cwd) + strlen("/lib") + 1);
   assert(p != NULL);

   strcpy(p, cwd);
   strcpy(p + strlen(cwd), "/lib");

   *path = p;
#endif
}

#endif
