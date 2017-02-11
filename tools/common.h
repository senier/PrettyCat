#ifndef _COMMON_H_
#define _COMMON_H_

#include <gcrypt.h>

void sexp_store (char *path, gcry_sexp_t sexp);
void sexp_load (char *file, gcry_sexp_t *sexp);

#endif // _COMMON_H_
