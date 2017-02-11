#include <stdio.h>
#include <err.h>
#include "common.h"

void print (FILE *stream, gcry_sexp_t sexp)
{
    size_t size;
    char *buffer;

    size = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buffer = gcry_xmalloc (size);

    gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, buffer, size);
    fprintf (stream, "%.*s", (int)size, buffer);
    gcry_free (buffer);
}

void sexp_store (char *path, gcry_sexp_t sexp)
{
    FILE *f = fopen (path, "w");
    if (!f)
    {
        err (1, "opening key file %s", path);
    }
    print (f, sexp);
}

void sexp_load (char *file, gcry_sexp_t *sexp)
{
    int rc;
    size_t bytes_read;
    char buffer[20000];

    FILE *f = fopen (file, "r");
    if (!f)
    {
        err (1, "loading sexp from %s", file);
    }

    bzero (buffer, sizeof (buffer));
    fread (buffer, sizeof (buffer), 1, f);
    
    rc = gcry_sexp_new (sexp, buffer, 0, 1);
    if (rc)
    {
        errx (1, "Error reading sexp from %s", file);
    }
}
