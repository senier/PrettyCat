#include <err.h>
#include "common.h"

int
main (int argc, char **argv)
{
    int rc;
    gcry_mpi_t mpi;
    gcry_sexp_t sexp;

    if (argc != 3)
    {
        errx (1, "dsasexp data output_file");
    }

    rc = gcry_sexp_build (&sexp, NULL, "(data (flags raw) (value \"foobar\"))", argv[1]);
    if (rc)
    {
        errx (1, "gcry_sexp_build: %s", gcry_strerror (rc));
    }
    sexp_store (argv[2], sexp);
}

