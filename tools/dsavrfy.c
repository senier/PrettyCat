#include <err.h>
#include "common.h"

int
main (int argc, char **argv)
{
    int rc;
    gcry_mpi_t mpi;
    gcry_sexp_t signature, value, pub;

    if (argc != 4)
    {
        errx (1, "dsavrfy pubkey_file data_file signature_file");
    }

    sexp_load (argv[1], &pub);
    sexp_load (argv[2], &value);
    sexp_load (argv[3], &signature);

    rc = gcry_pk_verify (signature, value, pub);
    if (rc)
    {
        errx (1, "gcry_pk_verify failed: %s", gcry_strerror (rc));
    }
}
