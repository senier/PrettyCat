#include <err.h>
#include "common.h"

int
main (int argc, char **argv)
{
    int rc;
    gcry_mpi_t mpi;
    gcry_sexp_t signature, value, priv;

    if (argc != 4)
    {
        errx (1, "dsasign privkey_file data_file signature_file");
    }

    sexp_load (argv[1], &priv);

#if 0
    rc = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, argv[2], strlen(argv[2]), NULL);
    if (rc)
    {
        errx (1, "gcry_mpi_scan: %s", gcry_strerror (rc));
    }

    rc = gcry_sexp_build (&value, NULL, "(%m)", mpi);
    if (rc)
    {
        errx (1, "gcry_sexp_build: %s", gcry_strerror (rc));
    }
    gcry_mpi_release (mpi);
#endif

    sexp_load (argv[2], &value);

    rc = gcry_pk_sign (&signature, value, priv);
    if (rc)
    {
        errx (1, "gcry_pk_sign: %s", gcry_strerror (rc));
    }
    sexp_store (argv[3], signature);
}
