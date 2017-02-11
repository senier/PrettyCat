#include <err.h>
#include <gcrypt.h>

#include "common.h"

int
main (int argc, char **argv)
{
    int rc;
    gcry_sexp_t key_spec, key, pub, priv;

    if (argc != 3)
    {
        errx (1, "dsagen privkey_file pubkey_file");
    }

    rc = gcry_sexp_new (&key_spec, "(genkey (dsa (nbits 4:1024)))", 0, 1);
    if (rc)
    {
        errx (1, gcry_strerror (rc));
    }

    rc = gcry_pk_genkey (&key, key_spec);
    gcry_sexp_release (key_spec);

    if (rc)
    {
        errx (1, gcry_strerror (rc));
    }

    priv = gcry_sexp_find_token (key, "private-key", 0);
    if (!priv)
    {
        errx (1, "No private key");
    }
    sexp_store (argv[1], priv);

    pub = gcry_sexp_find_token (key, "public-key", 0);
    if (!pub)
    {
        errx (1, "No public key");
    }
    sexp_store (argv[2], pub);

}
