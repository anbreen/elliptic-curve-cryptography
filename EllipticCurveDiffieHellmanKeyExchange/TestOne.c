#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/e_os.h"
#include <openssl/opensslconf.h>	/* for OPENSSL_NO_ECDH */
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#ifdef OPENSSL_NO_ECDH
int main(int argc, char *argv[])
{
    printf("No ECDH support\n");
    return(0);
}
#else
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK	_far _loadds
#else
#define MS_CALLBACK
#endif

#if 0
static void MS_CALLBACK cb(int p, int n, void *arg);
#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

/*
static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen,   void *out,              size_t *outlen)
//
	{
#ifndef OPENSSL_NO_SHA
	if (*outlen < SHA_DIGEST_LENGTH)
		return NULL;
	else
		*outlen = SHA_DIGEST_LENGTH;
	return SHA1(in, inlen, out);
#else
	return NULL;
#endif
	}

*/
void func(void *bb)
{
}

int main(int argc, char *argv[])
{
void *bb;
	BN_CTX *ctx=NULL;
	int nid;
	BIO *out;
	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	const char *text = "NIST Prime-Curve P-192";

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_malloc_init();
#endif

	RAND_seed(rnd_seed, sizeof rnd_seed);
	out=BIO_new(BIO_s_file());
	if (out == NULL) EXIT(1);
	BIO_set_fp(out,stdout,BIO_NOCLOSE);

	if ((ctx=BN_CTX_new()) == NULL) goto err;
	nid = NID_X9_62_prime192v1;

	//EC_POINT *bb;
	EC_KEY *a=NULL;    //EC_KEY is a structure
	BIGNUM *x_a=NULL, *y_a=NULL;

	char buf[12];
	//unsigned char *abuf=NULL,*bbuf=NULL;
	int i,alen,blen,aout,bout;
	const EC_GROUP *group;

	a = EC_KEY_new_by_curve_name(nid);
	if (a == NULL)
	goto err;

	group = EC_KEY_get0_group(a);

	if ((x_a=BN_new()) == NULL) goto err;    //BN_new returns a pointer to the bignum
	if ((y_a=BN_new()) == NULL) goto err;


	BIO_puts(out,"Testing key generation with ");
	BIO_puts(out,text);


	if (!EC_KEY_generate_key(a)) goto err;
	printf("\n1 ) generating keys\n");

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
		{
		if (!EC_POINT_get_affine_coordinates_GFp(group,EC_KEY_get0_public_key(a), x_a, y_a, ctx)) goto err;
		}
                                                                  //returns the public key
	else
		{
		if (!EC_POINT_get_affine_coordinates_GF2m(group,EC_KEY_get0_public_key(a), x_a, y_a, ctx)) goto err;
		}

	BIO_puts(out,"  pri 1=");
	BN_print(out,EC_KEY_get0_private_key(a));
	BIO_puts(out,"\n  pub 1=");
	BN_print(out,x_a);
	BIO_puts(out,",");
	BN_print(out,y_a);
	BIO_puts(out,"\n");


func(EC_KEY_get0_public_key(a));

err:
	ERR_print_errors_fp(stderr);

	if (x_a) BN_free(x_a);
	if (y_a) BN_free(y_a);
	if (a) EC_KEY_free(a);
	if (ctx) BN_CTX_free(ctx);
	BIO_free(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);
return 0;

}


#endif


