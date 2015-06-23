/*
 ** client.c -- a stream socket client demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

#define PORT 3490 // the port client will be connecting to#define MAXDATASIZE 100 // max number of bytes we can get at oncestatic const char rnd_seed[] ="string to make the random number generator think it has entropy";static const int KDF1_SHA1_len = 20;static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen)

{
#ifndef OPENSSL_NO_SHA
	if (*outlen < SHA_DIGEST_LENGTH)
		return NULL;
	else
		printf("\nin SHA");
	*outlen = SHA_DIGEST_LENGTH;
	return SHA1(in, inlen, out);
#else
	return NULL;
#endif
}

int main(int argc, char *argv[]) {

	unsigned char *abuf = NULL;
	int alen, aout, i;

	int sockfd, numbytes;
	char recvbuf[MAXDATASIZE];
	struct hostent *he;
	struct sockaddr_in their_addr; // connector's address information
	unsigned long help;

	/*////////////////////////////////////////////////////////////////////////////////////////*/

	BN_CTX *ctx = NULL;
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
	out = BIO_new(BIO_s_file());
	if (out == NULL)
		EXIT(1);
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	nid = NID_X9_62_prime192v1;

	EC_KEY *a = NULL;    //EC_KEY is a structure
	EC_KEY *vv = NULL;
	BIGNUM *x_a = NULL, *y_a = NULL, *z_a = NULL, *a_a = NULL;
	const EC_POINT *aa;
	const BIGNUM *big = NULL;
	char buf[12];
	const EC_GROUP *group;

	a = EC_KEY_new_by_curve_name(nid);
	if (a == NULL)
		goto err;

	group = EC_KEY_get0_group(a);
	aa = EC_POINT_new(group);

	if ((x_a = BN_new()) == NULL)
		goto err;
	//BN_new returns a pointer to the bignum
	if ((y_a = BN_new()) == NULL)
		goto err;

	BIO_puts(out, "Testing key generation with ");
	BIO_puts(out, text);

	if (!EC_KEY_generate_key(a))
		goto err;
	printf("\n1 ) generating keys\n");

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
			== NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group,
				EC_KEY_get0_public_key(a), x_a, y_a, ctx))
			goto err;
	}
	//returns the public key
	else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
				EC_KEY_get0_public_key(a), x_a, y_a, ctx))
			goto err;
	}

	BIO_puts(out, "  pri 1=");
	BN_print(out, EC_KEY_get0_private_key(a));
	BIO_puts(out, "\n  pub 1=");
	BN_print(out, x_a);
	BIO_puts(out, ",");
	BN_print(out, y_a);
	BIO_puts(out, "\n");

	/***********************************************************************************************************************/

	if (argc != 2) {
		fprintf(stderr, "usage: client hostname\n");
		exit(1);
	}

	if ((he = gethostbyname(argv[1])) == NULL) {  // get the host info
		herror("gethostbyname");
		exit(1);
	}

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	their_addr.sin_family = AF_INET;    // host byte order
	their_addr.sin_port = htons(PORT);  // short, network byte order
	their_addr.sin_addr = *((struct in_addr *) he->h_addr);
	memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);

	if (connect(sockfd, (struct sockaddr *) &their_addr, sizeof their_addr)
			== -1) {
		perror("connect");
		exit(1);
	}

	if ((numbytes = recv(sockfd, recvbuf, MAXDATASIZE - 1, 0)) == -1) {
		perror("recv");
		exit(1);
	}

	recvbuf[numbytes] = '\0';

	printf("%s", recvbuf);

	//  if ((numbytes=recv(sockfd, (BIGNUM*)&a_a, MAXDATASIZE-1, 0)) == -1) {
	//    perror("recv");
	//  exit(1);
	//  }

	//if ((numbytes=recv(sockfd,(BIGNUM*)&x_a, MAXDATASIZE-1, 0)) == -1) {
	//      perror("recv");
	//    exit(1);
	//}

	//    recvbuf[numbytes] = '\0';
	///////////////////////////////////////////////////////////////////////////////////
	//if ((numbytes=recv(sockfd, (EC_POINT*)&aa, sizeof(EC_POINT*), 0)) == -1) {
	//      perror("recv");
	//    exit(1);
	//}
	//////////////////////////////////////////////////////////////////////////////////
	printf("received bytes %d\n", numbytes);

	//BN_print(out,z_a);
	//x_a=(BIGNUM*)recvbuf;
	//x_a=(BIGNUM*)&recvbuf;
	//unsigned long au;
	//au=5;
	//const BIGNUM *bignum=NULL;
	//big = EC_KEY_get0_private_key(a);
	//printf("printing big number\n");
	//printf("%ul",big);
	//BN_print(out,big);
	//printf("Received: %s",recvbuf);

	/*
	 if ((numbytes=recv(sockfd,&recvbuf,200, 0)) == -1) {
	 perror("recv");
	 exit(1);
	 }
	 recvbuf[numbytes] = '\0';
	 printf("Received: %d\n",recvbuf);
	 printf("%d",numbytes);
	 printf("\npublic key recieved\n");*/
	//printf("Received: %s",recvbuf);
	//printf("%d",(int*)(aa->X));
	//BIO_puts(out,"  pri 1=");
	//BN_print(out,EC_KEY_get0_private_key(vv));
	/////////////////////////generating session keys//////////////////////////////////
	//alen=KDF1_SHA1_len; ///it is a static constant integer.
	//abuf=(unsigned char *)OPENSSL_malloc(alen);
	//aout=ECDH_compute_key(abuf,alen,aa,a,KDF1_SHA1);
	close(sockfd);
	err:


	if (x_a)
		BN_free(x_a);
	if (y_a)
		BN_free(y_a);
	if (a)
		EC_KEY_free(a);
	if (ctx)
		BN_CTX_free(ctx);
	BIO_free(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);

	return 0;
}
#endif
