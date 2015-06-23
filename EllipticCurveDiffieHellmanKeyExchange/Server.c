/*
 ** server.c -- a stream socket server demo
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
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

#define MYPORT 3490    // the port users will be connecting to#define BACKLOG 10     // how many pending connections queue will hold#define MAXDATASIZE 100 // max number of bytes we can get at oncestatic const char rnd_seed[] =
		"string to make the random number generator think it has entropy";

static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen)

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

int main(void) {

	unsigned char *abuf = NULL;
	//const EC_POINT *public_key;
	int i, alen, aout, jj = 0;
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct sockaddr_in my_addr;    // my address information
	struct sockaddr_in their_addr; // connector's address information
	socklen_t sin_size;
	int yes = 1, numbytes;
	char buf[MAXDATASIZE];
	/*//////////////////////////////////////////////////////////////Generating Keys/////////////////////////////////////*/

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
	BIGNUM *x_a = NULL, *y_a = NULL;
	const BIGNUM *BIG = NULL;
	char *buff;
	//unsigned char *abuf=NULL,*bbuf=NULL;

	const EC_GROUP *group;

	a = EC_KEY_new_by_curve_name(nid);
	if (a == NULL)
		goto err;

	group = EC_KEY_get0_group(a);
	//	aa=EC_POINT_new(group);

	if ((x_a = BN_new()) == NULL)
		goto err;
	//BN_new returns a pointer to the bignum
	if ((y_a = BN_new()) == NULL)
		goto err;
	//	if ((BIG=BN_new()) == NULL) goto err;

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

	/*
	 printf("importnt work\n");
	 //BN_print(out,x_a);
	 buff=BN_bn2dec(x_a);
	 printf("%s\n",buff);
	 BN_dec2bn(&(x_a),buff);
	 printf("%s\n",buff);
	 BN_print(out,x_a);
	 */

	/*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	my_addr.sin_family = AF_INET;         // host byte order
	my_addr.sin_port = htons(MYPORT);     // short, network byte order
	my_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
	memset(my_addr.sin_zero, '\0', sizeof my_addr.sin_zero);

	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof my_addr) == -1) {
		perror("bind");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	while (1) {  // main accept() loop
		sin_size = sizeof their_addr;
		if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size))
				== -1) {
			perror("accept");
			continue;
		}
		printf("server: got connection from %s\n",
				inet_ntoa(their_addr.sin_addr));

		if (send(new_fd, "Hello, world!\n", 14, 0) == -1)
			perror("send");

		//	BN_print(out,x_a);
		//  if ((jj=send(new_fd, &aa, sizeof(BIGNUM), 0)) == -1)
		//  perror("send");
		//////////////////////////////////////////////////////////////////////////////
		//printf("side %d\n",sizeof(EC_POINT*));
		//aa= EC_KEY_get0_public_key(a);
		//printf("side %d\n",sizeof(aa));
		// if ((jj=send(new_fd, &aa, sizeof(EC_POINT*), 0)) == -1)
		//perror("send");

		//printf("\nbytes send %d\n",jj);
		////////////////////////////////////////////////////////////////////////////////
		//x_a=(BIGNUM*)&buff;
		//BN_print(out,x_a);
		//printf("%d",sizeof(EC_POINT));
		//buff=(char*)&x_a;
		//if (send(new_fd, &x_a, sizeof(x_a), 0) == -1)
		//perror("send");
		//buff[10]='\0';
		//BIG =EC_KEY_get0_private_key(a);
		//BN_print(out,BIG);
		/*
		 buff=BN_bn2dec(x_a);
		 //	BN_print(out,BIG);
		 buff=(char*)&x_a;
		 //buff[10]='\0';
		 printf("%s\n",buff);
		 x_a=(BIGNUM*)&buff;
		 BN_dec2bn(&(y_a),buff);
		 printf("%s",buff);
		 */
		//sprintf(buff,"%u",EC_KEY_get0_private_key(a));
		//printf("send: %d\n",BIG);
		//printf("%s",buff);
		//printf("%d",strlen(buff));
		// float data1;
		//char  data2[64];
		//BIG=(BIGNUM*)(buff);
		//BIO_puts(out,BIG);
		//memcpy((void*)buff, (void*)EC_KEY_get0_private_key(a), 20);
		//printf("%s",buff);
		//for (i=0; i<10; i++)
		//{
		//printf("%c",buff[i]);
		//BIO_puts(out,buff);
		//}
		//if (send(new_fd,buff,strlen(buff), 0) == -1)
		//      {
		//      perror("send");
		//  }
		//printf("\npublic key send\n");
		/*
		 //EC_POINT *bb;
		 if ((numbytes=recv(new_fd,(char*)&bb,500, 0)) == -1) {
		 perror("recv");
		 exit(1);
		 }
		 printf("\npublic key received\n");
		 */
		/*  if ((numbytes=recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) {
		 perror("recv");
		 exit(1);
		 }
		 */
		//    buf[numbytes] = '\0';
		/*  printf("Received: %d",numbytes);
		 printf("working\n");
		 alen=KDF1_SHA1_len; ///it is a static constant integer.
		 printf("working\n");
		 abuf=(unsigned char *)OPENSSL_malloc(alen);
		 printf("working\n");
		 if(abuf==NULL || bb==NULL || a==NULL)
		 printf("i hate you error\n");
		 aout=ECDH_compute_key(abuf,alen,bb,a,KDF1_SHA1); //generating session key
		 printf("working\n");
		 //      BN_print(out, abuf);
		 //BIO_puts(out,"\n");
		 BIO_puts(out,"  key1 =");
		 for (i=0; i<aout; i++)
		 {
		 sprintf(buf,"%02X",abuf[i]);
		 BIO_puts(out,buf);
		 }
		 BIO_puts(out,"\n");
		 */
		close(new_fd);
		exit(0);
		close(new_fd);  // parent doesn't need this
	}
	err: ERR_print_errors_fp(stderr);
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
