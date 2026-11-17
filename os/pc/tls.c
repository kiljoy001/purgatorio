/*
 *  $TLS -- TLS 1.2 server sessions from the vendored BearSSL subset.
 *
 *  This is kernel-only: it is compiled into os/pc and registered in
 *  pc.c, so a Dis program can accept a TLS connection without a native
 *  helper.  Certificates are self-signed ECDSA P-256 leaves minted by
 *  certgen; the caller persists the returned DER and scalar.
 *
 *  BearSSL is freestanding, but it uses #if, which 8c's cpp does not
 *  understand.  os/pc builds tls.c in two steps: gcc -E, then 8c.
 */

#define _BEAR9_H
#include "lib9.h"
#include "kernel.h"
#include <isa.h>
#include "interp.h"
#include "runt.h"
#include "tlsif.h"
#include "tlsmod.h"
#include <bearssl.h>
#include <libsec.h>

#define MAXCONN		32
#define CERTMAX		1200
#define KEYLEN		32
#define SIGMAX		80

typedef struct TLSConn TLSConn;
struct TLSConn {
	int		used;
	int		fd;
	unsigned char	*pre;		/* bytes already read off fd */
	int		prelen;
	int		preoff;
	unsigned char	*iobuf;
	unsigned char	*cert;
	size_t		certlen;
	unsigned char	*key;
	size_t		keylen;
	br_x509_certificate chain;
	br_ec_private_key sk;
	br_ssl_server_context sc;
	br_sslio_context ioc;
};

static TLSConn *conns[MAXCONN];

static void ghash_plan9(void*, const void*, const void*, size_t);

void *
br_memcpy(void *d, void *s, ulong n)
{
	uchar *dp, *sp;

	dp = d;
	sp = s;
	while(n-- > 0)
		*dp++ = *sp++;
	return d;
}

static int
seed_rng(const br_prng_class **ctx)
{
	uchar seed[32];

	genrandom(seed, sizeof seed);
	(*ctx)->update(ctx, seed, sizeof seed);
	return 1;
}

br_prng_seeder
br_prng_seeder_system(const char **name)
{
	if(name != nil)
		*name = "inferno";
	return seed_rng;
}

static void
freearr(Array **p)
{
	Array *r;

	r = *p;
	*p = H;
	if(r != H)
		destroy(r);
}

static void
setarr(Array **p, void *data, int n)
{
	freearr(p);
	*p = mem2array(data, n);
}

static void
seterr(String **p, char *msg)
{
	if(*p != H)
		destroy(*p);
	*p = msg == nil ? H : c2string(msg, strlen(msg));
}

static int
tlsrecv(void *ctx, unsigned char *buf, size_t len)
{
	TLSConn *c;
	long n;

	c = ctx;
	if(c->preoff < c->prelen){
		n = c->prelen - c->preoff;
		if(n > len)
			n = len;
		memcpy(buf, c->pre + c->preoff, n);
		c->preoff += n;
		return (int)n;
	}
	release();
	n = kread(c->fd, buf, len);
	acquire();
	if(n <= 0)
		return -1;
	return (int)n;
}

static int
tlssend(void *ctx, const unsigned char *buf, size_t len)
{
	TLSConn *c;
	long n;

	c = ctx;
	release();
	n = kwrite(c->fd, (void*)buf, len);
	acquire();
	if(n <= 0)
		return -1;
	return (int)n;
}

static void
freeconn(TLSConn *c)
{
	if(c == nil)
		return;
	free(c->iobuf);
	free(c->pre);
	free(c->cert);
	free(c->key);
	memset(c, 0, sizeof *c);
}

static int
newconn(void)
{
	int i;

	for(i = 0; i < MAXCONN; i++)
		if(conns[i] == nil || !conns[i]->used)
			return i;
	return -1;
}

/* ---------------------------------------------------------------- */
/* DER certificate                                                   */

typedef struct Der Der;
struct Der {
	unsigned char	b[CERTMAX];
	int		n;
};

static void
dput(Der *d, void *p, int n)
{
	if(d->n + n > CERTMAX)
		return;
	memcpy(d->b + d->n, p, n);
	d->n += n;
}

static void
dbyte(Der *d, int c)
{
	unsigned char x;

	x = c;
	dput(d, &x, 1);
}

static void
dlen(Der *d, int n)
{
	if(n < 128)
		dbyte(d, n);
	else if(n < 256){
		dbyte(d, 0x81);
		dbyte(d, n);
	}else{
		dbyte(d, 0x82);
		dbyte(d, n >> 8);
		dbyte(d, n);
	}
}

static void
dwrap(Der *out, int tag, Der *child)
{
	dbyte(out, tag);
	dlen(out, child->n);
	dput(out, child->b, child->n);
}

static void
dseq(Der *out, Der *child)
{
	dwrap(out, 0x30, child);
}

static void
dset(Der *out, Der *child)
{
	dwrap(out, 0x31, child);
}

static void
doid(Der *out, unsigned char *oid, int n)
{
	dbyte(out, 0x06);
	dlen(out, n);
	dput(out, oid, n);
}

static void
dint(Der *out, unsigned char *p, int n)
{
	while(n > 1 && p[0] == 0){
		p++;
		n--;
	}
	dbyte(out, 0x02);
	if(p[0] & 0x80){
		dlen(out, n + 1);
		dbyte(out, 0);
	}else
		dlen(out, n);
	dput(out, p, n);
}

static void
dbitstr(Der *out, unsigned char *p, int n)
{
	dbyte(out, 0x03);
	dlen(out, n + 1);
	dbyte(out, 0);
	dput(out, p, n);
}

static void
dtime(Der *out, char *ts)
{
	dbyte(out, 0x17);
	dlen(out, 13);
	dput(out, ts, 13);
}

static void
dname(Der *out, char *cn)
{
	unsigned char oidcn[] = { 0x55, 0x04, 0x03 };
	Der o, body, atv, set;

	o.n = 0;
	doid(&o, oidcn, sizeof oidcn);

	body.n = 0;
	dput(&body, o.b, o.n);
	dbyte(&body, 0x13);
	dlen(&body, strlen(cn));
	dput(&body, cn, strlen(cn));

	atv.n = 0;
	dseq(&atv, &body);
	set.n = 0;
	dset(&set, &atv);

	out->n = 0;
	dseq(out, &set);
}

static int
certgen(char *cn, char *notbefore, char *notafter,
	unsigned char *certout, int *certlen,
	unsigned char *keyout, int *keylen)
{
	unsigned char oidec[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
	unsigned char oidecpub[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
	unsigned char oidp256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
	br_hmac_drbg_context rng;
	br_ec_private_key sk;
	br_ec_public_key pk;
	unsigned char seed[32], kbuf[BR_EC_KBUF_PRIV_MAX_SIZE];
	unsigned char pubbuf[BR_EC_KBUF_PUB_MAX_SIZE];
	unsigned char serial[8], hash[32], sig[SIGMAX];
	Der *der, *tbs, *tmp, *name, *val, *spki, *sigalg, *bit;
	Der *cert, *body, *times, *a, *b, *spbody;
	int klen, plen, slen;

	if(strlen(notbefore) != 13 || strlen(notafter) != 13)
		return -1;
	genrandom(seed, sizeof seed);
	br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof seed);
	br_hmac_drbg_generate(&rng, serial, sizeof serial);
	serial[0] &= 0x7f;
	if(serial[0] == 0 && serial[1] == 0)
		serial[0] = 1;

	klen = br_ec_keygen((const br_prng_class **)&rng, &br_ec_p256_m15,
		&sk, kbuf, BR_EC_secp256r1);
	if(klen != KEYLEN)
		return -1;
	plen = br_ec_compute_pub(&br_ec_p256_m15, &pk, pubbuf, &sk);
	if(plen != 65)
		return -1;

	/* The Der values are large; keep them off the small kernel stack. */
	der = mallocz(sizeof(Der) * 14, 1);
	if(der == nil)
		return -1;
	tbs = der + 0;
	tmp = der + 1;
	name = der + 2;
	val = der + 3;
	spki = der + 4;
	sigalg = der + 5;
	bit = der + 6;
	cert = der + 7;
	body = der + 8;
	times = der + 9;
	a = der + 10;
	b = der + 11;
	spbody = der + 12;

	sigalg->n = 0;
	{
		Der alg;

		alg.n = 0;
		doid(&alg, oidec, sizeof oidec);
		dseq(sigalg, &alg);
	}

	dname(name, cn);

	times->n = 0;
	dtime(times, notbefore);
	dtime(times, notafter);
	val->n = 0;
	dseq(val, times);

	a->n = 0;
	doid(a, oidecpub, sizeof oidecpub);
	b->n = 0;
	doid(b, oidp256, sizeof oidp256);
	spbody->n = 0;
	dput(spbody, a->b, a->n);
	dput(spbody, b->b, b->n);
	a->n = 0;
	dseq(a, spbody);
	b->n = 0;
	dbitstr(b, pk.q, pk.qlen);
	spbody->n = 0;
	dput(spbody, a->b, a->n);
	dput(spbody, b->b, b->n);
	spki->n = 0;
	dseq(spki, spbody);

	tbs->n = 0;
	{
		Der ver, verint;
		unsigned char ver2[1] = { 2 };

		verint.n = 0;
		dint(&verint, ver2, 1);
		ver.n = 0;
		dwrap(&ver, 0xa0, &verint);
		dput(tbs, ver.b, ver.n);
	}
	dint(tbs, serial, sizeof serial);
	dput(tbs, sigalg->b, sigalg->n);
	dput(tbs, name->b, name->n);
	dput(tbs, val->b, val->n);
	dput(tbs, name->b, name->n);
	dput(tbs, spki->b, spki->n);

	tmp->n = 0;
	dseq(tmp, tbs);

	{
		br_sha256_context hc;

		br_sha256_init(&hc);
		br_sha256_update(&hc, tmp->b, tmp->n);
		br_sha256_out(&hc, hash);
	}
	slen = br_ecdsa_i15_sign_asn1(&br_ec_p256_m15, &br_sha256_vtable,
		hash, &sk, sig);
	if(slen == 0){
		free(der);
		return -1;
	}

	bit->n = 0;
	dbitstr(bit, sig, slen);

	body->n = 0;
	dput(body, tmp->b, tmp->n);
	dput(body, sigalg->b, sigalg->n);
	dput(body, bit->b, bit->n);
	cert->n = 0;
	dseq(cert, body);

	if(cert->n > *certlen || klen > *keylen){
		free(der);
		return -1;
	}
	memcpy(certout, cert->b, cert->n);
	*certlen = cert->n;
	memcpy(keyout, sk.x, klen);
	*keylen = klen;
	free(der);
	return 0;
}

/* ---------------------------------------------------------------- */
/* Limbo interface                                                   */

/* Common part of accept and acceptpre.  pre, if not nil, holds bytes
 * already consumed from fd (a peeked ClientHello) which tlsrecv replays
 * before reading the socket again. */
static void
acceptconn(int fd, Array *certarr, Array *keyarr, Array *pre,
	int *reth, String **reterr)
{
	TLSConn *c;
	int h;

	*reth = -1;
	*reterr = H;
	if(certarr == H || keyarr == H || keyarr->len != KEYLEN){
		seterr(reterr, "tls: cert/key missing or key is not 32 bytes");
		return;
	}
	h = newconn();
	if(h < 0){
		seterr(reterr, "tls: too many connections");
		return;
	}
	c = mallocz(sizeof *c, 1);
	if(c == nil){
		seterr(reterr, "tls: out of memory");
		return;
	}
	c->iobuf = malloc(BR_SSL_BUFSIZE_BIDI);
	c->cert = malloc(certarr->len);
	c->key = malloc(KEYLEN);
	if(c->iobuf == nil || c->cert == nil || c->key == nil){
		freeconn(c);
		free(c);
		seterr(reterr, "tls: out of memory");
		return;
	}
	if(pre != H && pre->len > 0){
		c->pre = malloc(pre->len);
		if(c->pre == nil){
			freeconn(c);
			free(c);
			seterr(reterr, "tls: out of memory");
			return;
		}
		memcpy(c->pre, pre->data, pre->len);
		c->prelen = pre->len;
	}
	memcpy(c->cert, certarr->data, certarr->len);
	memcpy(c->key, keyarr->data, KEYLEN);
	c->certlen = certarr->len;
	c->keylen = KEYLEN;
	c->fd = fd;
	c->chain.data = c->cert;
	c->chain.data_len = c->certlen;
	c->sk.curve = BR_EC_secp256r1;
	c->sk.x = c->key;
	c->sk.xlen = c->keylen;

	br_ssl_server_zero(&c->sc);
	br_ssl_engine_set_versions(&c->sc.eng, BR_TLS12, BR_TLS12);
	{
		static const unsigned short suites[] = {
			BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		};

		br_ssl_engine_set_suites(&c->sc.eng, suites, 1);
	}
	br_ssl_engine_set_ec(&c->sc.eng, &br_ec_p256_m15);
	br_ssl_server_set_single_ec(&c->sc, &c->chain, 1, &c->sk,
		BR_KEYTYPE_SIGN, 0, &br_ec_p256_m15, br_ecdsa_i15_sign_asn1);
	br_ssl_engine_set_hash(&c->sc.eng, br_sha256_ID, &br_sha256_vtable);
	br_ssl_engine_set_prf_sha256(&c->sc.eng, &br_tls12_sha256_prf);
	br_ssl_engine_set_default_aes_gcm(&c->sc.eng);
	br_ssl_engine_set_ghash(&c->sc.eng, ghash_plan9);
	br_ssl_engine_set_buffer(&c->sc.eng, c->iobuf,
		BR_SSL_BUFSIZE_BIDI, 1);
	br_ssl_server_reset(&c->sc);
	br_sslio_init(&c->ioc, &c->sc.eng, tlsrecv, c, tlssend, c);

	c->used = 1;
	conns[h] = c;
	*reth = h;
}

void
TLS_accept(void *fp)
{
	F_TLS_accept *f;

	f = fp;
	acceptconn(f->fd, f->cert, f->key, H, &f->ret->t0, &f->ret->t1);
}

void
TLS_acceptpre(void *fp)
{
	F_TLS_acceptpre *f;

	f = fp;
	acceptconn(f->fd, f->cert, f->key, f->pre, &f->ret->t0, &f->ret->t1);
}

void
TLS_read(void *fp)
{
	F_TLS_read *f;
	TLSConn *c;
	int n;

	f = fp;
	if(f->h < 0 || f->h >= MAXCONN || (c = conns[f->h]) == nil || !c->used){
		*f->ret = -1;
		return;
	}
	if(f->buf == H || f->buf->len <= 0){
		*f->ret = 0;
		return;
	}
	n = br_sslio_read(&c->ioc, f->buf->data, f->buf->len);
	*f->ret = n;
}

void
TLS_write(void *fp)
{
	F_TLS_write *f;
	TLSConn *c;
	int n;

	f = fp;
	if(f->h < 0 || f->h >= MAXCONN || (c = conns[f->h]) == nil || !c->used){
		*f->ret = -1;
		return;
	}
	if(f->buf == H || f->buf->len <= 0){
		*f->ret = 0;
		return;
	}
	n = br_sslio_write_all(&c->ioc, f->buf->data, f->buf->len);
	*f->ret = n;
}

void
TLS_close(void *fp)
{
	F_TLS_close *f;
	TLSConn *c;

	f = fp;
	if(f->h < 0 || f->h >= MAXCONN || (c = conns[f->h]) == nil || !c->used)
		return;
	br_sslio_close(&c->ioc);
	freeconn(c);
	free(c);
	conns[f->h] = nil;
}

void
TLS_certgen(void *fp)
{
	F_TLS_certgen *f;
	char *cn, *nb, *na;
	unsigned char cert[CERTMAX], key[KEYLEN];
	int certlen, keylen;

	f = fp;
	f->ret->t0 = H;
	f->ret->t1 = H;
	f->ret->t2 = H;
	seterr(&f->ret->t2, nil);
	cn = string2c(f->cn);
	nb = string2c(f->notbefore);
	na = string2c(f->notafter);
	certlen = sizeof cert;
	keylen = sizeof key;
	if(cn == nil || nb == nil || na == nil ||
	   certgen(cn, nb, na, cert, &certlen, key, &keylen) < 0){
		seterr(&f->ret->t2, "tls: certificate generation failed");
		return;
	}
	setarr(&f->ret->t0, cert, certlen);
	setarr(&f->ret->t1, key, keylen);
}

static void
gfmul(unsigned char *x, unsigned char *h)
{
	unsigned char z[16], v[16];
	int i, j, lsb;

	memset(z, 0, sizeof z);
	memcpy(v, h, 16);
	for(i = 0; i < 128; i++){
		if(x[i >> 3] & (0x80 >> (i & 7)))
			for(j = 0; j < 16; j++)
				z[j] ^= v[j];
		lsb = v[15] & 1;
		for(j = 15; j > 0; j--)
			v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
		v[0] >>= 1;
		if(lsb)
			v[0] ^= 0xe1;
	}
	memcpy(x, z, 16);
}

static void
ghash_plan9(void *y, const void *h, const void *data, size_t len)
{
	unsigned char *yy, *hh, blk[16];
	const unsigned char *d;
	int i;

	yy = y;
	hh = (unsigned char*)h;
	d = data;
	while(len > 0){
		if(len >= 16){
			for(i = 0; i < 16; i++)
				yy[i] ^= d[i];
			d += 16;
			len -= 16;
		}else{
			memset(blk, 0, sizeof blk);
			memcpy(blk, d, len);
			for(i = 0; i < 16; i++)
				yy[i] ^= blk[i];
			len = 0;
		}
		gfmul(yy, hh);
	}
}

void
TLS_gcmseal(void *fp)
{
	F_TLS_gcmseal *f;
	Array *key, *nonce, *ad, *plain;
	br_aes_ct_ctr_keys ak;
	br_gcm_context gc;
	unsigned char tag[16], *out, *blob;
	int n;

	f = fp;
	*f->ret = H;
	key = f->key;
	nonce = f->nonce;
	ad = f->ad;
	plain = f->plain;
	if(key == H || nonce == H || plain == H ||
	   key->len != 16 || nonce->len != 12)
		return;
	n = plain->len;
	out = malloc(n ? n : 1);
	blob = malloc(n + 16);
	if(out == nil || blob == nil){
		free(out);
		free(blob);
		return;
	}
	memcpy(out, plain->data, n);
	br_aes_ct_ctr_init(&ak, key->data, 16);
	br_gcm_init(&gc, &ak.vtable, ghash_plan9);
	br_gcm_reset(&gc, nonce->data, 12);
	if(ad != H && ad->len > 0)
		br_gcm_aad_inject(&gc, ad->data, ad->len);
	br_gcm_flip(&gc);
	br_gcm_run(&gc, 1, out, n);
	br_gcm_get_tag(&gc, tag);
	memcpy(blob, out, n);
	memcpy(blob + n, tag, 16);
	*f->ret = mem2array(blob, n + 16);
	free(out);
	free(blob);
}

void
TLS_gcmopen(void *fp)
{
	F_TLS_gcmopen *f;
	Array *key, *nonce, *ad, *cipher;
	br_aes_ct_ctr_keys ak;
	br_gcm_context gc;
	unsigned char *out;
	int n;

	f = fp;
	*f->ret = H;
	key = f->key;
	nonce = f->nonce;
	ad = f->ad;
	cipher = f->cipher;
	if(key == H || nonce == H || cipher == H ||
	   key->len != 16 || nonce->len != 12 || cipher->len < 16)
		return;
	n = cipher->len - 16;
	out = malloc(n ? n : 1);
	if(out == nil)
		return;
	memcpy(out, cipher->data, n);
	br_aes_ct_ctr_init(&ak, key->data, 16);
	br_gcm_init(&gc, &ak.vtable, ghash_plan9);
	br_gcm_reset(&gc, nonce->data, 12);
	if(ad != H && ad->len > 0)
		br_gcm_aad_inject(&gc, ad->data, ad->len);
	br_gcm_flip(&gc);
	br_gcm_run(&gc, 0, out, n);
	if(!br_gcm_check_tag(&gc, cipher->data + n)){
		free(out);
		return;
	}
	*f->ret = mem2array(out, n);
	free(out);
}

void
TLS_sign(void *fp)
{
	F_TLS_sign *f;
	Array *key, *msg;
	br_ec_private_key sk;
	br_sha256_context hc;
	unsigned char hash[32], sig[80];
	size_t slen;
	int n;

	f = fp;
	*f->ret = H;
	key = f->key;
	msg = f->msg;
	if(key == H || key->len != 32)
		return;
	n = msg == H ? 0 : msg->len;
	br_sha256_init(&hc);
	if(n > 0)
		br_sha256_update(&hc, msg->data, n);
	br_sha256_out(&hc, hash);
	sk.curve = BR_EC_secp256r1;
	sk.x = key->data;
	sk.xlen = 32;
	slen = br_ecdsa_i15_sign_asn1(&br_ec_p256_m15, &br_sha256_vtable,
		hash, &sk, sig);
	if(slen == 0)
		return;
	*f->ret = mem2array(sig, slen);
}

void
tlsmodinit(void)
{
	builtinmod("$TLS", TLSmodtab, TLSmodlen);
}
