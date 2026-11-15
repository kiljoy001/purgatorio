/*
 *  $Mono -- Monocypher 4.0.2 as an Inferno builtin module.
 *
 *  The C library is the port in libsec/port/monocypher.c (itself from
 *  kiljoy001/factotum-libtab); this file is only the Limbo boundary.
 *  Arrays are copied in and out, so a Dis caller never sees a pointer
 *  into the interpreter heap.
 */

#include "lib9.h"
#include "kernel.h"
#include <isa.h>
#include "interp.h"
#include "runt.h"
#include "monoif.h"
#include "monomod.h"
#include <monocypher.h>

#define KEYLEN		32
#define NONCELEN	24
#define TAGLEN		16
#define SIGLEN		64
#define SEEDLEN		32
#define EDSKLEN		64

static void
freearr(Array **p)
{
	Array *r;

	r = *p;
	*p = H;
	if(r != H)
		destroy(r);
}

static uchar*
abytes(Array *a, int *n)
{
	if(a == H){
		*n = 0;
		return nil;
	}
	*n = a->len;
	return a->data;
}

static void
setarr(Array **p, void *data, int n)
{
	freearr(p);
	*p = mem2array(data, n);
}

static void
badargs(Array **t0, Array **t1, char *msg)
{
	kwerrstr(msg);
	freearr(t0);
	if(t1 != nil)
		freearr(t1);
}

void
Mono_aeadlock(void *fp)
{
	F_Mono_aeadlock *f;
	uchar *k, *no, *ad, *pt, *ct, mac[TAGLEN];
	int kn, non, adn, ptn;

	f = fp;
	k = abytes(f->key, &kn);
	no = abytes(f->nonce, &non);
	ad = abytes(f->ad, &adn);
	pt = abytes(f->plain, &ptn);
	if(kn != KEYLEN || non != NONCELEN){
		badargs(&f->ret->t0, &f->ret->t1,
			"mono: key must be 32 bytes and nonce 24");
		return;
	}
	ct = malloc(ptn > 0 ? ptn : 1);
	if(ct == nil){
		badargs(&f->ret->t0, &f->ret->t1, "mono: out of memory");
		return;
	}
	crypto_aead_lock(ct, mac, k, no, ad, adn, pt, ptn);
	setarr(&f->ret->t0, ct, ptn);
	setarr(&f->ret->t1, mac, TAGLEN);
	free(ct);
}

void
Mono_aeadunlock(void *fp)
{
	F_Mono_aeadunlock *f;
	uchar *k, *no, *tag, *ad, *ct, *pt;
	int kn, non, tagn, adn, ctn;

	f = fp;
	k = abytes(f->key, &kn);
	no = abytes(f->nonce, &non);
	tag = abytes(f->tag, &tagn);
	ad = abytes(f->ad, &adn);
	ct = abytes(f->cipher, &ctn);
	if(kn != KEYLEN || non != NONCELEN || tagn != TAGLEN){
		badargs(f->ret, nil, "mono: bad key, nonce or tag size");
		return;
	}
	pt = malloc(ctn > 0 ? ctn : 1);
	if(pt == nil){
		badargs(f->ret, nil, "mono: out of memory");
		return;
	}
	if(crypto_aead_unlock(pt, tag, k, no, ad, adn, ct, ctn) != 0){
		/* authentication failure: return nil, not an error */
		free(pt);
		freearr(f->ret);
		return;
	}
	setarr(f->ret, pt, ctn);
	free(pt);
}

void
Mono_blake2b(void *fp)
{
	F_Mono_blake2b *f;
	uchar *msg, *key, out[64];
	int msgn, keyn, n;

	f = fp;
	msg = abytes(f->msg, &msgn);
	key = abytes(f->key, &keyn);
	n = f->n;
	if(n < 1 || n > (int)sizeof(out) || keyn > 64){
		badargs(f->ret, nil, "mono: bad digest or key size");
		return;
	}
	if(keyn > 0)
		crypto_blake2b_keyed(out, n, key, keyn, msg, msgn);
	else
		crypto_blake2b(out, n, msg, msgn);
	setarr(f->ret, out, n);
}

void
Mono_x25519(void *fp)
{
	F_Mono_x25519 *f;
	uchar *sk, *pk, out[32];
	int skn, pkn;

	f = fp;
	sk = abytes(f->sk, &skn);
	pk = abytes(f->pk, &pkn);
	if(skn != 32 || pkn != 32){
		badargs(f->ret, nil, "mono: x25519 needs two 32-byte keys");
		return;
	}
	crypto_x25519(out, sk, pk);
	setarr(f->ret, out, 32);
}

void
Mono_xpublic(void *fp)
{
	F_Mono_xpublic *f;
	uchar *sk, out[32];
	int skn;

	f = fp;
	sk = abytes(f->sk, &skn);
	if(skn != 32){
		badargs(f->ret, nil, "mono: x25519 needs a 32-byte key");
		return;
	}
	crypto_x25519_public_key(out, sk);
	setarr(f->ret, out, 32);
}

void
Mono_edkeypair(void *fp)
{
	F_Mono_edkeypair *f;
	uchar *seed, sk[EDSKLEN], pk[32];
	int seedn;

	f = fp;
	seed = abytes(f->seed, &seedn);
	if(seedn != SEEDLEN){
		badargs(&f->ret->t0, &f->ret->t1, "mono: seed must be 32 bytes");
		return;
	}
	crypto_eddsa_key_pair(sk, pk, seed);
	setarr(&f->ret->t0, sk, EDSKLEN);
	setarr(&f->ret->t1, pk, 32);
}

void
Mono_edsign(void *fp)
{
	F_Mono_edsign *f;
	uchar *sk, *msg, sig[SIGLEN];
	int skn, msgn;

	f = fp;
	sk = abytes(f->sk, &skn);
	msg = abytes(f->msg, &msgn);
	if(skn != EDSKLEN){
		badargs(f->ret, nil, "mono: eddsa secret key must be 64 bytes");
		return;
	}
	crypto_eddsa_sign(sig, sk, msg, msgn);
	setarr(f->ret, sig, SIGLEN);
}

void
Mono_edcheck(void *fp)
{
	F_Mono_edcheck *f;
	uchar *sig, *pk, *msg;
	int sign, pkn, msgn;

	f = fp;
	sig = abytes(f->sig, &sign);
	pk = abytes(f->pk, &pkn);
	msg = abytes(f->msg, &msgn);
	if(sign != SIGLEN || pkn != 32){
		*f->ret = 0;
		return;
	}
	*f->ret = crypto_eddsa_check(sig, pk, msg, msgn) == 0;
}

void
Mono_equal(void *fp)
{
	F_Mono_equal *f;
	uchar *a, *b;
	int an, bn, i, diff;

	f = fp;
	a = abytes(f->a, &an);
	b = abytes(f->b, &bn);
	if(an != bn){
		*f->ret = 0;
		return;
	}
	diff = 0;
	for(i = 0; i < an; i++)
		diff |= a[i] ^ b[i];
	*f->ret = diff == 0;
}

void
Mono_version(void *fp)
{
	F_Mono_version *f;

	f = fp;
	retstr("Monocypher 4.0.2", f->ret);
}

void
monomodinit(void)
{
	builtinmod("$Mono", Monomodtab, Monomodlen);
}
