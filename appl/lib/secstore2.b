implement Secstore2;

include "sys.m";
	sys: Sys;

include "mono.m";
	mono: Mono;

include "secstore2.m";

inited := 0;

init()
{
	if(inited)
		return;
	sys = load Sys Sys->PATH;
	mono = load Mono Mono->PATH;
	if(mono != nil)
		inited = 1;
}

cat(a, b: array of byte): array of byte
{
	r := array[len a + len b] of byte;
	r[0:] = a;
	r[len a:] = b;
	return r;
}

copyarr(a: array of byte): array of byte
{
	if(a == nil)
		return nil;
	b := array[len a] of byte;
	b[0:] = a;
	return b;
}

slice(a: array of byte, off, n: int): array of byte
{
	b := array[n] of byte;
	for(i := 0; i < n; i++)
		b[i] = a[off+i];
	return b;
}

get32(b: array of byte, off: int): int
{
	return int b[off] | (int b[off+1] << 8) |
	       (int b[off+2] << 16) | (int b[off+3] << 24);
}

put32(b: array of byte, off, v: int)
{
	b[off] = byte v;
	b[off+1] = byte (v >> 8);
	b[off+2] = byte (v >> 16);
	b[off+3] = byte (v >> 24);
}

headinit(owner, name: string): ref Head
{
	h := ref Head;
	h.t = DEFT;
	h.m = DEFM;
	h.p = DEFP;
	h.keylen = KEYLEN;
	h.salt = array[SALTLEN] of {* => byte 0};
	h.nonce = array[NONCELEN] of {* => byte 0};
	h.ptxlen = 0;
	h.epoch = 1;
	h.rev = 1;
	h.owner = owner;
	h.name = name;
	h.ownerlen = len owner;
	h.namelen = len name;
	return h;
}

clone(h: ref Head): ref Head
{
	if(h == nil)
		return nil;
	n := ref Head;
	n.t = h.t;
	n.m = h.m;
	n.p = h.p;
	n.keylen = h.keylen;
	n.salt = copyarr(h.salt);
	n.nonce = copyarr(h.nonce);
	n.ptxlen = h.ptxlen;
	n.epoch = h.epoch;
	n.rev = h.rev;
	n.ownerlen = h.ownerlen;
	n.namelen = h.namelen;
	n.owner = h.owner;
	n.name = h.name;
	return n;
}

packhead(h: ref Head, b: array of byte)
{
	b[0] = byte 'S';
	b[1] = byte 'C';
	b[2] = byte '2';
	b[3] = byte 0;
	b[4] = byte VERSION;
	b[5] = byte KDFARGON2ID;
	b[6] = byte AEADXCHACHA;
	b[7] = byte 0;
	put32(b, 8, h.t);
	put32(b, 12, h.m);
	put32(b, 16, h.p);
	put32(b, 20, h.keylen);
	b[24:] = h.salt;
	b[40:] = h.nonce;
	put32(b, 64, h.ptxlen);
	put32(b, 68, h.epoch);
	put32(b, 72, h.rev);
	put32(b, 76, h.ownerlen);
	put32(b, 80, h.namelen);
}

parsehead(in: array of byte): (int, ref Head, string)
{
	if(in == nil || len in < HDRLEN+TAGLEN+DIGLEN)
		return (0, nil, "file too short");
	if(in[0] != byte 'S' || in[1] != byte 'C' || in[2] != byte '2' || in[3] != byte 0)
		return (0, nil, "not a secstore2 file");
	if(int in[4] != VERSION)
		return (0, nil, "unsupported secstore2 version");
	if(int in[5] != KDFARGON2ID || int in[6] != AEADXCHACHA || int in[7] != 0)
		return (0, nil, "unsupported secstore2 algorithms");

	h := ref Head;
	h.t = get32(in, 8);
	h.m = get32(in, 12);
	h.p = get32(in, 16);
	h.keylen = get32(in, 20);
	h.salt = slice(in, 24, SALTLEN);
	h.nonce = slice(in, 40, NONCELEN);
	h.ptxlen = get32(in, 64);
	h.epoch = get32(in, 68);
	h.rev = get32(in, 72);
	h.ownerlen = get32(in, 76);
	h.namelen = get32(in, 80);

	if(h.keylen != KEYLEN)
		return (0, nil, "unsupported key length");
	if(h.ownerlen < 0 || h.ownerlen > OWNERMAX ||
	   h.namelen < 0 || h.namelen > NAMEMAX)
		return (0, nil, "owner or name too long");
	if(h.ptxlen < 0 || h.ptxlen > MAXPT)
		return (0, nil, "plaintext too large");
	if(HDRLEN+h.ownerlen+h.namelen+h.ptxlen+TAGLEN+DIGLEN != len in)
		return (0, nil, "length mismatch (truncated or padded)");

	h.owner = string slice(in, HDRLEN, h.ownerlen);
	h.name = string slice(in, HDRLEN+h.ownerlen, h.namelen);
	return (1, h, nil);
}

derive(h: ref Head, pass: array of byte): (array of byte, string)
{
	init();
	if(mono == nil)
		return (nil, "cannot load Mono");
	if(h == nil || len h.salt != SALTLEN || len h.nonce != NONCELEN)
		return (nil, "bad header");
	if(h.m < MINKIB)
		return (nil, "KDF below the minimum work factor");
	if(h.m > MAXKIB)
		return (nil, "KDF above the maximum work factor");
	if(h.t < 1 || h.t > 64 || h.p < 1 || h.p > 16)
		return (nil, "invalid KDF parameters");
	# the $Mono Argon2 binding is single-lane
	if(h.p != 1)
		return (nil, "unsupported KDF lane count");
	if(h.m < 8*h.p)
		return (nil, "invalid KDF memory/lane ratio");

	master: array of byte;
	{
		master = mono->argon2(pass, h.salt, h.m, h.t);
	} exception e {
	"*" =>
		return (nil, "KDF failed: "+e);
	}
	if(master == nil || len master != 32)
		return (nil, "KDF failed");
	msg := cat(array of byte "secstore2 file", master);
	key := mono->blake2b(msg, nil, KEYLEN);
	mono->wipe(master);
	mono->wipe(msg);
	if(key == nil || len key != KEYLEN)
		return (nil, "hash failed");
	return (key, nil);
}

sealkey(h: ref Head, key: array of byte, plain: array of byte): (array of byte, string)
{
	init();
	if(mono == nil)
		return (nil, "cannot load Mono");
	if(h == nil || len h.salt != SALTLEN || len h.nonce != NONCELEN)
		return (nil, "bad header");
	if(key == nil || len key != KEYLEN)
		return (nil, "bad key");
	owner := array of byte h.owner;
	name := array of byte h.name;
	if(len owner > OWNERMAX || len name > NAMEMAX)
		return (nil, "owner or name too long");
	if(plain == nil)
		plain = array[0] of byte;
	if(len plain > MAXPT)
		return (nil, "plaintext too large");

	hh := clone(h);
	hh.ptxlen = len plain;
	hh.keylen = KEYLEN;
	hh.ownerlen = len owner;
	hh.namelen = len name;

	aadlen := HDRLEN+len owner+len name;
	total := aadlen+len plain+TAGLEN+DIGLEN;
	blob := array[total] of {* => byte 0};
	packhead(hh, blob);
	blob[HDRLEN:] = owner;
	blob[HDRLEN+len owner:] = name;

	(ct, tag) := mono->aeadlock(key, hh.nonce, blob[0:aadlen], plain);
	if(ct == nil || tag == nil)
		return (nil, "encryption failed");
	blob[aadlen:] = ct;
	blob[aadlen+len plain:] = tag;

	d := mono->blake2b(blob[0:total-DIGLEN], nil, DIGLEN);
	if(d == nil)
		return (nil, "digest failed");
	blob[total-DIGLEN:] = d;
	return (blob, nil);
}

seal(h: ref Head, pass: array of byte, plain: array of byte): (array of byte, string)
{
	(key, err) := derive(h, pass);
	if(key == nil)
		return (nil, err);
	(blob, serr) := sealkey(h, key, plain);
	mono->wipe(key);
	return (blob, serr);
}

openkey(in: array of byte, h: ref Head, key: array of byte): (array of byte, string)
{
	init();
	if(mono == nil)
		return (nil, "cannot load Mono");
	if(h == nil || key == nil || len key != KEYLEN)
		return (nil, "bad key");

	d := mono->blake2b(in[0:len in-DIGLEN], nil, DIGLEN);
	if(d == nil || !mono->equal(d, in[len in-DIGLEN:]))
		return (nil, "corrupt file (digest mismatch)");

	aadlen := HDRLEN+h.ownerlen+h.namelen;
	ct := slice(in, aadlen, h.ptxlen);
	tag := slice(in, aadlen+h.ptxlen, TAGLEN);
	pt := mono->aeadunlock(key, h.nonce, tag, in[0:aadlen], ct);
	if(pt == nil)
		return (nil, "wrong password or corrupt file");
	return (pt, nil);
}

open(in: array of byte, pass: array of byte): (array of byte, ref Head, string)
{
	(ok, h, err) := parsehead(in);
	if(!ok)
		return (nil, nil, err);
	(key, kerr) := derive(h, pass);
	if(key == nil)
		return (nil, nil, kerr);
	(pt, oerr) := openkey(in, h, key);
	mono->wipe(key);
	if(pt == nil)
		return (nil, nil, oerr);
	return (pt, h, nil);
}

digest(in: array of byte): array of byte
{
	init();
	if(mono == nil || in == nil)
		return nil;
	return mono->blake2b(in, nil, DIGLEN);
}

samekdf(a, b: ref Head): int
{
	init();
	if(mono == nil)
		return 0;
	if(a == nil || b == nil || len a.salt != len b.salt)
		return 0;
	return a.t == b.t && a.m == b.m && a.p == b.p &&
	       mono->equal(a.salt, b.salt);
}

validname(name: string): int
{
	if(name == nil || len name == 0 || len name > NAMEMAX || name[0] == '.')
		return 0;
	for(i := 0; i < len name; i++){
		c := name[i];
		if(c >= 'a' && c <= 'z')
			continue;
		if(c >= 'A' && c <= 'Z')
			continue;
		if(c >= '0' && c <= '9')
			continue;
		if(c == '.' || c == '_' || c == '-')
			continue;
		return 0;
	}
	return 1;
}

hexval(c: int): int
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

hex(a: array of byte): string
{
	if(a == nil)
		return nil;
	dig := "0123456789abcdef";
	s := "";
	for(i := 0; i < len a; i++){
		v := int a[i];
		s[len s] = dig[v >> 4];
		s[len s] = dig[v & 15];
	}
	return s;
}

unhex(s: string): array of byte
{
	if(s == nil || len s % 2 != 0)
		return nil;
	a := array[len s / 2] of byte;
	for(i := 0; i < len a; i++){
		hi := hexval(s[2*i]);
		lo := hexval(s[2*i+1]);
		if(hi < 0 || lo < 0)
			return nil;
		a[i] = byte ((hi << 4) | lo);
	}
	return a;
}

wipe(a: array of byte)
{
	init();
	if(mono != nil)
		mono->wipe(a);
}
