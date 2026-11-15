implement Monotest;

#
# monotest -- known-answer and round-trip tests for $Mono (Monocypher)
#
#	monotest
#
# Prints one line per test and raises "fail:tests" if any fail, so it
# can gate a build from sh(1).
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "mono.m";
	mono: Mono;

Monotest: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

nfail: int;

init(nil: ref Draw->Context, nil: list of string)
{
	sys = load Sys Sys->PATH;
	mono = load Mono Mono->PATH;
	if(mono == nil){
		sys->print("monotest: cannot load %s: %r\n", Mono->PATH);
		raise "fail:load";
	}

	sys->print("%s\n", mono->version());
	blake2b();
	aead();
	x25519();
	eddsa();

	if(nfail > 0){
		sys->print("%d test(s) failed\n", nfail);
		raise "fail:tests";
	}
	sys->print("all tests passed\n");
}

# BLAKE2b-512("abc"), from the BLAKE2 specification.
blake2b()
{
	want := hex2bytes("ba80a53f981c4d0d6a2797b69f12f6e9" +
			  "4c212f14685ac4b74b12bb6fdbffa2d1" +
			  "7d87c5392aab792dc252d5de4533cc95" +
			  "18d38aa8dbf1925ab92386edd4009923");
	got := mono->blake2b(array of byte "abc", nil, 64);
	check("blake2b abc", mono->equal(got, want));
}

aead()
{
	key := hex2bytes("000102030405060708090a0b0c0d0e0f" +
			 "101112131415161718191a1b1c1d1e1f");
	nonce := hex2bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
	ad := hex2bytes("50515253c0c1c2c3c4c5c6c7");
	pt := array of byte "a secret message";

	(ct, tag) := mono->aeadlock(key, nonce, ad, pt);
	check("aead ciphertext not plaintext", !mono->equal(ct, pt));
	back := mono->aeadunlock(key, nonce, tag, ad, ct);
	check("aead round trip", back != nil && mono->equal(back, pt));

	# any change to the tag must reject the message
	bad := array[16] of byte;
	for(i := 0; i < 16; i++)
		bad[i] = tag[i];
	bad[0] = byte (int bad[0] ^ 1);
	check("aead tampered tag rejected", mono->aeadunlock(key, nonce, bad, ad, ct) == nil);

	# and a change to the associated data
	badad := hex2bytes("50515254c0c1c2c3c4c5c6c7");
	check("aead tampered ad rejected", mono->aeadunlock(key, nonce, tag, badad, ct) == nil);
}

# X25519 is a Diffie-Hellman function: both sides must agree.
x25519()
{
	a := array[32] of byte;
	b := array[32] of byte;
	for(i := 0; i < 32; i++){
		a[i] = byte (i + 1);
		b[i] = byte (16r40 + i);
	}
	base := array[32] of byte;
	base[0] = byte 9;		# RFC 7748 base point u=9

	apub := mono->x25519(a, base);
	bpub := mono->x25519(b, apub);
	if(bpub == nil){
		check("x25519", 0);
		return;
	}
	ashared := mono->x25519(a, mono->x25519(b, base));
	check("x25519 shared secret", mono->equal(ashared, bpub));
}

eddsa()
{
	seed := array[32] of byte;
	for(i := 0; i < 32; i++)
		seed[i] = byte i;
	(sk, pk) := mono->edkeypair(seed);
	if(sk == nil || pk == nil){
		check("eddsa key pair", 0);
		return;
	}
	msg := array of byte "signed in inferno";
	sig := mono->edsign(sk, msg);
	check("eddsa sign/verify", mono->edcheck(sig, pk, msg) == 1);
	check("eddsa changed message rejected",
		mono->edcheck(sig, pk, array of byte "signed in infernO") == 0);
}

# ---- helpers ---------------------------------------------------------

check(name: string, ok: int)
{
	if(ok)
		sys->print("ok   %s\n", name);
	else {
		sys->print("FAIL %s\n", name);
		nfail++;
	}
}

hexval(c: int): int
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return 0;
}

hex2bytes(s: string): array of byte
{
	a := array[len s / 2] of byte;
	for(i := 0; i < len a; i++)
		a[i] = byte ((hexval(s[2*i]) << 4) | hexval(s[2*i+1]));
	return a;
}
