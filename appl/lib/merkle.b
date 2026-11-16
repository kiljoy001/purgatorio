implement Merkle;

include "sys.m";
	sys: Sys;

include "mono.m";
	mono: Mono;

include "merkle.m";

DIGEST:	con 32;
DOMAIN:	con "mono1";

# $Mono is a builtin module; load it on first use so callers do not have
# to remember an init call.
getmono(): int
{
	if(mono != nil)
		return 1;
	mono = load Mono Mono->PATH;
	return mono != nil;
}

# leaf hashes a fixed domain separator, the name, the public key and an
# expiry, so a certificate cannot be relabelled or reused for another
# purpose.
leaf(name: string, pk: array of byte, exp: int): array of byte
{
	if(!getmono())
		return nil;
	n := len DOMAIN + 1 + len name + 1 + len pk + 8;
	b := array[n] of byte;
	off := 0;
	for(i := 0; i < len DOMAIN; i++){
		b[off] = byte DOMAIN[i];
		off++;
	}
	b[off] = byte 0;
	off++;
	for(i = 0; i < len name; i++){
		b[off] = byte name[i];
		off++;
	}
	b[off] = byte 0;
	off++;
	for(i = 0; i < len pk; i++){
		b[off] = pk[i];
		off++;
	}
	for(i = 7; i >= 0; i--){
		b[off] = byte (exp >> (8*i));
		off++;
	}
	return mono->blake2b(b, nil, DIGEST);
}

hashpair(x, y: array of byte): array of byte
{
	if(!getmono())
		return nil;
	c := array[len x + len y] of byte;
	for(i := 0; i < len x; i++)
		c[i] = x[i];
	for(i = 0; i < len y; i++)
		c[len x + i] = y[i];
	return mono->blake2b(c, nil, DIGEST);
}

toarray(l: list of array of byte): array of array of byte
{
	n := 0;
	for(t := l; t != nil; t = tl t)
		n++;
	a := array[n] of array of byte;
	i := 0;
	for(t = l; t != nil; t = tl t){
		a[i] = hd t;
		i++;
	}
	return a;
}

nextlevel(a: array of array of byte): array of array of byte
{
	n := (len a + 1) / 2;
	b := array[n] of array of byte;
	for(i := 0; i < n; i++){
		j := 2*i;
		if(j+1 < len a)
			b[i] = hashpair(a[j], a[j+1]);
		else
			b[i] = a[j];		# odd node is promoted
	}
	return b;
}

root(leaves: list of array of byte): array of byte
{
	a := toarray(leaves);
	if(len a == 0)
		return nil;
	while(len a > 1)
		a = nextlevel(a);
	return a[0];
}

path(leaves: list of array of byte, i: int): list of array of byte
{
	a := toarray(leaves);
	p: list of array of byte;
	idx := i;
	while(len a > 1){
		j := idx ^ 1;
		if(j < len a)
			p = a[j] :: p;
		else
			p = nil :: p;
		idx = idx / 2;
		a = nextlevel(a);
	}
	return reverse(p);
}

verify(h: array of byte, path: list of array of byte, i: int, r: array of byte): int
{
	idx := i;
	for(; path != nil; path = tl path){
		s := hd path;
		if(s != nil){
			if(idx & 1)
				h = hashpair(s, h);
			else
				h = hashpair(h, s);
		}
		idx = idx / 2;
	}
	return mono->equal(h, r);
}

reverse(l: list of array of byte): list of array of byte
{
	r: list of array of byte;
	for(; l != nil; l = tl l)
		r = hd l :: r;
	return r;
}
