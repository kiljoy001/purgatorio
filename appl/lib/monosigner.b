implement Monosigner;

#
# monosigner -- the monoca signer secret, encrypted at rest
#
# The secret file holds either a plaintext EdDSA key:
#
#	sk <128 hex chars>
#
# or an encrypted record:
#
#	signer 2
#	kdf argon2id
#	salt <hex>	16 bytes
#	blocks 1024	Argon2 work area, in 1 KiB blocks
#	passes 3
#	nonce <hex>	24 bytes
#	tag <hex>	16 bytes
#	ct <hex>	64-byte secret key
#
# The key-encryption key comes from an explicit file, or from
# /n/host/keydb/mono.key when that exists.  Its content is either 32
# bytes of hex or a passphrase; Argon2id derives the record key from it.
# Verifiers never need this file: path+".pub" holds the public key.
#
# The decrypted key lives only in the caller's memory.  Limbo does not
# clear arrays when they are freed, so every intermediate secret is
# wiped with $Mono's wipe.
#

include "sys.m";
	sys: Sys;

include "mono.m";
	mono: Mono;

include "monosigner.m";

DEFAULTKEY:	con "/n/host/keydb/mono.key";
BLOCKS:		con 1024;
PASSES:		con 3;

secret(path, keyfile: string): (array of byte, string)
{
	if(!init())
		return (nil, "cannot load sys or mono");
	s := readfile(path);
	if(s == "")
		return (nil, "cannot read " + path);
	sk, ct, salt, nonce, tag: array of byte;
	blocks := BLOCKS;
	passes := PASSES;
	for(; len s > 0;){
		(rest, line) := nextline(s);
		s = rest;
		(f, v) := splitfield(line);
		case f {
		"sk" => sk = hex2bytes(v);
		"ct" => ct = hex2bytes(v);
		"salt" => salt = hex2bytes(v);
		"nonce" => nonce = hex2bytes(v);
		"tag" => tag = hex2bytes(v);
		"blocks" => blocks = int v;
		"passes" => passes = int v;
		}
	}
	if(sk != nil){
		if(len sk != 64)
			return (nil, path + ": sk must be 64 bytes");
		return (sk, nil);
	}
	if(ct == nil || salt == nil || nonce == nil || tag == nil)
		return (nil, path + ": no sk line and no encrypted record");
	if(len ct != 64 || len nonce != 24 || len tag != 16 || len salt < 8)
		return (nil, path + ": bad encrypted record");
	k := keypath(keyfile);
	if(k == "")
		return (nil, path + ": encrypted and no key file");
	pw := readkey(k);
	if(pw == nil)
		return (nil, "cannot read key " + k);
	key := mono->argon2(pw, salt, blocks, passes);
	mono->wipe(pw);
	if(key == nil)
		return (nil, "argon2 failed");
	out := mono->aeadunlock(key, nonce, tag, nil, ct);
	mono->wipe(key);
	if(out == nil || len out != 64)
		return (nil, path + ": wrong key or corrupt signer");
	return (out, nil);
}

pub(path: string): (array of byte, string)
{
	(l, e) := pubs(path);
	if(l == nil)
		return (nil, e);
	return (hd l, nil);
}

pubs(path: string): (list of array of byte, string)
{
	if(!init())
		return (nil, "cannot load sys or mono");
	s := readfile(path + ".pub");
	if(s != ""){
		l: list of array of byte;
		for(; len s > 0;){
			(rest, line) := nextline(s);
			s = rest;
			(f, v) := splitfield(line);
			if(f == "pk"){
				pk := hex2bytes(v);
				if(len pk == 32)
					l = pk :: l;
			}
		}
		if(l == nil)
			return (nil, path + ".pub: no 32-byte pk line");
		return (l, nil);
	}
	(sk, e) := secret(path, "");
	if(sk == nil)
		return (nil, e);
	return (pkof(sk) :: nil, nil);
}

addpub(path: string, pk: array of byte): string
{
	if(!init())
		return "cannot load sys or mono";
	if(pk == nil || len pk != 32)
		return "monosigner: pk must be 32 bytes";
	h := bytes2hex(pk);
	s := readfile(path + ".pub");
	for(t := s; len t > 0;){
		(rest, line) := nextline(t);
		t = rest;
		(f, v) := splitfield(line);
		if(f == "pk" && v == h)
			return "";
	}
	if(s != "" && s[len s-1] != '\n')
		s += "\n";
	if(writefile(path + ".pub", s + "pk " + h + "\n", 8r644) < 0)
		return "cannot write " + path + ".pub";
	return "";
}

save(path, keyfile: string, sk: array of byte): string
{
	if(!init())
		return "cannot load sys or mono";
	if(sk == nil || len sk != 64)
		return "monosigner: sk must be 64 bytes";
	pk := pkof(sk);
	if(writefile(path + ".pub", "pk " + bytes2hex(pk) + "\n", 8r644) < 0)
		return "cannot write " + path + ".pub";
	k := keypath(keyfile);
	if(k == ""){
		if(writefile(path, "sk " + bytes2hex(sk) + "\n", 8r600) < 0)
			return "cannot write " + path;
		return "";
	}
	pw := readkey(k);
	if(pw == nil)
		return "cannot read key " + k;
	salt := random(16);
	nonce := random(24);
	if(salt == nil || nonce == nil)
		return "cannot read /dev/random";
	key := mono->argon2(pw, salt, BLOCKS, PASSES);
	mono->wipe(pw);
	if(key == nil)
		return "argon2 failed";
	(ct, tag) := mono->aeadlock(key, nonce, nil, sk);
	mono->wipe(key);
	if(ct == nil || tag == nil)
		return "encryption failed";
	text := "signer 2\n" + "kdf argon2id\n" +
		"salt " + bytes2hex(salt) + "\n" +
		"blocks " + string BLOCKS + "\n" +
		"passes " + string PASSES + "\n" +
		"nonce " + bytes2hex(nonce) + "\n" +
		"tag " + bytes2hex(tag) + "\n" +
		"ct " + bytes2hex(ct) + "\n";
	if(writefile(path, text, 8r600) < 0)
		return "cannot write " + path;
	return "";
}

pkof(sk: array of byte): array of byte
{
	if(sk == nil || len sk != 64)
		return nil;
	pk := array[32] of byte;
	for(i := 0; i < 32; i++)
		pk[i] = sk[32+i];
	return pk;
}

keypath(explicit: string): string
{
	if(sys == nil)
		sys = load Sys Sys->PATH;
	if(explicit != "")
		return explicit;
	(ok, nil) := sys->stat(DEFAULTKEY);
	if(ok >= 0)
		return DEFAULTKEY;
	return "";
}

# ---- helpers ---------------------------------------------------------

init(): int
{
	if(sys == nil)
		sys = load Sys Sys->PATH;
	if(mono == nil)
		mono = load Mono Mono->PATH;
	return sys != nil && mono != nil;
}

# readkey returns the key file's bytes: 32 bytes of hex when the file
# holds 64 hex characters (a raw key), otherwise the trimmed text as a
# passphrase.  A "key <hex>" line is also accepted.
readkey(path: string): array of byte
{
	s := readfile(path);
	if(s == "")
		return nil;
	while(len s > 0 && (s[len s-1] == '\n' || s[len s-1] == '\r' || s[len s-1] == ' ' || s[len s-1] == '\t'))
		s = s[0:len s-1];
	if(len s == 64 && ishex(s))
		return hex2bytes(s);
	(f, v) := splitfield(s);
	if(f == "key"){
		s = v;
		while(len s > 0 && (s[len s-1] == '\n' || s[len s-1] == '\r' || s[len s-1] == ' ' || s[len s-1] == '\t'))
			s = s[0:len s-1];
	}
	if(s == "")
		return nil;
	return array of byte s;
}

readfile(path: string): string
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return "";
	buf := array[65536] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return "";
	return string buf[0:n];
}

writefile(path, s: string, mode: int): int
{
	fd := sys->create(path, Sys->OWRITE, mode);
	if(fd == nil)
		return -1;
	if(sys->write(fd, array of byte s, len s) != len s){
		fd = nil;
		return -1;
	}
	fd = nil;
	return 0;
}

random(n: int): array of byte
{
	fd := sys->open("/dev/random", Sys->OREAD);
	if(fd == nil)
		return nil;
	b := array[n] of byte;
	if(sys->readn(fd, b, n) != n){
		fd = nil;
		return nil;
	}
	fd = nil;
	return b;
}

nextline(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '\n')
			return (s[i+1:], s[0:i]);
	return ("", s);
}

splitfield(line: string): (string, string)
{
	i := 0;
	while(i < len line && (line[i] == ' ' || line[i] == '\t'))
		i++;
	j := i;
	while(j < len line && line[j] != ' ' && line[j] != '\t')
		j++;
	k := j;
	while(k < len line && (line[k] == ' ' || line[k] == '\t'))
		k++;
	if(i == j)
		return ("", "");
	return (line[i:j], line[k:]);
}

ishex(s: string): int
{
	for(i := 0; i < len s; i++){
		c := s[i];
		if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
			return 0;
	}
	return 1;
}

hex2bytes(s: string): array of byte
{
	if(len s % 2 != 0 || !ishex(s))
		return nil;
	a := array[len s / 2] of byte;
	for(i := 0; i < len a; i++)
		a[i] = byte ((hexval(s[2*i]) << 4) | hexval(s[2*i+1]));
	return a;
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

bytes2hex(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sys->sprint("%.2x", int a[i]);
	return s;
}
