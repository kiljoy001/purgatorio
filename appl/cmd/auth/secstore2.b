implement Secstore2cmd;

#
# auth/secstore2 -- Monocypher-backed per-user secure store
#
#	auth/secstore2 [-d root] [-u user] [-P pass] [-N newpass] [-e epoch]
#		{init|list|get|put|verify|digest|passwd} [name]
#
include "sys.m";
	sys: Sys;

include "draw.m";

include "arg.m";
	arg: Arg;

include "keyring.m";
	kr: Keyring;

include "security.m";
	random: Random;

include "secstore2.m";
	sc: Secstore2;
	Head: import sc;

Secstore2cmd: module
{
	init:	fn(nil: ref Draw->Context, args: list of string);
};

stderr: ref Sys->FD;
kcok := 0;
kch: ref Head;
kckey: array of byte;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg = load Arg Arg->PATH;
	random = load Random Random->PATH;
	sc = load Secstore2 Secstore2->PATH;
	if(arg == nil || random == nil || sc == nil)
		fail("cannot load modules");
	sc->init();
	stderr = sys->fildes(2);

	arg->init(args);
	arg->setusage("auth/secstore2 [-d root] [-u user] [-P pass] [-N newpass] [-e epoch] cmd [name]");
	root, user, passopt, newopt: string;
	epoch := 0;
	while((o := arg->opt()) != 0)
		case o {
		'd' =>	root = arg->earg();
		'u' =>	user = arg->earg();
		'P' =>	passopt = arg->earg();
		'N' =>	newopt = arg->earg();
		'e' =>	epoch = int arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(args == nil)
		arg->usage();
	cmd := hd args;
	args = tl args;
	name: string;
	if(args != nil)
		name = hd args;
	if(args != nil && tl args != nil)
		arg->usage();

	if(root == nil){
		home := readstr("/env/home");
		if(home == nil || home == "")
			home = "/tmp";
		root = home+"/lib/secstore2";
	}
	if(user == nil){
		user = readstr("/env/SC2_USER");
		if(user == nil || user == "")
			user = readstr("/dev/user");
	}
	if(user == nil || user == "")
		fail("no user");

	dir := root+"/"+user;
	if(mkdirp(root) < 0 || mkdirp(dir) < 0)
		fail(sys->sprint("cannot create %s: %r", dir));

	case cmd {
	"init" =>
		;
	"list" =>
		listfiles(dir);
	"get" =>
		getfile(dir, name, passopt);
	"put" =>
		putfile(dir, user, name, passopt, epoch);
	"verify" =>
		verifyfile(dir, name, passopt);
	"digest" =>
		digestfile(dir, name);
	"passwd" =>
		passwd(dir, passopt, newopt);
	* =>
		arg->usage();
	}
	wipekey();
}

fail(s: string)
{
	wipekey();
	sys->fprint(stderr, "secstore2: %s\n", s);
	raise "fail:error";
}

readstr(path: string): string
{
	a := readfile(path);
	if(a == nil)
		return nil;
	s := string a;
	while(len s > 0 && (s[len s-1] == '\n' || s[len s-1] == ' '))
		s = s[0:len s-1];
	return s;
}

readfile(path: string): array of byte
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return nil;
	return readall(fd);
}

readall(fd: ref Sys->FD): array of byte
{
	out := array[0] of byte;
	buf := array[16*1024] of byte;
	for(;;){
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			return nil;
		if(n == 0)
			break;
		if(len out+n > sc->MAXFILE)
			return nil;
		out = cat(out, buf[0:n]);
	}
	return out;
}

readstdin(): array of byte
{
	return readall(sys->fildes(0));
}

cat(a, b: array of byte): array of byte
{
	r := array[len a+len b] of byte;
	r[0:] = a;
	r[len a:] = b;
	return r;
}

writefile(path: string, data: array of byte): int
{
	fd := sys->create(path, Sys->OWRITE, 8r600);
	if(fd == nil)
		return -1;
	for(o := 0; o < len data;){
		n := sys->write(fd, data[o:], len data-o);
		if(n <= 0)
			return -1;
		o += n;
	}
	return 0;
}

mkdirp(path: string): int
{
	if(path == nil || path == "")
		return 0;
	abs := path[0] == '/';
	p := "";
	(nil, parts) := sys->tokenize(path, "/");
	for(l := parts; l != nil; l = tl l){
		part := hd l;
		if(part == "" || part == ".")
			continue;
		if(p == ""){
			if(abs)
				p = "/"+part;
			else
				p = part;
		}else
			p += "/"+part;
		(ok, d) := sys->stat(p);
		if(ok >= 0){
			if((d.mode & Sys->DMDIR) == 0)
				return -1;
			continue;
		}
		fd := sys->create(p, Sys->OREAD, Sys->DMDIR|8r700);
		if(fd == nil)
			return -1;
	}
	return 0;
}

storepath(dir, name: string): string
{
	return dir+"/"+name;
}

hidden(dir, name, suffix: string): string
{
	return dir+"/."+name+suffix;
}

readblob(dir, name: string): array of byte
{
	b := readfile(storepath(dir, name));
	if(b != nil)
		return b;
	return readfile(hidden(dir, name, ".old"));
}

listnames(dir: string): list of string
{
	fd := sys->open(dir, Sys->OREAD);
	if(fd == nil)
		return nil;
	names: list of string;
	have := "";
	for(;;){
		(n, d) := sys->dirread(fd);
		if(n <= 0)
			break;
		for(i := 0; i < n; i++){
			name := d[i].name;
			if(name == nil || name == "." || name == "..")
				continue;
			if(sc->validname(name)){
				if(!member(names, name))
					names = name :: names;
				continue;
			}
			# a replace cut short may leave only .name.old
			if(len name > 5 && name[0] == '.' &&
			   name[len name-4:] == ".old"){
				base := name[1:len name-4];
				if(!sc->validname(base))
					continue;
				if(readfile(storepath(dir, base)) != nil)
					continue;
				if(!member(names, base))
					names = base :: names;
			}
		}
	}
	return names;
}

member(l: list of string, s: string): int
{
	for(; l != nil; l = tl l)
		if(hd l == s)
			return 1;
	return 0;
}

hexfirst(a: array of byte, n: int): string
{
	if(a == nil || len a < n)
		return nil;
	return sc->hex(a[0:n]);
}

listfiles(dir: string)
{
	for(l := listnames(dir); l != nil; l = tl l){
		name := hd l;
		blob := readblob(dir, name);
		if(blob == nil){
			sys->print("%s  unreadable\n", name);
			continue;
		}
		(ok, h, err) := sc->parsehead(blob);
		if(!ok){
			sys->print("%s  bad header: %s\n", name, err);
			continue;
		}
		dig := hexfirst(blob[len blob-sc->DIGLEN:], 16);
		sys->print("%s  epoch %d  rev %d  ciphertext %d  plain %d  digest %s\n",
			name, h.epoch, h.rev, len blob, h.ptxlen, dig);
	}
}

getfile(dir, name, passopt: string)
{
	if(name == nil)
		fail("get needs a file name");
	blob := readblob(dir, name);
	if(blob == nil)
		fail(name+": cannot open file");
	pass := getpass(passopt, "password: ");
	(pt, h, err) := sc->open(blob, array of byte pass);
	wipe(pass);
	if(pt == nil)
		fail(name+": "+err);
	if(sys->write(sys->fildes(1), pt, len pt) != len pt)
		fail(sys->sprint("write: %r"));
	sc->wipe(pt);
}

verifyfile(dir, name, passopt: string)
{
	if(name == nil)
		fail("verify needs a file name");
	blob := readblob(dir, name);
	if(blob == nil)
		fail(name+": cannot open file");
	pass := getpass(passopt, "password: ");
	(pt, nil, err) := sc->open(blob, array of byte pass);
	wipe(pass);
	if(pt == nil)
		fail(name+": "+err);
	sys->print("ok %d bytes\n", len pt);
	sc->wipe(pt);
}

digestfile(dir, name: string)
{
	if(name == nil)
		fail("digest needs a file name");
	blob := readblob(dir, name);
	if(blob == nil)
		fail(name+": cannot open file");
	sys->print("%s\n", sc->hex(sc->digest(blob)));
}

# One password per store.  Reuse the KDF parameters and salt of the file
# being replaced, or of another file already in the store; only the first
# file in an empty store gets a fresh salt.
putfile(dir, user, name, passopt: string, epoch: int)
{
	if(name == nil)
		fail("put needs a file name");
	if(!sc->validname(name))
		fail(name+": invalid file name");
	plain := readstdin();
	if(plain == nil)
		fail("stdin: read failed");

	refblob: array of byte;
	refname: string;
	rh: ref Head;
	b := readfile(storepath(dir, name));
	if(b != nil){
		(ok, h, err) := sc->parsehead(b);
		if(!ok)
			fail(name+": the existing file is not a secstore2 file; remove it first");
		refblob = b;
		refname = name;
		rh = h;
	}else{
		for(l := listnames(dir); l != nil; l = tl l){
			other := hd l;
			b = readblob(dir, other);
			if(b == nil)
				continue;
			(ok, h, nil) := sc->parsehead(b);
			if(!ok)
				continue;
			refblob = b;
			refname = other;
			rh = h;
			break;
		}
	}

	h := sc->headinit(user, name);
	pass: string;
	if(refblob != nil){
		pass = getpass(passopt, "password: ");
		(key, kerr) := cachedkey(rh, pass);
		if(key == nil){
			wipe(pass);
			fail(refname+": "+kerr);
		}
		(pt, oerr) := sc->openkey(refblob, rh, key);
		if(pt == nil){
			wipe(pass);
			fail(refname+": "+oerr);
			fail("files in a store share one password; change it with passwd");
		}
		sc->wipe(pt);
		h.t = rh.t;
		h.m = rh.m;
		h.p = rh.p;
		h.salt[0:] = rh.salt;
		h.epoch = rh.epoch;
		if(refname == name)
			h.rev = rh.rev+1;
	}else{
		pass = getnewpass(passopt, "password: ");
		salt := random->randombuf(random->ReallyRandom, sc->SALTLEN);
		if(salt == nil || len salt != sc->SALTLEN)
			fail("no randomness available");
		h.salt[0:] = salt;
	}
	if(epoch > 0){
		if(refblob != nil && refname == name && epoch < rh.epoch){
			wipe(pass);
			fail(name+": epoch is lower than the existing file's");
		}
		h.epoch = epoch;
	}
	nonce := random->randombuf(random->ReallyRandom, sc->NONCELEN);
	if(nonce == nil || len nonce != sc->NONCELEN)
		fail("no randomness available");
	h.nonce[0:] = nonce;

	(key, kerr) := cachedkey(h, pass);
	if(key == nil){
		wipe(pass);
		fail(kerr);
	}
	(blob, serr) := sc->sealkey(h, key, plain);
	wipe(pass);
	sc->wipe(plain);
	if(blob == nil)
		fail(name+": "+serr);
	if(writefile(storepath(dir, name), blob) < 0)
		fail(sys->sprint("%s: write failed: %r", name));
}

# Decrypt every file before installing any, then seal them all under one
# new salt, so a wrong password or a sealing failure changes nothing.
passwd(dir, oldopt, newopt: string)
{
	names := listnames(dir);
	if(names == nil){
		sys->print("no files to re-encrypt\n");
		return;
	}
	oldpass := getpass(oldopt, "password: ");

	items: list of (string, array of byte, ref Head);
	for(l1 := names; l1 != nil; l1 = tl l1){
		name := hd l1;
		blob := readblob(dir, name);
		if(blob == nil){
			wipe(oldpass);
			fail(name+": cannot open file");
		}
		(ok, h, perr) := sc->parsehead(blob);
		if(!ok){
			wipe(oldpass);
			fail(name+": "+perr);
		}
		(pt, nil, oerr) := sc->open(blob, array of byte oldpass);
		if(pt == nil){
			wipe(oldpass);
			fail(name+": "+oerr);
		}
		items = (name, pt, h) :: items;
	}
	wipe(oldpass);

	newpass := getnewpass(newopt, "new password: ");
	salt := random->randombuf(random->ReallyRandom, sc->SALTLEN);
	if(salt == nil || len salt != sc->SALTLEN)
		fail("no randomness available");

	blobs: list of (string, array of byte, int);
	for(l2 := items; l2 != nil; l2 = tl l2){
		(name, pt, h) := hd l2;
		nh := sc->clone(h);
		nh.epoch++;
		nh.rev++;
		nh.salt[0:] = salt;
		nonce := random->randombuf(random->ReallyRandom, sc->NONCELEN);
		if(nonce == nil || len nonce != sc->NONCELEN){
			wipe(newpass);
			fail("no randomness available");
		}
		nh.nonce[0:] = nonce;
		(key, kerr) := cachedkey(nh, newpass);
		if(key == nil){
			wipe(newpass);
			fail(kerr);
		}
		(blob, serr) := sc->sealkey(nh, key, pt);
		if(blob == nil){
			wipe(newpass);
			fail(name+": "+serr);
		}
		blobs = (name, blob, nh.epoch) :: blobs;
	}
	wipe(newpass);

	for(l3 := items; l3 != nil; l3 = tl l3){
		(nil, pt, nil) := hd l3;
		sc->wipe(pt);
	}
	for(l4 := blobs; l4 != nil; l4 = tl l4){
		(name, blob, ep) := hd l4;
		if(writefile(storepath(dir, name), blob) < 0)
			fail(sys->sprint("%s: write failed: %r", name));
		sys->print("re-encrypted %s epoch %d\n", name, ep);
	}
}

cachedkey(h: ref Head, pass: string): (array of byte, string)
{
	if(kcok && sc->samekdf(kch, h))
		return (kckey, nil);
	wipekey();
	(key, err) := sc->derive(h, array of byte pass);
	if(key == nil)
		return (nil, err);
	kch = sc->clone(h);
	kckey = key;
	kcok = 1;
	return (key, nil);
}

wipekey()
{
	if(kckey != nil){
		sc->wipe(kckey);
		kckey = nil;
	}
	kch = nil;
	kcok = 0;
}

getpass(opt, prompt: string): string
{
	if(opt != nil)
		return opt;
	return readpassword(prompt);
}

getnewpass(opt, prompt: string): string
{
	if(opt != nil)
		return opt;
	pass := readpassword(prompt);
	if(pass == nil)
		return nil;
	again := readpassword("again: ");
	if(again == nil || pass != again)
		fail("passwords do not match");
	return pass;
}

readpassword(prompt: string): string
{
	cons := sys->open("/dev/cons", Sys->ORDWR);
	if(cons == nil)
		return nil;
	ctl := sys->open("/dev/consctl", Sys->OWRITE);
	if(ctl != nil)
		sys->fprint(ctl, "rawon");
	sys->fprint(cons, "%s", prompt);
	s := "";
	b := array[1] of byte;
	for(;;){
		n := sys->read(cons, b, 1);
		if(n <= 0)
			break;
		c := int b[0];
		if(c == '\n' || c == '\r')
			break;
		if(c == 8 || c == 127){
			if(len s > 0)
				s = s[0:len s-1];
			continue;
		}
		if(c == 21){
			s = "";
			continue;
		}
		s[len s] = c;
	}
	if(ctl != nil)
		sys->fprint(ctl, "rawoff");
	sys->fprint(cons, "\n");
	return s;
}

wipe(s: string)
{
	if(s == nil)
		return;
	for(i := 0; i < len s; i++)
		s[i] = 0;
}
