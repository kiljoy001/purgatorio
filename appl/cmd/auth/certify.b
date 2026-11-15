implement Certify;

#
# certify -- make and inspect authentication certificates
#
#	A server key and one certificate per user are enough for
#	Inferno's mutual authentication.  No key server, signer or
#	logind daemon is needed: listen(1) checks the peer's
#	certificate against the signer's public key carried in the
#	local certificate, and the client does the same in reverse.
#
#	certify init [owner]		create /keydb/signerkey
#	certify user name [file]	certificate for name
#	certify firstboot		init + the console user's certificate
#	certify show			what exists
#
#	A user's certificate goes to /usr/<name>/keyring/default, which
#	is where listen and rcmd look by default.
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "keyring.m";
	kr: Keyring;

include "security.m";
	auth: Auth;

include "sh.m";
	sh: Sh;

include "arg.m";

include "mono.m";
	mono: Mono;

Certify: module
{
	init:	fn(nil: ref Draw->Context, argv: list of string);
};

SIGNER:	con "/keydb/signerkey";
MONOSIGNER: con "/keydb/mono-signer";
KEYDIR:	con "/keyring";

stderr: ref Sys->FD;
ctxt: ref Draw->Context;

init(drawctxt: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;
	stderr = sys->fildes(2);
	ctxt = drawctxt;

	kr = load Keyring Keyring->PATH;
	if(kr == nil)
		fatal("cannot load " + Keyring->PATH);
	mono = load Mono Mono->PATH;
	if(mono == nil)
		fatal("cannot load " + Mono->PATH);
	auth = load Auth Auth->PATH;
	if(auth == nil)
		fatal("cannot load " + Auth->PATH);
	sh = load Sh Sh->PATH;
	if(sh == nil)
		fatal("cannot load " + Sh->PATH);

	arg := load Arg Arg->PATH;
	if(arg == nil)
		fatal("cannot load " + Arg->PATH);
	arg->init(argv);
	arg->setusage("certify [-f] init [owner] | user name [file] | firstboot | show");
	force := 0;
	while((o := arg->opt()) != 0){
		case o {
		'f' =>
			force = 1;
		* =>
			arg->usage();
		}
	}
	argv = arg->argv();
	if(argv == nil)
		usage();
	arg = nil;

	cmd := hd argv;
	rest := tl argv;

	case cmd {
	"init" =>
		owner := "signer";
		if(rest != nil)
			owner = hd rest;
		if(init_signer(owner) < 0)
			raise "fail:init";
	"user" =>
		if(rest == nil)
			usage();
		name := hd rest;
		file := "";
		if(tl rest != nil)
			file = hd tl rest;
		if(user_cert(name, file, force) < 0)
			raise "fail:user";
	"firstboot" =>
		firstboot(force);
	"show" =>
		show();
	* =>
		usage();
	}
}

usage()
{
	sys->fprint(stderr, "usage: certify init [owner] | user name [file] | firstboot | show\n");
	raise "fail:usage";
}

# Create the signer key.  Everything else is signed by it, so an
# existing key is left alone: replacing it invalidates every
# certificate already issued.
init_signer(owner: string): int
{
	if(statok(SIGNER)){
		sys->print("certify: %s exists, left alone\n", SIGNER);
		return 0;
	}
	if(mkdirp("/keydb") < 0){
		sys->fprint(stderr, "certify: cannot create /keydb: %r\n");
		return -1;
	}
	err := sh->run(ctxt, "/dis/auth/createsignerkey" :: "-f" :: SIGNER :: owner :: nil);
	if(err != nil){
		sys->fprint(stderr, "certify: createsignerkey: %s\n", err);
		return -1;
	}
	if(!statok(SIGNER)){
		sys->fprint(stderr, "certify: %s was not created\n", SIGNER);
		return -1;
	}
	sys->print("certify: signer key for %s in %s\n", owner, SIGNER);
	mono_init_signer();
	return 0;
}

# The EdDSA signer key used by monoauth(8); its public half is sk[32:64].
mono_init_signer()
{
	if(statok(MONOSIGNER)){
		sys->print("certify: %s exists, left alone\n", MONOSIGNER);
		return;
	}
	seed := readrandom(32);
	if(seed == nil){
		sys->fprint(stderr, "certify: cannot read /dev/random\n");
		return;
	}
	(sk, nil) := mono->edkeypair(seed);
	if(sk == nil){
		sys->fprint(stderr, "certify: cannot make the EdDSA signer key\n");
		return;
	}
	if(puts(MONOSIGNER, "sk " + bytes2hex(sk) + "\n") < 0)
		sys->fprint(stderr, "certify: cannot write %s: %r\n", MONOSIGNER);
	else
		sys->print("certify: EdDSA signer key in %s\n", MONOSIGNER);
}

user_cert(name, file: string, force: int): int
{
	if(name == nil || name == ""){
		sys->fprint(stderr, "certify: no user name\n");
		return -1;
	}
	if(file == nil || file == "")
		file = "/usr/" + name + KEYDIR + "/default";
	if(statok(file) && !force){
		sys->fprint(stderr, "certify: %s exists; use -f to replace it\n", file);
		sys->fprint(stderr, "certify: the old certificate stays valid until %s is replaced\n", SIGNER);
		return -1;
	}

	sai := auth->key("key=" + SIGNER);
	if(sai == nil){
		sys->fprint(stderr, "certify: cannot read %s: %r\n", SIGNER);
		return -1;
	}
	if(mkdirp(dirname(file)) < 0){
		sys->fprint(stderr, "certify: cannot create %s: %r\n", dirname(file));
		return -1;
	}

	info := ref Keyring->Authinfo;
	info.alpha = sai.alpha;
	info.p = sai.p;
	info.mysk = kr->genSKfromPK(sai.spk, name);
	info.mypk = kr->sktopk(info.mysk);
	info.spk = sai.mypk;
	pkbuf := array of byte kr->pktostr(info.mypk);
	state := kr->sha1(pkbuf, len pkbuf, nil, nil);
	# expiry 0 means "never"; see certify(8) BUGS about revocation.
	info.cert = kr->sign(sai.mysk, 0, state, "sha1");
	if(kr->writeauthinfo(file, info) < 0){
		sys->fprint(stderr, "certify: cannot write %s: %r\n", file);
		return -1;
	}
	sys->print("certify: %s -> %s\n", name, file);
	mono_user(name, force);
	return 0;
}

# EdDSA identity for monoauth(8): name, secret key, certificate.
mono_user(name: string, force: int)
{
	file := "/usr/" + name + KEYDIR + "/mono";
	if(statok(file) && !force)
		return;
	signer := readmonosigner();
	if(signer == nil)
		return;
	seed := readrandom(32);
	if(seed == nil)
		return;
	(sk, pk) := mono->edkeypair(seed);
	if(sk == nil || pk == nil)
		return;
	# edsign signs name || "\n" || pk, binding the name to the key.
	signed := array[len name + 1 + len pk] of byte;
	for(i := 0; i < len name; i++)
		signed[i] = byte name[i];
	signed[len name] = byte '\n';
	for(i = 0; i < len pk; i++)
		signed[len name + 1 + i] = pk[i];
	cert := mono->edsign(signer, signed);
	if(cert == nil)
		return;
	text := "name " + name + "\n" + "sk " + bytes2hex(sk) + "\n" +
		"cert " + bytes2hex(cert) + "\n";
	if(puts(file, text) < 0)
		sys->fprint(stderr, "certify: cannot write %s: %r\n", file);
	else
		sys->print("certify: %s -> %s\n", name, file);
}

readmonosigner(): array of byte
{
	data := readfile(MONOSIGNER);
	if(data == "")
		return nil;
	for(s := data; len s > 0;){
		(line, rest) := splitline(s);
		s = rest;
		(f, v) := splitfield(line);
		if(f == "sk"){
			sk := hex2bytes(v);
			if(len sk == 64)
				return sk;
		}
	}
	return nil;
}

# First boot: make the box usable without an operator.  A key that is
# generated here is local to this machine, so certificates are not
# shared between hosts; that is the point.
firstboot(force: int)
{
	if(!statok(SIGNER))
		if(init_signer("signer") < 0)
			return;
	mono_init_signer();		# in case only the RSA key existed
	user := trim(readfile("/dev/user"));
	if(user == "")
		user = "inferno";
	if(!statok("/usr/" + user + KEYDIR + "/default"))
		user_cert(user, "", force);
}

show()
{
	sys->print("signer  %s %s\n", SIGNER, exists(SIGNER));
	if(!statok("/usr"))
		return;
	fd := sys->open("/usr", Sys->OREAD);
	if(fd == nil)
		return;
	for(;;){
		(n, dirs) := sys->dirread(fd);
		if(n <= 0)
			break;
		for(i := 0; i < n; i++){
			f := "/usr/" + dirs[i].name + KEYDIR + "/default";
			if(statok(f))
				sys->print("user    %s %s\n", dirs[i].name, f);
		}
	}
	fd = nil;
}

exists(path: string): string
{
	if(statok(path))
		return "ok";
	return "missing";
}

# ---- utilities -------------------------------------------------------

fatal(s: string)
{
	sys->fprint(stderr, "certify: %s: %r\n", s);
	raise "fail:error";
}

statok(path: string): int
{
	(ok, nil) := sys->stat(path);
	return ok >= 0;
}

dirname(path: string): string
{
	for(i := len path - 1; i > 0; i--)
		if(path[i] == '/')
			return path[0:i];
	return ".";
}

# mkdirp creates path and any missing parents.
mkdirp(path: string): int
{
	if(path == nil || path == "" || path == "/")
		return 0;
	if(statok(path))
		return 0;
	if(mkdirp(dirname(path)) < 0)
		return -1;
	if(sys->create(path, Sys->OREAD, Sys->DMDIR|8r777) == nil){
		if(statok(path))
			return 0;
		return -1;
	}
	return 0;
}

readfile(path: string): string
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return "";
	buf := array[256] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return "";
	return string buf[0:n];
}

trim(s: string): string
{
	while(len s > 0 && (s[len s - 1] == '\n' || s[len s - 1] == '\r' ||
			    s[len s - 1] == ' ' || s[len s - 1] == '\t'))
		s = s[0:len s - 1];
	while(len s > 0 && (s[0] == ' ' || s[0] == '\t'))
		s = s[1:];
	return s;
}

# ---- small helpers for the EdDSA identity files ----------------------

readrandom(n: int): array of byte
{
	fd := sys->open("/dev/random", Sys->OREAD);
	if(fd == nil)
		return nil;
	buf := array[n] of byte;
	if(sys->readn(fd, buf, n) != n)
		return nil;
	return buf;
}

puts(path, data: string): int
{
	fd := sys->create(path, Sys->OWRITE, 8r600);
	if(fd == nil)
		return -1;
	n := sys->write(fd, array of byte data, len data);
	fd = nil;
	if(n != len data)
		return -1;
	return 0;
}

bytes2hex(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sys->sprint("%.2x", int a[i]);
	return s;
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

splitline(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '\n')
			return (s[0:i], s[i+1:]);
	return (s, "");
}

splitfield(s: string): (string, string)
{
	i := 0;
	while(i < len s && s[i] != ' ' && s[i] != '\t')
		i++;
	key := s[0:i];
	while(i < len s && (s[i] == ' ' || s[i] == '\t'))
		i++;
	val := s[i:];
	while(len val > 0 && (val[len val-1] == '\r' || val[len val-1] == ' '))
		val = val[0:len val-1];
	return (key, val);
}
