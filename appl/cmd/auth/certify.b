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

Certify: module
{
	init:	fn(nil: ref Draw->Context, argv: list of string);
};

SIGNER:	con "/keydb/signerkey";
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
	return 0;
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
	return 0;
}

# First boot: make the box usable without an operator.  A key that is
# generated here is local to this machine, so certificates are not
# shared between hosts; that is the point.
firstboot(force: int)
{
	if(!statok(SIGNER))
		if(init_signer("signer") < 0)
			return;
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
