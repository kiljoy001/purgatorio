implement InitShell;

include "sys.m";
include "draw.m";

sys: Sys;
gateway: string;		# default route from net.conf, if any

InitShell: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

Sh: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

Timed: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

Cs: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

Dns: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

Mount: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

Svcd: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

Certify: module
{
	init:	fn(nil: ref Draw->Context, argv: list of string);
};

init(drawcontext: ref Draw->Context, nil: list of string)
{
	shell := load Sh "/dis/sh.dis";

	sys = load Sys Sys->PATH;

	if(sys != nil)
		sys->print("init: starting shell\n");

	# Replace the embedded bootstrap root with the persistent kfs64
	# filesystem on the virtio-blk disk.  If the disk is missing or
	# blank the mount fails and we stay on the embedded root.
	rootmount(drawcontext);

	# The 9vm host shares its filesystem over a 9P ring (#~/host).
	# Best effort: kernels without the ring simply keep going.
	hostmount(drawcontext);

	sys->bind("#l", "/net", sys->MAFTER);	# ethernet
	sys->bind("#I", "/net", sys->MAFTER);	# IP
	sys->bind("#p", "/prog", sys->MREPL);	# prog device
	sys->bind("#d", "/fd", Sys->MREPL);
	sys->bind("#s", "/chan", sys->MREPL);	# srv (file2chan)
	sys->bind("#i", "/dev", sys->MREPL); 	# draw device
	sys->bind("#t", "/dev", sys->MAFTER);	# serial line
	sys->bind("#c", "/dev", sys->MAFTER); 	# console device
	sys->bind("#W","/dev",sys->MAFTER);	# Flash
	sys->create("/net.alt", Sys->OREAD, 8r777|Sys->DMDIR);

	# The root image's /dis is read-only.  A writable overlay, bound
	# after it, is where the control page installs dropped programs.
	if(sys->create("/dislocal", Sys->OREAD, Sys->DMDIR|8r777) == nil)
		;	# already there
	sys->bind("/dislocal", "/dis", Sys->MAFTER);
#	sys->bind("#O", "/dev", sys->MAFTER);	# Modem
#	sys->bind("#T","/dev",sys->MAFTER);	# Touchscreen

	selectjit();
	loopback();
	netstart();
	setclock();
	timedstart(drawcontext);
	firstboot();
	svcstart();
	sys->sleep(500);
	dnsstart(drawcontext);
	srv();

	spawn shell->init(nil, "sh" :: "-n" :: nil);
}

# Mount the kfs64 on the virtio-blk disk as the root filesystem.
# Done in the init process so that the shell is created with the new
# root already in place (and so the device binds below land on it).
rootmount(ctxt: ref Draw->Context)
{
	mount := load Mount "/dis/mount.dis";
	if(mount == nil){
		sys->print("init: cannot load mount: %r; using embedded root\n");
		return;
	}
	mounted := 0;
	{
		mount->init(ctxt, "mount" :: "-c" :: "{disk/kfs64 '#S/sd00/data'}" :: "/" :: nil);
		mounted = 1;
	} exception {
	"*" =>
		mounted = 0;
	}
	if(mounted)
		sys->print("init: mounted kfs64 root from #S/sd00/data\n");
	else
		sys->print("init: root mount failed; using embedded root\n");
}

# Mount the 9vm host filesystem served on the shared 9P ring at /n/host.
hostmount(ctxt: ref Draw->Context)
{
	mount := load Mount "/dis/mount.dis";
	fd: ref Sys->FD;

	if(mount == nil){
		sys->print("init: cannot load mount: %r\n");
		return;
	}
	fd = sys->open("#~/host", Sys->ORDWR);
	if(fd == nil){
		sys->print("init: no 9ring host transport: %r\n");
		return;
	}
	fd = nil;
	if(sys->create("/n/host", Sys->OREAD, Sys->DMDIR|8r777) == nil)
		;	# already there
	{
		mount->init(ctxt, "mount" :: "-A" :: "#~/host" :: "/n/host" :: nil);
		sys->print("init: mounted 9ring host at /n/host\n");
	} exception {
	"*" =>
		sys->print("init: 9ring host mount failed: %r\n");
	}
}

# Bring up 127.0.0.1.  Every host needs it: remote execution and file
# services are usually tested locally before they face the network.
loopback()
{
	cfd := sys->open("/net/ipifc/clone", Sys->ORDWR);
	if(cfd == nil){
		sys->print("init: no /net/ipifc/clone: %r\n");
		return;
	}
	buf := array[32] of byte;
	n := sys->read(cfd, buf, len buf);
	cfd = nil;
	if(n <= 0){
		sys->print("init: cannot clone a loopback interface\n");
		return;
	}
	# The clone file returns the interface number as decimal text.
	i := 0;
	while(i < n && buf[i] >= byte '0' && buf[i] <= byte '9')
		i++;
	if(i == 0)
		return;
	num := string buf[0:i];
	ctl := sys->open("/net/ipifc/" + num + "/ctl", Sys->OWRITE);
	if(ctl == nil){
		sys->print("init: cannot open /net/ipifc/%s/ctl: %r\n", num);
		return;
	}
	if(sys->fprint(ctl, "bind loopback") < 0 ||
	   sys->fprint(ctl, "add 127.0.0.1 255.0.0.0") < 0)
		sys->print("init: loopback setup failed: %r\n");
	else
		sys->print("init: loopback 127.0.0.1\n");
	ctl = nil;
}

# The hypervisor gives the guest no RTC, so the clock starts at 1970.
# 9vm serves its clock at /n/host/time as microseconds since the epoch
# (older hosts published seconds); read it and set /dev/time, without
# which every certificate expiry check is meaningless.
setclock()
{
	fd := sys->open("/n/host/time", Sys->OREAD);
	if(fd == nil){
		sys->print("init: no /n/host/time; clock left at boot time\n");
		return;
	}
	buf := array[32] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return;
	s := string buf[0:n];
	e := big 0;
	for(i := 0; i < len s && s[i] >= '0' && s[i] <= '9'; i++)
		e = e*big 10 + big (s[i] - '0');
	if(e <= big 0)
		return;
	# A value below 1e11 is seconds (the old format); anything larger is
	# already microseconds.
	if(e < big 100000000000)
		e *= big 1000000;
	cfd := sys->open("/dev/time", Sys->OWRITE);
	if(cfd == nil){
		sys->print("init: cannot open /dev/time: %r\n");
		return;
	}
	if(sys->fprint(cfd, "%bd", e) < 0)
		sys->print("init: cannot set the clock: %r\n");
	else
		sys->print("init: clock set from host to %bd\n", e / big 1000000);
	cfd = nil;
}

# The Dis JIT (cflag in os/port/dis.c) is on by default.  /n/host/jit
# overrides it for a boot: 0 runs the interpreter, 1 compiles modules on
# load.  The console can also write /dev/jit directly.
selectjit()
{
	fd := sys->open("/n/host/jit", Sys->OREAD);
	if(fd == nil)
		return;
	buf := array[8] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	i := 0;
	while(i < n && (buf[i] == byte ' ' || buf[i] == byte '\t' || buf[i] == byte '\n'))
		i++;
	if(i >= n || (buf[i] != byte '0' && buf[i] != byte '1'))
		return;
	v := string buf[i:i+1];
	if((jfd := sys->open("/dev/jit", Sys->OWRITE)) != nil){
		if(sys->fprint(jfd, "%s", v) > 0){
			if(v == "1")
				sys->print("init: Dis JIT on\n");
			else
				sys->print("init: Dis JIT off\n");
		}
		jfd = nil;
	}
}

# First boot: create the signer key and the console user's certificate
# if they are missing.  Every box gets its own key, so certificates are
# not shared between machines; the cost is that a client has to be given
# a certificate out of band, exactly like an ssh host key.
firstboot()
{
	c := load Certify "/dis/auth/certify.dis";
	if(c == nil){
		sys->print("init: no /dis/auth/certify.dis: %r; no certificates\n");
		return;
	}
	{
		c->init(nil, "certify" :: "firstboot" :: nil);
	} exception {
	"*" =>
		sys->print("init: firstboot certification failed\n");
	}
}

# Start the service manager.  It reads /lib/svcd.conf, or the host's
# /n/host/svcd.conf when present, and is responsible for everything
# that is not the console shell.  A root without svcd.dis (an old
# image) simply keeps the shell.
svcstart()
{
	svcd := load Svcd "/dis/svcd.dis";
	if(svcd == nil){
		sys->print("init: no /dis/svcd.dis: %r; no services\n");
		return;
	}
	spawn svcd->init(nil, "svcd" :: nil);
}

# Connection server: resolves names from the ndb files.  ndb/dns is
# not started in the native kernel yet (its UDP path faults), so
# unqualified sys= names resolve and domain names do not.
# True if a dns= resolver is configured (net.conf -> /net/ndb, or
# /lib/ndb/local).  Without one, dns would recurse from the roots,
# which the native kernel cannot do yet; cs alone still resolves the
# sys= names in the ndb files.
dnsconfigured(): int
{
	if(hasedns("/net/ndb"))
		return 1;
	return hasedns("/lib/ndb/local");
}

hasedns(path: string): int
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return 0;
	buf := array[4096] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return 0;
	(nil, lines) := sys->tokenize(string buf[0:n], "\n");
	for(; lines != nil; lines = tl lines){
		l := hd lines;
		while(len l > 0 && (l[0] == ' ' || l[0] == '\t'))
			l = l[1:];
		if(len l >= 4 && l[0:4] == "dns=")
			return 1;
	}
	return 0;
}

dnsstart(ctxt: ref Draw->Context)
{
	if(dnsconfigured() || gateway != nil){
		d := load Dns "/dis/ndb/dns.dis";
		if(d == nil)
			sys->print("init: no /dis/ndb/dns.dis: %r\n");
		else{
			# -h: no host resolver; -r: forward to dns=;
			# -d: ordinary UDP (no hosted header layout).
			spawn d->init(ctxt, "dns" :: "-h" :: "-r" :: "-d" :: nil);
			if(dnsconfigured())
				sys->print("init: dns forwarding\n");
			else
				sys->print("init: dns recursing\n");
		}
	}
	c := load Cs "/dis/ndb/cs.dis";
	if(c == nil){
		sys->print("init: no /dis/ndb/cs.dis: %r\n");
		return;
	}
	spawn c->init(ctxt, "cs" :: nil);
}

# Wall-clock service: boot source, SNTP when configured, and the
# /n/time/{now,status,ctl} namespace.
timedstart(ctxt: ref Draw->Context)
{
	t := load Timed "/dis/timed.dis";
	if(t == nil){
		sys->print("init: no /dis/timed.dis: %r\n");
		return;
	}
	spawn t->init(ctxt, "timed" :: nil);
}

# Optional per-VM network and payload configuration:
#   ip=10.0.0.2
#   mask=255.255.255.0
#   cmd=listen -A tcp!*!5750 {/n/host/payload.dis 0}
# The file is served by 9vm at /n/host/net.conf.
netstart()
{
	fd: ref Sys->FD;
	buf: array of byte;
	n: int;
	ip, mask, cmd, dns: string;
	nlines: int;
	lines: list of string;

	fd = sys->open("/n/host/net.conf", Sys->OREAD);
	if(fd == nil)
		return;
	buf = array[4096] of byte;
	n = sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return;
	(nlines, lines) = sys->tokenize(string buf[0:n], "\n");
	while(lines != nil){
		line := hd lines;
		lines = tl lines;
		(key, val) := split(line);
		case key {
		"ip" =>
			ip = val;
		"mask" =>
			mask = val;
		"cmd" =>
			cmd = val;
		"dns" =>
			dns = val;
		"gateway" =>
			gateway = val;
		}
	}
	if(ip == nil || mask == nil)
		return;
	cfd := sys->open("/net/ipifc/clone", Sys->ORDWR);
	if(cfd == nil){
		sys->print("net: open /net/ipifc/clone: %r\n");
		return;
	}
	if(sys->fprint(cfd, "bind ether ether0") < 0)
		sys->print("net: bind ether0: %r\n");
	if(sys->fprint(cfd, "add %s %s", ip, mask) < 0)
		sys->print("net: add %s: %r\n", ip);
	else
		sys->print("net: %s %s\n", ip, mask);
	if(gateway != nil){
		rfd := sys->open("/net/iproute", Sys->OWRITE);
		if(rfd == nil)
			sys->print("net: open /net/iproute: %r\n");
		else{
			if(sys->fprint(rfd, "add 0.0.0.0 0.0.0.0 %s\n", gateway) < 0)
				sys->print("net: gateway %s: %r\n", gateway);
			else
				sys->print("net: gateway %s\n", gateway);
			rfd = nil;
		}
	}
	if(dns != nil){
		nfd := sys->open("/net/ndb", Sys->OWRITE);
		if(nfd == nil)
			sys->print("net: open /net/ndb: %r\n");
		else{
			if(sys->fprint(nfd, "infernosite=\n\tdns=%s\n", dns) < 0)
				sys->print("net: dns=%s: %r\n", dns);
			else
				sys->print("net: dns %s\n", dns);
			nfd = nil;
		}
	}
	if(cmd != nil){
		sh := load Sh "/dis/sh.dis";
		if(sh == nil)
			sys->print("net: cannot load shell: %r\n");
		else
			spawn sh->init(nil, "sh" :: "-c" :: cmd :: nil);
	}
}

split(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '=')
			return (s[0:i], s[i+1:]);
	return (s, nil);
}

srv()
{
	remotedebug := sysenv("remotedebug");
	if(remotedebug != "1")
		return;

	sys->print("srv...");
	if(echoto("#t/eia0ctl", "b38400") < 0)
		return;

	fd := sys->open("/dev/eia0", Sys->ORDWR);
	if (fd == nil) {
		sys->print("eia data open: %r\n");
		return;
	}
	if (sys->export(fd, "/", Sys->EXPASYNC) < 0) {
		sys->print("export: %r\n");
		return;
	}
	sys->print("ok\n");
}

sysenv(param: string): string
{
	fd := sys->open("#c/sysenv", sys->OREAD);
	if (fd == nil)
		return(nil);
	buf := array[4096] of byte;
	nb := sys->read(fd, buf, len buf);
	(nfl,fl) := sys->tokenize(string buf, "\n");
	while (fl != nil) {
		pair := hd fl;
		(npl, pl) := sys->tokenize(pair, "=");
		if (npl > 1) {
			if ((hd pl) == param)
				return hd tl pl;
		}
		fl = tl fl;
	}
	return nil ;
}

echoto(fname, str: string): int
{
	fd := sys->open(fname, Sys->OWRITE);
	if(fd == nil) {
		sys->print("%s: %r\n", fname);
		return -1;
	}
	x := array of byte str;
	if(sys->write(fd, x, len x) == -1) {
		sys->print("write: %r\n");
		return -1;
	}
	return 0;
}
