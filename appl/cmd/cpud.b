implement Cpud;

#
# cpud -- policy-enforcing remote execution service
#
# A drop-in replacement for auxi/rstyxd for CLI-only Inferno servers.
# listen(1) authenticates the connection and runs this program with the
# authenticated user in /dev/user.  cpud reads the command the client
# exported, checks it against /lib/cpud.conf, logs the session, mounts
# the client's namespace on /n/client, and hands the command to the
# normal Dis module loader.
#
# The client is cpu(1) or rcmd(1); no draw device is involved.
#

include "sys.m";
	sys: Sys;
include "draw.m";
include "sh.m";
include "string.m";
	str: String;

stderr: ref Sys->FD;

Cpud: module
{
	init: fn(nil: ref Draw->Context, nil: list of string);
};

CONF:	con "/lib/cpud.conf";
DEFLOG:	con "/tmp/cpud.log";

init(nil: ref Draw->Context, nil: list of string)
{
	sys = load Sys Sys->PATH;
	if(sys == nil)
		return;
	str = load String String->PATH;
	if(str == nil)
		badmod(String->PATH);
	stderr = sys->fildes(2);

	fd := sys->fildes(0);
	sys->pctl(sys->FORKFD, fd.fd :: nil);

	args := readargs(fd);
	if(args == nil)
		err("error reading arguments");

	user := trim(readfile("/dev/user"));
	target := targetcmd(args);
	(ok, logpath) := policy(target);

	if(!ok) {
		logsession(logpath, user, target, args, "denied");
		err("command not allowed: " + target);
	}
	logsession(logpath, user, target, args, "start");

	cmd := hd args;
	s := "";
	for(a := args; a != nil; a = tl a)
		s += hd a + " ";

	file: string;
	if(cmd == "sh")
		file = "/dis/sh.dis";
	else
		file = cmd + ".dis";
	mod := load Command file;
	if(mod == nil) {
		mod = load Command "/dis/" + file;
		if(mod == nil)
			badmod("/dis/" + file);
	}

	sys->pctl(Sys->FORKNS|Sys->FORKENV, nil);

	# rstyxd assumes /n/client exists; a minimal server root may not
	# have it yet.
	sys->create("/n", Sys->OREAD, Sys->DMDIR|8r777);
	sys->create("/n/client", Sys->OREAD, Sys->DMDIR|8r777);

	if(sys->mount(fd, nil, "/n/client", Sys->MREPL, "") < 0)
		err("cannot mount connection on /n/client: " + sys->sprint("%r"));

	if(sys->bind("/n/client/dev", "/dev", Sys->MBEFORE) < 0)
		err("cannot bind /n/client/dev to /dev: " + sys->sprint("%r"));

	fd = sys->open("/dev/cons", Sys->OREAD);
	if(fd == nil)
		err("cannot open /dev/cons: " + sys->sprint("%r"));
	sys->dup(fd.fd, 0);
	fd = sys->open("/dev/cons", Sys->OWRITE);
	if(fd == nil)
		err("cannot open /dev/cons: " + sys->sprint("%r"));
	sys->dup(fd.fd, 1);
	sys->dup(fd.fd, 2);
	fd = nil;

	mod->init(nil, args);
}

# The protocol is rstyxd's: a decimal byte count, newline, then the
# UTF-6 encoded argument string.
readargs(fd: ref Sys->FD): list of string
{
	buf := array[1024] of byte;
	c := array[1] of byte;
	for(i := 0; ; i++) {
		if(i >= len buf || sys->read(fd, c, 1) != 1)
			return nil;
		buf[i] = c[0];
		if(c[0] == byte '\n')
			break;
	}
	nb := int string buf[0:i];
	if(nb <= 0)
		return nil;
	args := readn(fd, nb);
	if(args == nil)
		return nil;
	return str->unquoted(string args[0:nb]);
}

readn(fd: ref Sys->FD, nb: int): array of byte
{
	buf := array[nb] of byte;
	if(sys->readn(fd, buf, nb) != nb)
		return nil;
	return buf;
}

# cpu(1) wraps the real command in auxi/cpuslave; rcmd(1) sends the
# command directly.  Policy is applied to the real command.
targetcmd(args: list of string): string
{
	cmd := basename(hd args);
	if(cmd == "cpuslave") {
		rest := tl args;
		for(; rest != nil; rest = tl rest) {
			if(hd rest == "--") {
				rest = tl rest;
				if(rest != nil)
					return basename(hd rest);
				break;
			}
		}
		return "sh";
	}
	return cmd;
}

basename(s: string): string
{
	i := len s;
	while(i > 0 && s[i - 1] != '/')
		i--;
	s = s[i:];
	if(len s > 4 && s[len s - 4:] == ".dis")
		s = s[0:len s - 4];
	return s;
}

# policy reads the simple allow/deny/log config.  No allow lines means
# allow anything, which keeps cpud compatible with rstyxd out of the
# box.  deny always wins.
policy(target: string): (int, string)
{
	allow: list of string;
	deny: list of string;
	allowall := 0;
	logpath := DEFLOG;

	data := readfile(CONF);
	# Parse line by line; String->fields is per-call.
	for(s := data; len s > 0; ) {
		i := 0;
		while(i < len s && s[i] != '\n')
			i++;
		line := trim(s[0:i]);
		if(i < len s) {
			s = s[i + 1:];
		} else {
			s = "";
		}
		if(len line == 0 || line[0] == '#')
			continue;
		f := str->fields(line);
		if(f == nil)
			continue;
		key := hd f;
		val := "";
		if(tl f != nil)
			val = hd tl f;
		if(key == "allow") {
			if(val == "*")
				allowall = 1;
			else if(len val > 0)
				allow = val :: allow;
		} else if(key == "deny") {
			if(len val > 0)
				deny = val :: deny;
		} else if(key == "log") {
			if(len val > 0)
				logpath = val;
		}
	}

	if(inlist(target, deny))
		return (0, logpath);
	if(allowall)
		return (1, logpath);
	if(allow == nil)
		return (1, logpath);
	return (inlist(target, allow), logpath);
}

inlist(s: string, l: list of string): int
{
	for(; l != nil; l = tl l)
		if(hd l == s)
			return 1;
	return 0;
}

logsession(path, user, target: string, args: list of string, what: string)
{
	if(path == nil || len path == 0)
		path = DEFLOG;
	sys->create("/tmp", Sys->OREAD, Sys->DMDIR|8r777);
	fd := sys->open(path, Sys->OWRITE);
	if(fd == nil)
		fd = sys->create(path, Sys->OWRITE, 8r666);
	if(fd == nil) {
		sys->fprint(stderr, "cpud: cannot open log %s: %r\n", path);
		return;
	}
	sys->seek(fd, big 0, Sys->SEEKEND);
	sys->fprint(fd, "%s user=%s cmd=%s args=%s\n",
		what, user, target, str->quoted(args));
	fd = nil;
}

readfile(path: string): string
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return "";
	buf := array[4096] of byte;
	n := 0;
	for(;;) {
		m := sys->read(fd, buf[n:], len buf - n);
		if(m <= 0)
			break;
		n += m;
		if(n >= len buf)
			break;
	}
	if(n == 0)
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

err(s: string)
{
	sys->fprint(stderr, "cpud: %s\n", s);
	raise "fail:error";
}

badmod(p: string)
{
	sys->fprint(stderr, "cpud: cannot load %s: %r\n", p);
	raise "fail:bad module";
}
