implement Svcd;

#
# svcd -- smallest useful service manager for a CLI-only Inferno host
#
# Reads a list of services, runs each in its own namespace and process
# group, restarts it when it exits, and exposes status plus a control
# file.  It is the Inferno equivalent of the Android supervisor this
# project already runs: init starts svcd, svcd starts everything else.
#
# Config (/lib/svcd.conf, or /n/host/svcd.conf when present):
#
#	# name	command args...
#	cpu	/dis/cpud.dis
#	web	/dis/sh.dis -c 'listen -A tcp!*!80 {export /usr/inferno/www&}'
#	-crash	/dis/willfail.dis		# leading dash: disabled
#
# A service's stdio goes to /tmp/svcd/<name>.log.  Control with
# svcctl(1) or by writing /tmp/svcd/ctl ("start cpu", "stop cpu",
# "restart cpu", "stopall", "startall").
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "sh.m";

include "string.m";
	str: String;

include "arg.m";

Svcd: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

BASE:		con "/tmp/svcd";
DEFCONF:	con "/lib/svcd.conf";
HOSTCONF:	con "/n/host/svcd.conf";
MAXDELAY:	con 30;		# seconds between restarts
STARTWAIT:	con 10000;	# ms a service has to report a pid
STABLE:		con 30000;	# ms of uptime that resets the backoff

Svc: adt
{
	name:		string;
	argv:		list of string;
	pid:		int;
	state:		string;
	restarts:	int;
	delay:		int;
	started:	int;
	retry:		int;
	manual:		int;
	orphan:		int;
};

svcs:	list of ref Svc;
noprog:	int;

init(nil: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;
	str = load String String->PATH;
	if(str == nil){
		sys->fprint(sys->fildes(2), "svcd: cannot load %s: %r\n", String->PATH);
		return;
	}
	arg := load Arg Arg->PATH;
	if(arg == nil){
		sys->fprint(sys->fildes(2), "svcd: cannot load %s: %r\n", Arg->PATH);
		return;
	}
	conf := "";
	arg->init(argv);
	arg->setusage("svcd [-c config]");
	while((o := arg->opt()) != 0){
		case o {
		'c' =>
			conf = arg->earg();
		* =>
			arg->usage();
		}
	}
	arg = nil;

	if(conf == "")
		conf = defaultconf();

	if(mkdir("/tmp") < 0 || mkdir(BASE) < 0){
		sys->fprint(sys->fildes(2), "svcd: cannot create %s: %r\n", BASE);
		return;
	}

	if(!statok("/prog")){
		noprog = 1;
		log("no /prog; supervision is disabled");
	}

	# /tmp may be on persistent storage; start each run with a fresh log.
	puts(BASE + "/log", "");
	puts(BASE + "/svcd.pid", sys->sprint("%d\n", sys->pctl(0, nil)));
	svcs = readconf(conf);
	log(sys->sprint("svcd start pid=%d config=%s services=%d",
		sys->pctl(0, nil), conf, length(svcs)));
	status();

	for(l := svcs; l != nil; l = tl l)
		if(!(hd l).manual)
			start(hd l);

	for(;;){
		ctl();
		if(!noprog)
			check();
		sys->sleep(1000);
	}
}

# ---- config ----------------------------------------------------------

defaultconf(): string
{
	if(statok(HOSTCONF))
		return HOSTCONF;
	return DEFCONF;
}

readconf(path: string): list of ref Svc
{
	data := readfile(path);
	if(data == "")
		log("cannot read " + path);
	acc: list of ref Svc;
	for(s := data; len s > 0;){
		(rest, line) := splitline(s);
		s = rest;
		line = trim(line);
		if(len line == 0 || line[0] == '#')
			continue;
		manual := 0;
		if(line[0] == '-'){
			manual = 1;
			line = trim(line[1:]);
		}
		(name, tail) := str->splitl(line, " \t");
		if(name == "")
			continue;
		tail = str->drop(tail, " \t");
		if(tail == ""){
			log("config: " + name + ": no command");
			continue;
		}
		av := str->unquoted(tail);
		if(av == nil){
			log("config: " + name + ": empty command");
			continue;
		}
		sv := ref Svc;
		sv.name = name;
		sv.argv = av;
		sv.pid = 0;
		sv.state = "stopped";
		sv.restarts = 0;
		sv.delay = 0;
		sv.started = 0;
		sv.retry = 0;
		sv.manual = manual;
		sv.orphan = 0;
		acc = sv :: acc;
	}
	return reverse(acc);
}

# ---- service control -------------------------------------------------

start(s: ref Svc)
{
	if(s.manual)
		return;
	s.pid = 0;
	s.orphan = 0;
	s.started = sys->millisec();
	s.state = "starting";
	spawn runsvc(s);
	log("start " + s.name);
	status();
}

runsvc(s: ref Svc)
{
	# Own namespace and fd group, and a process group so a stop takes
	# the service's children with it.
	sys->pctl(Sys->NEWPGRP|Sys->FORKNS|Sys->FORKFD, nil);

	fd := sys->create(BASE + "/" + s.name + ".log", Sys->OWRITE, 8r666);
	if(fd != nil){
		sys->dup(fd.fd, 0);
		sys->dup(fd.fd, 1);
		sys->dup(fd.fd, 2);
		fd = nil;
	}

	s.pid = sys->pctl(0, nil);
	s.state = "running";
	status();

	run(s.argv);
}

run(argv: list of string)
{
	cmd := hd argv;
	mod := load Command cmd;
	if(mod == nil && str->contains(cmd, "/") == 0){
		mod = load Command "/dis/" + cmd;
		if(mod == nil)
			mod = load Command "/dis/" + cmd + ".dis";
	}
	if(mod == nil){
		sys->fprint(sys->fildes(2), "svcd: cannot load %s: %r\n", cmd);
		raise "fail:load";
	}
	mod->init(nil, argv);
}

stop(s: ref Svc)
{
	s.manual = 1;
	s.orphan = 0;
	s.state = "stopped";
	if(s.pid > 0)
		kill(s);
	s.pid = 0;
	log("stop " + s.name);
	status();
}

kill(s: ref Svc)
{
	pid := s.pid;
	if(!statok("/prog/" + string pid))
		pid = findmember(s.pid);
	if(pid <= 0)
		return;
	fd := sys->open("/prog/" + string pid + "/ctl", Sys->OWRITE);
	if(fd == nil)
		return;
	sys->fprint(fd, "killgrp");
	fd = nil;
}

check()
{
	t := sys->millisec();
	for(l := svcs; l != nil; l = tl l){
		s := hd l;
		if(s.manual)
			continue;
		if(s.state == "backoff"){
			if(t >= s.retry)
				start(s);
			continue;
		}
		if(s.pid <= 0){
			if(t - s.started > STARTWAIT){
				log(s.name + ": did not start");
				s.restarts++;
				backoff(s);
			}
			continue;
		}
		if(statok("/prog/" + string s.pid))
			continue;
		# listen(1) daemonises: its init spawns the listener and
		# returns.  The process group still exists and still serves,
		# so treat a live group as a live service instead of
		# restarting it into "address in use".
		if(findmember(s.pid) > 0){
			if(!s.orphan){
				s.orphan = 1;
				log(s.name + ": leader exited; supervising its process group");
				status();
			}
			continue;
		}
		if(t - s.started > STABLE)
			s.delay = 0;
		log(sys->sprint("%s: exited pid=%d", s.name, s.pid));
		s.pid = 0;
		s.restarts++;
		backoff(s);
	}
}

# backoff records when the next attempt is due.  The main loop keeps
# polling ctl while a service waits, so a stop or restart is immediate
# even during a 30 second backoff.
backoff(s: ref Svc)
{
	s.state = "backoff";
	if(s.delay <= 0)
		s.delay = 1;
	else
		s.delay *= 2;
	if(s.delay > MAXDELAY)
		s.delay = MAXDELAY;
	s.retry = sys->millisec() + s.delay * 1000;
	log(sys->sprint("%s: restart in %ds", s.name, s.delay));
	status();
}

# ---- control file ----------------------------------------------------

ctl()
{
	fd := sys->open(BASE + "/ctl", Sys->OREAD);
	if(fd == nil)
		return;
	buf := array[256] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return;
	# Truncate so the command runs once.
	puts(BASE + "/ctl", "");

	line := trim(string buf[0:n]);
	if(len line == 0)
		return;
	(cmd, tail) := str->splitl(line, " \t");
	tail = trim(str->drop(tail, " \t"));
	case cmd {
	"start" =>
		s := find(tail);
		if(s == nil)
			log("ctl: no such service: " + tail);
		else {
			s.manual = 0;
			start(s);
		}
	"stop" =>
		s := find(tail);
		if(s == nil)
			log("ctl: no such service: " + tail);
		else
			stop(s);
	"restart" =>
		s := find(tail);
		if(s == nil)
			log("ctl: no such service: " + tail);
		else {
			s.manual = 1;
			if(s.pid > 0)
				kill(s);
			s.pid = 0;
			s.manual = 0;
			s.delay = 0;
			start(s);
		}
	"stopall" =>
		for(l := svcs; l != nil; l = tl l)
			stop(hd l);
	"startall" =>
		for(l := svcs; l != nil; l = tl l){
			s := hd l;
			if(s.state != "running" && s.state != "starting"){
				s.manual = 0;
				start(s);
			}
		}
	"status" =>
		status();
	* =>
		log("ctl: unknown command: " + cmd);
	}
}

find(name: string): ref Svc
{
	for(l := svcs; l != nil; l = tl l)
		if((hd l).name == name)
			return hd l;
	return nil;
}

# ---- status ----------------------------------------------------------

# findmember returns a live pid in process group grp, or 0.
findmember(grp: int): int
{
	if(grp <= 0)
		return 0;
	fd := sys->open("/prog", Sys->OREAD);
	if(fd == nil)
		return 0;
	gs := string grp;
	found := 0;
	while(found == 0){
		(n, dirs) := sys->dirread(fd);
		if(n <= 0)
			break;
		for(i := 0; i < n; i++){
			st := readfile("/prog/" + dirs[i].name + "/status");
			if(st == "")
				continue;
			(nf, f) := sys->tokenize(st, " \t");
			if(nf < 2)
				continue;
			if(hd tl f == gs){
				found = int dirs[i].name;
				break;
			}
		}
	}
	fd = nil;
	return found;
}

status()
{
	out := "";
	for(l := svcs; l != nil; l = tl l){
		s := hd l;
		st := s.state;
		if(s.orphan)
			st += "(group)";
		out += sys->sprint("%s %s pid=%d restarts=%d\n",
			s.name, st, s.pid, s.restarts);
	}
	puts(BASE + "/status", out);
}

# ---- utilities -------------------------------------------------------

log(s: string)
{
	fd := sys->open(BASE + "/log", Sys->OWRITE);
	if(fd == nil)
		fd = sys->create(BASE + "/log", Sys->OWRITE, 8r666);
	if(fd == nil)
		return;
	sys->seek(fd, big 0, Sys->SEEKEND);
	sys->fprint(fd, "[%d] %s\n", sys->millisec() / 1000, s);
	fd = nil;
}

puts(path, s: string)
{
	fd := sys->create(path, Sys->OWRITE, 8r666);
	if(fd == nil)
		return;
	sys->fprint(fd, "%s", s);
	fd = nil;
}

readfile(path: string): string
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return "";
	buf := array[8192] of byte;
	n := 0;
	for(;;){
		m := sys->read(fd, buf[n:], len buf - n);
		if(m <= 0)
			break;
		n += m;
		if(n >= len buf)
			break;
	}
	fd = nil;
	if(n == 0)
		return "";
	return string buf[0:n];
}

mkdir(path: string): int
{
	fd := sys->create(path, Sys->OREAD, Sys->DMDIR|8r777);
	if(fd != nil){
		fd = nil;
		return 0;
	}
	(ok, nil) := sys->stat(path);
	return ok;
}

statok(path: string): int
{
	(ok, nil) := sys->stat(path);
	return ok >= 0;
}

splitline(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '\n')
			return (s[i+1:], s[0:i]);
	return ("", s);
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

reverse(l: list of ref Svc): list of ref Svc
{
	r: list of ref Svc;
	for(; l != nil; l = tl l)
		r = hd l :: r;
	return r;
}

length(l: list of ref Svc): int
{
	n := 0;
	for(; l != nil; l = tl l)
		n++;
	return n;
}
