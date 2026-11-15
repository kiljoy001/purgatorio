implement Svcctl;

#
# svcctl -- inspect and control svcd(8)
#
#	svcctl			status of every service
#	svcctl start name
#	svcctl stop name
#	svcctl restart name
#	svcctl stopall | startall
#	svcctl log name		service output
#	svcctl ctl			the svcd log
#
# Status is read from /tmp/svcd/status; commands are written to
# /tmp/svcd/ctl, which svcd polls once a second.
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "arg.m";

Svcctl: module
{
	init:	fn(nil: ref Draw->Context, argv: list of string);
};

BASE:	con "/tmp/svcd";

stderr: ref Sys->FD;

init(nil: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;
	stderr = sys->fildes(2);

	arg := load Arg Arg->PATH;
	if(arg == nil){
		sys->fprint(stderr, "svcctl: cannot load %s: %r\n", Arg->PATH);
		return;
	}
	arg->init(argv);
	arg->setusage("svcctl [start|stop|restart|log] name | stopall | startall");
	argv = arg->argv();
	if(argv == nil){
		usagecheck();
		cat(BASE + "/status");
		return;
	}
	cmd := hd argv;
	rest := tl argv;
	arg = nil;

	case cmd {
	"status" =>
		cat(BASE + "/status");
	"start" or "stop" or "restart" or "log" =>
		if(rest == nil)
			usage();
		name := hd rest;
		if(cmd == "log")
			cat(BASE + "/" + name + ".log");
		else
			send(cmd + " " + name);
	"stopall" or "startall" =>
		send(cmd);
	"ctl" =>
		cat(BASE + "/log");
	* =>
		usage();
	}
}

usage()
{
	sys->fprint(stderr, "usage: svcctl [start|stop|restart|log] name | stopall | startall\n");
	raise "fail:usage";
}

# The daemon writes the pid file; if it is gone svcd is not running.
usagecheck()
{
	fd := sys->open(BASE + "/svcd.pid", Sys->OREAD);
	if(fd == nil)
		raise "fail:svcd not running";
}

send(cmd: string)
{
	usagecheck();
	# Truncate first: svcd reads the whole file, and a second command
	# written before it polls would otherwise run together with this one.
	fd := sys->create(BASE + "/ctl", Sys->OWRITE, 8r666);
	if(fd == nil){
		sys->fprint(stderr, "svcctl: cannot open %s/ctl: %r\n", BASE);
		raise "fail:ctl";
	}
	sys->fprint(fd, "%s", cmd);
	fd = nil;
}

cat(path: string)
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil){
		sys->fprint(stderr, "svcctl: cannot open %s: %r\n", path);
		raise "fail:open";
	}
	buf := array[8192] of byte;
	for(;;){
		n := sys->read(fd, buf, len buf);
		if(n <= 0)
			break;
		sys->fprint(sys->fildes(1), "%s", string buf[0:n]);
	}
	fd = nil;
}
