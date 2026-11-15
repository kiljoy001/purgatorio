#!/dis/sh.dis -n
#
# Start the CLI-only remote execution service.
#
# listen authenticates the connection and puts the caller in $user;
# runas drops to that user and cpud applies /lib/cpud.conf policy.
#
# This is the same rstyx service name/port that cpu(1) and rcmd(1)
# dial, so no client change is needed.  Keep svc/rstyx.sh for the
# original auxi/rstyxd behaviour, or use this in place of it.
#
load std
or {ftest -e /net/dns} {ftest -e /env/emuhost} {ndb/dns}
or {ftest -e /net/cs} {ndb/cs}
listen -v 'tcp!*!rstyx' {runas $user cpud&}
