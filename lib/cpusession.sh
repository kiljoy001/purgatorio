# /lib/cpusession.sh -- one authenticated remote-execution session.
#
# listen(1) authenticates the caller and sets $user to the name in the
# client's certificate; runas switches this process to that user before
# cpud mounts the client namespace and runs the command.
runas $user /dis/cpud.dis
