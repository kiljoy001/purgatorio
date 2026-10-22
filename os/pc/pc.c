#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "io.h"
#include "../port/uart.h"
#include "../port/error.h"
#include "interp.h"

#include "pc.root.h"

ulong ndevs = 31;
extern Dev rootdevtab;
extern Dev consdevtab;
extern Dev archdevtab;
extern Dev envdevtab;
extern Dev mntdevtab;
extern Dev pipedevtab;
extern Dev progdevtab;
extern Dev rtcdevtab;
extern Dev srvdevtab;
extern Dev dupdevtab;
extern Dev ssldevtab;
extern Dev capdevtab;
extern Dev drawdevtab;
extern Dev pointerdevtab;
extern Dev vgadevtab;
extern Dev ipdevtab;
extern Dev etherdevtab;
extern Dev audiodevtab;
extern Dev uartdevtab;
extern Dev floppydevtab;
extern Dev sddevtab;
extern Dev tinyfsdevtab;
extern Dev dbgdevtab;
Dev* devtab[31]={
	&rootdevtab,
	&consdevtab,
	&archdevtab,
	&envdevtab,
	&mntdevtab,
	&pipedevtab,
	&progdevtab,
	&rtcdevtab,
	&srvdevtab,
	&dupdevtab,
	&ssldevtab,
	&capdevtab,
	&drawdevtab,
	&pointerdevtab,
	&vgadevtab,
	&ipdevtab,
	&etherdevtab,
	&audiodevtab,
	&uartdevtab,
	&floppydevtab,
	&sddevtab,
	&tinyfsdevtab,
	&dbgdevtab,
	nil,
};

extern void ether79c970link(void);
extern void ether2114xlink(void);
extern void ether82557link(void);
extern void ether83815link(void);
extern void etherelnk3link(void);
extern void ps2mouselink(void);
extern void ethermediumlink(void);
void links(void){
	ether79c970link();
	ether2114xlink();
	ether82557link();
	ether83815link();
	etherelnk3link();
	ps2mouselink();
	ethermediumlink();
}

extern void sysmodinit(void);
extern void drawmodinit(void);
extern void tkmodinit(void);
extern void keyringmodinit(void);
extern void mathmodinit(void);
void modinit(void){
	sysmodinit();
	drawmodinit();
	tkmodinit();
	keyringmodinit();
	mathmodinit();
}

extern PCArch archmp;
extern PCArch archacpi;
PCArch* knownarch[] = {
	&archmp,
	&archacpi,
	nil,
};

#include "../port/sd.h"
extern SDifc sdataifc;
extern SDifc sdvirtioifc;
SDifc* sdifc[] = {
	&sdataifc,
	&sdvirtioifc,
	nil,
};

extern PhysUart i8250physuart;
PhysUart* physuart[] = {
	&i8250physuart,
	nil,
};

#include <draw.h>
#include <memdraw.h>
#include "screen.h"
extern VGAdev vgas3dev;
extern VGAdev vgamach64xxdev;
VGAdev* vgadev[] = {
	&vgas3dev,
	&vgamach64xxdev,
	nil,
};

extern VGAcur vgas3cur;
VGAcur* vgacur[] = {
	&vgas3cur,
	nil,
};

#include "../ip/ip.h"
extern void tcpinit(Fs*);
extern void udpinit(Fs*);
extern void ipifcinit(Fs*);
extern void icmpinit(Fs*);
extern void icmp6init(Fs*);
extern void ipmuxinit(Fs*);
void (*ipprotoinit[])(Fs*) = {
	tcpinit,
	udpinit,
	ipifcinit,
	icmpinit,
	icmp6init,
	ipmuxinit,
	nil,
};

	int kernel_pool_pcnt = 10;
	int main_pool_pcnt = 40;
	int heap_pool_pcnt = 20;
	int image_pool_pcnt = 40;
	int cflag=0;
	int swcursor=0;
	int consoleprint=1;
char* conffile = "pc";
ulong kerndate = KERNDATE;
