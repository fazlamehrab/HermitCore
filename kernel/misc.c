#include <hermit/misc.h>
#include <hermit/stddef.h>
#include <hermit/stdio.h>
#include <hermit/string.h>
#include <hermit/time.h>
#include <hermit/tasks.h>
#include <hermit/processor.h>
#include <hermit/tasks.h>
#include <hermit/syscall.h>
#include <hermit/memory.h>
#include <hermit/spinlock.h>
#include <hermit/rcce.h>
#include <hermit/logging.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/uart.h>
#include <asm/multiboot.h>

#include <lwip/init.h>
#include <lwip/sys.h>
#include <lwip/stats.h>
#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>
#include <lwip/dhcp.h>
#include <lwip/netifapi.h>
#include <lwip/ip_addr.h>
#include <lwip/sockets.h>
#include <lwip/err.h>
#include <lwip/stats.h>
#include <netif/etharp.h>
#include <net/mmnif.h>
#include <net/rtl8139.h>
#include <net/e1000.h>
#include <net/vioif.h>
#include <hermit/logging.h>

#define HERMIT_PORT	0x494E
#define HERMIT_MAGIC	0x7E317

static const int sobufsize = 131072;

int hermit_lwip_write(int s, const void *data, size_t size)
{
	int ret;

	LOG_INFO("Inside hermit lwip wirte\n");
	ret = lwip_write(s, data, size);
	LOG_INFO("RET = %d\n", ret);
	if(ret < 0)
	{
		LOG_INFO("Re-Initializing\n");
		reinitd();
		s = libc_sd;
		while((ret = lwip_write(s, data, size))<0);
		LOG_INFO("After a while RET = %d\n", ret);
	}
	
	just_a_flag = 2;

	return ret;
}

int hermit_lwip_read(int s, void *mem, size_t len)
{
	int ret;

	LOG_INFO("Inside hermit lwip read\n");
	ret = lwip_read(s, mem, len);
	LOG_INFO("RET = %d\n", ret);
	if(ret < 0)
	{
		LOG_INFO("Re-Initializing\n");
		reinitd();
		s = libc_sd;
		ret = lwip_read(s, mem, len);
	}
	
	just_a_flag = 1;

	return ret;
}

int reinitd()
{
	int c = -1;
	int i, j, flag;
	int len, err;
	int magic = 0;
	struct sockaddr_in6 server, client;
	int argc, envc;
	//char** argv = NULL;
	//char **cenviron = NULL;

	LOG_INFO("Re-Initd is running\n");
//Reset
	if (cargv) {
		for(i=0; i<argc; i++) {
			if (cargv[i])
				kfree(cargv[i]);
		}

		kfree(cargv);
	}

	if (cenviron) {
		i = 0;
		while(cenviron[i]) {
			kfree(cenviron[i]);
			i++;
		}

		kfree(cenviron);
	}

	if (c > 0)
		lwip_close(c);
	libc_sd = -1;
	
	len = sizeof(struct sockaddr_in);

	LOG_INFO("TCP server is listening.\n");

	if ((c = lwip_accept(soc, (struct sockaddr *)&client, (socklen_t*)&len)) < 0)
	{
		LOG_ERROR("accept faild: %d\n", errno);
		lwip_close(soc);
		return -1;
	}

	LOG_INFO("Establish IP connection\n");

	lwip_setsockopt(c, SOL_SOCKET, SO_RCVBUF, (char *) &sobufsize, sizeof(sobufsize));
	lwip_setsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *) &sobufsize, sizeof(sobufsize));
	flag = 1;
	lwip_setsockopt(soc, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag));
	flag = 0;
	lwip_setsockopt(soc, SOL_SOCKET, SO_KEEPALIVE, (char *) &flag, sizeof(flag));

	magic = 0;
	lwip_read(c, &magic, sizeof(magic));
	if (magic != HERMIT_MAGIC)
	{
		LOG_ERROR("Invalid magic number %d\n", magic);
		lwip_close(c);
		return -1;
	}

	err = lwip_read(c, &argc, sizeof(argc));
	if (err != sizeof(argc))
		goto out;

	cargv = kmalloc((argc+1)*sizeof(char*));
	if (!cargv)
		goto out;
	memset(cargv, 0x00, (argc+1)*sizeof(char*));

	for(i=0; i<argc; i++)
	{
		err = lwip_read(c, &len, sizeof(len));
		if (err != sizeof(len))
			goto out;

		cargv[i] = kmalloc(len);
		if (!cargv[i])
			goto out;

		j = 0;
		while(j < len) {
			err = lwip_read(c, cargv[i]+j, len-j);
			if (err < 0)
				goto out;
			j += err;
		}

	}

	err = lwip_read(c, &envc, sizeof(envc));
	if (err != sizeof(envc))
		goto out;

	cenviron = kmalloc((envc+1)*sizeof(char**));
	if (!cenviron)
		goto out;
	memset(cenviron, 0x00, (envc+1)*sizeof(char*));

	for(i=0; i<envc; i++)
	{
		err = lwip_read(c, &len, sizeof(len));
		if (err != sizeof(len))
			goto out;

		cenviron[i] = kmalloc(len);
		if (!cenviron[i])
			goto out;

		j = 0;
		while(j < len) {
			err = lwip_read(c, cenviron[i]+j, len-j);
			if (err < 0)
				goto out;
			j += err;
		}
	}

	libc_sd = c;

	return 0;

out:
	if (cargv) {
		for(i=0; i<argc; i++) {
			if (cargv[i])
				kfree(cargv[i]);
		}

		kfree(cargv);
	}

	if (cenviron) {
		i = 0;
		while(cenviron[i]) {
			kfree(cenviron[i]);
			i++;
		}

		kfree(cenviron);
	}

	if (c > 0)
		lwip_close(c);
	libc_sd = -1;

	if (soc > 0)
		lwip_close(soc);

	return 0;
}

int sample()
{
	return 5;
}
