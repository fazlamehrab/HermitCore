/*
 * Copyright (c) 2010, Stefan Lankes, RWTH Aachen University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
#include <hermit/misc.h>

#define HERMIT_PORT	0x494E
#define HERMIT_MAGIC	0x7E317

static struct netif	default_netif;
static const int sobufsize = 131072;

/*
 * Note that linker symbols are not variables, they have no memory allocated for
 * maintaining a value, rather their address is their value.
 */
extern const void kernel_start;
extern const void hbss_start;
extern const void tls_start;
extern const void tls_end;
extern const void __bss_start;
extern const void percore_start;
extern const void percore_end0;
extern const void percore_end;
extern char __BUILD_DATE;
extern size_t hbmem_base;
extern size_t hbmem_size;

/* Page frame counters */
extern atomic_int64_t total_pages;
extern atomic_int64_t total_allocated_pages;
extern atomic_int64_t total_available_pages;

extern atomic_int32_t cpu_online;
extern atomic_int32_t possible_cpus;
extern int32_t isle;
extern int32_t possible_isles;
extern uint32_t boot_processor;
extern volatile int libc_sd;

islelock_t* rcce_lock = NULL;
rcce_mpb_t* rcce_mpb = NULL;

extern void signal_init();

#if 0
static int foo(void* arg)
{
	int i;

	for(i=0; i<5; i++) {
		LOG_INFO("hello from %s\n", (char*) arg);
		sleep(1);
	}

	return 0;
}
#endif

static int hermit_init(void)
{
	uint32_t i;
	size_t sz = (size_t) &percore_end0 - (size_t) &percore_start;

	// initialize .kbss sections
	memset((void*)&hbss_start, 0x00, (size_t) &__bss_start - (size_t) &hbss_start);

	// initialize .percore section => copy first section to all other sections
	for(i=1; i<MAX_CORES; i++)
		memcpy((char*) &percore_start + i*sz, (char*) &percore_start, sz);

	koutput_init();
	system_init();
	irq_init();
	timer_init();
	multitasking_init();
	memory_init();
	signal_init();

	return 0;
}

static void print_status(void)
{
	static spinlock_t status_lock = SPINLOCK_INIT;

	spinlock_lock(&status_lock);
	LOG_INFO("CPU %d of isle %d is now online (CR0 0x%zx, CR4 0x%zx)\n", CORE_ID, isle, read_cr0(), read_cr4());
	spinlock_unlock(&status_lock);
}

static void tcpip_init_done(void* arg)
{
	sys_sem_t* sem = (sys_sem_t*)arg;

	LOG_INFO("LwIP's tcpip thread has task id %d\n", per_core(current_task)->id);

	sys_sem_signal(sem);
}

static int init_netifs(void)
{
	ip_addr_t	ipaddr;
	ip_addr_t	netmask;
	ip_addr_t	gw;
	sys_sem_t	sem;
	err_t		err;

	if(sys_sem_new(&sem, 0) != ERR_OK)
		LWIP_ASSERT("Failed to create semaphore", 0);

	// part of bss => memset not required
	//memset(&default_netif, 0x00, sizeof(struct netif));

	tcpip_init(tcpip_init_done, &sem);
	sys_sem_wait(&sem);
	LOG_INFO("TCP/IP initialized.\n");
	sys_sem_free(&sem);

	if (is_uhyve()) {
		LOG_INFO("HermitCore is running on uhyve!\n");
		return -ENODEV;
	}

	if (!is_single_kernel())
	{
		LOG_INFO("HermitCore is running side-by-side to Linux!\n");

		/* Set network address variables */
		IP_ADDR4(&gw, 192,168,28,1);
		IP_ADDR4(&ipaddr, 192,168,28,isle+2);
		IP_ADDR4(&netmask, 255,255,255,0);

		/* register our Memory Mapped Virtual IP interface in the lwip stack
		 * and tell him how to use the interface:
		 *  - mmnif_dev : the device data storage
		 *  - ipaddr : the ip address wich should be used
		 *  - gw : the gateway wicht should be used
		 *  - mmnif_init : the initialization which has to be done in order to use our interface
		 *  - ip_input : tells him that he should use ip_input
		 *
		 * Note: Our drivers guarantee that the input function will be called in the context of the tcpip thread.
		 * => Therefore, we are able to use ip_input instead of tcpip_input
		 */
		if ((err = netifapi_netif_add(&default_netif, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gw), NULL, mmnif_init, ip_input)) != ERR_OK)
		{
			LOG_ERROR("Unable to add the intra network interface: err = %d\n", err);
			return -ENODEV;
		}

		/* tell lwip all initialization is done and we want to set it up */
		netifapi_netif_set_default(&default_netif);
		netifapi_netif_set_up(&default_netif);
	} else {
		/* Clear network address because we use DHCP to get an ip address */
		IP_ADDR4(&gw, 0,0,0,0);
		IP_ADDR4(&ipaddr, 0,0,0,0);
		IP_ADDR4(&netmask, 0,0,0,0);

		/* Note: Our drivers guarantee that the input function will be called in the context of the tcpip thread.
		 * => Therefore, we are able to use ethernet_input instead of tcpip_input */
		if ((err = netifapi_netif_add(&default_netif, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gw), NULL, vioif_init, ethernet_input)) == ERR_OK)
			goto success;
		if ((err = netifapi_netif_add(&default_netif, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gw), NULL, rtl8139if_init, ethernet_input)) == ERR_OK)
			goto success;
		if ((err = netifapi_netif_add(&default_netif, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gw), NULL, e1000if_init, ethernet_input)) == ERR_OK)
			goto success;

		LOG_ERROR("Unable to add the network interface: err = %d\n", err);

		return -ENODEV;

success:
		netifapi_netif_set_default(&default_netif);
		netifapi_netif_set_up(&default_netif);

		LOG_INFO("Starting DHCPD...\n");
		netifapi_dhcp_start(&default_netif);

		int mscnt = 0;
		int ip_counter = 0;
		/* wait for ip address */
		while(!ip_2_ip4(&default_netif.ip_addr)->addr && (ip_counter < 20)) {
			uint64_t end_tsc, start_tsc = rdtsc();

			do {
				if (ip_2_ip4(&default_netif.ip_addr)->addr)
					return 0;
				check_workqueues();
				end_tsc = rdtsc();
			} while(((end_tsc - start_tsc) / (get_cpu_frequency() * 1000)) < DHCP_FINE_TIMER_MSECS);

			dhcp_fine_tmr();
			mscnt += DHCP_FINE_TIMER_MSECS;
			if (mscnt >= DHCP_COARSE_TIMER_SECS*1000) {
				dhcp_coarse_tmr();
				mscnt = 0;
			}

			ip_counter++;
		}

		if (!ip_2_ip4(&default_netif.ip_addr)->addr)
			return -ENODEV;
	}

	return 0;
}

int network_shutdown(void)
{
	LOG_INFO("Shutdown LwIP\n");

	if (libc_sd >= 0) {
		int s = libc_sd;
		libc_sd = -1;
		lwip_close(s);
	}

	mmnif_shutdown();
	//stats_display();

	return 0;
}

#if MAX_CORES > 1
int smp_main(void)
{
	timer_init();
#ifdef DYNAMIC_TICKS
	enable_dynticks();
#endif

	print_status();

	/* wait for the other cpus */
	while(atomic_int32_read(&cpu_online) < atomic_int32_read(&possible_cpus))
		PAUSE;

	//create_kernel_task(NULL, foo, "foo2", NORMAL_PRIO);

	while(1) {
		check_workqueues();
		wait_for_task();
	}

	return 0;
}
#endif

static int init_rcce(void)
{
	size_t addr, flags = PG_GLOBAL|PG_RW;

	addr = vma_alloc(PAGE_SIZE, VMA_READ|VMA_WRITE|VMA_CACHEABLE);
	if (BUILTIN_EXPECT(!addr, 0))
		return -ENOMEM;
	if (has_nx())
		flags |= PG_XD;
	if (page_map(addr, phy_rcce_internals, 1, flags)) {
		vma_free(addr, addr + PAGE_SIZE);
		return -ENOMEM;
	}

	rcce_lock = (islelock_t*) addr;
	rcce_mpb = (rcce_mpb_t*) (addr + CACHE_LINE*(RCCE_MAXNP+1));

	LOG_INFO("Map rcce_lock at %p and rcce_mpb at %p\n", rcce_lock, rcce_mpb);

	return 0;
}

#if 0
// some stress tests
static void lock_test(void)
{
	uint64_t start, end;
	int i;
	static spinlock_t _lock = SPINLOCK_INIT;
	static sem_t _sem = SEM_INIT(1);

	start = rdtsc();

	for(i=0; i<10000; i++)
	{
		spinlock_lock(&_lock);
		NOP;
		spinlock_unlock(&_lock);
	}

	end = rdtsc();

	LOG_INFO("locks %lld (iterations %d)\n", end-start, i);

	start = rdtsc();

	for(i=0; i<10000; i++)
	{
		sem_wait(&_sem, 0);
		NOP;
		sem_post(&_sem);
	}

	end = rdtsc();

	LOG_INFO("sem %lld (iterations %d)\n", end-start, i);
}
#endif

int libc_start(int argc, char** argv, char** env);

// init task => creates all other tasks an initialize the LwIP
static int initd(void* arg)
{
	int c = -1;
	int i, j, flag;
	int len, err;
	int magic = 0;
	struct sockaddr_in6 server, client;
	task_t* curr_task = per_core(current_task);
	size_t heap = HEAP_START;
	int argc, envc;
	//char** argv = NULL;
	//char **environ = NULL;

	LOG_INFO("Initd is running\n");

	// initialized bss section
	memset((void*)&__bss_start, 0x00, (size_t) &kernel_start + image_size - (size_t) &__bss_start);

	// setup heap
	if (!curr_task->heap)
		curr_task->heap = (vma_t*) kmalloc(sizeof(vma_t));

	if (BUILTIN_EXPECT(!curr_task->heap, 0)) {
		LOG_ERROR("load_task: heap is missing!\n");
		return -ENOMEM;
	}

	curr_task->heap->flags = VMA_HEAP|VMA_USER;
	curr_task->heap->start = PAGE_FLOOR(heap);
	curr_task->heap->end = PAGE_FLOOR(heap);

	// region is already reserved for the heap, we have to change the
	// property of the first page
	vma_free(curr_task->heap->start, curr_task->heap->start+PAGE_SIZE);
	vma_add(curr_task->heap->start, curr_task->heap->start+PAGE_SIZE, VMA_HEAP|VMA_USER);

	//create_kernel_task(NULL, foo, "foo1", NORMAL_PRIO);
	//create_kernel_task(NULL, foo, "foo2", NORMAL_PRIO);

	// initialize network
	err = init_netifs();

	if ((err != 0) || !is_proxy())
	{
		char* dummy[] = {"app_name", NULL};

		LOG_INFO("Boot time: %d ms\n", (get_clock_tick() * 1000) / TIMER_FREQ);
		// call user code
		libc_start(1, dummy, NULL); //argc, argv, environ);

		return 0;
	}

	// initialize iRCCE
	if (!is_single_kernel())
		init_rcce();

	soc = lwip_socket(AF_INET6, SOCK_STREAM , 0);
	if (soc < 0) {
		LOG_ERROR("socket failed: %d\n", server);
		return -1;
	}

	// prepare the sockaddr_in structure
	memset((char *) &server, 0x00, sizeof(server));
	server.sin6_family = AF_INET6;
	server.sin6_addr = in6addr_any;
	server.sin6_port = htons(HERMIT_PORT);

	if ((err = lwip_bind(soc, (struct sockaddr *) &server, sizeof(server))) < 0)
	{
		LOG_ERROR("bind failed: %d\n", errno);
		lwip_close(soc);
		return -1;
	}

	if ((err = lwip_listen(soc, 2)) < 0)
	{
		LOG_ERROR("listen failed: %d\n", errno);
		lwip_close(soc);
		return -1;
	}

	len = sizeof(struct sockaddr_in);

	LOG_INFO("Boot time: %d ms\n", (get_clock_tick() * 1000) / TIMER_FREQ);
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

	// call user code
	libc_sd = c;
	libc_start(argc, cargv, cenviron);

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

int hermit_main(void)
{
	hermit_init();
	system_calibration(); // enables also interrupts

	LOG_INFO("This is Hermit %s, build date %u\n", PACKAGE_VERSION, &__DATE__);
	LOG_INFO("Isle %d of %d possible isles\n", isle, possible_isles);
	LOG_INFO("Kernel starts at %p and ends at %p\n", &kernel_start, (size_t)&kernel_start + image_size);
	LOG_INFO("TLS image starts at %p and ends at %p (size 0x%zx)\n", &tls_start, &tls_end, ((size_t) &tls_end) - ((size_t) &tls_start));
	LOG_INFO("BBS starts at %p and ends at %p\n", &hbss_start, (size_t)&kernel_start + image_size);
	LOG_INFO("Per core data starts at %p and ends at %p\n", &percore_start, &percore_end);
	LOG_INFO("Per core size 0x%zx\n", (size_t) &percore_end0 - (size_t) &percore_start);
	LOG_INFO("Processor frequency: %u MHz\n", get_cpu_frequency());
	LOG_INFO("Total memory: %zd MiB\n", atomic_int64_read(&total_pages) * PAGE_SIZE / (1024ULL*1024ULL));
	LOG_INFO("Current allocated memory: %zd KiB\n", atomic_int64_read(&total_allocated_pages) * PAGE_SIZE / 1024ULL);
	LOG_INFO("Current available memory: %zd MiB\n", atomic_int64_read(&total_available_pages) * PAGE_SIZE / (1024ULL*1024ULL));
	LOG_INFO("Core %d is the boot processor\n", boot_processor);
	LOG_INFO("System is able to use %d processors\n", possible_cpus);
	if (mb_info)
		LOG_INFO("Kernel cmdline: %s\n", (char*) (size_t) mb_info->cmdline);
	if (hbmem_base)
		LOG_INFO("Found high bandwidth memory at 0x%zx (size 0x%zx)\n", hbmem_base, hbmem_size);

#if 0
	print_pci_adapters();
#endif

#ifdef DYNAMIC_TICKS
	enable_dynticks();
#endif

	/* wait for the other cpus */
	while(atomic_int32_read(&cpu_online) < atomic_int32_read(&possible_cpus))
		PAUSE;

	print_status();
	//vma_dump();

	create_kernel_task_on_core(NULL, initd, NULL, NORMAL_PRIO, boot_processor);

	while(1) {
		check_workqueues();
		wait_for_task();
	}

	return 0;
}
