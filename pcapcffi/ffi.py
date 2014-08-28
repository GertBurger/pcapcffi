import cffi
ffi = cffi.FFI()

ffi.cdef("""
typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;


typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;

typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;

typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;


typedef int bpf_int32;
typedef unsigned int bpf_u_int32;

typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;

struct timeval
  {
    __time_t tv_sec;
    __suseconds_t tv_usec;
  };

typedef ... pcap_dumper;
typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;
struct pcap_file_header {
 bpf_u_int32 magic;
 u_short version_major;
 u_short version_minor;
 bpf_int32 thiszone;
 bpf_u_int32 sigfigs;
 bpf_u_int32 snaplen;
 bpf_u_int32 linktype;
};
typedef enum {
       PCAP_D_INOUT = 0,
       PCAP_D_IN,
       PCAP_D_OUT
} pcap_direction_t;
struct pcap_pkthdr {
 struct timeval ts;
 bpf_u_int32 caplen;
 bpf_u_int32 len;
};




struct pcap_stat {
 u_int ps_recv;
 u_int ps_drop;
 u_int ps_ifdrop;



};
struct pcap_if {
 struct pcap_if *next;
 char *name;
 char *description;
 struct pcap_addr *addresses;
 bpf_u_int32 flags;
};






struct pcap_addr {
 struct pcap_addr *next;
 struct sockaddr *addr;
 struct sockaddr *netmask;
 struct sockaddr *broadaddr;
 struct sockaddr *dstaddr;
};

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
        const u_char *);
char *pcap_lookupdev(char *);
int pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);

pcap_t *pcap_create(const char *, char *);
int pcap_set_snaplen(pcap_t *, int);
int pcap_set_promisc(pcap_t *, int);
int pcap_can_set_rfmon(pcap_t *);
int pcap_set_rfmon(pcap_t *, int);
int pcap_set_timeout(pcap_t *, int);
int pcap_set_tstamp_type(pcap_t *, int);
int pcap_set_immediate_mode(pcap_t *, int);
int pcap_set_buffer_size(pcap_t *, int);
int pcap_set_tstamp_precision(pcap_t *, int);
int pcap_get_tstamp_precision(pcap_t *);
int pcap_activate(pcap_t *);

int pcap_list_tstamp_types(pcap_t *, int **);
void pcap_free_tstamp_types(int *);
int pcap_tstamp_type_name_to_val(const char *);
const char *pcap_tstamp_type_val_to_name(int);
const char *pcap_tstamp_type_val_to_description(int);
pcap_t *pcap_open_live(const char *, int, int, int, char *);
pcap_t *pcap_open_dead(int, int);
pcap_t *pcap_open_dead_with_tstamp_precision(int, int, u_int);
pcap_t *pcap_open_offline_with_tstamp_precision(const char *, u_int, char *);
pcap_t *pcap_open_offline(const char *, char *);
pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *, u_int, char *);
pcap_t *pcap_fopen_offline(FILE *, char *);


void pcap_close(pcap_t *);
int pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
const u_char*
 pcap_next(pcap_t *, struct pcap_pkthdr *);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
void pcap_breakloop(pcap_t *);
int pcap_stats(pcap_t *, struct pcap_stat *);
int pcap_setfilter(pcap_t *, struct bpf_program *);
int pcap_setdirection(pcap_t *, pcap_direction_t);
int pcap_getnonblock(pcap_t *, char *);
int pcap_setnonblock(pcap_t *, int, char *);
int pcap_inject(pcap_t *, const void *, size_t);
int pcap_sendpacket(pcap_t *, const u_char *, int);
const char *pcap_statustostr(int);
const char *pcap_strerror(int);
char *pcap_geterr(pcap_t *);
void pcap_perror(pcap_t *, char *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int,
     bpf_u_int32);
int pcap_compile_nopcap(int, int, struct bpf_program *, const char *, int, bpf_u_int32);
void pcap_freecode(struct bpf_program *);
int pcap_offline_filter(const struct bpf_program *,
     const struct pcap_pkthdr *, const u_char *);
int pcap_datalink(pcap_t *);
int pcap_datalink_ext(pcap_t *);
int pcap_list_datalinks(pcap_t *, int **);
int pcap_set_datalink(pcap_t *, int);
void pcap_free_datalinks(int *);
int pcap_datalink_name_to_val(const char *);
const char *pcap_datalink_val_to_name(int);
const char *pcap_datalink_val_to_description(int);
int pcap_snapshot(pcap_t *);
int pcap_is_swapped(pcap_t *);
int pcap_major_version(pcap_t *);
int pcap_minor_version(pcap_t *);


FILE *pcap_file(pcap_t *);
int pcap_fileno(pcap_t *);

pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp);
FILE *pcap_dump_file(pcap_dumper_t *);
long pcap_dump_ftell(pcap_dumper_t *);
int pcap_dump_flush(pcap_dumper_t *);
void pcap_dump_close(pcap_dumper_t *);
void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);

int pcap_findalldevs(pcap_if_t **, char *);
void pcap_freealldevs(pcap_if_t *);

const char *pcap_lib_version(void);
u_int bpf_filter(const struct bpf_insn *, const u_char *, u_int, u_int);

int bpf_validate(const struct bpf_insn *f, int len);
char *bpf_image(const struct bpf_insn *, int);
void bpf_dump(const struct bpf_program *, int);
int pcap_get_selectable_fd(pcap_t *);

#define PCAP_ERRBUF_SIZE ...
#define PCAP_ERROR			...     /* generic error code */
#define PCAP_ERROR_BREAK		...     /* loop terminated by pcap_breakloop */
#define PCAP_ERROR_NOT_ACTIVATED	...     /* the capture needs to be activated */
#define PCAP_ERROR_ACTIVATED		...     /* the operation can't be performed on already activated captures */
#define PCAP_ERROR_NO_SUCH_DEVICE	...     /* no such device exists */
#define PCAP_ERROR_RFMON_NOTSUP		...     /* this device doesn't support rfmon (monitor) mode */
#define PCAP_ERROR_NOT_RFMON		...     /* operation supported only in monitor mode */
#define PCAP_ERROR_PERM_DENIED		...     /* no permission to open the device */
#define PCAP_ERROR_IFACE_NOT_UP		...     /* interface isn't up */
#define PCAP_ERROR_CANTSET_TSTAMP_TYPE	...	/* this device doesn't support setting the time stamp type */
#define PCAP_ERROR_PROMISC_PERM_DENIED	...	/* you don't have permission to capture in promiscuous mode */
#define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP ...  /* the requested time stamp precision is not supported */

/*
 * Warning codes for the pcap API.
 * These will all be positive and non-zero, so they won't look like
 * errors.
 */
#define PCAP_WARNING			...	/* generic warning code */
#define PCAP_WARNING_PROMISC_NOTSUP	...	/* this device doesn't support promiscuous mode */
#define PCAP_WARNING_TSTAMP_TYPE_NOTSUP	...	/* the requested time stamp type is not supported */

/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define PCAP_NETMASK_UNKNOWN	...
""")

libpcap = ffi.verify('''
#include <sys/types.h>
#include <sys/time.h>
#include <pcap/pcap.h>
''', libraries=['pcap'])

errbuf = ffi.new('char[]', libpcap.PCAP_ERRBUF_SIZE)


def pcap_error():
    raise RuntimeError(errbuf)


def pcap_statustostr(error):
    return ffi.string(libpcap.pcap_statustostr(error))
