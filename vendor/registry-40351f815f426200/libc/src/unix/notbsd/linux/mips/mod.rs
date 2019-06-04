pub type pthread_t = c_ulong;
pub type shmatt_t = ::c_ulong;
pub type msgqnum_t = ::c_ulong;
pub type msglen_t = ::c_ulong;
pub type fsblkcnt_t = ::c_ulong;
pub type fsfilcnt_t = ::c_ulong;
pub type rlim_t = c_ulong;
pub type __priority_which_t = ::c_uint;
pub type __rlimit_resource_t = ::c_uint;

s! {
    pub struct glob64_t {
        pub gl_pathc: ::size_t,
        pub gl_pathv: *mut *mut ::c_char,
        pub gl_offs: ::size_t,
        pub gl_flags: ::c_int,

        __unused1: *mut ::c_void,
        __unused2: *mut ::c_void,
        __unused3: *mut ::c_void,
        __unused4: *mut ::c_void,
        __unused5: *mut ::c_void,
    }

    pub struct termios2 {
        pub c_iflag: ::tcflag_t,
        pub c_oflag: ::tcflag_t,
        pub c_cflag: ::tcflag_t,
        pub c_lflag: ::tcflag_t,
        pub c_line: ::cc_t,
        pub c_cc: [::cc_t; 23],
        pub c_ispeed: ::speed_t,
        pub c_ospeed: ::speed_t,
    }

    pub struct nlmsghdr {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    pub struct nlmsgerr {
        pub error: ::c_int,
        pub msg: nlmsghdr,
    }

    pub struct nl_pktinfo {
        pub group: u32,
    }

    pub struct nl_mmap_req {
        pub nm_block_size: ::c_uint,
        pub nm_block_nr: ::c_uint,
        pub nm_frame_size: ::c_uint,
        pub nm_frame_nr: ::c_uint,
    }

    pub struct nl_mmap_hdr {
        pub nm_status: ::c_uint,
        pub nm_len: ::c_uint,
        pub nm_group: u32,
        pub nm_pid: u32,
        pub nm_uid: u32,
        pub nm_gid: u32,
    }

    pub struct nlattr {
        pub nla_len: u16,
        pub nla_type: u16,
    }
}

pub const MS_RMT_MASK: ::c_ulong = 0x02800051;

pub const SFD_CLOEXEC: ::c_int = 0x080000;

pub const NCCS: usize = 32;

pub const O_TRUNC: ::c_int = 512;

pub const O_NOATIME: ::c_int = 0o1000000;
pub const O_CLOEXEC: ::c_int = 0x80000;
pub const O_PATH: ::c_int = 0o10000000;
pub const O_TMPFILE: ::c_int = 0o20000000 | O_DIRECTORY;

pub const EBFONT: ::c_int = 59;
pub const ENOSTR: ::c_int = 60;
pub const ENODATA: ::c_int = 61;
pub const ETIME: ::c_int = 62;
pub const ENOSR: ::c_int = 63;
pub const ENONET: ::c_int = 64;
pub const ENOPKG: ::c_int = 65;
pub const EREMOTE: ::c_int = 66;
pub const ENOLINK: ::c_int = 67;
pub const EADV: ::c_int = 68;
pub const ESRMNT: ::c_int = 69;
pub const ECOMM: ::c_int = 70;
pub const EPROTO: ::c_int = 71;
pub const EDOTDOT: ::c_int = 73;

pub const SA_NODEFER: ::c_int = 0x40000000;
pub const SA_RESETHAND: ::c_int = 0x80000000;
pub const SA_RESTART: ::c_int = 0x10000000;
pub const SA_NOCLDSTOP: ::c_int = 0x00000001;

pub const EPOLL_CLOEXEC: ::c_int = 0x80000;

pub const EFD_CLOEXEC: ::c_int = 0x80000;

pub const BUFSIZ: ::c_uint = 8192;
pub const TMP_MAX: ::c_uint = 238328;
pub const FOPEN_MAX: ::c_uint = 16;
pub const POSIX_FADV_DONTNEED: ::c_int = 4;
pub const POSIX_FADV_NOREUSE: ::c_int = 5;
pub const POSIX_MADV_DONTNEED: ::c_int = 4;
pub const _SC_EQUIV_CLASS_MAX: ::c_int = 41;
pub const _SC_CHARCLASS_NAME_MAX: ::c_int = 45;
pub const _SC_PII: ::c_int = 53;
pub const _SC_PII_XTI: ::c_int = 54;
pub const _SC_PII_SOCKET: ::c_int = 55;
pub const _SC_PII_INTERNET: ::c_int = 56;
pub const _SC_PII_OSI: ::c_int = 57;
pub const _SC_POLL: ::c_int = 58;
pub const _SC_SELECT: ::c_int = 59;
pub const _SC_PII_INTERNET_STREAM: ::c_int = 61;
pub const _SC_PII_INTERNET_DGRAM: ::c_int = 62;
pub const _SC_PII_OSI_COTS: ::c_int = 63;
pub const _SC_PII_OSI_CLTS: ::c_int = 64;
pub const _SC_PII_OSI_M: ::c_int = 65;
pub const _SC_T_IOV_MAX: ::c_int = 66;
pub const _SC_2_C_VERSION: ::c_int = 96;
pub const _SC_CHAR_BIT: ::c_int = 101;
pub const _SC_CHAR_MAX: ::c_int = 102;
pub const _SC_CHAR_MIN: ::c_int = 103;
pub const _SC_INT_MAX: ::c_int = 104;
pub const _SC_INT_MIN: ::c_int = 105;
pub const _SC_LONG_BIT: ::c_int = 106;
pub const _SC_WORD_BIT: ::c_int = 107;
pub const _SC_MB_LEN_MAX: ::c_int = 108;
pub const _SC_SSIZE_MAX: ::c_int = 110;
pub const _SC_SCHAR_MAX: ::c_int = 111;
pub const _SC_SCHAR_MIN: ::c_int = 112;
pub const _SC_SHRT_MAX: ::c_int = 113;
pub const _SC_SHRT_MIN: ::c_int = 114;
pub const _SC_UCHAR_MAX: ::c_int = 115;
pub const _SC_UINT_MAX: ::c_int = 116;
pub const _SC_ULONG_MAX: ::c_int = 117;
pub const _SC_USHRT_MAX: ::c_int = 118;
pub const _SC_NL_ARGMAX: ::c_int = 119;
pub const _SC_NL_LANGMAX: ::c_int = 120;
pub const _SC_NL_MSGMAX: ::c_int = 121;
pub const _SC_NL_NMAX: ::c_int = 122;
pub const _SC_NL_SETMAX: ::c_int = 123;
pub const _SC_NL_TEXTMAX: ::c_int = 124;
pub const _SC_BASE: ::c_int = 134;
pub const _SC_C_LANG_SUPPORT: ::c_int = 135;
pub const _SC_C_LANG_SUPPORT_R: ::c_int = 136;
pub const _SC_DEVICE_IO: ::c_int = 140;
pub const _SC_DEVICE_SPECIFIC: ::c_int = 141;
pub const _SC_DEVICE_SPECIFIC_R: ::c_int = 142;
pub const _SC_FD_MGMT: ::c_int = 143;
pub const _SC_FIFO: ::c_int = 144;
pub const _SC_PIPE: ::c_int = 145;
pub const _SC_FILE_ATTRIBUTES: ::c_int = 146;
pub const _SC_FILE_LOCKING: ::c_int = 147;
pub const _SC_FILE_SYSTEM: ::c_int = 148;
pub const _SC_MULTI_PROCESS: ::c_int = 150;
pub const _SC_SINGLE_PROCESS: ::c_int = 151;
pub const _SC_NETWORKING: ::c_int = 152;
pub const _SC_REGEX_VERSION: ::c_int = 156;
pub const _SC_SIGNALS: ::c_int = 158;
pub const _SC_SYSTEM_DATABASE: ::c_int = 162;
pub const _SC_SYSTEM_DATABASE_R: ::c_int = 163;
pub const _SC_USER_GROUPS: ::c_int = 166;
pub const _SC_USER_GROUPS_R: ::c_int = 167;
pub const _SC_LEVEL1_ICACHE_SIZE: ::c_int = 185;
pub const _SC_LEVEL1_ICACHE_ASSOC: ::c_int = 186;
pub const _SC_LEVEL1_ICACHE_LINESIZE: ::c_int = 187;
pub const _SC_LEVEL1_DCACHE_SIZE: ::c_int = 188;
pub const _SC_LEVEL1_DCACHE_ASSOC: ::c_int = 189;
pub const _SC_LEVEL1_DCACHE_LINESIZE: ::c_int = 190;
pub const _SC_LEVEL2_CACHE_SIZE: ::c_int = 191;
pub const _SC_LEVEL2_CACHE_ASSOC: ::c_int = 192;
pub const _SC_LEVEL2_CACHE_LINESIZE: ::c_int = 193;
pub const _SC_LEVEL3_CACHE_SIZE: ::c_int = 194;
pub const _SC_LEVEL3_CACHE_ASSOC: ::c_int = 195;
pub const _SC_LEVEL3_CACHE_LINESIZE: ::c_int = 196;
pub const _SC_LEVEL4_CACHE_SIZE: ::c_int = 197;
pub const _SC_LEVEL4_CACHE_ASSOC: ::c_int = 198;
pub const _SC_LEVEL4_CACHE_LINESIZE: ::c_int = 199;
pub const O_ACCMODE: ::c_int = 3;
pub const O_DIRECT: ::c_int = 0x8000;
pub const O_DIRECTORY: ::c_int = 0x10000;
pub const O_NOFOLLOW: ::c_int = 0x20000;
pub const ST_RELATIME: ::c_ulong = 4096;
pub const NI_MAXHOST: ::socklen_t = 1025;

pub const RLIMIT_NOFILE: ::__rlimit_resource_t = 5;
pub const RLIMIT_AS: ::__rlimit_resource_t = 6;
pub const RLIMIT_RSS: ::__rlimit_resource_t = 7;
pub const RLIMIT_NPROC: ::__rlimit_resource_t = 8;
pub const RLIMIT_MEMLOCK: ::__rlimit_resource_t = 9;
pub const RLIMIT_NLIMITS: ::__rlimit_resource_t = 16;

pub const O_APPEND: ::c_int = 8;
pub const O_CREAT: ::c_int = 256;
pub const O_EXCL: ::c_int = 1024;
pub const O_NOCTTY: ::c_int = 2048;
pub const O_NONBLOCK: ::c_int = 128;
pub const O_SYNC: ::c_int = 0x4010;
pub const O_RSYNC: ::c_int = 0x4010;
pub const O_DSYNC: ::c_int = 0x10;
pub const O_FSYNC: ::c_int = 0x4010;
pub const O_ASYNC: ::c_int = 0x1000;
pub const O_NDELAY: ::c_int = 0x80;

pub const SOCK_NONBLOCK: ::c_int = 128;

pub const EDEADLK: ::c_int = 45;
pub const ENAMETOOLONG: ::c_int = 78;
pub const ENOLCK: ::c_int = 46;
pub const ENOSYS: ::c_int = 89;
pub const ENOTEMPTY: ::c_int = 93;
pub const ELOOP: ::c_int = 90;
pub const ENOMSG: ::c_int = 35;
pub const EIDRM: ::c_int = 36;
pub const ECHRNG: ::c_int = 37;
pub const EL2NSYNC: ::c_int = 38;
pub const EL3HLT: ::c_int = 39;
pub const EL3RST: ::c_int = 40;
pub const ELNRNG: ::c_int = 41;
pub const EUNATCH: ::c_int = 42;
pub const ENOCSI: ::c_int = 43;
pub const EL2HLT: ::c_int = 44;
pub const EBADE: ::c_int = 50;
pub const EBADR: ::c_int = 51;
pub const EXFULL: ::c_int = 52;
pub const ENOANO: ::c_int = 53;
pub const EBADRQC: ::c_int = 54;
pub const EBADSLT: ::c_int = 55;
pub const EDEADLOCK: ::c_int = 56;
pub const EMULTIHOP: ::c_int = 74;
pub const EOVERFLOW: ::c_int = 79;
pub const ENOTUNIQ: ::c_int = 80;
pub const EBADFD: ::c_int = 81;
pub const EBADMSG: ::c_int = 77;
pub const EREMCHG: ::c_int = 82;
pub const ELIBACC: ::c_int = 83;
pub const ELIBBAD: ::c_int = 84;
pub const ELIBSCN: ::c_int = 85;
pub const ELIBMAX: ::c_int = 86;
pub const ELIBEXEC: ::c_int = 87;
pub const EILSEQ: ::c_int = 88;
pub const ERESTART: ::c_int = 91;
pub const ESTRPIPE: ::c_int = 92;
pub const EUSERS: ::c_int = 94;
pub const ENOTSOCK: ::c_int = 95;
pub const EDESTADDRREQ: ::c_int = 96;
pub const EMSGSIZE: ::c_int = 97;
pub const EPROTOTYPE: ::c_int = 98;
pub const ENOPROTOOPT: ::c_int = 99;
pub const EPROTONOSUPPORT: ::c_int = 120;
pub const ESOCKTNOSUPPORT: ::c_int = 121;
pub const EOPNOTSUPP: ::c_int = 122;
pub const ENOTSUP: ::c_int = EOPNOTSUPP;
pub const EPFNOSUPPORT: ::c_int = 123;
pub const EAFNOSUPPORT: ::c_int = 124;
pub const EADDRINUSE: ::c_int = 125;
pub const EADDRNOTAVAIL: ::c_int = 126;
pub const ENETDOWN: ::c_int = 127;
pub const ENETUNREACH: ::c_int = 128;
pub const ENETRESET: ::c_int = 129;
pub const ECONNABORTED: ::c_int = 130;
pub const ECONNRESET: ::c_int = 131;
pub const ENOBUFS: ::c_int = 132;
pub const EISCONN: ::c_int = 133;
pub const ENOTCONN: ::c_int = 134;
pub const ESHUTDOWN: ::c_int = 143;
pub const ETOOMANYREFS: ::c_int = 144;
pub const ETIMEDOUT: ::c_int = 145;
pub const ECONNREFUSED: ::c_int = 146;
pub const EHOSTDOWN: ::c_int = 147;
pub const EHOSTUNREACH: ::c_int = 148;
pub const EALREADY: ::c_int = 149;
pub const EINPROGRESS: ::c_int = 150;
pub const ESTALE: ::c_int = 151;
pub const EUCLEAN: ::c_int = 135;
pub const ENOTNAM: ::c_int = 137;
pub const ENAVAIL: ::c_int = 138;
pub const EISNAM: ::c_int = 139;
pub const EREMOTEIO: ::c_int = 140;
pub const EDQUOT: ::c_int = 1133;
pub const ENOMEDIUM: ::c_int = 159;
pub const EMEDIUMTYPE: ::c_int = 160;
pub const ECANCELED: ::c_int = 158;
pub const ENOKEY: ::c_int = 161;
pub const EKEYEXPIRED: ::c_int = 162;
pub const EKEYREVOKED: ::c_int = 163;
pub const EKEYREJECTED: ::c_int = 164;
pub const EOWNERDEAD: ::c_int = 165;
pub const ENOTRECOVERABLE: ::c_int = 166;
pub const ERFKILL: ::c_int = 167;

pub const LC_PAPER: ::c_int = 7;
pub const LC_NAME: ::c_int = 8;
pub const LC_ADDRESS: ::c_int = 9;
pub const LC_TELEPHONE: ::c_int = 10;
pub const LC_MEASUREMENT: ::c_int = 11;
pub const LC_IDENTIFICATION: ::c_int = 12;
pub const LC_PAPER_MASK: ::c_int = (1 << LC_PAPER);
pub const LC_NAME_MASK: ::c_int = (1 << LC_NAME);
pub const LC_ADDRESS_MASK: ::c_int = (1 << LC_ADDRESS);
pub const LC_TELEPHONE_MASK: ::c_int = (1 << LC_TELEPHONE);
pub const LC_MEASUREMENT_MASK: ::c_int = (1 << LC_MEASUREMENT);
pub const LC_IDENTIFICATION_MASK: ::c_int = (1 << LC_IDENTIFICATION);
pub const LC_ALL_MASK: ::c_int = ::LC_CTYPE_MASK
                               | ::LC_NUMERIC_MASK
                               | ::LC_TIME_MASK
                               | ::LC_COLLATE_MASK
                               | ::LC_MONETARY_MASK
                               | ::LC_MESSAGES_MASK
                               | LC_PAPER_MASK
                               | LC_NAME_MASK
                               | LC_ADDRESS_MASK
                               | LC_TELEPHONE_MASK
                               | LC_MEASUREMENT_MASK
                               | LC_IDENTIFICATION_MASK;

pub const MAP_NORESERVE: ::c_int = 0x400;
pub const MAP_ANON: ::c_int = 0x800;
pub const MAP_ANONYMOUS: ::c_int = 0x800;
pub const MAP_GROWSDOWN: ::c_int = 0x1000;
pub const MAP_DENYWRITE: ::c_int = 0x2000;
pub const MAP_EXECUTABLE: ::c_int = 0x4000;
pub const MAP_LOCKED: ::c_int = 0x8000;
pub const MAP_POPULATE: ::c_int = 0x10000;
pub const MAP_NONBLOCK: ::c_int = 0x20000;
pub const MAP_STACK: ::c_int = 0x40000;
pub const MAP_SHARED_VALIDATE: ::c_int = 0x3;
pub const MAP_FIXED_NOREPLACE: ::c_int = 0x100000;

pub const SOCK_STREAM: ::c_int = 2;
pub const SOCK_DGRAM: ::c_int = 1;
pub const SOCK_SEQPACKET: ::c_int = 5;
pub const SOCK_DCCP: ::c_int = 6;
pub const SOCK_PACKET: ::c_int = 10;

pub const SOL_SOCKET: ::c_int = 0xffff;

pub const SO_REUSEADDR: ::c_int = 0x0004;
pub const SO_KEEPALIVE: ::c_int = 0x0008;
pub const SO_DONTROUTE: ::c_int = 0x0010;
pub const SO_BROADCAST: ::c_int = 0x0020;
pub const SO_LINGER: ::c_int = 0x0080;
pub const SO_OOBINLINE: ::c_int = 0x0100;
pub const SO_REUSEPORT: ::c_int = 0x0200;
pub const SO_TYPE: ::c_int = 0x1008;
pub const SO_STYLE: ::c_int = SO_TYPE;
pub const SO_ERROR: ::c_int = 0x1007;
pub const SO_SNDBUF: ::c_int = 0x1001;
pub const SO_RCVBUF: ::c_int = 0x1002;
pub const SO_SNDLOWAT: ::c_int = 0x1003;
pub const SO_RCVLOWAT: ::c_int = 0x1004;
pub const SO_SNDTIMEO: ::c_int = 0x1005;
pub const SO_RCVTIMEO: ::c_int = 0x1006;
pub const SO_ACCEPTCONN: ::c_int = 0x1009;
pub const SO_PROTOCOL: ::c_int = 0x1028;
pub const SO_DOMAIN: ::c_int = 0x1029;
pub const SO_NO_CHECK: ::c_int = 11;
pub const SO_PRIORITY: ::c_int = 12;
pub const SO_BSDCOMPAT: ::c_int = 14;
pub const SO_PASSCRED: ::c_int = 17;
pub const SO_PEERCRED: ::c_int = 18;
pub const SO_SECURITY_AUTHENTICATION: ::c_int = 22;
pub const SO_SECURITY_ENCRYPTION_TRANSPORT: ::c_int = 23;
pub const SO_SECURITY_ENCRYPTION_NETWORK: ::c_int = 24;
pub const SO_BINDTODEVICE: ::c_int = 25;
pub const SO_ATTACH_FILTER: ::c_int = 26;
pub const SO_DETACH_FILTER: ::c_int = 27;
pub const SO_GET_FILTER: ::c_int = SO_ATTACH_FILTER;
pub const SO_PEERNAME: ::c_int = 28;
pub const SO_TIMESTAMP: ::c_int = 29;
pub const SO_PEERSEC: ::c_int = 30;
pub const SO_SNDBUFFORCE: ::c_int = 31;
pub const SO_RCVBUFFORCE: ::c_int = 33;
pub const SO_PASSSEC: ::c_int = 34;
pub const SO_TIMESTAMPNS: ::c_int = 35;
pub const SCM_TIMESTAMPNS: ::c_int = SO_TIMESTAMPNS;
pub const SO_MARK: ::c_int = 36;
pub const SO_RXQ_OVFL: ::c_int = 40;
pub const SO_WIFI_STATUS: ::c_int = 41;
pub const SCM_WIFI_STATUS: ::c_int = SO_WIFI_STATUS;
pub const SO_PEEK_OFF: ::c_int = 42;
pub const SO_NOFCS: ::c_int = 43;
pub const SO_LOCK_FILTER: ::c_int = 44;
pub const SO_SELECT_ERR_QUEUE: ::c_int = 45;
pub const SO_BUSY_POLL: ::c_int = 46;
pub const SO_MAX_PACING_RATE: ::c_int = 47;
pub const SO_BPF_EXTENSIONS: ::c_int = 48;
pub const SO_INCOMING_CPU: ::c_int = 49;
pub const SO_ATTACH_BPF: ::c_int = 50;
pub const SO_DETACH_BPF: ::c_int = SO_DETACH_FILTER;

/* DCCP socket options */
pub const DCCP_SOCKOPT_PACKET_SIZE: ::c_int = 1;
pub const DCCP_SOCKOPT_SERVICE: ::c_int = 2;
pub const DCCP_SOCKOPT_CHANGE_L: ::c_int = 3;
pub const DCCP_SOCKOPT_CHANGE_R: ::c_int = 4;
pub const DCCP_SOCKOPT_GET_CUR_MPS: ::c_int = 5;
pub const DCCP_SOCKOPT_SERVER_TIMEWAIT: ::c_int = 6;
pub const DCCP_SOCKOPT_SEND_CSCOV: ::c_int = 10;
pub const DCCP_SOCKOPT_RECV_CSCOV: ::c_int = 11;
pub const DCCP_SOCKOPT_AVAILABLE_CCIDS: ::c_int = 12;
pub const DCCP_SOCKOPT_CCID: ::c_int = 13;
pub const DCCP_SOCKOPT_TX_CCID: ::c_int = 14;
pub const DCCP_SOCKOPT_RX_CCID: ::c_int = 15;
pub const DCCP_SOCKOPT_QPOLICY_ID: ::c_int = 16;
pub const DCCP_SOCKOPT_QPOLICY_TXQLEN: ::c_int = 17;
pub const DCCP_SOCKOPT_CCID_RX_INFO: ::c_int = 128;
pub const DCCP_SOCKOPT_CCID_TX_INFO: ::c_int = 192;

/// maximum number of services provided on the same listening port
pub const DCCP_SERVICE_LIST_MAX_LEN: ::c_int = 32;

pub const FIOCLEX: ::c_ulong = 0x6601;
pub const FIONBIO: ::c_ulong = 0x667e;

pub const SA_ONSTACK: ::c_int = 0x08000000;
pub const SA_SIGINFO: ::c_int = 0x00000008;
pub const SA_NOCLDWAIT: ::c_int = 0x00010000;

pub const SIGCHLD: ::c_int = 18;
pub const SIGBUS: ::c_int = 10;
pub const SIGTTIN: ::c_int = 26;
pub const SIGTTOU: ::c_int = 27;
pub const SIGXCPU: ::c_int = 30;
pub const SIGXFSZ: ::c_int = 31;
pub const SIGVTALRM: ::c_int = 28;
pub const SIGPROF: ::c_int = 29;
pub const SIGWINCH: ::c_int = 20;
pub const SIGUSR1: ::c_int = 16;
pub const SIGUSR2: ::c_int = 17;
pub const SIGCONT: ::c_int = 25;
pub const SIGSTOP: ::c_int = 23;
pub const SIGTSTP: ::c_int = 24;
pub const SIGURG: ::c_int = 21;
pub const SIGIO: ::c_int = 22;
pub const SIGSYS: ::c_int = 12;
pub const SIGPOLL: ::c_int = 22;
pub const SIGPWR: ::c_int = 19;
pub const SIG_SETMASK: ::c_int = 3;
pub const SIG_BLOCK: ::c_int = 0x1;
pub const SIG_UNBLOCK: ::c_int = 0x2;

pub const POLLWRNORM: ::c_short = 0x004;
pub const POLLWRBAND: ::c_short = 0x100;

pub const PTHREAD_STACK_MIN: ::size_t = 131072;
pub const PTHREAD_MUTEX_ADAPTIVE_NP: ::c_int = 3;

pub const ADFS_SUPER_MAGIC: ::c_long = 0x0000adf5;
pub const AFFS_SUPER_MAGIC: ::c_long = 0x0000adff;
pub const CODA_SUPER_MAGIC: ::c_long = 0x73757245;
pub const CRAMFS_MAGIC: ::c_long = 0x28cd3d45;
pub const EFS_SUPER_MAGIC: ::c_long = 0x00414a53;
pub const EXT2_SUPER_MAGIC: ::c_long = 0x0000ef53;
pub const EXT3_SUPER_MAGIC: ::c_long = 0x0000ef53;
pub const EXT4_SUPER_MAGIC: ::c_long = 0x0000ef53;
pub const HPFS_SUPER_MAGIC: ::c_long = 0xf995e849;
pub const HUGETLBFS_MAGIC: ::c_long = 0x958458f6;
pub const ISOFS_SUPER_MAGIC: ::c_long = 0x00009660;
pub const JFFS2_SUPER_MAGIC: ::c_long = 0x000072b6;
pub const MINIX_SUPER_MAGIC: ::c_long = 0x0000137f;
pub const MINIX_SUPER_MAGIC2: ::c_long = 0x0000138f;
pub const MINIX2_SUPER_MAGIC: ::c_long = 0x00002468;
pub const MINIX2_SUPER_MAGIC2: ::c_long = 0x00002478;
pub const MSDOS_SUPER_MAGIC: ::c_long = 0x00004d44;
pub const NCP_SUPER_MAGIC: ::c_long = 0x0000564c;
pub const NFS_SUPER_MAGIC: ::c_long = 0x00006969;
pub const OPENPROM_SUPER_MAGIC: ::c_long = 0x00009fa1;
pub const PROC_SUPER_MAGIC: ::c_long = 0x00009fa0;
pub const QNX4_SUPER_MAGIC: ::c_long = 0x0000002f;
pub const REISERFS_SUPER_MAGIC: ::c_long = 0x52654973;
pub const SMB_SUPER_MAGIC: ::c_long = 0x0000517b;
pub const TMPFS_MAGIC: ::c_long = 0x01021994;
pub const USBDEVICE_SUPER_MAGIC: ::c_long = 0x00009fa2;

pub const VEOF: usize = 16;
pub const VEOL: usize = 17;
pub const VEOL2: usize = 6;
pub const VMIN: usize = 4;
pub const IEXTEN: ::tcflag_t = 0x00000100;
pub const TOSTOP: ::tcflag_t = 0x00008000;
pub const FLUSHO: ::tcflag_t = 0x00002000;
pub const EXTPROC: ::tcflag_t = 0o200000;
pub const TCSANOW: ::c_int = 0x540e;
pub const TCSADRAIN: ::c_int = 0x540f;
pub const TCSAFLUSH: ::c_int = 0x5410;

pub const CPU_SETSIZE: ::c_int = 0x400;

pub const PTRACE_TRACEME: ::c_uint = 0;
pub const PTRACE_PEEKTEXT: ::c_uint = 1;
pub const PTRACE_PEEKDATA: ::c_uint = 2;
pub const PTRACE_PEEKUSER: ::c_uint = 3;
pub const PTRACE_POKETEXT: ::c_uint = 4;
pub const PTRACE_POKEDATA: ::c_uint = 5;
pub const PTRACE_POKEUSER: ::c_uint = 6;
pub const PTRACE_CONT: ::c_uint = 7;
pub const PTRACE_KILL: ::c_uint = 8;
pub const PTRACE_SINGLESTEP: ::c_uint = 9;
pub const PTRACE_ATTACH: ::c_uint = 16;
pub const PTRACE_DETACH: ::c_uint = 17;
pub const PTRACE_SYSCALL: ::c_uint = 24;
pub const PTRACE_SETOPTIONS: ::c_uint = 0x4200;
pub const PTRACE_GETEVENTMSG: ::c_uint = 0x4201;
pub const PTRACE_GETSIGINFO: ::c_uint = 0x4202;
pub const PTRACE_SETSIGINFO: ::c_uint = 0x4203;
pub const PTRACE_GETFPREGS: ::c_uint = 14;
pub const PTRACE_SETFPREGS: ::c_uint = 15;
pub const PTRACE_GETFPXREGS: ::c_uint = 18;
pub const PTRACE_SETFPXREGS: ::c_uint = 19;
pub const PTRACE_GETREGS: ::c_uint = 12;
pub const PTRACE_SETREGS: ::c_uint = 13;

pub const MAP_HUGETLB: ::c_int = 0x080000;

pub const EFD_NONBLOCK: ::c_int = 0x80;

pub const F_RDLCK: ::c_int = 0;
pub const F_WRLCK: ::c_int = 1;
pub const F_UNLCK: ::c_int = 2;
pub const F_GETLK: ::c_int = 14;
pub const F_GETOWN: ::c_int = 23;
pub const F_SETOWN: ::c_int = 24;
pub const F_SETLK: ::c_int = 6;
pub const F_SETLKW: ::c_int = 7;

pub const SFD_NONBLOCK: ::c_int = 0x80;

pub const TCGETS: ::c_ulong = 0x540d;
pub const TCSETS: ::c_ulong = 0x540e;
pub const TCSETSW: ::c_ulong = 0x540f;
pub const TCSETSF: ::c_ulong = 0x5410;
pub const TCGETA: ::c_ulong = 0x5401;
pub const TCSETA: ::c_ulong = 0x5402;
pub const TCSETAW: ::c_ulong = 0x5403;
pub const TCSETAF: ::c_ulong = 0x5404;
pub const TCSBRK: ::c_ulong = 0x5405;
pub const TCXONC: ::c_ulong = 0x5406;
pub const TCFLSH: ::c_ulong = 0x5407;
pub const TIOCGSOFTCAR: ::c_ulong = 0x5481;
pub const TIOCSSOFTCAR: ::c_ulong = 0x5482;
pub const TIOCINQ: ::c_ulong = 0x467f;
pub const TIOCLINUX: ::c_ulong = 0x5483;
pub const TIOCGSERIAL: ::c_ulong = 0x5484;
pub const TIOCEXCL: ::c_ulong = 0x740d;
pub const TIOCNXCL: ::c_ulong = 0x740e;
pub const TIOCSCTTY: ::c_ulong = 0x5480;
pub const TIOCGPGRP: ::c_ulong = 0x40047477;
pub const TIOCSPGRP: ::c_ulong = 0x80047476;
pub const TIOCOUTQ: ::c_ulong = 0x7472;
pub const TIOCSTI: ::c_ulong = 0x5472;
pub const TIOCGWINSZ: ::c_ulong = 0x40087468;
pub const TIOCSWINSZ: ::c_ulong = 0x80087467;
pub const TIOCMGET: ::c_ulong = 0x741d;
pub const TIOCMBIS: ::c_ulong = 0x741b;
pub const TIOCMBIC: ::c_ulong = 0x741c;
pub const TIOCMSET: ::c_ulong = 0x741a;
pub const FIONREAD: ::c_ulong = 0x467f;
pub const TIOCCONS: ::c_ulong = 0x80047478;

pub const RTLD_DEEPBIND: ::c_int = 0x10;
pub const RTLD_GLOBAL: ::c_int = 0x4;
pub const RTLD_NOLOAD: ::c_int = 0x8;

pub const LINUX_REBOOT_MAGIC1: ::c_int = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2: ::c_int = 672274793;
pub const LINUX_REBOOT_MAGIC2A: ::c_int = 85072278;
pub const LINUX_REBOOT_MAGIC2B: ::c_int = 369367448;
pub const LINUX_REBOOT_MAGIC2C: ::c_int = 537993216;

pub const LINUX_REBOOT_CMD_RESTART: ::c_int = 0x01234567;
pub const LINUX_REBOOT_CMD_HALT: ::c_int = 0xCDEF0123;
pub const LINUX_REBOOT_CMD_CAD_ON: ::c_int = 0x89ABCDEF;
pub const LINUX_REBOOT_CMD_CAD_OFF: ::c_int = 0x00000000;
pub const LINUX_REBOOT_CMD_POWER_OFF: ::c_int = 0x4321FEDC;
pub const LINUX_REBOOT_CMD_RESTART2: ::c_int = 0xA1B2C3D4;
pub const LINUX_REBOOT_CMD_SW_SUSPEND: ::c_int = 0xD000FCE2;
pub const LINUX_REBOOT_CMD_KEXEC: ::c_int = 0x45584543;

pub const MCL_CURRENT: ::c_int = 0x0001;
pub const MCL_FUTURE: ::c_int = 0x0002;

pub const SIGSTKSZ: ::size_t = 8192;
pub const MINSIGSTKSZ: ::size_t = 2048;
pub const CBAUD: ::tcflag_t = 0o0010017;
pub const TAB1: ::tcflag_t = 0x00000800;
pub const TAB2: ::tcflag_t = 0x00001000;
pub const TAB3: ::tcflag_t = 0x00001800;
pub const CR1: ::tcflag_t = 0x00000200;
pub const CR2: ::tcflag_t = 0x00000400;
pub const CR3: ::tcflag_t = 0x00000600;
pub const FF1: ::tcflag_t = 0x00008000;
pub const BS1: ::tcflag_t = 0x00002000;
pub const VT1: ::tcflag_t = 0x00004000;
pub const VWERASE: usize = 14;
pub const VREPRINT: usize = 12;
pub const VSUSP: usize = 10;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VDISCARD: usize = 13;
pub const VTIME: usize = 5;
pub const IXON: ::tcflag_t = 0x00000400;
pub const IXOFF: ::tcflag_t = 0x00001000;
pub const ONLCR: ::tcflag_t = 0x4;
pub const CSIZE: ::tcflag_t = 0x00000030;
pub const CS6: ::tcflag_t = 0x00000010;
pub const CS7: ::tcflag_t = 0x00000020;
pub const CS8: ::tcflag_t = 0x00000030;
pub const CSTOPB: ::tcflag_t = 0x00000040;
pub const CREAD: ::tcflag_t = 0x00000080;
pub const PARENB: ::tcflag_t = 0x00000100;
pub const PARODD: ::tcflag_t = 0x00000200;
pub const HUPCL: ::tcflag_t = 0x00000400;
pub const CLOCAL: ::tcflag_t = 0x00000800;
pub const ECHOKE: ::tcflag_t = 0x00000800;
pub const ECHOE: ::tcflag_t = 0x00000010;
pub const ECHOK: ::tcflag_t = 0x00000020;
pub const ECHONL: ::tcflag_t = 0x00000040;
pub const ECHOPRT: ::tcflag_t = 0x00000400;
pub const ECHOCTL: ::tcflag_t = 0x00000200;
pub const ISIG: ::tcflag_t = 0x00000001;
pub const ICANON: ::tcflag_t = 0x00000002;
pub const PENDIN: ::tcflag_t = 0x00004000;
pub const NOFLSH: ::tcflag_t = 0x00000080;
pub const CIBAUD: ::tcflag_t = 0o02003600000;
pub const CBAUDEX: ::tcflag_t = 0o010000;
pub const VSWTC: usize = 7;
pub const OLCUC:  ::tcflag_t = 0o000002;
pub const NLDLY:  ::tcflag_t = 0o000400;
pub const CRDLY:  ::tcflag_t = 0o003000;
pub const TABDLY: ::tcflag_t = 0o014000;
pub const BSDLY:  ::tcflag_t = 0o020000;
pub const FFDLY:  ::tcflag_t = 0o100000;
pub const VTDLY:  ::tcflag_t = 0o040000;
pub const XTABS:  ::tcflag_t = 0o014000;

pub const B0: ::speed_t = 0o000000;
pub const B50: ::speed_t = 0o000001;
pub const B75: ::speed_t = 0o000002;
pub const B110: ::speed_t = 0o000003;
pub const B134: ::speed_t = 0o000004;
pub const B150: ::speed_t = 0o000005;
pub const B200: ::speed_t = 0o000006;
pub const B300: ::speed_t = 0o000007;
pub const B600: ::speed_t = 0o000010;
pub const B1200: ::speed_t = 0o000011;
pub const B1800: ::speed_t = 0o000012;
pub const B2400: ::speed_t = 0o000013;
pub const B4800: ::speed_t = 0o000014;
pub const B9600: ::speed_t = 0o000015;
pub const B19200: ::speed_t = 0o000016;
pub const B38400: ::speed_t = 0o000017;
pub const EXTA: ::speed_t = B19200;
pub const EXTB: ::speed_t = B38400;
pub const BOTHER: ::speed_t = 0o010000;
pub const B57600: ::speed_t = 0o010001;
pub const B115200: ::speed_t = 0o010002;
pub const B230400: ::speed_t = 0o010003;
pub const B460800: ::speed_t = 0o010004;
pub const B500000: ::speed_t = 0o010005;
pub const B576000: ::speed_t = 0o010006;
pub const B921600: ::speed_t = 0o010007;
pub const B1000000: ::speed_t = 0o010010;
pub const B1152000: ::speed_t = 0o010011;
pub const B1500000: ::speed_t = 0o010012;
pub const B2000000: ::speed_t = 0o010013;
pub const B2500000: ::speed_t = 0o010014;
pub const B3000000: ::speed_t = 0o010015;
pub const B3500000: ::speed_t = 0o010016;
pub const B4000000: ::speed_t = 0o010017;

pub const TIOCM_LE: ::c_int = 0x001;
pub const TIOCM_DTR: ::c_int = 0x002;
pub const TIOCM_RTS: ::c_int = 0x004;
pub const TIOCM_ST: ::c_int = 0x010;
pub const TIOCM_SR: ::c_int = 0x020;
pub const TIOCM_CTS: ::c_int = 0x040;
pub const TIOCM_CAR: ::c_int = 0x100;
pub const TIOCM_CD: ::c_int = TIOCM_CAR;
pub const TIOCM_RNG: ::c_int = 0x200;
pub const TIOCM_RI: ::c_int = TIOCM_RNG;
pub const TIOCM_DSR: ::c_int = 0x400;

pub const EHWPOISON: ::c_int = 168;
pub const SIGEV_THREAD_ID: ::c_int = 4;
pub const EPOLLWAKEUP: ::c_int = 0x20000000;

pub const NF_NETDEV_INGRESS: ::c_int = 0;
pub const NF_NETDEV_NUMHOOKS: ::c_int = 1;

pub const NFPROTO_INET: ::c_int = 1;
pub const NFPROTO_NETDEV: ::c_int = 5;

pub const NLA_ALIGNTO: ::c_int = 4;

pub const GENL_UNS_ADMIN_PERM: ::c_int = 0x10;

pub const GENL_ID_VFS_DQUOT: ::c_int = ::NLMSG_MIN_TYPE + 1;
pub const GENL_ID_PMCRAID: ::c_int = ::NLMSG_MIN_TYPE + 2;

pub const NFT_TABLE_MAXNAMELEN: ::c_int = 256;
pub const NFT_CHAIN_MAXNAMELEN: ::c_int = 256;
pub const NFT_SET_MAXNAMELEN: ::c_int = 256;
pub const NFT_OBJ_MAXNAMELEN: ::c_int = 256;
pub const NFT_USERDATA_MAXLEN: ::c_int = 256;

pub const NFT_REG_VERDICT: ::c_int = 0;
pub const NFT_REG_1: ::c_int = 1;
pub const NFT_REG_2: ::c_int = 2;
pub const NFT_REG_3: ::c_int = 3;
pub const NFT_REG_4: ::c_int = 4;
pub const __NFT_REG_MAX: ::c_int = 5;
pub const NFT_REG32_00: ::c_int = 8;
pub const NFT_REG32_01: ::c_int = 9;
pub const NFT_REG32_02: ::c_int = 10;
pub const NFT_REG32_03: ::c_int = 11;
pub const NFT_REG32_04: ::c_int = 12;
pub const NFT_REG32_05: ::c_int = 13;
pub const NFT_REG32_06: ::c_int = 14;
pub const NFT_REG32_07: ::c_int = 15;
pub const NFT_REG32_08: ::c_int = 16;
pub const NFT_REG32_09: ::c_int = 17;
pub const NFT_REG32_10: ::c_int = 18;
pub const NFT_REG32_11: ::c_int = 19;
pub const NFT_REG32_12: ::c_int = 20;
pub const NFT_REG32_13: ::c_int = 21;
pub const NFT_REG32_14: ::c_int = 22;
pub const NFT_REG32_15: ::c_int = 23;

pub const NFT_REG_SIZE: ::c_int = 16;
pub const NFT_REG32_SIZE: ::c_int = 4;

pub const NFT_CONTINUE: ::c_int = -1;
pub const NFT_BREAK: ::c_int = -2;
pub const NFT_JUMP: ::c_int = -3;
pub const NFT_GOTO: ::c_int = -4;
pub const NFT_RETURN: ::c_int = -5;

pub const NFT_MSG_NEWTABLE: ::c_int = 0;
pub const NFT_MSG_GETTABLE: ::c_int = 1;
pub const NFT_MSG_DELTABLE: ::c_int = 2;
pub const NFT_MSG_NEWCHAIN: ::c_int = 3;
pub const NFT_MSG_GETCHAIN: ::c_int = 4;
pub const NFT_MSG_DELCHAIN: ::c_int = 5;
pub const NFT_MSG_NEWRULE: ::c_int = 6;
pub const NFT_MSG_GETRULE: ::c_int = 7;
pub const NFT_MSG_DELRULE: ::c_int = 8;
pub const NFT_MSG_NEWSET: ::c_int = 9;
pub const NFT_MSG_GETSET: ::c_int = 10;
pub const NFT_MSG_DELSET: ::c_int = 11;
pub const NFT_MSG_NEWSETELEM: ::c_int = 12;
pub const NFT_MSG_GETSETELEM: ::c_int = 13;
pub const NFT_MSG_DELSETELEM: ::c_int = 14;
pub const NFT_MSG_NEWGEN: ::c_int = 15;
pub const NFT_MSG_GETGEN: ::c_int = 16;
pub const NFT_MSG_TRACE: ::c_int = 17;
pub const NFT_MSG_NEWOBJ: ::c_int = 18;
pub const NFT_MSG_GETOBJ: ::c_int = 19;
pub const NFT_MSG_DELOBJ: ::c_int = 20;
pub const NFT_MSG_GETOBJ_RESET: ::c_int = 21;
pub const NFT_MSG_MAX: ::c_int = 25;

pub const NFT_SET_ANONYMOUS: ::c_int = 0x1;
pub const NFT_SET_CONSTANT: ::c_int = 0x2;
pub const NFT_SET_INTERVAL: ::c_int = 0x4;
pub const NFT_SET_MAP: ::c_int = 0x8;
pub const NFT_SET_TIMEOUT: ::c_int = 0x10;
pub const NFT_SET_EVAL: ::c_int = 0x20;

pub const NFT_SET_POL_PERFORMANCE: ::c_int = 0;
pub const NFT_SET_POL_MEMORY: ::c_int = 1;

pub const NFT_SET_ELEM_INTERVAL_END: ::c_int = 0x1;

pub const NFT_DATA_VALUE: ::c_uint = 0;
pub const NFT_DATA_VERDICT: ::c_uint = 0xffffff00;

pub const NFT_DATA_RESERVED_MASK: ::c_uint = 0xffffff00;

pub const NFT_DATA_VALUE_MAXLEN: ::c_int = 64;

pub const NFT_BYTEORDER_NTOH: ::c_int = 0;
pub const NFT_BYTEORDER_HTON: ::c_int = 1;

pub const NFT_CMP_EQ: ::c_int = 0;
pub const NFT_CMP_NEQ: ::c_int = 1;
pub const NFT_CMP_LT: ::c_int = 2;
pub const NFT_CMP_LTE: ::c_int = 3;
pub const NFT_CMP_GT: ::c_int = 4;
pub const NFT_CMP_GTE: ::c_int = 5;

pub const NFT_RANGE_EQ: ::c_int = 0;
pub const NFT_RANGE_NEQ: ::c_int = 1;

pub const NFT_LOOKUP_F_INV: ::c_int = (1 << 0);

pub const NFT_DYNSET_OP_ADD: ::c_int = 0;
pub const NFT_DYNSET_OP_UPDATE: ::c_int = 1;

pub const NFT_DYNSET_F_INV: ::c_int = (1 << 0);

pub const NFT_PAYLOAD_LL_HEADER: ::c_int = 0;
pub const NFT_PAYLOAD_NETWORK_HEADER: ::c_int = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: ::c_int = 2;

pub const NFT_PAYLOAD_CSUM_NONE: ::c_int = 0;
pub const NFT_PAYLOAD_CSUM_INET: ::c_int = 1;

pub const NFT_META_LEN: ::c_int = 0;
pub const NFT_META_PROTOCOL: ::c_int = 1;
pub const NFT_META_PRIORITY: ::c_int = 2;
pub const NFT_META_MARK: ::c_int = 3;
pub const NFT_META_IIF: ::c_int = 4;
pub const NFT_META_OIF: ::c_int = 5;
pub const NFT_META_IIFNAME: ::c_int = 6;
pub const NFT_META_OIFNAME: ::c_int = 7;
pub const NFT_META_IIFTYPE: ::c_int = 8;
pub const NFT_META_OIFTYPE: ::c_int = 9;
pub const NFT_META_SKUID: ::c_int = 10;
pub const NFT_META_SKGID: ::c_int = 11;
pub const NFT_META_NFTRACE: ::c_int = 12;
pub const NFT_META_RTCLASSID: ::c_int = 13;
pub const NFT_META_SECMARK: ::c_int = 14;
pub const NFT_META_NFPROTO: ::c_int = 15;
pub const NFT_META_L4PROTO: ::c_int = 16;
pub const NFT_META_BRI_IIFNAME: ::c_int = 17;
pub const NFT_META_BRI_OIFNAME: ::c_int = 18;
pub const NFT_META_PKTTYPE: ::c_int = 19;
pub const NFT_META_CPU: ::c_int = 20;
pub const NFT_META_IIFGROUP: ::c_int = 21;
pub const NFT_META_OIFGROUP: ::c_int = 22;
pub const NFT_META_CGROUP: ::c_int = 23;
pub const NFT_META_PRANDOM: ::c_int = 24;

pub const NFT_CT_STATE: ::c_int = 0;
pub const NFT_CT_DIRECTION: ::c_int = 1;
pub const NFT_CT_STATUS: ::c_int = 2;
pub const NFT_CT_MARK: ::c_int = 3;
pub const NFT_CT_SECMARK: ::c_int = 4;
pub const NFT_CT_EXPIRATION: ::c_int = 5;
pub const NFT_CT_HELPER: ::c_int = 6;
pub const NFT_CT_L3PROTOCOL: ::c_int = 7;
pub const NFT_CT_SRC: ::c_int = 8;
pub const NFT_CT_DST: ::c_int = 9;
pub const NFT_CT_PROTOCOL: ::c_int = 10;
pub const NFT_CT_PROTO_SRC: ::c_int = 11;
pub const NFT_CT_PROTO_DST: ::c_int = 12;
pub const NFT_CT_LABELS: ::c_int = 13;
pub const NFT_CT_PKTS: ::c_int = 14;
pub const NFT_CT_BYTES: ::c_int = 15;

pub const NFT_LIMIT_PKTS: ::c_int = 0;
pub const NFT_LIMIT_PKT_BYTES: ::c_int = 1;

pub const NFT_LIMIT_F_INV: ::c_int = (1 << 0);

pub const NFT_QUEUE_FLAG_BYPASS: ::c_int = 0x01;
pub const NFT_QUEUE_FLAG_CPU_FANOUT: ::c_int = 0x02;
pub const NFT_QUEUE_FLAG_MASK: ::c_int = 0x03;

pub const NFT_QUOTA_F_INV: ::c_int = (1 << 0);

pub const NFT_REJECT_ICMP_UNREACH: ::c_int = 0;
pub const NFT_REJECT_TCP_RST: ::c_int = 1;
pub const NFT_REJECT_ICMPX_UNREACH: ::c_int = 2;

pub const NFT_REJECT_ICMPX_NO_ROUTE: ::c_int = 0;
pub const NFT_REJECT_ICMPX_PORT_UNREACH: ::c_int = 1;
pub const NFT_REJECT_ICMPX_HOST_UNREACH: ::c_int = 2;
pub const NFT_REJECT_ICMPX_ADMIN_PROHIBITED: ::c_int = 3;

pub const NFT_NAT_SNAT: ::c_int = 0;
pub const NFT_NAT_DNAT: ::c_int = 1;

pub const NFT_TRACETYPE_UNSPEC: ::c_int = 0;
pub const NFT_TRACETYPE_POLICY: ::c_int = 1;
pub const NFT_TRACETYPE_RETURN: ::c_int = 2;
pub const NFT_TRACETYPE_RULE: ::c_int = 3;

pub const NFT_NG_INCREMENTAL: ::c_int = 0;
pub const NFT_NG_RANDOM: ::c_int = 1;

pub const RLIMIT_CPU: ::__rlimit_resource_t = 0;
pub const RLIMIT_FSIZE: ::__rlimit_resource_t = 1;
pub const RLIMIT_DATA: ::__rlimit_resource_t = 2;
pub const RLIMIT_STACK: ::__rlimit_resource_t = 3;
pub const RLIMIT_CORE: ::__rlimit_resource_t = 4;
pub const RLIMIT_LOCKS: ::__rlimit_resource_t = 10;
pub const RLIMIT_SIGPENDING: ::__rlimit_resource_t = 11;
pub const RLIMIT_MSGQUEUE: ::__rlimit_resource_t = 12;
pub const RLIMIT_NICE: ::__rlimit_resource_t = 13;
pub const RLIMIT_RTPRIO: ::__rlimit_resource_t = 14;

#[doc(hidden)]
#[deprecated(
    since = "0.2.55",
    note = "If you are using this report to: \
            https://github.com/rust-lang/libc/issues/665"
)]
pub const AF_MAX: ::c_int = 45;
#[doc(hidden)]
#[deprecated(
    since = "0.2.55",
    note = "If you are using this report to: \
            https://github.com/rust-lang/libc/issues/665"
)]
#[allow(deprecated)]
pub const PF_MAX: ::c_int = AF_MAX;

f! {
    pub fn NLA_ALIGN(len: ::c_int) -> ::c_int {
        return ((len) + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
    }
}

#[link(name = "util")]
extern {
    pub fn sendmmsg(sockfd: ::c_int, msgvec: *mut ::mmsghdr, vlen: ::c_uint,
                    flags: ::c_int) -> ::c_int;
    pub fn recvmmsg(sockfd: ::c_int, msgvec: *mut ::mmsghdr, vlen: ::c_uint,
                    flags: ::c_int, timeout: *mut ::timespec) -> ::c_int;

    pub fn getrlimit64(resource: ::__rlimit_resource_t,
                       rlim: *mut ::rlimit64) -> ::c_int;
    pub fn setrlimit64(resource: ::__rlimit_resource_t,
                       rlim: *const ::rlimit64) -> ::c_int;
    pub fn getrlimit(resource: ::__rlimit_resource_t,
                     rlim: *mut ::rlimit) -> ::c_int;
    pub fn setrlimit(resource: ::__rlimit_resource_t,
                     rlim: *const ::rlimit) -> ::c_int;
    pub fn prlimit(pid: ::pid_t,
                   resource: ::__rlimit_resource_t, new_limit: *const ::rlimit,
                   old_limit: *mut ::rlimit) -> ::c_int;
    pub fn prlimit64(pid: ::pid_t,
                     resource: ::__rlimit_resource_t,
                     new_limit: *const ::rlimit64,
                     old_limit: *mut ::rlimit64) -> ::c_int;
    pub fn sysctl(name: *mut ::c_int,
                  namelen: ::c_int,
                  oldp: *mut ::c_void,
                  oldlenp: *mut ::size_t,
                  newp: *mut ::c_void,
                  newlen: ::size_t)
                  -> ::c_int;
    pub fn ioctl(fd: ::c_int, request: ::c_ulong, ...) -> ::c_int;
    pub fn backtrace(buf: *mut *mut ::c_void,
                     sz: ::c_int) -> ::c_int;
    pub fn glob64(pattern: *const ::c_char,
                  flags: ::c_int,
                  errfunc: ::Option<extern fn(epath: *const ::c_char,
                                                   errno: ::c_int)
                                                   -> ::c_int>,
                  pglob: *mut glob64_t) -> ::c_int;
    pub fn globfree64(pglob: *mut glob64_t);
    pub fn ptrace(request: ::c_uint, ...) -> ::c_long;
    pub fn pthread_attr_getaffinity_np(attr: *const ::pthread_attr_t,
                                       cpusetsize: ::size_t,
                                       cpuset: *mut ::cpu_set_t) -> ::c_int;
    pub fn pthread_attr_setaffinity_np(attr: *mut ::pthread_attr_t,
                                       cpusetsize: ::size_t,
                                       cpuset: *const ::cpu_set_t) -> ::c_int;
    pub fn getpriority(which: ::__priority_which_t, who: ::id_t) -> ::c_int;
    pub fn setpriority(which: ::__priority_which_t, who: ::id_t,
                                       prio: ::c_int) -> ::c_int;
    pub fn pthread_getaffinity_np(thread: ::pthread_t,
                                  cpusetsize: ::size_t,
                                  cpuset: *mut ::cpu_set_t) -> ::c_int;
    pub fn pthread_setaffinity_np(thread: ::pthread_t,
                                  cpusetsize: ::size_t,
                                  cpuset: *const ::cpu_set_t) -> ::c_int;
    pub fn sched_getcpu() -> ::c_int;
}

cfg_if! {
    if #[cfg(target_arch = "mips")] {
        mod mips32;
        pub use self::mips32::*;
    } else if #[cfg(target_arch = "mips64")] {
        mod mips64;
        pub use self::mips64::*;
    } else {
        // Unknown target_arch
    }
}

cfg_if! {
    if #[cfg(libc_align)] {
        mod align;
        pub use self::align::*;
    } else {
        mod no_align;
        pub use self::no_align::*;
    }
}
