#![no_std]
#![no_main]

use aya_ebpf::{
  helpers::bpf_get_current_pid_tgid,
  helpers::bpf_probe_read,
  helpers::bpf_probe_read_user_buf,
  macros::{map, tracepoint, uprobe, uretprobe},
  maps::HashMap,
  maps::PerCpuArray,
  maps::RingBuf,
  programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use misbar_ssl_agent_common::ConnectArgs;
use misbar_ssl_agent_common::DNSEvent;
use misbar_ssl_agent_common::EGRESS;
use misbar_ssl_agent_common::SSLArgs;
use misbar_ssl_agent_common::SocketInfo;
use misbar_ssl_agent_common::sockaddr;
use misbar_ssl_agent_common::sockaddr_in;
use misbar_ssl_agent_common::{ConnEvent, EVENT_BUFFER_LENGTH};

#[map]
static CONNECT_ARGS: HashMap<u64, ConnectArgs> = HashMap::with_max_entries(8192, 0);

#[map]
static INGRESS_SOCKET_INFO: HashMap<i32, SocketInfo> = HashMap::with_max_entries(16384, 0);

#[map]
static EGRESS_SOCKET_INFO: HashMap<u64, SocketInfo> = HashMap::with_max_entries(16384, 0);

// Value type was supposed to be *const u8, but due to lack of Sync complaints:
// - `*const u8` cannot be shared between threads safely
// - the trait `Sync` is not implemented for `*const u8`
// - required for `HashMap<u64, *const u8>` to implement `Sync`
// - shared static variables must have a type that implements `Sync`
// we changed it to u64 and then we cast back and forth in caller function
#[map]
static GETADDRINFO_ARGS: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static DNS_DATA: PerCpuArray<DNSEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 4096, 0);

#[map]
static CONN_DATA: PerCpuArray<ConnEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CONN_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 4096, 0);

#[map]
static SSL_FDS: HashMap<u64, i32> = HashMap::with_max_entries(16384, 0);

#[map]
static SSL_ARGS: HashMap<u64, SSLArgs> = HashMap::with_max_entries(16384, 0);

#[tracepoint]
pub fn tp_sys_connect_entry(ctx: TracePointContext) -> i64 {
  match try_tp_sys_connect_entry(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_tp_sys_connect_entry(ctx: TracePointContext) -> Result<i64, i64> {
  unsafe {
    let fd: i32 = ctx.read_at(16)?;
    let socket_address: *const sockaddr = ctx.read_at(24)?;
    let Ok(()) = CONNECT_ARGS.insert(
      &bpf_get_current_pid_tgid(),
      &ConnectArgs { fd, socket_address },
      0,
    ) else {
      return Err(0);
    };
  }
  Ok(0)
}

#[tracepoint]
pub fn tp_sys_connect_return(ctx: TracePointContext) -> u32 {
  match try_tp_sys_connect_return(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_tp_sys_connect_return(ctx: TracePointContext) -> Result<u32, u32> {
  unsafe {
    // Get the ConnectArgs object inserted in entry function
    let Some(args) = CONNECT_ARGS.get(&bpf_get_current_pid_tgid()) else {
      return Err(0);
    };
    // Read the socket details to socket_in type (converted from *const sockaddr)
    let socket_address_in: sockaddr_in =
      bpf_probe_read(args.socket_address as *const sockaddr_in).map_err(|e| e as u32)?;
    let info = SocketInfo {
      addr: socket_address_in.sin_addr.s_addr,
      port: socket_address_in.sin_port,
      direction: EGRESS,
    };

    // If traffic is ipv4
    if socket_address_in.sin_family == 2 {
      let _ = EGRESS_SOCKET_INFO
        .insert(&bpf_get_current_pid_tgid(), &info, 0)
        .map_err(|e| e as u32);
    }

    let _ = CONNECT_ARGS.remove(&bpf_get_current_pid_tgid());
  }
  Ok(0)
}

#[uprobe]
pub fn up_libc_getaddrinfo_entry(ctx: ProbeContext) -> u32 {
  match try_up_libc_getaddrinfo_entry(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_libc_getaddrinfo_entry(ctx: ProbeContext) -> Result<u32, u32> {
  let node: *const u8 = ctx.arg(0).ok_or(0u32)?;
  // Check note above GETADDRINFO_ARGS definition to understand why the casting is needed
  let node_addr = node as u64;
  let _ = GETADDRINFO_ARGS.insert(&bpf_get_current_pid_tgid(), &node_addr, 0);
  Ok(0)
}

#[uretprobe]
pub fn up_libc_getaddrinfo_return(ctx: RetProbeContext) -> u32 {
  match try_up_libc_getaddrinfo_return(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_libc_getaddrinfo_return(ctx: RetProbeContext) -> Result<u32, u32> {
  unsafe {
    let ret: i64 = ctx.ret().ok_or(0u32)?;
    if ret == 0 {
      if let Some(node) = GETADDRINFO_ARGS.get(&bpf_get_current_pid_tgid()) {
        let data: &mut DNSEvent = {
          let ptr: *mut DNSEvent = DNS_DATA.get_ptr_mut(0).ok_or(0u32)?;
          &mut *ptr
        };
        let err = bpf_probe_read_user_buf(*node as *const u8, &mut data.hostname);
        if err.is_err() {
          return Ok(0);
        }
        let _ = GETADDRINFO_ARGS.remove(&bpf_get_current_pid_tgid());
        let _ = DNS_EVENTS.output(data, 0);
      }
    }
    Ok(0)
  }
}

#[uprobe]
pub fn up_openssl_ssl_set_fd_entry(ctx: ProbeContext) -> u32 {
  match try_up_openssl_ssl_set_fd_entry(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_openssl_ssl_set_fd_entry(ctx: ProbeContext) -> Result<u32, u32> {
  let ssl_ctx: u64 = ctx.arg(0).ok_or(0u32)?;
  let fd: i32 = ctx.arg(1).ok_or(0u32)?;
  if fd == 0 {
  } else {
    let _ = SSL_FDS.insert(&ssl_ctx, &fd, 0);
  }
  Ok(0)
}

#[uprobe]
pub fn up_openssl_ssl_write_entry(ctx: ProbeContext) -> u32 {
  match try_up_openssl_ssl_write_entry(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_openssl_ssl_write_entry(ctx: ProbeContext) -> Result<u32, u32> {
  unsafe {
    let ssl_ctx: u64 = ctx.arg(0).ok_or(0u32)?;
    let buf: usize = ctx.arg(1).ok_or(0u32)?;
    let written_bytes: i32 = ctx.arg(2).ok_or(0u32)?;

    if written_bytes <= 0 {
      return Ok(0);
    }

    // Get file descriptor from SSL context, may fail if SSL_set_fd wasn't called
    let ssl_fd = SSL_FDS.get(&ssl_ctx);

    // Check for socket info using either SSL fd or pid-based tracking
    let info = if let Some(ssl_fd) = ssl_fd {
      INGRESS_SOCKET_INFO
        .get(&ssl_fd)
        .or_else(|| EGRESS_SOCKET_INFO.get(&bpf_get_current_pid_tgid()))
    } else {
      EGRESS_SOCKET_INFO.get(&bpf_get_current_pid_tgid())
    };

    if let Some(info) = info {
      // Get ptr to per cpu data object
      let data = {
        let ptr = CONN_DATA.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
      };

      data.info = *info;
      data.pid = bpf_get_current_pid_tgid();

      let mut read = 0;
      let len = written_bytes as usize;
      let read_len = EVENT_BUFFER_LENGTH;
      let mut emit = false;
      let num_of_chunks = if len == 0 {
        0
      } else {
        (len + EVENT_BUFFER_LENGTH - 1) / EVENT_BUFFER_LENGTH
      } as u16;
      data.num_of_chunks = num_of_chunks;
      data.data_length = len;
      data.ssl_direction = 1;

      for i in 0..300 {
        // Read the buffer data into data.payload
        let err = bpf_probe_read_user_buf((buf as *const u8).add(read), &mut data.payload);
        if err.is_err() {
          break;
        }
        let left = len - read;
        if left > read_len {
          read += read_len;
        } else {
          read = len;
        }
        if i == 0 {
          let http_type = get_http_type(data.payload, len);
          if http_type >= 0 {
            emit = true;
            data.http_type = http_type;
          }
        }
        if emit {
          let _ = CONN_EVENTS.output(data, 0);
        }
        if read == len {
          break;
        }
      }
    }
  }
  Ok(0)
}

#[uretprobe]
pub fn up_openssl_ssl_write_return(ctx: RetProbeContext) -> u32 {
  match try_up_openssl_ssl_write_return(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_openssl_ssl_write_return(ctx: RetProbeContext) -> Result<u32, u32> {
  // info!(&ctx, "function SSL_write called by libssl");
  Ok(0)
}

#[uprobe]
pub fn up_openssl_ssl_read_entry(ctx: ProbeContext) -> u32 {
  match try_up_openssl_ssl_read_entry(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_openssl_ssl_read_entry(ctx: ProbeContext) -> Result<u32, u32> {
  unsafe {
    let ssl_ctx: u64 = ctx.arg(0).ok_or(0u32)?;

    // Try to get file descriptor from SSL context (may fail if SSL_set_fd wasn't called)
    let ssl_fd = SSL_FDS.get(&ssl_ctx);

    // Check for socket info - try both SSL fd and pid-based patterns
    let socket_info = if let Some(ssl_fd) = ssl_fd {
      // SSL_read executed in server mode - use ssl_fd to retrieve accepted connection socket info
      if let Some(info) = INGRESS_SOCKET_INFO.get(&ssl_fd) {
        Some(info)
      } else if let Some(info) = EGRESS_SOCKET_INFO.get(&bpf_get_current_pid_tgid()) {
        // SSL_read executed in client mode - use pid to retrieve remote server connection information
        Some(info)
      } else {
        None
      }
    } else {
      // Fallback to pid-based egress tracking (client mode)
      EGRESS_SOCKET_INFO.get(&bpf_get_current_pid_tgid())
    };

    if let Some(info) = socket_info {
      // Prepare the socket details to be passed to ssl_args map
      let socket_info = SocketInfo {
        addr: info.addr,
        port: info.port,
        direction: info.direction,
      };
      let buf: usize = ctx.arg(1).ok_or(0u32)?;
      let ssl_len: u64 = ctx.arg(2).ok_or(0u32)?;
      if ssl_len <= 0 {
        return Ok(0);
      }
      // Save args with pid as key
      let _ = SSL_ARGS.insert(
        &bpf_get_current_pid_tgid(),
        &SSLArgs {
          buf,
          info: socket_info,
          ssl_len,
        },
        0,
      );
    }
  }
  Ok(0)
}

#[uretprobe]
pub fn up_openssl_ssl_read_return(ctx: RetProbeContext) -> u32 {
  match try_up_openssl_ssl_read_return(ctx) {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

fn try_up_openssl_ssl_read_return(ctx: RetProbeContext) -> Result<u32, u32> {
  unsafe {
    let read_bytes: i32 = ctx.ret().ok_or(0u32)?;
    if read_bytes <= 0 {
      return Ok(0);
    }
    // Retrive args using pid
    let args: Option<&SSLArgs> = SSL_ARGS.get(&bpf_get_current_pid_tgid());
    if let Some(SSLArgs {
      buf,
      info,
      ssl_len: _,
    }) = args
    {
      // Get ptr to per cpu data object
      let data = {
        let ptr = CONN_DATA.get_ptr_mut(0).ok_or(0u32)?;
        &mut *ptr
      };
      data.info = *info;
      data.pid = bpf_get_current_pid_tgid();
      let mut read = 0;
      let len = read_bytes as usize;
      let mut emit = false;
      let num_of_chunks = if len == 0 {
        0
      } else {
        (len + EVENT_BUFFER_LENGTH - 1) / EVENT_BUFFER_LENGTH
      } as u16;
      data.num_of_chunks = num_of_chunks;
      data.data_length = len;
      data.ssl_direction = 2;

      for i in 0..300 {
        let err = bpf_probe_read_user_buf((*buf as *const u8).add(read), &mut data.payload);
        if err.is_err() {
          break;
        }
        let left = len - read;
        if left > EVENT_BUFFER_LENGTH {
          read += EVENT_BUFFER_LENGTH;
        } else {
          read = len;
        }
        if i == 0 {
          let http_type = get_http_type(data.payload, len);
          if http_type >= 0 {
            emit = true;
            data.http_type = http_type;
          }
        }
        if emit {
          let _ = CONN_EVENTS.output(data, 0);
        }
        if read == len {
          break;
        }
      }
    }
  }
  Ok(0)
}

/// Returns the http type of the request or response
/// -1: not http
/// 0: request
/// 1: response
/// 2: http2
fn get_http_type(buffer: [u8; EVENT_BUFFER_LENGTH], count: usize) -> i8 {
  if count < 16 {
    return -1;
  }
  let mut http_type = 0;
  if buffer[0] == b'H'
    && buffer[1] == b'T'
    && buffer[2] == b'T'
    && buffer[3] == b'P'
    && buffer[4] == b'/'
    && buffer[5] == b'1'
    && buffer[6] == b'.'
  {
    // Http1.1 - response
    http_type = 1;
  }
  // Http1.1 - request
  else if buffer[0] == b'G' && buffer[1] == b'E' && buffer[2] == b'T' {
    http_type = 0;
  } else if buffer[0] == b'P' && buffer[1] == b'O' && buffer[2] == b'S' && buffer[3] == b'T' {
    http_type = 0;
  } else if buffer[0] == b'P' && buffer[1] == b'U' && buffer[2] == b'T' {
    http_type = 0;
  } else if buffer[0] == b'P'
    && buffer[1] == b'A'
    && buffer[2] == b'T'
    && buffer[3] == b'C'
    && buffer[4] == b'H'
  {
    http_type = 0;
  } else if buffer[0] == b'D'
    && buffer[1] == b'E'
    && buffer[2] == b'L'
    && buffer[3] == b'E'
    && buffer[4] == b'T'
    && buffer[5] == b'E'
  {
    http_type = 0;
  }
  // Check for HTTP/2
  else if buffer[0] == b'P' && buffer[1] == b'R' && buffer[2] == b'I' {
    http_type = 2;
  }
  http_type
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
