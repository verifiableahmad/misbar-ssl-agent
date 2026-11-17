#![no_std]

pub const EVENT_BUFFER_LENGTH: usize = 1024;
pub const INGRESS: u16 = 0;
pub const EGRESS: u16 = 1;

#[repr(C)]
pub struct sockaddr {
  sa_family: u16,
  sa_data: [u8; 14],
}

#[repr(C)]
pub struct sockaddr_in {
  pub sin_family: u16,
  pub sin_port: u16,
  pub sin_addr: in_addr,
  pub sin_zero: [u8; 8],
}

#[repr(C)]
pub struct in_addr {
  pub s_addr: u32,
}

#[repr(C, packed)]
pub struct ConnectArgs {
  pub fd: i32,
  pub socket_address: *const sockaddr,
}

// To resolve "ConnectArgs doesn't implement Sync"
// This is acceptable here since ebpf has different
// concurrency model
unsafe impl Sync for ConnectArgs {}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SocketInfo {
  pub addr: u32,
  pub port: u16,
  pub direction: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DNSEvent {
  pub hostname: [u8; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnEvent {
  pub payload: [u8; EVENT_BUFFER_LENGTH],
  pub data_length: usize,
  pub info: SocketInfo,
  pub pid: u64,
  pub num_of_chunks: u16,
  pub http_type: i8,
  pub ssl_direction: u8,
  pub timestamp: u64,
  pub http_version: i8,
  pub final_chunk: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SSLArgs {
  pub buf: usize,
  pub info: SocketInfo,
  pub ssl_len: u64,
}
