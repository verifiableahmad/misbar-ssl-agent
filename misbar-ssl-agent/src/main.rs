use std::{collections::HashMap, time::Duration};

use aya::{
  Ebpf,
  maps::RingBuf,
  programs::{TracePoint, UProbe},
};
// use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use chrono::Utc;
use md5;
use misbar_ssl_agent::{config::load_config, websocket::ArcMutexWSClient};
use misbar_ssl_agent::{
  event::{AggEvent, Event},
  websocket,
};
use misbar_ssl_agent_common::{ConnEvent, DNSEvent, EGRESS, INGRESS};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Message, connect, http::Uri};

// #[derive(Debug, Parser)]
// struct Opt {
//     #[clap(short, long)]
//     pid: Option<i32>,
// }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // let opt = Opt::parse();

  env_logger::init();

  // Bump the memlock rlimit. This is needed for older kernels that don't use the
  // new memcg based accounting, see https://lwn.net/Articles/837122/
  let rlim = libc::rlimit {
    rlim_cur: libc::RLIM_INFINITY,
    rlim_max: libc::RLIM_INFINITY,
  };
  let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
  if ret != 0 {
    debug!("remove limit on locked memory failed, ret is: {ret}");
  }

  // Capture CTRL+C signal
  let ctrl_c = signal::ctrl_c();
  println!("Waiting for Ctrl-C...");

  // This will include your eBPF object file as raw bytes at compile-time and load it at
  // runtime. This approach is recommended for most real-world use cases. If you would
  // like to specify the eBPF program at runtime rather than at compile-time, you can
  // reach for `Bpf::load_file` instead.
  let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/misbar-ssl-agent"
  )))?;
  if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
    // This can happen if you remove all log statements from your eBPF program.
    warn!("failed to initialize eBPF logger: {e}");
  }
  // let Opt { pid } = opt;

  // Load config
  let misbar_config = load_config()?;

  // Register probes
  register_probes(&mut ebpf)?;

  // Shared states
  let event = Arc::new(Mutex::new(Event::new()));
  let agg_events = Arc::new(Mutex::new(HashMap::<[u8; 16], AggEvent>::new()));
  let agg_event_clone = Arc::clone(&agg_events);
  let dns_event_clone = Arc::clone(&event);
  let conn_event_clone = Arc::clone(&event);

  // Channels
  let (tx, mut rx) = mpsc::channel::<Event>(1024);

  // Websocket setup
  let ws_client: ArcMutexWSClient;
  // Loop until we connect to a backend
  loop {
    let uri = format!("ws://{}/api/ws", misbar_config.endpoint.clone().unwrap());
    let token = misbar_config.agent_token.clone().unwrap();
    let builder = websocket::get_ws_builder(uri.parse::<Uri>()?, token);
    match connect(builder) {
      Ok((ws, _response)) => {
        ws_client = Arc::new(Mutex::new(ws));
        break;
      }
      Err(error) => {
        warn!(
          "couldn't connect to websocket server: {}. retrying...",
          error
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
      }
    }
  }

  // Define DNS ebpf map
  let mut dns_events_ringbuf: RingBuf<aya::maps::MapData> = RingBuf::try_from(
    ebpf
      .take_map("DNS_EVENTS")
      .expect("couldn't initialize dns events ringbuf"),
  )?;

  // Thread capturing DNS queries
  let dns_task = tokio::spawn(async move {
    loop {
      // Capture and print dns events
      if let Some(event) = dns_events_ringbuf.next() {
        let ptr = event.as_ptr() as *const DNSEvent;
        let data = unsafe { ptr.read_unaligned() };
        match str::from_utf8(&data.hostname) {
          // If hostname is valid utf-8 string
          Ok(hostname) => {
            let mut inner_event = dns_event_clone.lock().await;
            inner_event.hostname = hostname.trim_matches(char::from(0)).to_string();
          }
          // If hostname is not valid utf-8 string
          Err(e) => {
            let valid_bytes = &data.hostname[..e.valid_up_to()];
            if let Ok(hostname_str) = str::from_utf8(valid_bytes) {
              let mut inner_event = dns_event_clone.lock().await;
              inner_event.hostname = hostname_str.trim_matches(char::from(0)).to_string();
            }
          }
        }
      } else {
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
    }
  });

  // Define Connection ebpf map
  let mut conn_events_ringbuf: RingBuf<aya::maps::MapData> = RingBuf::try_from(
    ebpf
      .take_map("CONN_EVENTS")
      .expect("couldn't initialize conn events ringbuf"),
  )?;

  // Thread capturing Connection queries
  let conn_task = tokio::spawn(async move {
    loop {
      // Capture and print dns events
      if let Some(event) = conn_events_ringbuf.next() {
        let ptr = event.as_ptr() as *const ConnEvent;
        let data = unsafe { ptr.read_unaligned() };
        let info = data.info;
        let mut direction = EGRESS;
        if info.direction == INGRESS {
          direction = INGRESS;
        }

        let ip = u32::to_be(info.addr);
        let ipv4addr = Ipv4Addr::new(
          (ip >> 24) as u8,
          (ip >> 16) as u8,
          (ip >> 8) as u8,
          ip as u8,
        );

        let port = u16::to_be(info.port);
        let timestamp = Utc::now().timestamp_millis();
        let hash_id = md5::compute(format!("{}:{}:{}", ipv4addr.to_string(), port, data.pid));

        let mut inner_event = conn_event_clone.lock().await;
        let safe_len = data.data_length.min(data.payload.len());
        inner_event.payload = data.payload[..safe_len].to_vec();
        inner_event.data_length = data.data_length;
        inner_event.ip = ipv4addr.into();
        inner_event.port = port;
        inner_event.direction = direction;
        // Timestamps are different for every portion
        // Something to consider when aggregating complete events
        inner_event.timestamp = timestamp;
        inner_event.http_type = data.http_type;
        inner_event.hash_id = hash_id.0;
        inner_event.ssl_direction = data.ssl_direction;

        // Send this portion to aggregator channel
        tx.send(inner_event.clone()).await.unwrap();
        drop(inner_event);
      } else {
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
    }
  });

  let send_task = tokio::spawn(async move {
    loop {
      let mut send_list = Vec::new();
      {
        let mut events = agg_event_clone.lock().await;
        let mut complete_events = Vec::new();
        for (hash_id, agg_event) in events.iter_mut() {
          if agg_event.is_complete() {
            send_list.push(agg_event.complete.clone());
            complete_events.push(*hash_id);
          }
        }
        for hash_id in complete_events {
          events.remove(&hash_id);
        }
      }
      for event in send_list {
        println!("sending completed event to backend: {:?}", event.hash_id);
        let event_json_bytes = serde_json::to_vec(&event).unwrap();
        ws_client
          .lock()
          .await
          .send(Message::Binary(event_json_bytes.into()))
          .unwrap();
      }
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
  });

  let agg_task = tokio::spawn(async move {
    // Capture events to be aggregated
    while let Some(portion) = rx.recv().await {
      agg_events
        .lock()
        .await
        .entry(portion.hash_id)
        .or_insert_with(|| AggEvent {
          portions: vec![portion.clone()],
          complete: portion.clone(),
          payload_buffer: vec![],
          request_buffer: vec![],
          response_buffer: vec![],
          headers_complete: false,
          stream_complete: false,
          last_activity_timestamp: 0,
          last_data_frame_time: 0,
          processed_offset: 0,
          complete_event_length: None,
        })
        .aggregate(portion)
        .await;
    }
  });

  tokio::select! {
    _ = dns_task => {
      println!("closing dns task...")
    }
    _ = conn_task => {
      println!("closing conn task...")
    }
    _ = agg_task => {
      println!("closing agg task...")
    }
    _ = send_task => {
      println!("closing send task...")
    }
    _ = ctrl_c => {
      println!("closing misbar...");
    }
  }

  Ok(())
}

fn register_probes(ebpf: &mut Ebpf) -> anyhow::Result<()> {
  let program: &mut TracePoint = ebpf
    .program_mut("tp_sys_connect_entry")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach("syscalls", "sys_enter_connect")?;

  let program: &mut TracePoint = ebpf
    .program_mut("tp_sys_connect_return")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach("syscalls", "sys_exit_connect")?;

  let program: &mut UProbe = ebpf
    .program_mut("up_libc_getaddrinfo_entry")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach(
    Some("getaddrinfo"),
    0,
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
    None,
  )?;

  let program: &mut UProbe = ebpf
    .program_mut("up_libc_getaddrinfo_return")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach(
    Some("getaddrinfo"),
    0,
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
    None,
  )?;

  // OpenSSL Probes
  // Reference for openssl API: https://docs.openssl.org/3.0/man7/ssl/#name
  // Consider ssl_set_fd, ssl_*_ex, ssl_set_bio, etc
  let program: &mut UProbe = ebpf
    .program_mut("up_openssl_ssl_write_entry")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach(
    Some("SSL_write"),
    0,
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    None,
  )?;

  let program: &mut UProbe = ebpf
    .program_mut("up_openssl_ssl_write_return")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach(
    Some("SSL_write"),
    0,
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    None,
  )?;

  let program: &mut UProbe = ebpf
    .program_mut("up_openssl_ssl_read_entry")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach(
    Some("SSL_read"),
    0,
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    None,
  )?;

  let program: &mut UProbe = ebpf
    .program_mut("up_openssl_ssl_read_return")
    .unwrap()
    .try_into()?;
  program.load()?;
  program.attach(
    Some("SSL_read"),
    0,
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    None,
  )?;

  Ok(())
}
