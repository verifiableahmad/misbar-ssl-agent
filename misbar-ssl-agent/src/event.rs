use crate::http2::decode_hpack_headers;
use log::warn;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Event {
  pub payload: Vec<u8>,
  pub req_payload: Vec<u8>,
  pub res_payload: Vec<u8>,
  pub req_headers: Vec<(String, String)>,
  pub res_headers: Vec<(String, String)>,
  pub data_length: usize,
  pub ip: u32,
  pub port: u16,
  pub direction: u16,
  pub timestamp: i64,
  pub http_type: i8,
  pub http_version: i8,
  pub hash_id: [u8; 16],
  pub hostname: String,
  pub ssl_direction: u8,
}

impl Event {
  pub fn new() -> Self {
    Event {
      payload: Vec::new(),
      req_payload: Vec::new(),
      res_payload: Vec::new(),
      req_headers: Vec::new(),
      res_headers: Vec::new(),
      data_length: 0,
      ip: 0,
      port: 0,
      direction: 0,
      timestamp: 0,
      http_type: 0,
      http_version: 0,
      hash_id: [0; 16],
      hostname: String::new(),
      ssl_direction: 0,
    }
  }

  pub fn clear(&mut self) {
    self.payload.clear();
    self.req_payload.clear();
    self.res_payload.clear();
    self.data_length = 0;
    self.ip = 0;
    self.port = 0;
    self.direction = 0;
    self.timestamp = 0;
    self.http_type = 0;
    self.http_version = 0;
    self.hash_id = [0; 16];
    self.hostname.clear();
    self.ssl_direction = 0;
  }
}

#[derive(Clone)]
pub struct AggEvent {
  pub portions: Vec<Event>,
  pub complete: Event,
  pub payload_buffer: Vec<u8>,
  pub request_buffer: Vec<u8>,
  pub response_buffer: Vec<u8>,
  pub headers_complete: bool,
  pub stream_complete: bool,
  pub last_activity_timestamp: i64,
  pub last_data_frame_time: i64,
  pub processed_offset: usize,
  pub complete_event_length: Option<usize>,
}

impl AggEvent {
  pub fn new() -> Self {
    AggEvent {
      portions: vec![],
      complete: Event::new(),
      payload_buffer: vec![],
      request_buffer: vec![],
      response_buffer: vec![],
      headers_complete: false,
      stream_complete: false,
      last_activity_timestamp: 0,
      last_data_frame_time: 0,
      processed_offset: 0,
      complete_event_length: None,
    }
  }

  pub async fn aggregate(&mut self, portion: Event) {
    // Return, nothing to process
    if portion.payload.is_empty() {
      return;
    }

    // First request portion? extract request-specific fields
    // http_type is 1 when it's an http1.1 response (check get_http_type func)
    if portion.req_payload.is_empty() && portion.http_type != 1 {
      self.complete.ip = portion.ip;
      self.complete.port = portion.port;
      self.complete.direction = portion.direction;
      self.complete.hash_id = portion.hash_id;
      self.complete.hostname = portion.hostname.clone();
    }

    // Every time this function is called, we 1) update current buffer index
    // 2) append the payload to the payload buffer and 3) update the last activity timestamp
    // Note: last activity timestamp is used for the timeout check for http2 payloads
    let buffer_len = self.payload_buffer.len();
    self.payload_buffer.extend_from_slice(&portion.payload);
    self.last_activity_timestamp = portion.timestamp;

    // Send payload to process_payload() for further http processing
    self.process_payload(portion, buffer_len).await;
  }

  async fn process_payload(&mut self, portion: Event, buffer_len: usize) {
    let buffer = self.payload_buffer.clone();
    let mut offset = self.processed_offset;

    const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let is_http2 = if self.processed_offset == 0
      && buffer.len() >= HTTP2_PREFACE.len()
      && buffer.starts_with(HTTP2_PREFACE)
    {
      true
    } else {
      false
    };

    // Check if we have an http2 payload
    if is_http2 {
      self.complete.http_version = 2;
      offset = HTTP2_PREFACE.len();
      self.processed_offset = offset;
    }

    // We have an http2 payload
    if self.complete.http_version == 2 {
      self
        .process_http2(offset, buffer, &portion, buffer_len)
        .await;
    } else {
      self.process_http1(offset, buffer, &portion).await;
    }
  }

  async fn process_http1(&mut self, mut offset: usize, buffer: Vec<u8>, portion: &Event) {
    // We have a response
    if portion.http_type == 1 {
      // Find the end of headers (double CRLF)
      let mut headers_end = None;
      for i in offset..buffer.len().saturating_sub(3) {
        if buffer[i] == b'\r'
          && buffer[i + 1] == b'\n'
          && buffer[i + 2] == b'\r'
          && buffer[i + 3] == b'\n'
        {
          headers_end = Some(i + 4);
          break;
        }
      }

      if let Some(headers_end) = headers_end {
        // Extract headers
        let headers = &buffer[offset..headers_end];
        let headers_str = String::from_utf8_lossy(headers);
        // Parse headers into name-value pairs
        for line in headers_str.lines() {
          if let Some((name, value)) = line.split_once(':') {
            self
              .complete
              .res_headers
              .push((name.trim().to_string(), value.trim().to_string()));
          } else {
            // Get the status line - only add if status_code not already present
            let status_line = line.split_once(' ');
            if let Some((_, status_code)) = status_line {
              let has_status = self
                .complete
                .res_headers
                .iter()
                .any(|(name, _)| name == "status_code");
              if !has_status {
                self.complete.res_headers.push((
                  "status_code".to_string(),
                  status_code.split_whitespace().next().unwrap().to_string(),
                ));
              }
            }
          }
        }

        // Parse Content-Length if present
        let content_length = self
          .complete
          .res_headers
          .iter()
          .find(|(name, _)| name.to_lowercase() == "content-length")
          .and_then(|(_, value)| value.parse::<usize>().ok());

        // If we have content-length and enough data, process the body
        if let Some(content_len) = content_length {
          let body_start = headers_end;
          let body_end = body_start + content_len;
          // Assign to aggregator to be used in determining completion status
          self.complete_event_length = Some(body_end);

          if body_end <= buffer.len() {
            // We have the complete body
            let body = &buffer[body_start..body_end];
            self.response_buffer.extend(body);

            // Update offset to after the body
            offset = body_end;
            self.processed_offset = offset;
          } else {
            self.processed_offset = offset;
          }
        }
      } else {
        self.processed_offset = offset;
      }
    } else {
      // We land here for requests
      let snippet_len = buffer.len().min(100);
      self
        .request_buffer
        .extend(&buffer[offset..offset + snippet_len]);
      self.processed_offset = buffer.len();
    }
  }

  async fn process_http2(
    &mut self,
    mut offset: usize,
    buffer: Vec<u8>,
    portion: &Event,
    previous_buffer_len: usize,
  ) {
    let mut new_req_data: Vec<u8> = Vec::new();
    let mut new_res_data: Vec<u8> = Vec::new();

    // Process the request buffer
    let mut frames_processed = 0;
    let mut consecutive_invalid_frames = 0;

    // We need at least 9 bytes for the frame header
    while offset + 9 <= buffer.len() {
      let length_byte1 = buffer[offset];
      let length_byte2 = buffer[offset + 1];
      let length_byte3 = buffer[offset + 2];
      let frame_length =
        ((length_byte1 as u32) << 16) | ((length_byte2 as u32) << 8) | (length_byte3 as u32);
      let frame_type = buffer[offset + 3];
      let frame_flags = buffer[offset + 4];

      // If we encounter an invalid frame type, dump more context
      if frame_type > 8 && frame_type != 0x0C {
        // Dump some context around this position
        let context_start = offset.saturating_sub(20);
        let context_end = (offset + 30).min(buffer.len());
        let context_bytes: Vec<String> = buffer[context_start..context_end]
          .iter()
          .enumerate()
          .map(|(i, b)| {
            let pos = context_start + i;
            if pos == offset {
              format!("[{:02x}]", b) // Mark the problematic offset
            } else {
              format!("{:02x}", b)
            }
          })
          .collect();
        warn!("invalid frame type, context: {:?}", context_bytes);
      }

      // Calculate frame end offset first
      let frame_end_offset = offset + 9 + frame_length as usize;

      // Check if we have the entire frame (or even more) before processing
      if frame_end_offset > buffer.len() {
        self.processed_offset = offset;
        return;
      }

      // Now it's safe to get the frame payload
      let frame_payload = if frame_length > 0 {
        &buffer[offset + 9..offset + 9 + frame_length as usize]
      } else {
        &[] // Empty slice for zero-length frames
      };

      // Validate frame length - http2 limits frames to 16,384 bytes by default
      if frame_length > 16384 {
        warn!("frame length is greater than 16,384 bytes");
        // This is likely not a valid frame header
        if offset > previous_buffer_len && previous_buffer_len > 0 {
          // Stop here and wait for more data
          self.processed_offset = previous_buffer_len;
          return;
        }
        // If we see an invalid frame length, we might be reading past the end of HTTP/2 data
        // Stop processing and wait for more data
        self.processed_offset = offset;
        return;
      }

      // Process the frame based on its type
      match frame_type {
        0 => {
          // DATA frame
          consecutive_invalid_frames = 0; // Reset counter on valid frame
          if frame_length > 0 {
            // Check for padded flag
            let is_padded = (frame_flags & 0x08) == 0x08;
            let mut data_offset = 0;
            let mut data_length = frame_payload.len();

            if is_padded && !frame_payload.is_empty() {
              // First byte indicates padding length
              let pad_length = frame_payload[0] as usize;
              data_offset = 1;
              data_length = frame_payload.len().saturating_sub(pad_length);
            }

            // Make sure we have valid data boundaries
            if data_offset < data_length && data_length <= frame_payload.len() {
              let actual_data = &frame_payload[data_offset..data_length];
              // If response data
              if portion.ssl_direction == 2 {
                new_res_data.extend_from_slice(actual_data);
              } else {
                new_req_data.extend_from_slice(actual_data);
              }
            }
            self.last_data_frame_time = portion.timestamp;
          }

          // Check for END_STREAM flag (0x01)
          if (frame_flags & 0x01) == 0x01 {
            self.stream_complete = true;
          }
        }
        1 => {
          // HEADERS frame
          consecutive_invalid_frames = 0; // Reset counter on valid frame
          match decode_hpack_headers(frame_payload) {
            Ok(headers) => {
              // Determine if this is a request or response based on pseudo-headers
              let is_request = headers.iter().any(|(name, _)| {
                name.starts_with(':')
                  && (name == ":method"
                    || name == ":path"
                    || name == ":scheme"
                    || name == ":authority")
              });
              let is_response = headers.iter().any(|(name, _)| name == ":status");

              if is_response {
                // This is a response - only set if not already set to prevent duplicates
                if self.complete.res_headers.is_empty() {
                  self.complete.res_headers = headers.clone();
                }
              } else if is_request {
                self.complete.req_headers = headers.clone();
              }
            }
            Err(e) => {
              warn!(
                "http2: Failed to decode HPACK headers for hash_id {:?}: {}",
                self.complete.hash_id, e
              );
            }
          }

          if (frame_flags & 0x04) == 0x04 {
            self.headers_complete = true;
          }

          // Check for END_STREAM flag (0x01)
          if (frame_flags & 0x01) == 0x01 {
            self.stream_complete = true;
          }
        }
        4 => {
          // SETTINGS frame
          consecutive_invalid_frames = 0; // Reset counter on valid frame
        }
        8 => {
          // WINDOW_UPDATE frame
          consecutive_invalid_frames = 0; // Reset counter on valid frame
        }
        _ => {
          consecutive_invalid_frames += 1;
          // If we see multiple consecutive invalid frame types, we're likely reading garbage
          if consecutive_invalid_frames >= 3 {
            self.processed_offset = offset;
            return;
          }
        }
      }

      // Move to the next frame
      offset = frame_end_offset;
      frames_processed += 1;

      // Safety check to avoid infinite loops
      if frames_processed > 100 {
        warn!(
          "processed too many frames ({}), breaking loop",
          frames_processed
        );
        break;
      }
      self.processed_offset = offset;
    }

    // We've processed all complete frames
    self.request_buffer.extend(new_req_data.clone());
    self.response_buffer.extend(new_res_data.clone());
  }

  pub fn clear(&mut self) {
    self.portions.clear();
    self.complete.clear();
  }

  pub fn is_complete(&mut self) -> bool {
    if self.complete.http_version == 2 {
      // http2 completion is a bit trickier:
      // if GET, no END_STREAM will be set
      let is_get = self
        .complete
        .req_headers
        .iter()
        .any(|(name, value)| name == ":method" && value == "GET");
      if is_get {
        if self.headers_complete {
          self.complete.req_payload = self.request_buffer.clone();
          self.complete.res_payload = self.response_buffer.clone();
          println!("(HTTP2 [GET]) Complete Event: {:?}", self.complete);
          return true;
        } else {
          return false;
        }
      } else if self.headers_complete && self.stream_complete {
        self.complete.req_payload = self.request_buffer.clone();
        self.complete.res_payload = self.response_buffer.clone();
        println!("(HTTP2 [POST]) Complete Event: {:?}", self.complete);
        return true;
      }
      return false;
    } else {
      if self.complete_event_length.is_some()
        && self.complete_event_length.unwrap() == self.processed_offset
      {
        self.complete.req_payload = self.request_buffer.clone();
        self.complete.res_payload = self.response_buffer.clone();
        println!("(HTTP1 [ALL]) Complete Event: {:?}", self.complete);
        return true;
      }
      return false;
    }
  }
}
