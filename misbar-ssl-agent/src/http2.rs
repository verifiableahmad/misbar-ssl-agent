use hpack::Decoder;

struct Http2State {
  hpack_decoder: Decoder<'static>,
}

impl Http2State {
  fn new() -> Self {
    Http2State {
      hpack_decoder: Decoder::new(),
    }
  }
}

pub fn decode_hpack_headers(payload: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
  thread_local! {
      static HTTP2_STATE: std::cell::RefCell<Http2State> = std::cell::RefCell::new(Http2State::new());
  }
  HTTP2_STATE.with(|state| {
    let mut state = state.borrow_mut();
    let mut decoded_headers = Vec::new();
    let result = state.hpack_decoder.decode(payload);
    match result {
      Ok(headers) => {
        for (name, value) in headers {
          let name_str = String::from_utf8_lossy(&name).to_string();
          let value_str = String::from_utf8_lossy(&value).to_string();
          decoded_headers.push((name_str, value_str));
        }
        Ok(decoded_headers)
      }
      Err(e) => Err(anyhow::anyhow!("HPACK decode error: {:?}", e)),
    }
  })
}
