use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::{self, ClientRequestBuilder, http::Uri};

pub type ArcMutexWSClient =
  Arc<Mutex<tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>>>;

pub fn get_ws_builder(uri: Uri, token: String) -> ClientRequestBuilder {
  let builder: ClientRequestBuilder =
    ClientRequestBuilder::new(uri).with_header("Authorization", format!("Bearer {}", token));
  return builder;
}
