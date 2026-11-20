use prost::Message;
use std::collections::HashMap;
use std::time::Duration;
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::{Channel, Endpoint};

#[derive(Clone, PartialEq, Message)]
pub struct Stat {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int64, tag = "2")]
    pub value: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueryStatsRequest {
    #[prost(string, tag = "1")]
    pub pattern: String,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueryStatsResponse {
    #[prost(message, repeated, tag = "1")]
    pub stat: Vec<Stat>,
}

pub struct XrayStatsClient {
    endpoint: String,
    channel: Option<Channel>,
}

impl XrayStatsClient {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            channel: None,
        }
    }

    async fn get_channel(&mut self) -> Result<Channel, String> {
        if let Some(ch) = &self.channel {
            return Ok(ch.clone());
        }
        let ch = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|e| format!("invalid Xray gRPC endpoint {}: {e}", self.endpoint))?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .map_err(|e| format!("failed to connect to Xray API {}: {e}", self.endpoint))?;
        self.channel = Some(ch.clone());
        Ok(ch)
    }

    /// Queries and optionally resets user traffic counters in a single gRPC call.
    pub async fn query_user_traffic(
        &mut self,
        count_uplink: bool,
        reset: bool,
    ) -> Result<HashMap<String, u64>, String> {
        let pattern = if count_uplink {
            "user>>>".to_owned()
        } else {
            ">>>traffic>>>downlink".to_owned()
        };

        let channel = self.get_channel().await?;
        let mut grpc = Grpc::new(channel);
        if let Err(err) = grpc.ready().await {
            self.channel = None;
            return Err(format!("Xray gRPC channel not ready: {err}"));
        }

        let codec: ProstCodec<QueryStatsRequest, QueryStatsResponse> = ProstCodec::default();
        let path = PathAndQuery::from_static("/xray.app.stats.command.StatsService/QueryStats");
        let req = tonic::Request::new(QueryStatsRequest { pattern, reset });

        let response = match grpc.unary(req, path, codec).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                self.channel = None;
                return Err(format!("Xray QueryStats RPC failed: {status}"));
            }
        };

        let mut usage: HashMap<String, u64> = HashMap::new();
        for stat in response.stat {
            if stat.value <= 0 {
                continue;
            }
            if let Some(username) = parse_user_stat_name(&stat.name, count_uplink) {
                *usage.entry(username.to_owned()).or_insert(0) += stat.value as u64;
            }
        }

        Ok(usage)
    }
}

fn parse_user_stat_name(name: &str, count_uplink: bool) -> Option<&str> {
    let mut parts = name.split(">>>");
    let scope = parts.next()?;
    let username = parts.next()?;
    let metric = parts.next()?;
    let direction = parts.next()?;

    if scope != "user" || metric != "traffic" || username.is_empty() {
        return None;
    }

    if direction == "downlink" || (count_uplink && direction == "uplink") {
        Some(username)
    } else {
        None
    }
}
