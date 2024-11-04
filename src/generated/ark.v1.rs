// This file is @generated by prost-build.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct GetScheduledSweepRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetScheduledSweepResponse {
    #[prost(message, repeated, tag = "1")]
    pub sweeps: ::prost::alloc::vec::Vec<ScheduledSweep>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SweepableOutput {
    #[prost(string, tag = "1")]
    pub txid: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub vout: u32,
    #[prost(string, tag = "3")]
    pub amount: ::prost::alloc::string::String,
    #[prost(int64, tag = "4")]
    pub scheduled_at: i64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScheduledSweep {
    #[prost(string, tag = "1")]
    pub round_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub outputs: ::prost::alloc::vec::Vec<SweepableOutput>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRoundDetailsRequest {
    #[prost(string, tag = "1")]
    pub round_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRoundDetailsResponse {
    #[prost(string, tag = "1")]
    pub round_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub txid: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub forfeited_amount: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub total_vtxos_amount: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub total_exit_amount: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub fees_amount: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "7")]
    pub inputs_vtxos: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "8")]
    pub outputs_vtxos: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "9")]
    pub exit_addresses: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct GetRoundsRequest {
    #[prost(int64, tag = "1")]
    pub after: i64,
    #[prost(int64, tag = "2")]
    pub before: i64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRoundsResponse {
    #[prost(string, repeated, tag = "1")]
    pub rounds: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Generated client implementations.
pub mod admin_service_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value,
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct AdminServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl AdminServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> AdminServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> AdminServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            AdminServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn get_scheduled_sweep(
            &mut self,
            request: impl tonic::IntoRequest<super::GetScheduledSweepRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetScheduledSweepResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/ark.v1.AdminService/GetScheduledSweep",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("ark.v1.AdminService", "GetScheduledSweep"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_round_details(
            &mut self,
            request: impl tonic::IntoRequest<super::GetRoundDetailsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetRoundDetailsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/ark.v1.AdminService/GetRoundDetails",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("ark.v1.AdminService", "GetRoundDetails"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_rounds(
            &mut self,
            request: impl tonic::IntoRequest<super::GetRoundsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::GetRoundsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::unknown(
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/ark.v1.AdminService/GetRounds",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("ark.v1.AdminService", "GetRounds"));
            self.inner.unary(req, path, codec).await
        }
    }
}
