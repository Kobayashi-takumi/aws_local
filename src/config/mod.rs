use crate::error::{Error, Result};
use log::error;
use std::env::var;

///
/// アプリケーションの設定値
///
#[derive(Debug, PartialEq, Clone)]
pub struct Config {
    /// AWS Cognitoのpool id
    pub pool_id: String,
    /// AWS Cognitoのclinet id
    pub client_id: String,
    /// AWSのアクセスキー
    pub aws_access_key: String,
    /// AWSのシークレットキー
    pub aws_secret_key: String,
    /// AWSのリージョン
    pub region: String,
    /// S3のバケット名
    pub bucket_name: String,
    /// S3のドメイン名
    pub s3_domain: String,
    /// ローカル用のエンドポイント
    pub endpoint_url: Option<String>,
    /// ローカル環境
    pub is_local: bool,
}

impl Config {
    ///
    /// コンストラクタ
    ///
    pub fn new() -> Result<Self> {
        let pool_id = var("POOL_ID").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("POOL_ID".to_string())
        })?;
        let client_id = var("CLIENT_ID").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("CLIENT_ID".to_string())
        })?;
        let aws_access_key = var("AWS_ACCESS_KEY").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("AWS_ACCESS_KEY".to_string())
        })?;
        let aws_secret_key = var("AWS_SERCRET_KEY").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("AWS_SERCRET_KEY".to_string())
        })?;
        let region = var("REGION").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("REGION".to_string())
        })?;
        let bucket_name = var("BUCKET_NAME").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("BUCKET_NAME".to_string())
        })?;
        let s3_domain = var("S3_DOMAIN").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("S3_DOMAIN".to_string())
        })?;
        let endpoint_url = var("ENDPOINT_URL").map_or(None, |v| Some(v));
        let is_local = var("ENVIRONMENT").map_or(false, |v| v == "local");
        Ok(Self {
            pool_id,
            client_id,
            aws_access_key,
            aws_secret_key,
            region,
            bucket_name,
            s3_domain,
            endpoint_url,
            is_local,
        })
    }
}
