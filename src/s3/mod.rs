use crate::error::{Error, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    config::{Credentials, Region},
    presigning, Client as S3Client,
};
use futures::future::join_all;
use log::error;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct PutRequest {
    pub bytes: Vec<u8>,
    pub key: String,
    pub dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PutResponse {
    pub key: String,
    pub file_name: String,
    pub path: String,
}

///
/// Url
///
#[derive(Debug, PartialEq, Clone)]
pub struct Url {
    key: String,
    url: String,
}

impl Url {
    pub fn new(key: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            url: url.into(),
        }
    }
    //
    // Getter
    //
    pub fn key(&self) -> String {
        self.key.clone()
    }
    pub fn url(&self) -> String {
        self.url.clone()
    }
}

pub struct Client {
    bucket_name: String,
    domain: String,
    client: S3Client,
}

impl Client {
    pub async fn new(
        access_key: String,
        secret_key: String,
        region: String,
        bucket_name: String,
        domain: String,
        endpoint_url: Option<String>,
    ) -> Result<Self> {
        let credentials = Credentials::new(access_key, secret_key, None, None, "test");
        let mut config = aws_config::defaults(BehaviorVersion::v2024_03_28())
            .region(Region::new(region.clone()))
            .credentials_provider(credentials);
        if let Some(url) = endpoint_url {
            config = config.endpoint_url(url);
        }
        let config = config.load().await;
        let client = S3Client::new(&config);
        Ok(Self {
            bucket_name,
            domain,
            client,
        })
    }
    pub async fn presign(
        &self,
        key: impl Into<String>,
        content_type: Option<impl Into<String>>,
        dir: Option<impl Into<String>>,
    ) -> Result<Url> {
        let key = Self::create_key(&key.into(), &dir.map(|d| d.into()));
        let presigning_config =
            presigning::PresigningConfig::expires_in(Duration::from_secs(86400))?;
        let query = || {
            let mut query = self
                .client
                .put_object()
                .bucket(self.bucket_name.clone())
                .key(key.clone());
            if let Some(val) = content_type {
                let content_type: String = val.into();
                query = query.content_type(content_type);
            }
            query.presigned(presigning_config)
        };
        let url = query()
            .await
            .map_err(|e| {
                error!("{}", e);
                Error::Unknown
            })?
            .uri()
            .to_string();
        Ok(Url::new(key, url))
    }
    pub async fn presign_multiple(
        &self,
        keys: Vec<String>,
        content_types: Vec<Option<impl Into<String>>>,
        dir: Option<impl Into<String> + Clone>,
    ) -> Result<Vec<Url>> {
        let futures = keys
            .into_iter()
            .zip(content_types.into_iter())
            .map(|i| self.presign(i.0, i.1, dir.clone()));
        let res = join_all(futures).await;
        let mut items = vec![];
        for i in res {
            let i = match i {
                Ok(val) => val,
                Err(e) => {
                    error!("{e}");
                    return Err(e);
                }
            };
            items.push(i);
        }
        Ok(items)
    }
    pub async fn put(&self, request: PutRequest) -> Result<PutResponse> {
        let key = Self::create_key(&request.key, &request.dir);
        self.client
            .put_object()
            .bucket(&self.bucket_name)
            .key(key.clone())
            .body(request.bytes.into())
            .send()
            .await
            .map_err(|e| {
                error!("{e}");
                Error::Unknown
            })?;
        let res = PutResponse {
            key: key.clone(),
            file_name: request.key,
            path: format!("{}/{}/{}", self.domain, self.bucket_name, key.clone()).to_string(),
        };
        Ok(res)
    }
    fn create_key(key: &str, dir: &Option<String>) -> String {
        let mut key = format!("{}-{}", Uuid::new_v4(), key);
        if let Some(dir) = dir {
            key = format!("{}/{}", dir, key);
        }
        key
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::Config;
    use dotenv::dotenv;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[tokio::test]
    async fn test() -> Result<()> {
        init();
        dotenv().ok();
        let config = Config::new()?;
        let s3 = Client::new(
            config.aws_access_key,
            config.aws_secret_key,
            config.region,
            config.bucket_name,
            config.s3_domain,
            config.endpoint_url,
        )
        .await?;
        let res = s3.presign("key", Some("image/jpeg"), Some("/test")).await;
        log::info!("{res:?}");
        assert!(res.is_ok());
        Ok(())
    }
}
