use aws_sdk_s3::presigning::PresigningConfigError;
use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("データが見つかりませんでした。")]
    NotFound,
    #[error("パラメータが不正です。")]
    InvalidArgument,
    #[error("処理に失敗しました。")]
    ProcessFail,
    #[error("Unknown Error")]
    Unknown,
    #[error("{0}")]
    InvalidFormat(String),
    #[error("{0}が不正です。")]
    InvalidValue(String),
    #[error("{0}に無効な値が設定されています。")]
    ConfigurationError(String),
    #[error("実装がされていません。")]
    NotImplemented,
    #[error("権限がありません。")]
    Unauthorized,
    #[error("{0}")]
    DatabaseError(String),
    #[error("{0}")]
    Custom(String),
}

impl From<PresigningConfigError> for Error {
    fn from(value: PresigningConfigError) -> Self {
        match value {
            _ => Error::Custom("S3の処理に失敗しました".to_string()),
        }
    }
}
