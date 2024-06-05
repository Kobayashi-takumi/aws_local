use crate::error::{Error, Result};
use aws_config::BehaviorVersion;
use aws_sdk_cognitoidentityprovider::{
    config::{Credentials, Region},
    types::{AttributeType, AuthFlowType, ChallengeNameType},
    Client as CognitoClient,
};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[async_trait::async_trait]
pub trait AuthGateway {
    async fn sing_up(&self, email: &str, password: &str) -> Result<String>;
    async fn resend_comfirmation_code(&self, email: &str) -> Result<()>;
    async fn verify(&self, email: &str, verification_code: &str) -> Result<()>;
    async fn force_verify(&self, email: &str) -> Result<()>;
    async fn jwt_parse(&self, token: &str) -> Result<String>;
    async fn delete(&self, email: &str) -> Result<()>;
    async fn update(&self, email: &str, new_email: &str) -> Result<()>;
    async fn get_token(&self, email: &str, password: &str) -> Result<String>;
}

#[derive(Debug, Clone)]
pub struct Client {
    client: CognitoClient,
    pool_id: String,
    client_id: String,
    region: String,
}

impl Client {
    pub async fn new(
        pool_id: String,
        client_id: String,
        access_key: String,
        secret_key: String,
        region: String,
        endpoint_url: Option<String>,
    ) -> Result<Self> {
        let credentials = Credentials::new(access_key, secret_key, None, None, "test");
        let mut cognito_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
            .region(Region::new(region.clone()))
            .credentials_provider(credentials);
        if let Some(url) = endpoint_url {
            cognito_config = cognito_config.endpoint_url(url);
        }
        let cognito_config = cognito_config.load().await;
        let client = CognitoClient::new(&cognito_config);
        Ok(Self {
            client,
            pool_id,
            client_id,
            region,
        })
    }
}

#[async_trait::async_trait]
impl AuthGateway for Client {
    async fn sing_up(&self, email: &str, password: &str) -> Result<String> {
        let res = self
            .client
            .sign_up()
            .client_id(self.client_id.clone())
            .username(email)
            .password(password)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                Error::NotFound
            })?;
        Ok(res.user_sub)
    }
    async fn resend_comfirmation_code(&self, email: &str) -> Result<()> {
        self.client
            .resend_confirmation_code()
            .client_id(self.client_id.clone())
            .username(email)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                Error::Custom(e.to_string())
            })?;
        Ok(())
    }
    async fn verify(&self, email: &str, verification_code: &str) -> Result<()> {
        if let Err(e) = self
            .client
            .confirm_sign_up()
            .client_id(self.client_id.clone())
            .username(email)
            .confirmation_code(verification_code)
            .send()
            .await
        {
            error!("{:?}", e);
            return Err(Error::Custom(e.to_string()));
        };
        Ok(())
    }
    async fn force_verify(&self, email: &str) -> Result<()> {
        if let Err(e) = self
            .client
            .admin_confirm_sign_up()
            .user_pool_id(self.pool_id.clone())
            .username(email)
            .send()
            .await
        {
            error!("{:?}", e);
            return Err(Error::Custom(e.to_string()));
        };
        Ok(())
    }
    async fn jwt_parse(&self, token: &str) -> Result<String> {
        log::info!("{token}");
        let region = self.region.clone();
        let pool_id = self.pool_id.clone();
        let jwks_url = format!(
            "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
            region, pool_id
        );

        let _iss = format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}");
        let mut iss = HashSet::new();
        iss.insert(_iss.clone());
        let header = decode_header(token).map_err(|e| {
            error!("{}", e);
            Error::Unknown
        })?;
        let kid = match header.kid {
            Some(k) => k,
            None => return Err(Error::Unknown),
        };
        let jwks = reqwest::get(jwks_url)
            .await
            .map_err(|e| {
                error!("{:?}", e);
                Error::Unknown
            })?
            .json::<JwkSet>()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                Error::Unknown
            })?;

        let jwk = jwks.find(&kid).ok_or(Error::Unknown)?;
        match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                let decoding_key =
                    DecodingKey::from_rsa_components(&rsa.n, &rsa.e).map_err(|e| {
                        error!("{}", e);
                        Error::Unknown
                    })?;

                let mut validation = Validation::new(Algorithm::RS256);
                validation.iss = Some(iss);
                validation.set_audience(&[self.client_id.clone()]);

                let decoded_token =
                    decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
                        error!("{:?}", e);
                        Error::Unknown
                    })?;
                if decoded_token.claims.token_use != "id" {
                    return Err(Error::Unknown);
                }
                Ok(decoded_token.claims.sub)
            }
            _ => Err(Error::Unknown),
        }
    }
    async fn delete(&self, email: &str) -> Result<()> {
        let pool_id = self.pool_id.clone();
        self.client
            .admin_delete_user()
            .user_pool_id(pool_id)
            .username(email)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                Error::Unknown
            })?;
        Ok(())
    }
    async fn update(&self, email: &str, new_email: &str) -> Result<()> {
        let pool_id = self.pool_id.clone();
        self.client
            .admin_update_user_attributes()
            .user_pool_id(pool_id)
            .username(email)
            .user_attributes(
                AttributeType::builder()
                    .name("email")
                    .value(new_email)
                    .build()
                    .map_err(|e| {
                        error!("{}", e);
                        Error::Custom(e.to_string())
                    })?,
            )
            .user_attributes(
                AttributeType::builder()
                    .name("email_verified")
                    .value("true")
                    .build()
                    .map_err(|e| {
                        error!("{}", e);
                        Error::Custom(e.to_string())
                    })?,
            )
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                Error::Unknown
            })?;
        Ok(())
    }
    async fn get_token(&self, email: &str, password: &str) -> Result<String> {
        let mut auth_params: HashMap<String, String> = HashMap::new();
        auth_params.insert("USERNAME".into(), email.to_string());
        auth_params.insert("PASSWORD".into(), password.to_string());

        let output = match self
            .client
            .admin_initiate_auth()
            .auth_flow(AuthFlowType::AdminUserPasswordAuth)
            .user_pool_id(self.pool_id.clone())
            .client_id(self.client_id.clone())
            .set_auth_parameters(Some(auth_params))
            .send()
            .await
        {
            Ok(val) => val,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(Error::Custom(e.to_string()));
            }
        };
        if let Some(challenge_name) = output.challenge_name() {
            if challenge_name == &ChallengeNameType::NewPasswordRequired {
                return Err(Error::Unknown);
            }
        }
        output
            .authentication_result()
            .ok_or(Error::Unknown)?
            .id_token()
            .map(|x| x.to_string())
            .ok_or(Error::Unknown)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
    token_use: String,
    #[serde(alias = "cognito:username")]
    pub user_name: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub birthdate: Option<String>,
    pub gender: Option<String>,
    #[serde(alias = "custom:jpn_phone_number")]
    pub jpn_phone_number: Option<String>,
    #[serde(alias = "custom:prefecture")]
    pub prefecture: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::Config;
    use dotenv::dotenv;
    use std::env::var;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[tokio::test]
    async fn test() -> Result<()> {
        init();
        dotenv().ok();
        let email = var("COGNITO_TEST_EMAIL").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("COGNITO_TEST_EMAIL".to_string())
        })?;
        let password = var("COGNITO_TEST_PASSWORD").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("COGNITO_TEST_PASSWORD".to_string())
        })?;
        // let verification_code = "";
        let new_email = var("COGNITO_TEST_NEW_EMAIL").map_err(|e| {
            error!("{}", e);
            Error::ConfigurationError("COGNITO_TEST_NEW_EMAIL".to_string())
        })?;
        let config = Config::new()?;
        let client = Client::new(
            config.pool_id.clone(),
            config.client_id.clone(),
            config.aws_access_key.clone(),
            config.aws_secret_key.clone(),
            config.region.clone(),
            config.endpoint_url,
        )
        .await?;
        client.sing_up(&email, &password).await?;
        // client.verify(&email, &verification_code).await?;
        client.force_verify(&email).await?;
        // let res = client.get_token(&email, &password).await?;
        // let res = client.jwt_parse(&res).await?;
        client.update(&email, &new_email).await?;
        // let res = client.get_token(&email, &password).await?;
        // let res = client.jwt_parse(&res).await?;
        // client.delete(&res).await?;
        Ok(())
    }
}
