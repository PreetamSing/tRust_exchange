#![allow(dead_code)] // TODO: remove this

use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;

#[derive(Debug)]
struct Authenticator {
    configuration: Conf,
    pub_key: RsaPublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    iat: usize,
    sub: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct Conf {
    // Put your plugin configuration here. It will automatically be deserialized from JSON.
    pub_key_file: String, // RSA public key against which JWT shall be verified.
}

#[async_trait::async_trait]
impl Plugin for Authenticator {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let pub_key_string = fs::read_to_string(&init.config.pub_key_file)?;
        let pub_key = RsaPublicKey::from_pkcs1_pem(&pub_key_string)?;
        Ok(Authenticator {
            configuration: init.config,
            pub_key,
        })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        println!("Inside `supergraph_service`");
        let pub_key = self.pub_key.clone();
        // Always use service builder to compose your plugins.
        // It provides off the shelf building blocks for your plugin.
        ServiceBuilder::new()
            .map_request(move |mut req: supergraph::Request| {
                let mut is_valid = false; // Keep valid token indicator to false initially and only set to true once validated.
                if let Some(bearer) = req.supergraph_request.headers().get("authorization") {
                    let verify_token = |token: &str| {
                        let _ = dbg!(&pub_key);
                        // let _ = dbg!(pub_key.verify_token::<NoCustomClaims>(&token, None));
                        // TODO: verify authenticity of JWT token using public key.
                        todo!("verify_token")
                    };

                    let token = bearer.to_str().unwrap_or("").split_whitespace().skip(1).next();
                    if let Some(token) = token {
                        println!("Token: {}", token);
                        // Try to validate if token is present, and set indicator to true if it is valid.
                        if verify_token(token) {
                            is_valid = true;
                        }
                    }
                }

                // If there is no valid token, then delete invalid token from request headers, if any exists.
                if !is_valid {
                    req.supergraph_request.headers_mut().remove("authorization");
                }
                let _ = dbg!(&req.supergraph_request.headers().get("authorization"));
                req
            })
            .service(service)
            .boxed()
    }
}

// This macro allows us to use it in our plugin registry!
// register_plugin takes a group name, and a plugin name.
//
// In order to keep the plugin names consistent,
// we use using the `Reverse domain name notation`
register_plugin!("router", "authenticator", Authenticator);

#[cfg(test)]
mod tests {
    // use apollo_router::graphql;
    // use apollo_router::plugin::{test, Plugin};
    // use apollo_router::services::supergraph;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use std::fs;

    // use super::*;
    use super::Claims;

    const PUB_KEY_PATH: &'_ str = "./test_keys/rsa.pub";
    const PVT_KEY_PATH: &'_ str = "./test_keys/rsa";
    const TEST_KEYS_DIR: &'_ str = "./test_keys";

    fn create_test_keys() -> Result<RsaPrivateKey, anyhow::Error> {
        let mut rng = rand::thread_rng();
        const MODULUS_BITS: usize = 4096;
        let pvt_key = RsaPrivateKey::new(&mut rng, MODULUS_BITS)?;
        let pub_key = pvt_key.to_public_key();

        fs::create_dir_all(TEST_KEYS_DIR)?;
        fs::write(PUB_KEY_PATH, pub_key.to_public_key_pem(Default::default())?)?;
        fs::write(PVT_KEY_PATH, pvt_key.to_pkcs8_pem(Default::default())?)?;

        Ok(pvt_key)
    }

    #[tokio::test]
    async fn validates_token_correctly() -> Result<(), anyhow::Error> {
        let pub_key_result: Result<RsaPublicKey, _> = DecodePublicKey::read_public_key_pem_file(PUB_KEY_PATH);
        let pvt_key_result: Result<RsaPrivateKey, _> = DecodePrivateKey::read_pkcs8_pem_file(PVT_KEY_PATH);

        let pvt_key;
        let pub_key;
        if pub_key_result.is_err() || pvt_key_result.is_err() {
            pvt_key = create_test_keys()?;
            pub_key = pvt_key.to_public_key();
        } else {
            pvt_key = pvt_key_result.unwrap();
            pub_key = pub_key_result.unwrap();
        }
        // let mut
        let config = serde_json::json!({
            "plugins": {
                "router.authenticator": {
                    "pub_key_file": "./test_keys/rsa.pub",
                }
            }
        });

        let my_claims = Claims {
            exp: (Utc::now().timestamp() + Duration::seconds(5).num_seconds()) as usize,
            iat: Utc::now().timestamp() as usize,
            sub: "user_id".to_string(),
        };
        let header = Header::new(Algorithm::RS256);
        let token = dbg!(encode(
            &header,
            &my_claims,
            &EncodingKey::from_rsa_pem(pvt_key.to_pkcs8_pem(Default::default())?.as_bytes())?
        )?);
        std::thread::sleep(std::time::Duration::from_secs(6));
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.leeway = 0;
        let _ = dbg!(decode::<Claims>(
            &token,
            &DecodingKey::from_rsa_pem(pub_key.to_public_key_pem(Default::default())?.as_bytes())?,
            &validation
        )?);
        todo!("completed as much was possible");

        // let mock_service = test::MockSupergraphService
        Ok(())
    }
}
