#![allow(dead_code)] // TODO: remove this

use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use jwt_simple::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use std::fs;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;

#[derive(Debug)]
struct Authenticator {
    configuration: Conf,
    pub_key: RS256PublicKey,
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
        let pub_key = RS256PublicKey::from_pem(&pub_key_string)?;
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
                        let _ = dbg!(pub_key.verify_token::<NoCustomClaims>(&token, None));
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
    use apollo_router::graphql;
    use apollo_router::plugin::{test, Plugin};
    use apollo_router::services::supergraph;
    use std::fs;

    use super::*;

    #[tokio::test]
    async fn validates_token_correctly() -> Result<(), Box<dyn std::error::Error>> {
        let key_pair = RS256KeyPair::generate(4096)?;
        let pub_key = key_pair.public_key();

        fs::create_dir("./test_keys")?;
        fs::write("rsa.pub", pub_key.to_pem()?)?;
        let config = serde_json::json!({
            "plugins": {
                "router.authenticator": {
                    "pub_key_file": "./test_keys/rsa.pub",
                }
            }
        });

        // let mock_service = test::MockSupergraphService
        Ok(())
    }
}
