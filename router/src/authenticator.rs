use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use http::HeaderValue;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use schemars::JsonSchema;
use serde::Deserialize;
use std::fs;
use std::sync::Arc;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;
use trex_common::jwt_helper::JWTHelper;

const X_SUBJECT: &str = "x-subject";

#[derive(Debug)]
struct Authenticator {
    jwt_helper: Arc<JWTHelper>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct Conf {
    // Put your plugin configuration here. It will automatically be deserialized from JSON.
    pub_key_file: String, // RSA public key against which JWT shall be verified.
    expiry_secs: usize,
    leeway: u64,
}

#[async_trait::async_trait]
impl Plugin for Authenticator {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let pub_key_string = fs::read_to_string(&init.config.pub_key_file)?;
        let jwt_helper = JWTHelper::builder()
            .expiry_secs(init.config.expiry_secs)
            .leeway(init.config.leeway)
            .pub_key(RsaPublicKey::from_public_key_pem(&pub_key_string)?)
            .build()
            .into();

        Ok(Authenticator { jwt_helper })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        // Always use service builder to compose your plugins.
        // It provides off the shelf building blocks for your plugin.
        let jwt_helper = Arc::clone(&self.jwt_helper);
        ServiceBuilder::new()
            .map_request(move |mut req: supergraph::Request| {
                // Remove any preset value of X_SUBJECT header in receiving request.
                req.supergraph_request.headers_mut().remove(X_SUBJECT);

                if let Some(bearer) = req.supergraph_request.headers().get("authorization") {
                    let token = bearer.to_str().unwrap_or("").split_whitespace().nth(1);

                    // Try to validate if token is present, and set X_SUBJECT header to validated subject value.
                    if let Some(token) = token {
                        if let Ok(subject) = jwt_helper.validate_token(token) {
                            req.supergraph_request
                                .headers_mut()
                                .insert(X_SUBJECT, HeaderValue::from_str(&subject).expect("Invalid subject value"));
                        }
                    }
                }

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
