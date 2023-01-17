use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::execution;
use apollo_router::services::subgraph;
use apollo_router::services::supergraph;
use schemars::JsonSchema;
use serde::Deserialize;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;

#[derive(Debug)]
struct Authenticator {
    #[allow(dead_code)] // TODO: remove this
    configuration: Conf,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct Conf {
    // Put your plugin configuration here. It will automatically be deserialized from JSON.
    rsa_pub_key: String, // RSA public key against which JWT shall be verified.
}

#[async_trait::async_trait]
impl Plugin for Authenticator {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        println!("Initializing Plugin with rsa_pub_key: {}", &init.config.rsa_pub_key);
        Ok(Authenticator {
            configuration: init.config,
        })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        println!("Inside `supergraph_service`");
        // Always use service builder to compose your plugins.
        // It provides off the shelf building blocks for your plugin.
        ServiceBuilder::new()
            .map_request(|mut req: supergraph::Request| {
                let mut is_valid = false; // Keep valid token indicator to false initially and only set to true once validated.
                if let Some(bearer) = req.supergraph_request.headers().get("authorization") {
                    let verify_token = |_token: &str| {
                        // TODO: verify token using rsa_pub_key.
                        true
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

    fn execution_service(&self, service: execution::BoxService) -> execution::BoxService {
        //This is the default implementation and does not modify the default service.
        // The trait also has this implementation, and we just provide it here for illustration.
        println!("Inside `execution_service`");
        service
    }

    // Called for each subgraph
    fn subgraph_service(&self, name: &str, service: subgraph::BoxService) -> subgraph::BoxService {
        println!("Inside \"{}\"`subgraph_service`", name);
        // Always use service builder to compose your plugins.
        // It provides off the shelf building blocks for your plugin.
        ServiceBuilder::new().service(service).boxed()
    }
}

// This macro allows us to use it in our plugin registry!
// register_plugin takes a group name, and a plugin name.
//
// In order to keep the plugin names consistent,
// we use using the `Reverse domain name notation`
register_plugin!("router", "authenticator", Authenticator);
