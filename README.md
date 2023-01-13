# tRust_exchange
It is aimed to be a reliable, event-driven implementation of an `Asset-trading Exchange` which is not too fancy, but at the same time not too crude in its functioning.  
Stack used will roughly include:
- Federated Supergraph implementation for client facing interface using [Apollo Federation](https://www.apollographql.com/docs/federation/).
- Apache Kafka for event streaming.
- PostgreSQL as primary database.
- All the subgraph services would be implemented in Rust using [async graphql](https://crates.io/crates/async-graphql) and [actix_web](https://crates.io/crates/actix_web) crates.

## FYI
- `tRust_exchange` name has been majorly inspired from [Jon Gjengset](https://www.youtube.com/@JonGjengset) naming his crate `trust` in his [stream](https://youtu.be/bzja9fQWzdA?t=1148) of implementing TCP in Rust. Though in this context, the name tries to signify a reliable and trustworthy implementation of an exchange in Rust.
- This repository is meant to serve as a root repository for connecting several others where implementation of particular services will reside.
- Major implementation of the project is yet to be done.

## Disclaimer
- This is a personal project for practicing my skills, and you are free to use it the way you like, though I take **no** responsibility of whatsoever consequences you might have to bear by using any piece of this codebase.
