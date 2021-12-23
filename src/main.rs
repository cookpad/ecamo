#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = envy::prefixed("ECAMO_")
        .from_env::<ecamo::config::Config>()
        .unwrap();
    ecamo::app::main(config).await.unwrap().await
}
