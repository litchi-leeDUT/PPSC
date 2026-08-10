use ppsc_runtime::postgres::PostgresRuntimeRepository;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set, for example postgres://ppsc:ppsc@localhost/ppsc")?;
    let repository = PostgresRuntimeRepository::connect(&database_url)?;
    repository.migrate()?;
    println!("PPSC PostgreSQL migration completed");
    Ok(())
}
