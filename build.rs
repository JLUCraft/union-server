use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let schema_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("../federated-skinstation/shared/contracts/session-profile.schema.json");
    println!("cargo:rerun-if-changed={}", schema_path.display());
    let schema = serde_json::from_str(&fs::read_to_string(schema_path)?)?;
    let mut types = typify::TypeSpace::default();
    types.add_root_schema(schema)?;
    let output = PathBuf::from(env::var("OUT_DIR")?).join("skin_contracts.rs");
    fs::write(output, types.to_stream().to_string())?;
    Ok(())
}
