use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let contracts = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("../federated-skinstation/shared/contracts");
    for (filename, root, output) in [
        ("session-profile", None, "skin_contracts.rs"),
        ("league", Some("GameScoringSession"), "game_contracts.rs"),
    ] {
        let schema_path = contracts.join(format!("{filename}.schema.json"));
        println!("cargo:rerun-if-changed={}", schema_path.display());
        let mut schema: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(schema_path)?)?;
        if let Some(root) = root {
            schema["title"] = format!("{root}Response").into();
            schema["$ref"] = format!("#/definitions/{root}").into();
        }
        let mut types = typify::TypeSpace::default();
        types.add_root_schema(serde_json::from_value(schema)?)?;
        fs::write(
            PathBuf::from(env::var("OUT_DIR")?).join(output),
            types.to_stream().to_string(),
        )?;
    }
    Ok(())
}
