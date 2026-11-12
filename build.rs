use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let contracts = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("../federated-skinstation/shared/contracts");
    for (filename, root, output) in [
        ("session-profile", None, "skin_contracts.rs"),
        ("league", Some("GameScoringSession"), "game_contracts.rs"),
        ("points", Some("ActivityDelivery"), "point_contracts.rs"),
    ] {
        let schema_path = contracts.join(format!("{filename}.schema.json"));
        println!("cargo:rerun-if-changed={}", schema_path.display());
        let mut schema: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(schema_path)?)?;
        if let Some(root) = root {
            schema["title"] = format!("{root}Response").into();
            schema["$ref"] = format!("#/definitions/{root}").into();
        }
        let mut constants = String::new();
        if filename == "points" {
            let office_path = contracts.join("office.schema.json");
            println!("cargo:rerun-if-changed={}", office_path.display());
            let office: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(office_path)?)?;
            schema["definitions"]["OfficeId"] = office["definitions"]["OfficeId"].clone();
            let root = schema.clone();
            expand_point_refs(&mut schema, &root)?;
            for (name, value, kind) in [
                (
                    "ACTIVITY_SLICE_MS",
                    &root["definitions"]["ActivityLimits"]["properties"]["sliceMs"]["const"],
                    "u64",
                ),
                (
                    "DAY_MS",
                    &root["definitions"]["ActivityLimits"]["properties"]["dayMs"]["const"],
                    "u64",
                ),
                (
                    "MAX_REPORT_PLAYERS",
                    &root["definitions"]["ActivityLimits"]["properties"]["maxPlayers"]["const"],
                    "usize",
                ),
                (
                    "MAX_EVIDENCE_BYTES",
                    &office["definitions"]["OfficeArtifact"]["properties"]["size"]["maximum"],
                    "usize",
                ),
            ] {
                let value = value.as_u64().ok_or("invalid central activity limit")?;
                constants.push_str(&format!("pub const {name}: {kind} = {value};\n"));
            }
        }
        let mut types = typify::TypeSpace::default();
        types.add_root_schema(serde_json::from_value(schema)?)?;
        fs::write(
            PathBuf::from(env::var("OUT_DIR")?).join(output),
            format!("{}\n{constants}", types.to_stream()),
        )?;
    }
    Ok(())
}

// Property references retain their canonical definitions in the producer schema.
fn expand_point_refs(
    value: &mut serde_json::Value,
    root: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    if let Some(reference) = value.get("$ref").and_then(serde_json::Value::as_str) {
        if reference == "https://skin.jlucraft.com/contracts/office#/definitions/OfficeId" {
            value["$ref"] = "#/definitions/OfficeId".into();
        } else if reference.starts_with('#') && reference.contains("/properties/") {
            *value = root
                .pointer(&reference[1..])
                .ok_or("missing contract property")?
                .clone();
        }
    }
    match value {
        serde_json::Value::Object(object) => {
            for value in object.values_mut() {
                expand_point_refs(value, root)?;
            }
        }
        serde_json::Value::Array(array) => {
            for value in array {
                expand_point_refs(value, root)?;
            }
        }
        _ => {}
    }
    Ok(())
}
