use std::{env, error::Error, fs, path::PathBuf};
use syn::visit_mut::{self, VisitMut};

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
        let mut syntax = syn::parse2(types.to_stream())?;
        FalliblePatterns.visit_file_mut(&mut syntax);
        fs::write(
            PathBuf::from(env::var("OUT_DIR")?).join(output),
            format!("{}\n{constants}", prettyplease::unparse(&syntax)),
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

// Keep schema pattern compilation fallible in the generated string parsers.
struct FalliblePatterns;

impl VisitMut for FalliblePatterns {
    fn visit_item_static_mut(&mut self, item: &mut syn::ItemStatic) {
        if item.ident == "PATTERN" {
            *item.ty = syn::parse_quote! {
                ::std::sync::LazyLock<::std::result::Result<::regress::Regex, ::regress::Error>>
            };
            PatternInitializer.visit_expr_mut(&mut item.expr);
        }
        visit_mut::visit_item_static_mut(self, item);
    }

    fn visit_expr_method_call_mut(&mut self, call: &mut syn::ExprMethodCall) {
        if call.method == "find"
            && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("PATTERN"))
        {
            *call.receiver = syn::parse_quote! {
                PATTERN.as_ref().map_err(|error| {
                    self::error::ConversionError::from(format!("invalid schema pattern: {error}"))
                })?
            };
        }
        visit_mut::visit_expr_method_call_mut(self, call);
    }
}

struct PatternInitializer;

impl VisitMut for PatternInitializer {
    fn visit_expr_mut(&mut self, expression: &mut syn::Expr) {
        if let syn::Expr::MethodCall(call) = expression
            && call.method == "unwrap"
        {
            *expression = (*call.receiver).clone();
        }
        visit_mut::visit_expr_mut(self, expression);
    }
}
