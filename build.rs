use std::{env, error::Error, fs, path::PathBuf};
use syn::visit_mut::{self, VisitMut};

fn main() -> Result<(), Box<dyn Error>> {
    let contracts = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("../union-skinstation/shared/contracts");
    for (filename, root, output) in [
        ("session-profile", None, "skin_contracts.rs"),
        ("league", Some("GameScoringSession"), "game_contracts.rs"),
        ("points", Some("ActivityDelivery"), "point_contracts.rs"),
        ("operations", None, "operation_contracts.rs"),
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
        if filename == "operations" {
            // Wire messages are definitions; the document root is a bundle.
            schema
                .as_object_mut()
                .ok_or("invalid operations contract")?
                .remove("title");
            let approval_actions =
                serde_json::to_string(&schema["definitions"]["OperationsSensitiveAction"]["enum"])?;
            constants.push_str(&format!(
                "pub const OPERATIONS_APPROVAL_ACTIONS: &[&str] = &{approval_actions};\n"
            ));
            let backups =
                schema["definitions"]["OperationsBackupPage"]["properties"]["backups"]["maxItems"]
                    .as_u64()
                    .ok_or("invalid backup page limit")?;
            constants.push_str(&format!(
                "pub const OPERATIONS_MAX_BACKUPS: usize = {backups};\n"
            ));
            let protocol = &schema["definitions"]["OperationsProtocol"]["properties"];
            for (name, property, kind) in [
                ("OPERATIONS_LEASE_SECONDS", "leaseSeconds", "u64"),
                ("OPERATIONS_APPROVAL_SECONDS", "approvalSeconds", "u64"),
                ("OPERATIONS_MAX_PAGE_ROWS", "maxPageRows", "usize"),
                ("OPERATIONS_WATCH_SECONDS", "watchSeconds", "u64"),
                ("OPERATIONS_MAX_REQUEST_BYTES", "maxRequestBytes", "usize"),
            ] {
                let value = protocol[property]["const"]
                    .as_u64()
                    .ok_or("invalid operations limit")?;
                constants.push_str(&format!("pub const {name}: {kind} = {value};\n"));
            }
            for (name, property) in [
                ("EXECUTOR_SNAPSHOT_PATH", "snapshotPath"),
                ("OPERATIONS_CLAIM_PATH", "claimPath"),
                ("OPERATIONS_CLAIM_HEADER", "claimHeader"),
                ("EXECUTOR_JOBS_PATH", "jobsPath"),
                ("EXECUTOR_INSTANCES_PATH", "instancesPath"),
                ("OPERATIONS_SCOPE_HEADER", "scopeHeader"),
            ] {
                let value = protocol[property]["const"]
                    .as_str()
                    .ok_or("invalid operations path")?;
                constants.push_str(&format!("pub const {name}: &str = {value:?};\n"));
            }
        }
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
        derive_default_structs(&mut syntax);
        FalliblePatterns.visit_file_mut(&mut syntax);
        fs::write(
            PathBuf::from(env::var("OUT_DIR")?).join(output),
            format!("{}\n{constants}", prettyplease::unparse(&syntax)),
        )?;
    }
    Ok(())
}

fn derive_default_structs(file: &mut syn::File) {
    let structures: std::collections::HashSet<String> = file
        .items
        .iter()
        .filter_map(|item| {
            if let syn::Item::Struct(item) = item {
                Some(item.ident.to_string())
            } else {
                None
            }
        })
        .collect();
    let mut derived = std::collections::HashSet::new();
    file.items.retain(|item| {
        let syn::Item::Impl(item) = item else {
            return true;
        };
        if !item.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments
                .last()
                .is_some_and(|part| part.ident == "Default")
        }) {
            return true;
        }
        let syn::Type::Path(target) = item.self_ty.as_ref() else {
            return true;
        };
        let Some(name) = target
            .path
            .segments
            .last()
            .map(|part| part.ident.to_string())
        else {
            return true;
        };
        if !structures.contains(&name) {
            return true;
        }
        let [syn::ImplItem::Fn(method)] = item.items.as_slice() else {
            return true;
        };
        let [syn::Stmt::Expr(syn::Expr::Struct(value), None)] = method.block.stmts.as_slice()
        else {
            return true;
        };
        if !value.path.is_ident("Self") || value.rest.is_some() {
            return true;
        }
        if !value.fields.iter().all(|field| {
            let syn::Expr::Call(call) = &field.expr else {
                return false;
            };
            let syn::Expr::Path(function) = call.func.as_ref() else {
                return false;
            };
            call.args.is_empty()
                && function
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .eq(["Default", "default"])
        }) {
            return true;
        }
        derived.insert(name);
        false
    });
    for item in &mut file.items {
        if let syn::Item::Struct(item) = item
            && derived.contains(&item.ident.to_string())
        {
            item.attrs.push(syn::parse_quote!(#[derive(Default)]));
        }
    }
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
