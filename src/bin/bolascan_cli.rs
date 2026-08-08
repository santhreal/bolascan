//! Minimal CLI: `bolascan scan --roles roles.toml --target URL`

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use appmap::{AppMap, Endpoint, Method, ParameterClassifier, RoleAuth};
use bolascan::{BolaScan, ScanConfig};
use clap::{Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "bolascan-cli", version, about = "IDOR / BOLA scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run cross-role IDOR scan against a target.
    Scan {
        /// Base target URL (e.g. https://api.example.com)
        #[arg(long)]
        target: String,
        /// Roles TOML (see README)
        #[arg(long)]
        roles: PathBuf,
        /// Optional JSON findings output path
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Deserialize)]
struct RolesFile {
    #[serde(default)]
    roles: Vec<RoleSpec>,
    #[serde(default)]
    endpoints: Vec<EndpointSpec>,
}

#[derive(Debug, Deserialize)]
struct RoleSpec {
    name: String,
    #[serde(default)]
    cookies: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct EndpointSpec {
    method: String,
    path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { target, roles, out } => run_scan(&target, &roles, out.as_deref()).await?,
    }
    Ok(())
}

async fn run_scan(
    target: &str,
    roles_path: &std::path::Path,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let toml_src = fs::read_to_string(roles_path)?;
    let spec: RolesFile = toml::from_str(&toml_src)?;

    let roles: Vec<RoleAuth> = spec
        .roles
        .into_iter()
        .map(|r| {
            let mut auth = RoleAuth::new(&r.name);
            for (k, v) in r.cookies {
                auth = auth.with_cookie(k, v);
            }
            auth
        })
        .collect();

    let classifier = ParameterClassifier::embedded()?;
    let mut builder = AppMap::builder().with_roles(roles.clone());
    let endpoint_specs = spec.endpoints;

    if endpoint_specs.is_empty() {
        builder = builder.endpoint(
            Endpoint::new(Method::Get, "/api/users/{id}")
                .with_parameter(classifier.classify("id", Some("1"))),
        );
    } else {
        for ep in endpoint_specs {
            let method = Method::parse(&ep.method).ok_or_else(|| {
                format!(
                    "invalid HTTP method '{}' for endpoint '{}'",
                    ep.method, ep.path
                )
            })?;
            let mut endpoint = Endpoint::new(method, ep.path);
            for seg in endpoint.template_segment_names() {
                endpoint = endpoint.with_parameter(classifier.classify(&seg, Some("1")));
            }
            builder = builder.endpoint(endpoint);
        }
    }

    let appmap = builder.build()?;
    let config = ScanConfig::new(target);

    // Offline substrate: synthetic replay from roles file only (no live HTTP in v0.1 CLI).
    let findings = BolaScan::new().scan_with_replay(&appmap, &roles, &config, |_role, probe| {
        let body = format!(
            r#"{{"email":"probe@example.com","resource":"{}","role":"{}"}}"#,
            probe.url,
            probe.role.role.as_str()
        );
        (200, body.into_bytes())
    })?;

    if let Some(path) = out {
        let json = serde_json::to_string_pretty(&findings)?;
        fs::write(path, json)?;
    } else {
        for f in &findings {
            writeln!(std::io::stdout().lock(), "{}", serde_json::to_string(f)?)?;
        }
    }

    writeln!(
        std::io::stderr().lock(),
        "bolascan: {} finding(s)",
        findings.len()
    )?;
    Ok(())
}
