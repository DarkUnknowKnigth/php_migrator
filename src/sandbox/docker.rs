use crate::models::{DbEngine, DbIsolationMode, PhpVersion};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Configuración del sandbox Docker comparativo (PHP origen vs. PHP destino).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub project_root: PathBuf,
    pub source_php: PhpVersion,
    pub target_php: PhpVersion,
    pub db_mode: DbIsolationMode,
    pub routes_to_test: Vec<String>,
    pub source_port: u16,
    pub target_port: u16,
}

fn normalize_docker_path(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = resolved.to_string_lossy();
    let without_unc = if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!("//{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    };
    without_unc.replace('\\', "/")
}

fn yaml_escape_dq(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn append_php_service(
    out: &mut String,
    service_name: &str,
    image: &str,
    host_port: u16,
    project_vol: &str,
    db_mode: &DbIsolationMode,
    is_source: bool,
) {
    let _ = writeln!(out, "  {service_name}:");
    let _ = writeln!(out, "    image: {image}");
    let _ = writeln!(out, "    ports:");
    let _ = writeln!(out, "      - \"{host_port}:80\"");
    let _ = writeln!(out, "    volumes:");
    let _ = writeln!(
        out,
        "      - \"{}:/var/www/html:ro\"",
        yaml_escape_dq(project_vol)
    );

    match db_mode {
        DbIsolationMode::SqlDumpClone { engine, .. } => {
            let db_service = if is_source { "db_source" } else { "db_target" };
            let db_port = match engine {
                DbEngine::MySql | DbEngine::MariaDb => 3306,
                DbEngine::Postgres => 5432,
            };
            let _ = writeln!(out, "    depends_on:");
            let _ = writeln!(out, "      - {db_service}");
            let _ = writeln!(out, "    environment:");
            let _ = writeln!(out, "      DB_HOST: \"{db_service}\"");
            let _ = writeln!(out, "      DB_PORT: \"{db_port}\"");
            let _ = writeln!(out, "      DB_NAME: \"app_sandbox\"");
            let _ = writeln!(out, "      DB_USER: \"migrator\"");
            let _ = writeln!(out, "      DB_PASSWORD: \"migrator_secret\"");
        }
        DbIsolationMode::ExistingReadOnly {
            host,
            port,
            database,
            user,
        } => {
            let _ = writeln!(
                out,
                "    # Modo solo lectura contra base de datos existente (sin escrituras destructivas)"
            );
            let _ = writeln!(out, "    extra_hosts:");
            let _ = writeln!(out, "      - \"host.docker.internal:host-gateway\"");
            let _ = writeln!(out, "    environment:");
            let _ = writeln!(out, "      DB_HOST: \"{}\"", yaml_escape_dq(host));
            let _ = writeln!(out, "      DB_PORT: \"{port}\"");
            let _ = writeln!(out, "      DB_NAME: \"{}\"", yaml_escape_dq(database));
            let _ = writeln!(out, "      DB_USER: \"{}\"", yaml_escape_dq(user));
            let _ = writeln!(out, "      DB_READ_ONLY: \"true\"");
        }
        DbIsolationMode::NoDatabase => {}
    }
}

fn append_db_service(out: &mut String, service_name: &str, engine: DbEngine, dump_vol: &str) {
    let _ = writeln!(out, "  {service_name}:");
    match engine {
        DbEngine::MySql => {
            let _ = writeln!(out, "    image: mysql:8.0");
            let _ = writeln!(out, "    environment:");
            let _ = writeln!(out, "      MYSQL_ROOT_PASSWORD: \"migrator_secret\"");
            let _ = writeln!(out, "      MYSQL_DATABASE: \"app_sandbox\"");
            let _ = writeln!(out, "      MYSQL_USER: \"migrator\"");
            let _ = writeln!(out, "      MYSQL_PASSWORD: \"migrator_secret\"");
        }
        DbEngine::MariaDb => {
            let _ = writeln!(out, "    image: mariadb:10.11");
            let _ = writeln!(out, "    environment:");
            let _ = writeln!(out, "      MARIADB_ROOT_PASSWORD: \"migrator_secret\"");
            let _ = writeln!(out, "      MARIADB_DATABASE: \"app_sandbox\"");
            let _ = writeln!(out, "      MARIADB_USER: \"migrator\"");
            let _ = writeln!(out, "      MARIADB_PASSWORD: \"migrator_secret\"");
        }
        DbEngine::Postgres => {
            let _ = writeln!(out, "    image: postgres:16");
            let _ = writeln!(out, "    environment:");
            let _ = writeln!(out, "      POSTGRES_DB: \"app_sandbox\"");
            let _ = writeln!(out, "      POSTGRES_USER: \"migrator\"");
            let _ = writeln!(out, "      POSTGRES_PASSWORD: \"migrator_secret\"");
        }
    }
    let _ = writeln!(out, "    volumes:");
    let _ = writeln!(
        out,
        "      - \"{}:/docker-entrypoint-initdb.d/init.sql:ro\"",
        yaml_escape_dq(dump_vol)
    );
}

/// Genera el contenido YAML de `docker-compose.yml` para levantar dos contenedores PHP Apache
/// (`php_source` y `php_target`) con la estrategia de aislamiento de base de datos configurada.
pub fn generate_docker_compose(config: &SandboxConfig) -> String {
    let project_vol = normalize_docker_path(&config.project_root);
    let mut yaml = String::new();

    yaml.push_str("# Generado automáticamente por php-migrator (Sandbox Dual)\n");
    yaml.push_str("services:\n");

    append_php_service(
        &mut yaml,
        "php_source",
        config.source_php.docker_apache_image(),
        config.source_port,
        &project_vol,
        &config.db_mode,
        true,
    );

    yaml.push('\n');

    append_php_service(
        &mut yaml,
        "php_target",
        config.target_php.docker_apache_image(),
        config.target_port,
        &project_vol,
        &config.db_mode,
        false,
    );

    if let DbIsolationMode::SqlDumpClone { dump_path, engine } = &config.db_mode {
        let resolved_dump = if dump_path.is_relative() {
            config.project_root.join(dump_path)
        } else {
            dump_path.clone()
        };
        let dump_vol = normalize_docker_path(&resolved_dump);

        yaml.push('\n');
        append_db_service(&mut yaml, "db_source", *engine, &dump_vol);
        yaml.push('\n');
        append_db_service(&mut yaml, "db_target", *engine, &dump_vol);
    }

    yaml
}

/// Escribe `<project_root>/.php-migrator/sandbox/docker-compose.yml` y devuelve la ruta generada.
pub fn write_sandbox_files(config: &SandboxConfig) -> Result<PathBuf> {
    let sandbox_dir = config.project_root.join(".php-migrator").join("sandbox");
    std::fs::create_dir_all(&sandbox_dir).with_context(|| {
        format!(
            "No se pudo crear el directorio del sandbox {}",
            sandbox_dir.display()
        )
    })?;

    let compose_path = sandbox_dir.join("docker-compose.yml");
    let content = generate_docker_compose(config);

    std::fs::write(&compose_path, content).with_context(|| {
        format!(
            "No se pudo escribir docker-compose.yml en {}",
            compose_path.display()
        )
    })?;

    Ok(compose_path)
}

/// Comprueba de forma segura si Docker y su daemon están disponibles en el sistema.
pub async fn check_docker_available() -> bool {
    match Command::new("docker").args(["info"]).output().await {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_compose_with_isolated_db_clones() {
        let cfg = SandboxConfig {
            project_root: PathBuf::from(r"D:\laragon\www\legacy_app"),
            source_php: PhpVersion::Php74,
            target_php: PhpVersion::Php85,
            db_mode: DbIsolationMode::SqlDumpClone {
                dump_path: PathBuf::from(r"db\schema.sql"),
                engine: DbEngine::MySql,
            },
            routes_to_test: vec!["/".to_string()],
            source_port: 18074,
            target_port: 18085,
        };

        let yml = generate_docker_compose(&cfg);
        assert!(yml.contains("php:7.4-apache"));
        assert!(yml.contains("php:8.5-apache"));
        assert!(yml.contains("18074:80"));
        assert!(yml.contains("18085:80"));
        assert!(yml.contains("db_source:"));
        assert!(yml.contains("db_target:"));
        assert!(yml.contains("DB_HOST: \"db_source\""));
        assert!(yml.contains("DB_HOST: \"db_target\""));
        assert!(yml.contains("/docker-entrypoint-initdb.d/init.sql:ro"));
        assert!(!yml.contains(r"D:\laragon"));
        assert!(yml.contains("D:/laragon/www/legacy_app:/var/www/html:ro"));
    }

    #[test]
    fn generates_compose_without_database() {
        let cfg = SandboxConfig {
            project_root: PathBuf::from("/srv/app"),
            source_php: PhpVersion::Php80,
            target_php: PhpVersion::Php84,
            db_mode: DbIsolationMode::NoDatabase,
            routes_to_test: vec!["/health.php".to_string()],
            source_port: 8080,
            target_port: 8084,
        };

        let yml = generate_docker_compose(&cfg);
        assert!(yml.contains("php_source:"));
        assert!(yml.contains("php_target:"));
        assert!(!yml.contains("db_source:"));
        assert!(!yml.contains("db_target:"));
    }
}
