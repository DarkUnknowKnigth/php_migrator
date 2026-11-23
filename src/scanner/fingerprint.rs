use crate::models::{
    DependencyInfo, DependencySource, FileSummary, FrameworkKind, PhpVersion,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// Resultado del reconocimiento de stack, versión PHP, dependencias y directorios locales.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintReport {
    pub detected_php: PhpVersion,
    pub version_evidence: Vec<String>,
    pub framework: FrameworkKind,
    pub dependencies: Vec<DependencyInfo>,
    pub include_dirs: Vec<PathBuf>,
    pub vendor_dirs: Vec<PathBuf>,
}

const INCLUDE_FOLDER_NAMES: &[&str] = &[
    "includes",
    "include",
    "inc",
    "lib",
    "libs",
    "classes",
    "plugins",
    "third_party",
];

/// Inspecciona archivos de configuración, carpetas locales y resúmenes AST para estimar el perfil del proyecto.
pub fn inspect_project_fingerprint(
    root: &Path,
    all_files: &[PathBuf],
    summaries: &[FileSummary],
) -> FingerprintReport {
    let mut version_evidence: Vec<String> = Vec::new();
    let mut dependencies: Vec<DependencyInfo> = Vec::new();
    let mut dep_index: HashMap<String, usize> = HashMap::new();

    let mut include_dir_set: BTreeSet<PathBuf> = BTreeSet::new();
    let mut vendor_dir_set: BTreeSet<PathBuf> = BTreeSet::new();

    // Detectar directorios relevantes desde la lista de archivos y raíz directa
    for dir_name in INCLUDE_FOLDER_NAMES {
        if root.join(dir_name).is_dir() {
            include_dir_set.insert(PathBuf::from(dir_name));
        }
    }
    if root.join("vendor").is_dir() {
        vendor_dir_set.insert(PathBuf::from("vendor"));
    }

    for file in all_files {
        let rel = file.strip_prefix(root).unwrap_or(file);
        let mut prefix = PathBuf::new();
        for comp in rel.components() {
            if let Component::Normal(part) = comp {
                prefix.push(part);
                let lower = part.to_string_lossy().to_ascii_lowercase();
                if lower == "vendor" {
                    vendor_dir_set.insert(prefix.clone());
                } else if INCLUDE_FOLDER_NAMES.contains(&lower.as_str()) {
                    include_dir_set.insert(prefix.clone());
                }
            }
        }
    }

    // 1. Leer composer.json y composer.lock
    let composer_json_path = root.join("composer.json");
    let has_composer_json = composer_json_path.is_file();
    let mut composer_php_constraint: Option<String> = None;
    let mut composer_platform_php: Option<String> = None;
    let mut framework_from_composer: Option<FrameworkKind> = None;

    if has_composer_json {
        if let Ok(raw) = fs::read_to_string(&composer_json_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(platform_php) = json
                    .get("config")
                    .and_then(|c| c.get("platform"))
                    .and_then(|p| p.get("php"))
                    .and_then(|v| v.as_str())
                {
                    composer_platform_php = Some(platform_php.to_string());
                    version_evidence.push(format!(
                        "composer.json config.platform.php: {platform_php}"
                    ));
                }

                parse_composer_section(
                    json.get("require"),
                    DependencySource::Composer,
                    &mut composer_php_constraint,
                    &mut version_evidence,
                    &mut framework_from_composer,
                    &mut dependencies,
                    &mut dep_index,
                );

                parse_composer_section(
                    json.get("require-dev"),
                    DependencySource::ComposerDev,
                    &mut composer_php_constraint,
                    &mut version_evidence,
                    &mut framework_from_composer,
                    &mut dependencies,
                    &mut dep_index,
                );
            }
        }
    }

    let composer_lock_path = root.join("composer.lock");
    let has_composer_lock = composer_lock_path.is_file();
    if has_composer_lock {
        if let Ok(raw) = fs::read_to_string(&composer_lock_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                parse_composer_lock_packages(
                    json.get("packages"),
                    DependencySource::Composer,
                    &mut framework_from_composer,
                    &mut dependencies,
                    &mut dep_index,
                );
                parse_composer_lock_packages(
                    json.get("packages-dev"),
                    DependencySource::ComposerDev,
                    &mut framework_from_composer,
                    &mut dependencies,
                    &mut dep_index,
                );
            }
        }
    }

    let has_composer_managed_vendor =
        has_composer_json || has_composer_lock || root.join("vendor/composer/installed.json").is_file();

    // 2. Evidencias adicionales de versión PHP: .php-version, Dockerfile, .htaccess
    let mut explicit_runtime_php: Option<PhpVersion> = None;

    let php_version_file = root.join(".php-version");
    if php_version_file.is_file() {
        if let Ok(raw) = fs::read_to_string(&php_version_file) {
            let trimmed = raw.trim();
            if let Some(ver) = parse_major_minor_php(trimmed) {
                explicit_runtime_php = Some(ver);
                version_evidence.push(format!(".php-version: {trimmed} -> PHP {ver}"));
            }
        }
    }

    for dockerfile_name in ["Dockerfile", "dockerfile", "docker/Dockerfile"] {
        let df_path = root.join(dockerfile_name);
        if df_path.is_file() {
            if let Ok(raw) = fs::read_to_string(&df_path) {
                if let Some(ver) = extract_dockerfile_php(&raw) {
                    if explicit_runtime_php.is_none() {
                        explicit_runtime_php = Some(ver);
                    }
                    version_evidence.push(format!("{dockerfile_name}: detectada imagen PHP {ver}"));
                }
            }
        }
    }

    let htaccess_path = root.join(".htaccess");
    if htaccess_path.is_file() {
        if let Ok(raw) = fs::read_to_string(&htaccess_path) {
            if let Some(ver) = extract_htaccess_php(&raw) {
                if explicit_runtime_php.is_none() {
                    explicit_runtime_php = Some(ver);
                }
                version_evidence.push(format!(".htaccess: directiva PHP {ver}"));
            }
        }
    }

    // 3. Escanear librerías embebidas sin Composer en carpetas locales
    scan_bundled_libraries(
        root,
        all_files,
        has_composer_managed_vendor,
        &dep_index,
        &mut dependencies,
    );

    // 3b. Inferir extensiones PHP usadas en el código (ej. ext-oci8, ext-mysql, ext-openssl, ext-curl)
    detect_implicit_php_extensions(summaries, &mut dep_index, &mut dependencies);

    // 4. Detectar Framework
    let framework = detect_framework(root, all_files, framework_from_composer);

    // 5. Estimar versión PHP cruzando configuración + marcadores sintácticos
    let detected_php = estimate_php_version(
        explicit_runtime_php,
        composer_platform_php.as_deref(),
        composer_php_constraint.as_deref(),
        summaries,
        &mut version_evidence,
    );

    FingerprintReport {
        detected_php,
        version_evidence,
        framework,
        dependencies,
        include_dirs: include_dir_set.into_iter().collect(),
        vendor_dirs: vendor_dir_set.into_iter().collect(),
    }
}

fn parse_composer_section(
    section: Option<&serde_json::Value>,
    source: DependencySource,
    php_constraint: &mut Option<String>,
    version_evidence: &mut Vec<String>,
    framework: &mut Option<FrameworkKind>,
    dependencies: &mut Vec<DependencyInfo>,
    dep_index: &mut HashMap<String, usize>,
) {
    let Some(obj) = section.and_then(|v| v.as_object()) else {
        return;
    };

    for (name, val) in obj {
        let Some(constraint) = val.as_str() else {
            continue;
        };

        if name == "php" {
            if php_constraint.is_none() || source == DependencySource::Composer {
                *php_constraint = Some(constraint.to_string());
            }
            version_evidence.push(format!("composer.json require.php: {constraint}"));
            continue;
        }

        let dep_source = if name.starts_with("ext-") {
            DependencySource::PhpExtension
        } else {
            source
        };

        if name == "laravel/framework" {
            *framework = Some(FrameworkKind::Laravel {
                version: Some(constraint.to_string()),
            });
        } else if name == "symfony/framework-bundle" && framework.is_none() {
            *framework = Some(FrameworkKind::Symfony {
                version: Some(constraint.to_string()),
            });
        } else if name == "codeigniter4/framework" && framework.is_none() {
            *framework = Some(FrameworkKind::CodeIgniter {
                version: Some(constraint.to_string()),
            });
        }

        let (compatible, notes) = evaluate_known_dependency_notes(name, dep_source);
        let key = name.to_ascii_lowercase();
        if !dep_index.contains_key(&key) {
            dep_index.insert(key, dependencies.len());
            dependencies.push(DependencyInfo {
                name: name.clone(),
                detected_version: Some(constraint.to_string()),
                path: Some("composer.json".to_string()),
                source: dep_source,
                target_compatible: compatible,
                notes,
            });
        }
    }
}

fn parse_composer_lock_packages(
    packages: Option<&serde_json::Value>,
    source: DependencySource,
    framework: &mut Option<FrameworkKind>,
    dependencies: &mut Vec<DependencyInfo>,
    dep_index: &mut HashMap<String, usize>,
) {
    let Some(arr) = packages.and_then(|v| v.as_array()) else {
        return;
    };

    for pkg in arr {
        let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if name == "laravel/framework" {
            *framework = Some(FrameworkKind::Laravel {
                version: version.clone(),
            });
        } else if name == "symfony/framework-bundle" {
            *framework = Some(FrameworkKind::Symfony {
                version: version.clone(),
            });
        } else if name == "codeigniter4/framework" {
            *framework = Some(FrameworkKind::CodeIgniter {
                version: version.clone(),
            });
        }

        let key = name.to_ascii_lowercase();
        if let Some(&idx) = dep_index.get(&key) {
            if let Some(locked_ver) = version {
                dependencies[idx].detected_version = Some(locked_ver);
                dependencies[idx].path = Some("composer.lock".to_string());
            }
        } else {
            let (compatible, notes) = evaluate_known_dependency_notes(name, source);
            dep_index.insert(key, dependencies.len());
            dependencies.push(DependencyInfo {
                name: name.to_string(),
                detected_version: version,
                path: Some("composer.lock".to_string()),
                source,
                target_compatible: compatible,
                notes,
            });
        }
    }
}

fn evaluate_known_dependency_notes(name: &str, source: DependencySource) -> (Option<bool>, String) {
    match name.to_ascii_lowercase().as_str() {
        "ext-mysql" => (
            Some(false),
            "Extensión mysql eliminada en PHP 7.0; migrar a mysqli o PDO.".to_string(),
        ),
        "ext-mcrypt" => (
            Some(false),
            "Extensión mcrypt eliminada en PHP 7.2; migrar a OpenSSL o Sodium.".to_string(),
        ),
        "ext-imap" | "ext-pspell" | "ext-oci8" => (
            Some(false),
            "Extensión desacoplada a PECL en PHP 8.4.".to_string(),
        ),
        "swiftmailer/swiftmailer" => (
            Some(false),
            "SwiftMailer abandonado; incompatible con PHP 8.2+ y reemplazado por Symfony Mailer."
                .to_string(),
        ),
        "phpoffice/phpexcel" => (
            Some(false),
            "PHPExcel está obsoleto; migrar a phpoffice/phpspreadsheet.".to_string(),
        ),
        _ => (None, format!("Detectado vía {source}")),
    }
}

struct BundledSignature {
    display_name: &'static str,
    composer_aliases: &'static [&'static str],
    path_markers: &'static [&'static str],
    file_markers: &'static [&'static str],
}

const BUNDLED_SIGNATURES: &[BundledSignature] = &[
    BundledSignature {
        display_name: "PHPMailer",
        composer_aliases: &["phpmailer/phpmailer"],
        path_markers: &["phpmailer"],
        file_markers: &["class.phpmailer.php", "phpmailer.php"],
    },
    BundledSignature {
        display_name: "FPDF",
        composer_aliases: &["setasign/fpdf"],
        path_markers: &["fpdf"],
        file_markers: &["fpdf.php"],
    },
    BundledSignature {
        display_name: "TCPDF",
        composer_aliases: &["tecnickcom/tcpdf"],
        path_markers: &["tcpdf"],
        file_markers: &["tcpdf.php"],
    },
    BundledSignature {
        display_name: "Smarty",
        composer_aliases: &["smarty/smarty"],
        path_markers: &["smarty"],
        file_markers: &["smarty.class.php", "smarty.php"],
    },
    BundledSignature {
        display_name: "PhpSpreadsheet",
        composer_aliases: &["phpoffice/phpspreadsheet"],
        path_markers: &["phpspreadsheet"],
        file_markers: &["spreadsheet.php"],
    },
    BundledSignature {
        display_name: "PHPExcel",
        composer_aliases: &["phpoffice/phpexcel"],
        path_markers: &["phpexcel"],
        file_markers: &["phpexcel.php"],
    },
    BundledSignature {
        display_name: "ADOdb",
        composer_aliases: &["adodb/adodb-php"],
        path_markers: &["adodb"],
        file_markers: &["adodb.inc.php"],
    },
    BundledSignature {
        display_name: "SwiftMailer",
        composer_aliases: &["swiftmailer/swiftmailer"],
        path_markers: &["swiftmailer"],
        file_markers: &["swift_required.php", "swift.php"],
    },
    BundledSignature {
        display_name: "Monolog",
        composer_aliases: &["monolog/monolog"],
        path_markers: &["monolog"],
        file_markers: &["logger.php"],
    },
];

fn scan_bundled_libraries(
    root: &Path,
    all_files: &[PathBuf],
    has_composer_managed_vendor: bool,
    composer_dep_index: &HashMap<String, usize>,
    dependencies: &mut Vec<DependencyInfo>,
) {
    let mut found_libraries: HashSet<&'static str> = HashSet::new();

    for file in all_files {
        let rel = file.strip_prefix(root).unwrap_or(file);
        let comps: Vec<String> = rel
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
                _ => None,
            })
            .collect();

        if comps.is_empty() {
            continue;
        }

        let in_vendor = comps.iter().any(|c| c == "vendor");
        let in_local_lib = comps
            .iter()
            .any(|c| INCLUDE_FOLDER_NAMES.contains(&c.as_str()));
        let in_root_lib_dir = comps.len() >= 2
            && !in_vendor
            && BUNDLED_SIGNATURES
                .iter()
                .any(|sig| sig.path_markers.iter().any(|m| comps[0] == *m));

        if !in_local_lib && !in_root_lib_dir && (!in_vendor || has_composer_managed_vendor) {
            continue;
        }

        let file_name = comps.last().map(String::as_str).unwrap_or("");
        if !file_name.ends_with(".php") && !file_name.ends_with(".inc") {
            continue;
        }

        let rel_lower = comps.join("/");

        for sig in BUNDLED_SIGNATURES {
            if found_libraries.contains(sig.display_name) {
                continue;
            }
            let already_in_composer = sig
                .composer_aliases
                .iter()
                .any(|alias| composer_dep_index.contains_key(*alias));
            if already_in_composer && in_vendor {
                continue;
            }

            let file_match = sig.file_markers.iter().any(|m| file_name == *m);
            let dir_match = sig.path_markers.iter().any(|m| rel_lower.contains(m))
                && (file_name.contains("version")
                    || file_name.contains("index")
                    || file_name.contains(sig.path_markers[0])
                    || file_match);

            if !file_match && !dir_match {
                continue;
            }

            let disk_path = if file.is_absolute() {
                file.to_path_buf()
            } else {
                root.join(rel)
            };
            let version = read_header_version(&disk_path);
            let bundled_path = rel
                .parent()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| rel.to_string_lossy().replace('\\', "/"));

            found_libraries.insert(sig.display_name);
            let notes = if sig.display_name == "PHPExcel" || sig.display_name == "SwiftMailer" {
                format!(
                    "Librería embebida legada ({}) detectada sin Composer; requiere actualización o reemplazo para PHP 8.x.",
                    sig.display_name
                )
            } else {
                format!(
                    "Librería embebida sin Composer detectada en '{bundled_path}'. Verifica compatibilidad manual."
                )
            };

            dependencies.push(DependencyInfo {
                name: sig.display_name.to_string(),
                detected_version: version,
                path: Some(bundled_path),
                source: DependencySource::BundledFolder,
                target_compatible: None,
                notes,
            });
        }
    }
}

fn read_header_version(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let slice = &bytes[..bytes.len().min(16 * 1024)];
    let text = String::from_utf8_lossy(slice);

    static VERSION_CONST_RE: OnceLock<Regex> = OnceLock::new();
    let const_re = VERSION_CONST_RE.get_or_init(|| {
        Regex::new(
            r#"(?im)(?:const\s+\w*VERSION\w*\s*=|define\s*\(\s*['"]\w*VERSION\w*['"]\s*,|\$(?:Version|ADODB_vers)\s*=)\s*['"]([0-9]+(?:\.[0-9]+){1,3}[A-Za-z0-9.-]*)['"]"#,
        )
        .expect("regex válido")
    });

    if let Some(cap) = const_re.captures(&text) {
        return cap.get(1).map(|m| m.as_str().to_string());
    }

    static DOC_VERSION_RE: OnceLock<Regex> = OnceLock::new();
    let doc_re = DOC_VERSION_RE.get_or_init(|| {
        Regex::new(r#"(?im)(?:@version|\*\s*version\s*:?)\s+v?([0-9]+(?:\.[0-9]+){1,3}[A-Za-z0-9.-]*)"#)
            .expect("regex válido")
    });

    doc_re
        .captures(&text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn detect_framework(
    root: &Path,
    all_files: &[PathBuf],
    from_composer: Option<FrameworkKind>,
) -> FrameworkKind {
    // WordPress tiene marcadores inequívocos incluso si hay otros archivos
    if root.join("wp-config.php").is_file()
        || root.join("wp-config-sample.php").is_file()
        || root.join("wp-includes/version.php").is_file()
        || all_files.iter().any(|f| {
            let s = f.to_string_lossy().replace('\\', "/");
            s.ends_with("/wp-config.php") || s.ends_with("/wp-includes/version.php")
        })
    {
        return FrameworkKind::WordPress;
    }

    if let Some(fw) = from_composer {
        if let FrameworkKind::Laravel { version: None } = &fw {
            if let Some(v) = read_laravel_application_version(root) {
                return FrameworkKind::Laravel { version: Some(v) };
            }
        }
        return fw;
    }

    // Laravel sin composer.lock/constraint claro
    if root.join("artisan").is_file()
        && (root.join("bootstrap/app.php").is_file() || root.join("app/Http/Kernel.php").is_file())
    {
        let version = read_laravel_application_version(root);
        return FrameworkKind::Laravel { version };
    }

    // CodeIgniter 3 / 4
    let ci3_core = root.join("system/core/CodeIgniter.php");
    if ci3_core.is_file() {
        let ver = read_ci_version(&ci3_core);
        return FrameworkKind::CodeIgniter { version: ver };
    }
    if root.join("spark").is_file() && root.join("app/Config/App.php").is_file() {
        let ver = read_ci_version(&root.join("system/CodeIgniter.php"));
        return FrameworkKind::CodeIgniter { version: ver };
    }

    // Symfony
    if root.join("bin/console").is_file()
        && (root.join("config/bundles.php").is_file() || root.join("src/Kernel.php").is_file())
    {
        let ver = read_symfony_kernel_version(root);
        return FrameworkKind::Symfony { version: ver };
    }

    FrameworkKind::VanillaPhp
}

fn read_laravel_application_version(root: &Path) -> Option<String> {
    let app_file = root.join("vendor/laravel/framework/src/Illuminate/Foundation/Application.php");
    let raw = fs::read_to_string(app_file).ok()?;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"const\s+VERSION\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9A-Za-z.-]+)['"]"#)
            .expect("regex válido")
    });
    re.captures(&raw)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn read_ci_version(path: &Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:CI_VERSION['"]\s*,\s*|const\s+CI_VERSION\s*=\s*)['"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['"]"#)
            .expect("regex válido")
    });
    re.captures(&raw)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn read_symfony_kernel_version(root: &Path) -> Option<String> {
    let path = root.join("vendor/symfony/http-kernel/Kernel.php");
    let raw = fs::read_to_string(path).ok()?;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"const\s+VERSION\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9A-Za-z.-]+)['"]"#)
            .expect("regex válido")
    });
    re.captures(&raw)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn estimate_php_version(
    explicit_runtime: Option<PhpVersion>,
    composer_platform: Option<&str>,
    composer_require: Option<&str>,
    summaries: &[FileSummary],
    evidence: &mut Vec<String>,
) -> PhpVersion {
    let mut has_legacy_markers = false;
    let mut max_php8_feature: Option<PhpVersion> = None;

    for summary in summaries {
        for (ver, desc) in &summary.syntax_version_markers {
            let lower = desc.to_ascii_lowercase();
            let is_legacy = lower.contains("deprecated")
                || lower.contains("deprecad")
                || lower.contains("removed")
                || lower.contains("eliminad")
                || lower.contains("mysql_")
                || lower.contains("{0}")
                || lower.contains("{}")
                || lower.contains("curly")
                || lower.contains("(real)")
                || lower.contains("create_function")
                || lower.contains("each(")
                || lower.contains("magic_quotes")
                || *ver < PhpVersion::Php80;

            if is_legacy {
                has_legacy_markers = true;
            } else if *ver >= PhpVersion::Php80 {
                max_php8_feature = Some(match max_php8_feature {
                    Some(prev) if prev >= *ver => prev,
                    _ => *ver,
                });
            }
        }

        for call in &summary.calls {
            let lower = call.name.to_ascii_lowercase();
            if lower.starts_with("mysql_")
                || lower == "each"
                || lower == "create_function"
                || lower == "get_magic_quotes_gpc"
            {
                has_legacy_markers = true;
            }
        }
    }

    if has_legacy_markers {
        evidence.push(
            "Marcadores de código legado detectados (ej. mysql_* / sintaxis pre-8.0)".to_string(),
        );
    }
    if let Some(feat_ver) = max_php8_feature {
        evidence.push(format!(
            "Sintaxis moderna PHP {feat_ver}+ detectada en el código fuente"
        ));
    } else {
        evidence.push("No se detectaron construcciones exclusivas de PHP 8.x".to_string());
    }

    if let Some(runtime) = explicit_runtime {
        if let Some(feat) = max_php8_feature {
            if feat > runtime {
                evidence.push(format!(
                    "Conflicto: código usa sintaxis PHP {feat} superior a configuración {runtime}"
                ));
                return feat;
            }
        }
        return runtime;
    }

    if let Some(platform) = composer_platform.and_then(parse_min_php_from_constraint) {
        return match max_php8_feature {
            Some(feat) if feat > platform => feat,
            _ => platform,
        };
    }

    if let Some(constraint) = composer_require {
        let allows_74 = constraint.contains("7.") || constraint.contains("<8");
        if let Some(min_ver) = parse_min_php_from_constraint(constraint) {
            if allows_74 && min_ver == PhpVersion::Php74 {
                if has_legacy_markers || max_php8_feature.is_none() {
                    return PhpVersion::Php74;
                }
                if let Some(feat) = max_php8_feature {
                    return feat;
                }
            }
            return match max_php8_feature {
                Some(feat) if feat > min_ver => feat,
                _ => min_ver,
            };
        }
    }

    if has_legacy_markers {
        return PhpVersion::Php74;
    }

    max_php8_feature.unwrap_or(PhpVersion::Php74)
}

fn parse_major_minor_php(raw: &str) -> Option<PhpVersion> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(\d+)\.(\d+)"#).expect("regex válido"));
    let cap = re.captures(raw)?;
    let major: u32 = cap.get(1)?.as_str().parse().ok()?;
    let minor: u32 = cap.get(2)?.as_str().parse().ok()?;
    map_major_minor(major, minor)
}

fn parse_min_php_from_constraint(constraint: &str) -> Option<PhpVersion> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(\d+)\.(\d+)"#).expect("regex válido"));

    let mut versions: Vec<PhpVersion> = re
        .captures_iter(constraint)
        .filter_map(|cap| {
            let maj: u32 = cap.get(1)?.as_str().parse().ok()?;
            let min: u32 = cap.get(2)?.as_str().parse().ok()?;
            map_major_minor(maj, min)
        })
        .collect();

    if versions.is_empty() {
        // Caso como "^8" o ">=8"
        if constraint.contains('7') {
            return Some(PhpVersion::Php74);
        }
        if constraint.contains('8') {
            return Some(PhpVersion::Php80);
        }
        return None;
    }

    versions.sort();
    versions.into_iter().next()
}

fn map_major_minor(major: u32, minor: u32) -> Option<PhpVersion> {
    match (major, minor) {
        (5, _) | (7, 0..=4) => Some(PhpVersion::Php74),
        (8, 0) => Some(PhpVersion::Php80),
        (8, 1) => Some(PhpVersion::Php81),
        (8, 2) => Some(PhpVersion::Php82),
        (8, 3) => Some(PhpVersion::Php83),
        (8, 4) => Some(PhpVersion::Php84),
        (8, m) if m >= 5 => Some(PhpVersion::Php85),
        _ => None,
    }
}

fn extract_dockerfile_php(raw: &str) -> Option<PhpVersion> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?im)^\s*FROM\s+(?:[\w./-]+/)?php:(\d+)\.(\d+)"#).expect("regex válido")
    });
    let cap = re.captures(raw)?;
    let maj: u32 = cap.get(1)?.as_str().parse().ok()?;
    let min: u32 = cap.get(2)?.as_str().parse().ok()?;
    map_major_minor(maj, min)
}

fn detect_implicit_php_extensions(
    summaries: &[FileSummary],
    dep_index: &mut HashMap<String, usize>,
    dependencies: &mut Vec<DependencyInfo>,
) {
    let mut uses_oci8 = false;
    let mut uses_mysql = false;
    let mut uses_mysqli = false;
    let mut uses_pdo = false;
    let mut uses_openssl = false;
    let mut uses_curl = false;
    let mut uses_mbstring = false;
    let mut uses_soap = false;

    for summary in summaries {
        for db in &summary.db_interactions {
            match db.driver.as_str() {
                "oci8" => uses_oci8 = true,
                "mysql" => uses_mysql = true,
                "mysqli" => uses_mysqli = true,
                "pdo" => uses_pdo = true,
                _ => {}
            }
        }
        for call in &summary.calls {
            let lower = call.name.to_ascii_lowercase();
            if lower.starts_with("oci_") {
                uses_oci8 = true;
            } else if lower.starts_with("openssl_") {
                uses_openssl = true;
            } else if lower.starts_with("curl_") {
                uses_curl = true;
            } else if lower.starts_with("mb_") {
                uses_mbstring = true;
            } else if lower.contains("soap") {
                uses_soap = true;
            }
        }
    }

    let candidates = [
        (
            uses_oci8,
            "ext-oci8",
            Some(false),
            "Usada vía funciones oci_* (Oracle); movida del core a PECL en PHP 8.4 (requiere Oracle Instant Client y compilación PECL en 8.5).",
        ),
        (
            uses_mysql,
            "ext-mysql",
            Some(false),
            "Extensión mysql_* eliminada desde PHP 7.0; debe migrarse a PDO o mysqli.",
        ),
        (
            uses_mysqli,
            "ext-mysqli",
            Some(true),
            "Usada en el código fuente (compatible con PHP 8.5).",
        ),
        (
            uses_pdo,
            "ext-pdo",
            Some(true),
            "Usada en el código fuente (compatible con PHP 8.5).",
        ),
        (
            uses_openssl,
            "ext-openssl",
            Some(true),
            "Usada vía funciones openssl_* (compatible con PHP 8.5).",
        ),
        (
            uses_curl,
            "ext-curl",
            Some(true),
            "Usada vía funciones curl_* (compatible con PHP 8.5).",
        ),
        (
            uses_mbstring,
            "ext-mbstring",
            Some(true),
            "Usada vía funciones mb_* (compatible con PHP 8.5).",
        ),
        (
            uses_soap,
            "ext-soap",
            Some(true),
            "Uso de cliente/funciones SOAP detectado.",
        ),
    ];

    for (active, ext_name, compat, notes) in candidates {
        if active && !dep_index.contains_key(ext_name) {
            let idx = dependencies.len();
            dep_index.insert(ext_name.to_string(), idx);
            dependencies.push(DependencyInfo {
                name: ext_name.to_string(),
                detected_version: None,
                path: None,
                source: DependencySource::PhpExtension,
                target_compatible: compat,
                notes: notes.to_string(),
            });
        }
    }
}

fn extract_htaccess_php(raw: &str) -> Option<PhpVersion> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:x-httpd-(?:ea-)?php|application/x-httpd-php)(\d)\.?(\d)"#)
            .expect("regex válido")
    });
    let cap = re.captures(raw)?;
    let maj: u32 = cap.get(1)?.as_str().parse().ok()?;
    let min: u32 = cap.get(2)?.as_str().parse().ok()?;
    map_major_minor(maj, min)
}
