use super::FrameworkAdapter;
use crate::models::{
    DependencyInfo, DecisionBucket, FileSummary, MigrationFinding, PhpVersion, ResolutionStatus,
    RuleCategory, Span,
};
use crate::parser::lexer::{span_from_bytes, PhpToken, PhpTokenKind};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Paso documentado de actualización entre versiones mayores de Laravel.
#[derive(Debug, Clone)]
pub struct LaravelPlaybookStep {
    pub from_version: &'static str,
    pub to_version: &'static str,
    pub min_php: PhpVersion,
    pub title: &'static str,
    pub impact: &'static str,
    pub doc_url: &'static str,
    pub checklist: Vec<&'static str>,
    pub code_patterns: Vec<(&'static str, &'static str)>,
}

/// Catálogo oficial resumido de saltos Laravel 6 -> 12 con guías y patrones clave.
pub fn laravel_playbooks() -> Vec<LaravelPlaybookStep> {
    vec![
        LaravelPlaybookStep {
            from_version: "6.x",
            to_version: "7.x",
            min_php: PhpVersion::Php74,
            title: "Laravel 6 -> 7: Throwable en Handler, Symfony 5 y fechas ISO-8601",
            impact: "Cambia la firma de excepciones (`Exception` -> `Throwable`) y el formato por defecto de `toArray()/toJson()` para fechas Eloquent.",
            doc_url: "https://laravel.com/docs/7.x/upgrade",
            checklist: vec![
                "Actualizar `app/Exceptions/Handler.php`: métodos `report(Throwable $e)` y `render($request, Throwable $e)`.",
                "Revisar serialización de fechas Eloquent (`serializeDate`) si clientes esperan formato `Y-m-d H:i:s` en lugar de ISO-8601.",
                "Actualizar `laravel/framework` a `^7.0`, `phpunit/phpunit` a `^8.5` y reemplazar paquetes incompatibles con Symfony 5.",
                "Migrar `factory()` o helpers `Str::` / `Arr::` si seguían usando `laravel/helpers`.",
            ],
            code_patterns: vec![
                ("public function report(Exception $exception)", "public function report(\\Throwable $exception)"),
                ("public function render($request, Exception $exception)", "public function render($request, \\Throwable $exception)"),
            ],
        },
        LaravelPlaybookStep {
            from_version: "7.x",
            to_version: "8.x",
            min_php: PhpVersion::Php74,
            title: "Laravel 7 -> 8: Factories basadas en clases, RouteServiceProvider y Paginator",
            impact: "Las factories de modelos pasan a clases con trait `HasFactory`; `RouteServiceProvider` deja de anteponer `$namespace` automáticamente.",
            doc_url: "https://laravel.com/docs/8.x/upgrade",
            checklist: vec![
                "Reescribir factories antiguas `factory(User::class)` a clases `Database\\Factories\\UserFactory` usando `User::factory()`.",
                "En `RouteServiceProvider`, declarar `protected $namespace` si aún usas rutas con strings `'UserController@index'` o migrar a `[UserController::class, 'index']`.",
                "Si usas Bootstrap en paginación, invocar `Paginator::useBootstrap()` en `AppServiceProvider::boot()` (Tailwind pasó a ser default).",
                "Renombrar propiedad `$retryAfter` a `backoff()` en Jobs/Mailables y revisar columna `uuid` en `failed_jobs`.",
            ],
            code_patterns: vec![
                ("factory(App\\Models\\User::class)->create()", "User::factory()->create()"),
                ("Route::get('/users', 'UserController@index')", "Route::get('/users', [UserController::class, 'index'])"),
            ],
        },
        LaravelPlaybookStep {
            from_version: "8.x",
            to_version: "9.x",
            min_php: PhpVersion::Php80,
            title: "Laravel 8 -> 9: PHP 8.0+, Symfony Mailer, Flysystem 3 y CORS integrado",
            impact: "Elimina SwiftMailer en favor de Symfony Mailer, actualiza Flysystem 1 -> 3 e integra CORS/TrustProxies en el núcleo.",
            doc_url: "https://laravel.com/docs/9.x/upgrade",
            checklist: vec![
                "Requerir PHP >= 8.0.2 y `laravel/framework` `^9.0`.",
                "Eliminar `swiftmailer/swiftmailer`; migrar configuraciones SMTP/callbacks a `symfony/mailer`.",
                "Eliminar `fideloper/proxy` y usar `Illuminate\\Http\\Middleware\\TrustProxies`; migrar `fruitcake/laravel-cors` a `HandleCors`.",
                "Reemplazar `facade/ignition` por `spatie/laravel-ignition` y revisar llamadas a `Storage::get()` (Flysystem 3).",
                "Considerar migración de `$dates` en modelos Eloquent hacia `$casts`.",
            ],
            code_patterns: vec![
                ("use Fideloper\\Proxy\\TrustProxies as Middleware;", "use Illuminate\\Http\\Middleware\\TrustProxies as Middleware;"),
                ("Storage::disk('s3')->get($path); // retorna null o lanza según config", "Storage::disk('s3')->get($path); // verificar throw => false en filesystems.php"),
            ],
        },
        LaravelPlaybookStep {
            from_version: "9.x",
            to_version: "10.x",
            min_php: PhpVersion::Php81,
            title: "Laravel 9 -> 10: PHP 8.1+, eliminación de $dates y dispatchNow",
            impact: "Se elimina `Model::$dates`, `Bus::dispatchNow()`, `Redirect::home()` y se adoptan tipos nativos en el skeleton.",
            doc_url: "https://laravel.com/docs/10.x/upgrade",
            checklist: vec![
                "Requerir PHP >= 8.1 y actualizar `laravel/framework` a `^10.0`.",
                "Reemplazar `protected $dates = [...]` en todos los modelos Eloquent por `protected $casts = ['campo' => 'datetime']`.",
                "Reemplazar `Bus::dispatchNow()` y `dispatch_now()` por `Bus::dispatchSync()` y `dispatch_sync()`.",
                "Eliminar llamadas a `Redirect::home()` y actualizar expresiones `DB::raw()` si se usan con Doctrine DBAL 3.",
            ],
            code_patterns: vec![
                ("protected $dates = ['published_at'];", "protected $casts = ['published_at' => 'datetime'];"),
                ("Bus::dispatchNow($job);", "Bus::dispatchSync($job);"),
            ],
        },
        LaravelPlaybookStep {
            from_version: "10.x",
            to_version: "11.x",
            min_php: PhpVersion::Php82,
            title: "Laravel 10 -> 11: PHP 8.2+, bootstrap/app.php y Carbon 3",
            impact: "Introduce estructura simplificada sin `app/Http/Kernel.php` para proyectos nuevos, retira Doctrine DBAL en migraciones y soporta Carbon 3.",
            doc_url: "https://laravel.com/docs/11.x/upgrade",
            checklist: vec![
                "Requerir PHP >= 8.2 y actualizar `laravel/framework` a `^11.0`.",
                "Decidir si mantener `app/Http/Kernel.php` y `app/Console/Kernel.php` existentes o migrar configuración a `bootstrap/app.php` (`Application::configure()`).",
                "Revisar uso de `Doctrine\\DBAL` en migraciones (`Schema::getTables()` reemplaza introspección anterior).",
                "Verificar compatibilidad de tipos con Carbon 3 (`diffInDays` retorna float en Carbon 3 y respeta signo).",
            ],
            code_patterns: vec![
                ("app/Http/Kernel.php ($middlewareGroups)", "bootstrap/app.php ->withMiddleware(function (Middleware $middleware) { ... })"),
                ("protected $casts = ['is_admin' => 'boolean'];", "protected function casts(): array { return ['is_admin' => 'boolean']; }"),
            ],
        },
        LaravelPlaybookStep {
            from_version: "11.x",
            to_version: "12.x",
            min_php: PhpVersion::Php82,
            title: "Laravel 11 -> 12: PHP 8.2-8.5, Carbon 3 obligatorio y UUIDv7",
            impact: "Carbon 3 pasa a ser obligatorio, `HasUuids` genera UUIDv7 por defecto y se endurecen reglas de validación de imágenes/arrays.",
            doc_url: "https://laravel.com/docs/12.x/upgrade",
            checklist: vec![
                "Actualizar `laravel/framework` a `^12.0` (compatible con PHP 8.2, 8.3, 8.4 y 8.5).",
                "Confirmar migración completa a `nesbot/carbon` `^3.0` (Carbon 2 ya no está soportado).",
                "Si modelos con `HasUuids` deben conservar UUIDv4, cambiar al trait `HasVersion4Uuids`.",
                "Revisar reglas de validación `image` (ya no permite SVG por defecto salvo `image:allow_svg`) y dependencias `phpunit`/`pest`.",
            ],
            code_patterns: vec![
                ("use Illuminate\\Database\\Eloquent\\Concerns\\HasUuids;", "use Illuminate\\Database\\Eloquent\\Concerns\\HasVersion4Uuids; // si requieres UUIDv4"),
                ("'avatar' => 'image'", "'avatar' => 'image:allow_svg' // solo si aceptas SVG"),
            ],
        },
    ]
}

/// Adaptador de reglas de actualización específicas para Laravel.
pub struct LaravelAdapter;

impl FrameworkAdapter for LaravelAdapter {
    fn name(&self) -> &'static str {
        "Laravel"
    }

    fn check_upgrade(
        &self,
        root: &Path,
        current_php: PhpVersion,
        target_php: PhpVersion,
        deps: &[DependencyInfo],
        summaries: &[FileSummary],
    ) -> Vec<MigrationFinding> {
        let mut findings = Vec::new();

        // 1. Validar versión de Laravel y paquetes del ecosistema en composer.json
        check_composer_laravel_packages(root, current_php, target_php, deps, &mut findings);

        // 2. Inspeccionar resúmenes AST del proyecto
        for summary in summaries {
            let disk_path = resolve_disk_path(root, &summary.path);
            let Ok(source) = read_utf8_lossy(&disk_path) else {
                continue;
            };

            check_eloquent_dates_property(summary, &source, target_php, &mut findings);
            check_exception_handler_throwable(summary, &source, target_php, &mut findings);
            check_laravel11_kernel_structure(summary, &source, target_php, &mut findings);
            check_laravel_legacy_calls(summary, &source, target_php, &mut findings);
        }

        findings
    }
}

fn check_composer_laravel_packages(
    root: &Path,
    current_php: PhpVersion,
    target_php: PhpVersion,
    deps: &[DependencyInfo],
    findings: &mut Vec<MigrationFinding>,
) {
    let composer_path = root.join("composer.json");
    let Ok(raw) = fs::read_to_string(&composer_path) else {
        return;
    };
    let rel_composer = PathBuf::from("composer.json");

    let laravel_dep = deps
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case("laravel/framework"));
    let detected_major = laravel_dep
        .and_then(|d| d.detected_version.as_deref())
        .and_then(parse_laravel_major);

    let min_laravel_major = match target_php {
        PhpVersion::Php74 => 7,
        PhpVersion::Php80 => 8,
        PhpVersion::Php81 => 9,
        PhpVersion::Php82 | PhpVersion::Php83 => 10,
        PhpVersion::Php84 | PhpVersion::Php85 => 11,
    };

    if let Some(cur_major) = detected_major {
        if cur_major < min_laravel_major {
            let span = find_json_key_line_span(&raw, "laravel/framework")
                .unwrap_or_else(|| span_from_bytes(&raw, 0, raw.len().min(1)));

            let playbooks = laravel_playbooks();
            let applicable_steps: Vec<String> = playbooks
                .iter()
                .filter(|step| {
                    let from_maj = step
                        .from_version
                        .trim_end_matches(".x")
                        .parse::<u32>()
                        .unwrap_or(0);
                    let to_maj = step
                        .to_version
                        .trim_end_matches(".x")
                        .parse::<u32>()
                        .unwrap_or(0);
                    from_maj >= cur_major && to_maj <= min_laravel_major
                })
                .map(|s| format!("{} ({})", s.title, s.doc_url))
                .collect();

            let bucket = if min_laravel_major.saturating_sub(cur_major) >= 2
                || (cur_major <= 8 && target_php >= PhpVersion::Php82)
            {
                DecisionBucket::RedBlocker
            } else {
                DecisionBucket::YellowNeedsDecision
            };

            if let Some(f) = make_finding(
                &rel_composer,
                &raw,
                "LARAVEL-FRAMEWORK-VERSION",
                target_php,
                bucket,
                RuleCategory::FrameworkUpgrade,
                span,
                None,
                format!(
                    "Laravel {cur_major}.x (sobre PHP {current_php}) requiere actualizarse al menos a Laravel {min_laravel_major}.x para ejecutarse en PHP {target_php}. Pasos sugeridos: {}",
                    if applicable_steps.is_empty() {
                        "https://laravel.com/docs/upgrade".to_string()
                    } else {
                        applicable_steps.join(" | ")
                    }
                ),
                "La actualización entre versiones mayores de Laravel exige revisar composer.json, middlewares, modelos Eloquent y dependencias de terceros en orden secuencial.".to_string(),
            ) {
                findings.push(f);
            }
        }
    }

    // Paquetes del ecosistema Laravel reemplazados o eliminados en 9.x+
    let ecosystem_checks: &[(&str, &str, &str)] = &[
        (
            "swiftmailer/swiftmailer",
            "LARAVEL-ECOSYSTEM-SWIFTMAILER",
            "SwiftMailer fue eliminado en Laravel 9 y es incompatible con PHP 8.2+. Migra a `symfony/mailer` (https://laravel.com/docs/9.x/upgrade).",
        ),
        (
            "fideloper/proxy",
            "LARAVEL-ECOSYSTEM-TRUSTPROXIES",
            "`fideloper/proxy` fue reemplazado por `Illuminate\\Http\\Middleware\\TrustProxies` en Laravel 9.",
        ),
        (
            "fruitcake/laravel-cors",
            "LARAVEL-ECOSYSTEM-CORS",
            "`fruitcake/laravel-cors` fue integrado en el núcleo de Laravel 9.2+ como `Illuminate\\Http\\Middleware\\HandleCors`.",
        ),
        (
            "facade/ignition",
            "LARAVEL-ECOSYSTEM-IGNITION",
            "`facade/ignition` fue reemplazado por `spatie/laravel-ignition` a partir de Laravel 9.",
        ),
    ];

    if target_php >= PhpVersion::Php81 || detected_major.is_some_and(|m| m < 9) {
        for &(pkg, rule_id, desc) in ecosystem_checks {
            if deps.iter().any(|d| d.name.eq_ignore_ascii_case(pkg)) {
                if let Some(span) = find_json_key_line_span(&raw, pkg) {
                    if let Some(f) = make_finding(
                        &rel_composer,
                        &raw,
                        rule_id,
                        target_php,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::FrameworkUpgrade,
                        span,
                        None,
                        desc.to_string(),
                        "Paquete incompatible con versiones recientes de Laravel / PHP; requiere reemplazo en composer.json y namespaces.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            }
        }
    }
}

fn check_eloquent_dates_property(
    summary: &FileSummary,
    source: &str,
    target_php: PhpVersion,
    findings: &mut Vec<MigrationFinding>,
) {
    for class in &summary.classes {
        let extends_eloquent = class.extends.as_deref().is_some_and(|e| {
            let base = e.trim_start_matches('\\').rsplit('\\').next().unwrap_or(e);
            matches!(
                base,
                "Model" | "Authenticatable" | "Pivot" | "MorphPivot" | "User"
            )
        });
        let has_dates_prop = class
            .declared_properties
            .iter()
            .any(|p| p.trim_start_matches('$') == "dates");

        if !extends_eloquent && !has_dates_prop {
            continue;
        }

        // Buscar `protected $dates` / `public $dates` / `var $dates` dentro del bloque de la clase
        for block in summary.blocks.iter().filter(|b| b.is_php) {
            if block.span.end_byte < class.span.start_byte
                || block.span.start_byte > class.span.end_byte
            {
                continue;
            }
            let tokens = crate::parser::tokenize_php_block(source, block);
            let sig: Vec<PhpToken> = tokens
                .into_iter()
                .filter(|t| !matches!(t.kind, PhpTokenKind::Comment | PhpTokenKind::Whitespace))
                .collect();

            for idx in 1..sig.len() {
                if sig[idx].kind == PhpTokenKind::Variable
                    && sig[idx].text == "$dates"
                    && sig[idx].span.start_byte >= class.span.start_byte
                    && sig[idx].span.end_byte <= class.span.end_byte
                    && matches!(
                        sig[idx - 1].text.to_ascii_lowercase().as_str(),
                        "protected" | "public" | "private" | "var"
                    )
                {
                    let span = span_from_bytes(
                        source,
                        sig[idx - 1].span.start_byte,
                        sig[idx].span.end_byte,
                    );
                    if let Some(f) = make_finding(
                        &summary.path,
                        source,
                        "LARAVEL-ELOQUENT-DATES",
                        target_php,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::FrameworkUpgrade,
                        span,
                        None,
                        format!(
                            "La propiedad `$dates` en el modelo `{}` fue deprecada en Laravel 9 y eliminada en Laravel 10 (https://laravel.com/docs/10.x/upgrade).",
                            class.name
                        ),
                        "Migra los atributos de `$dates` a `$casts = ['campo' => 'datetime']` (o método `casts()` en Laravel 11+).".to_string(),
                    ) {
                        findings.push(f);
                    }
                    return;
                }
            }
        }
    }
}

fn check_exception_handler_throwable(
    summary: &FileSummary,
    source: &str,
    target_php: PhpVersion,
    findings: &mut Vec<MigrationFinding>,
) {
    let path_norm = summary.path.to_string_lossy().replace('\\', "/");
    let is_handler_file = path_norm.ends_with("Exceptions/Handler.php");

    for class in &summary.classes {
        let is_handler_class = is_handler_file
            || class
                .extends
                .as_deref()
                .is_some_and(|e| e.ends_with("ExceptionHandler"));
        if !is_handler_class {
            continue;
        }

        for method in &class.methods {
            if !matches!(method.name.as_str(), "report" | "render" | "shouldReport") {
                continue;
            }
            for param in &method.params {
                if let Some(th) = &param.type_hint {
                    let clean = th.trim_start_matches('\\');
                    if clean == "Exception" {
                        let span = param.type_span.unwrap_or(method.signature_span);
                        let repl = param.type_span.map(|_| "\\Throwable".to_string());
                        if let Some(f) = make_finding(
                            &summary.path,
                            source,
                            "LARAVEL-HANDLER-THROWABLE",
                            target_php,
                            DecisionBucket::YellowNeedsDecision,
                            RuleCategory::FrameworkUpgrade,
                            span,
                            repl,
                            format!(
                                "En `{}::{}()`, el parámetro `{}` usa `Exception` en lugar de `\\Throwable` (cambio obligatorio desde Laravel 7: https://laravel.com/docs/7.x/upgrade).",
                                class.name, method.name, param.name
                            ),
                            "En PHP 7+/8+ los `Error` fatales implementan `Throwable` pero no heredan de `Exception`; actualizar la firma evita TypeError en el Handler.".to_string(),
                        ) {
                            findings.push(f);
                        }
                    }
                }
            }
        }
    }
}

fn check_laravel11_kernel_structure(
    summary: &FileSummary,
    source: &str,
    target_php: PhpVersion,
    findings: &mut Vec<MigrationFinding>,
) {
    if target_php < PhpVersion::Php82 {
        return;
    }

    let path_norm = summary.path.to_string_lossy().replace('\\', "/");
    if !path_norm.ends_with("app/Http/Kernel.php") && !path_norm.ends_with("app/Console/Kernel.php")
    {
        return;
    }

    if let Some(class) = summary.classes.first() {
        if let Some(f) = make_finding(
            &summary.path,
            source,
            "LARAVEL-11-KERNEL-STRUCTURE",
            target_php,
            DecisionBucket::YellowNeedsDecision,
            RuleCategory::FrameworkUpgrade,
            class.header_span,
            None,
            format!(
                "Archivo `{}` detectado: a partir de Laravel 11+ (PHP 8.2+), la estructura estándar mueve middlewares y scheduling a `bootstrap/app.php` (https://laravel.com/docs/11.x/upgrade).",
                path_norm
            ),
            "En proyectos actualizados desde Laravel 10 o anterior puedes conservar los Kernel mientras `bootstrap/app.php` los registre, o migrar progresivamente a `Application::configure()`.".to_string(),
        ) {
            findings.push(f);
        }
    }
}

fn check_laravel_legacy_calls(
    summary: &FileSummary,
    source: &str,
    target_php: PhpVersion,
    findings: &mut Vec<MigrationFinding>,
) {
    for block in summary.blocks.iter().filter(|b| b.is_php) {
        let tokens = crate::parser::tokenize_php_block(source, block);
        let sig: Vec<PhpToken> = tokens
            .into_iter()
            .filter(|t| !matches!(t.kind, PhpTokenKind::Comment | PhpTokenKind::Whitespace))
            .collect();

        for i in 0..sig.len() {
            if sig[i].kind != PhpTokenKind::Word {
                continue;
            }
            if i + 1 >= sig.len() || sig[i + 1].text != "(" {
                continue;
            }

            let lower = sig[i].text.to_ascii_lowercase();
            let prev_text = if i > 0 { sig[i - 1].text.as_str() } else { "" };

            // factory(Model::class) eliminado en Laravel 8+
            if lower == "factory" && !matches!(prev_text, "->" | "?->" | "::" | "function") {
                if let Some(f) = make_finding(
                    &summary.path,
                    source,
                    "LARAVEL-LEGACY-FACTORY",
                    target_php,
                    DecisionBucket::YellowNeedsDecision,
                    RuleCategory::FrameworkUpgrade,
                    sig[i].span,
                    None,
                    "Helper global `factory()` eliminado en Laravel 8+ (requiere `laravel/legacy-factories` o migración a `Model::factory()`).".to_string(),
                    "Reemplaza por class-based factories con el trait `HasFactory` (`https://laravel.com/docs/8.x/upgrade`).".to_string(),
                ) {
                    findings.push(f);
                }
            }

            // dispatchNow / dispatch_now eliminado en Laravel 10
            if (lower == "dispatchnow" && prev_text == "::")
                || (lower == "dispatch_now" && !matches!(prev_text, "->" | "::" | "function"))
            {
                let repl = if lower == "dispatchnow" {
                    "dispatchSync".to_string()
                } else {
                    "dispatch_sync".to_string()
                };
                if let Some(f) = make_finding(
                    &summary.path,
                    source,
                    "LARAVEL-DISPATCH-NOW",
                    target_php,
                    DecisionBucket::YellowNeedsDecision,
                    RuleCategory::FrameworkUpgrade,
                    sig[i].span,
                    Some(repl.clone()),
                    format!("`{}()` fue eliminado en Laravel 10.", sig[i].text),
                    format!("Reemplaza por `{repl}()` (`https://laravel.com/docs/10.x/upgrade`)."),
                ) {
                    findings.push(f);
                }
            }

            // Redirect::home() eliminado en Laravel 10
            if lower == "home"
                && i >= 2
                && prev_text == "::"
                && sig[i - 2].text.eq_ignore_ascii_case("Redirect")
                && sig.get(i + 2).is_some_and(|t| t.text == ")")
            {
                let span = span_from_bytes(source, sig[i - 2].span.start_byte, sig[i + 2].span.end_byte);
                if let Some(f) = make_finding(
                    &summary.path,
                    source,
                    "LARAVEL-REDIRECT-HOME",
                    target_php,
                    DecisionBucket::YellowNeedsDecision,
                    RuleCategory::FrameworkUpgrade,
                    span,
                    None,
                    "`Redirect::home()` fue eliminado en Laravel 10.".to_string(),
                    "Usa `Redirect::route('home')` o `to_route('home')` explícitamente.".to_string(),
                ) {
                    findings.push(f);
                }
            }
        }
    }
}

fn parse_laravel_major(version_str: &str) -> Option<u32> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(\d+)\."#).expect("regex válido"));
    if let Some(cap) = re.captures(version_str) {
        return cap.get(1)?.as_str().parse().ok();
    }
    static MAJ_RE: OnceLock<Regex> = OnceLock::new();
    let maj_re = MAJ_RE.get_or_init(|| Regex::new(r#"(\d+)"#).expect("regex válido"));
    maj_re
        .captures(version_str)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

fn find_json_key_line_span(raw: &str, key: &str) -> Option<Span> {
    let needle = format!("\"{key}\"");
    let pos = raw.find(&needle)?;
    let line_start = raw[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_end = raw[pos..]
        .find('\n')
        .map(|p| pos + p)
        .unwrap_or(raw.len())
        .min(raw.len());
    let trimmed_end = raw[line_start..line_end].trim_end_matches('\r').len() + line_start;
    if trimmed_end > line_start {
        Some(span_from_bytes(raw, line_start, trimmed_end))
    } else {
        None
    }
}

fn resolve_disk_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn read_utf8_lossy(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    file_path: &Path,
    source: &str,
    rule_id: &str,
    target_step: PhpVersion,
    bucket: DecisionBucket,
    category: RuleCategory,
    span: Span,
    suggested_replacement: Option<String>,
    explanation: String,
    logic_impact: String,
) -> Option<MigrationFinding> {
    if span.is_empty()
        || span.end_byte > source.len()
        || !source.is_char_boundary(span.start_byte)
        || !source.is_char_boundary(span.end_byte)
    {
        return None;
    }

    let original_code = source[span.start_byte..span.end_byte].to_string();
    let hash_input = format!(
        "{}:{}:{}:{}",
        file_path.to_string_lossy(),
        rule_id,
        span.start_byte,
        span.end_byte
    );
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in hash_input.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    Some(MigrationFinding {
        id: format!("{rule_id}-{hash:08x}"),
        rule_id: rule_id.to_string(),
        target_step,
        bucket,
        category,
        file: file_path.to_path_buf(),
        span,
        original_code,
        suggested_replacement,
        explanation,
        logic_impact,
        status: ResolutionStatus::Pending,
    })
}
