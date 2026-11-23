use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

/// Versiones de PHP soportadas por el motor de migración.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PhpVersion {
    Php74,
    Php80,
    Php81,
    Php82,
    Php83,
    Php84,
    Php85,
}

impl PhpVersion {
    /// Todas las versiones soportadas en orden ascendente.
    pub fn all() -> &'static [PhpVersion] {
        &[
            PhpVersion::Php74,
            PhpVersion::Php80,
            PhpVersion::Php81,
            PhpVersion::Php82,
            PhpVersion::Php83,
            PhpVersion::Php84,
            PhpVersion::Php85,
        ]
    }

    /// Devuelve todos los saltos intermedios entre `from` (exclusivo) y `to` (inclusivo).
    pub fn all_hops_between(from: PhpVersion, to: PhpVersion) -> Vec<PhpVersion> {
        if from >= to {
            return Vec::new();
        }
        Self::all()
            .iter()
            .copied()
            .filter(|&v| v > from && v <= to)
            .collect()
    }

    /// Representación textual corta (ej. "7.4", "8.5").
    pub fn as_str(&self) -> &'static str {
        match self {
            PhpVersion::Php74 => "7.4",
            PhpVersion::Php80 => "8.0",
            PhpVersion::Php81 => "8.1",
            PhpVersion::Php82 => "8.2",
            PhpVersion::Php83 => "8.3",
            PhpVersion::Php84 => "8.4",
            PhpVersion::Php85 => "8.5",
        }
    }

    /// Etiqueta oficial de imagen Docker PHP con Apache.
    pub fn docker_apache_image(&self) -> &'static str {
        match self {
            PhpVersion::Php74 => "php:7.4-apache",
            PhpVersion::Php80 => "php:8.0-apache",
            PhpVersion::Php81 => "php:8.1-apache",
            PhpVersion::Php82 => "php:8.2-apache",
            PhpVersion::Php83 => "php:8.3-apache",
            PhpVersion::Php84 => "php:8.4-apache",
            PhpVersion::Php85 => "php:8.5-apache",
        }
    }

    /// Etiqueta oficial de imagen Docker PHP CLI.
    pub fn docker_cli_image(&self) -> &'static str {
        match self {
            PhpVersion::Php74 => "php:7.4-cli",
            PhpVersion::Php80 => "php:8.0-cli",
            PhpVersion::Php81 => "php:8.1-cli",
            PhpVersion::Php82 => "php:8.2-cli",
            PhpVersion::Php83 => "php:8.3-cli",
            PhpVersion::Php84 => "php:8.4-cli",
            PhpVersion::Php85 => "php:8.5-cli",
        }
    }
}

impl fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PhpVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s
            .trim()
            .to_ascii_lowercase()
            .trim_start_matches("php")
            .trim()
            .to_string();
        match normalized.as_str() {
            "7.4" | "74" | "7.4.0" => Ok(PhpVersion::Php74),
            "8.0" | "80" | "8.0.0" => Ok(PhpVersion::Php80),
            "8.1" | "81" | "8.1.0" => Ok(PhpVersion::Php81),
            "8.2" | "82" | "8.2.0" => Ok(PhpVersion::Php82),
            "8.3" | "83" | "8.3.0" => Ok(PhpVersion::Php83),
            "8.4" | "84" | "8.4.0" => Ok(PhpVersion::Php84),
            "8.5" | "85" | "8.5.0" => Ok(PhpVersion::Php85),
            _ => Err(format!(
                "Versión de PHP no soportada: '{s}'. Usa una de: 7.4, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5"
            )),
        }
    }
}

/// Rango exacto de bytes y coordenadas línea/columna (base 1) dentro de un archivo fuente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

impl Span {
    pub fn len(&self) -> usize {
        self.end_byte.saturating_sub(self.start_byte)
    }

    pub fn is_empty(&self) -> bool {
        self.start_byte >= self.end_byte
    }
}

/// Stack o framework principal detectado en el proyecto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameworkKind {
    VanillaPhp,
    Laravel { version: Option<String> },
    WordPress,
    CodeIgniter { version: Option<String> },
    Symfony { version: Option<String> },
}

impl fmt::Display for FrameworkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameworkKind::VanillaPhp => write!(f, "PHP Vanilla"),
            FrameworkKind::Laravel { version: Some(v) } => write!(f, "Laravel ({v})"),
            FrameworkKind::Laravel { version: None } => write!(f, "Laravel"),
            FrameworkKind::WordPress => write!(f, "WordPress"),
            FrameworkKind::CodeIgniter { version: Some(v) } => write!(f, "CodeIgniter ({v})"),
            FrameworkKind::CodeIgniter { version: None } => write!(f, "CodeIgniter"),
            FrameworkKind::Symfony { version: Some(v) } => write!(f, "Symfony ({v})"),
            FrameworkKind::Symfony { version: None } => write!(f, "Symfony"),
        }
    }
}

/// Origen desde donde se detectó una dependencia o extensión.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencySource {
    Composer,
    ComposerDev,
    BundledFolder,
    PhpExtension,
}

impl fmt::Display for DependencySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DependencySource::Composer => write!(f, "composer.json"),
            DependencySource::ComposerDev => write!(f, "composer.json (dev)"),
            DependencySource::BundledFolder => write!(f, "Carpeta local / embebida"),
            DependencySource::PhpExtension => write!(f, "Extensión PHP"),
        }
    }
}

/// Información de una librería, dependencia o extensión PHP detectada.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub detected_version: Option<String>,
    pub path: Option<String>,
    pub source: DependencySource,
    pub target_compatible: Option<bool>,
    pub notes: String,
}

/// Severidad de un hallazgo de seguridad (orden ascendente de menor a mayor impacto).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "BAJA"),
            Severity::Medium => write!(f, "MEDIA"),
            Severity::High => write!(f, "ALTA"),
            Severity::Critical => write!(f, "CRÍTICA"),
        }
    }
}

/// Categoría de riesgo de seguridad (enfocada en PHP2Shell / RCE y vulnerabilidades clásicas).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityCategory {
    RemoteCodeExecution,
    CommandInjection,
    UnsafeDeserialization,
    DynamicIncludeLfi,
    SqlInjectionRisk,
    ArbitraryFileUpload,
    BackdoorPattern,
}

impl fmt::Display for SecurityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityCategory::RemoteCodeExecution => write!(f, "Ejecución Remota de Código (RCE)"),
            SecurityCategory::CommandInjection => write!(f, "Inyección de Comandos"),
            SecurityCategory::UnsafeDeserialization => write!(f, "Deserialización Insegura"),
            SecurityCategory::DynamicIncludeLfi => write!(f, "Include Dinámico (LFI/RFI)"),
            SecurityCategory::SqlInjectionRisk => write!(f, "Riesgo de Inyección SQL"),
            SecurityCategory::ArbitraryFileUpload => write!(f, "Subida de Archivos Sin Validación"),
            SecurityCategory::BackdoorPattern => write!(f, "Patrón Sospechoso de Webshell"),
        }
    }
}

/// Alerta de seguridad detectada durante el análisis estático.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub severity: Severity,
    pub category: SecurityCategory,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub description: String,
    pub remediation: String,
}

/// Clasificación de resolución para cada incompatibilidad de migración.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DecisionBucket {
    GreenAutoFix,
    YellowNeedsDecision,
    RedBlocker,
}

impl fmt::Display for DecisionBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecisionBucket::GreenAutoFix => write!(f, "VERDE (Auto-fix seguro)"),
            DecisionBucket::YellowNeedsDecision => write!(f, "AMARILLO (Decisión / IA)"),
            DecisionBucket::RedBlocker => write!(f, "ROJO (Bloqueante)"),
        }
    }
}

/// Categoría técnica de regla de migración.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleCategory {
    RemovedFunction,
    DeprecatedSyntax,
    TypeSafety,
    ImplicitNullable,
    DynamicProperty,
    LooseComparisonRisk,
    SignatureMismatch,
    ExtensionRemoved,
    FrameworkUpgrade,
    SecurityFix,
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleCategory::RemovedFunction => write!(f, "Función eliminada"),
            RuleCategory::DeprecatedSyntax => write!(f, "Sintaxis deprecada"),
            RuleCategory::TypeSafety => write!(f, "Seguridad de tipos / null"),
            RuleCategory::ImplicitNullable => write!(f, "Parámetro implícitamente anulable"),
            RuleCategory::DynamicProperty => write!(f, "Propiedad dinámica"),
            RuleCategory::LooseComparisonRisk => write!(f, "Comparación débil riesgosa"),
            RuleCategory::SignatureMismatch => write!(f, "Firma / retorno incompatible"),
            RuleCategory::ExtensionRemoved => write!(f, "Extensión eliminada o movida a PECL"),
            RuleCategory::FrameworkUpgrade => write!(f, "Actualización de Framework"),
            RuleCategory::SecurityFix => write!(f, "Corrección de Seguridad"),
        }
    }
}

/// Estado de resolución de un hallazgo durante el asistente de migración.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionStatus {
    Pending,
    AppliedDeterministic,
    AppliedAi,
    MarkedTodo,
    Skipped,
}

impl fmt::Display for ResolutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolutionStatus::Pending => write!(f, "Pendiente"),
            ResolutionStatus::AppliedDeterministic => write!(f, "Aplicado (Determinista)"),
            ResolutionStatus::AppliedAi => write!(f, "Aplicado (Asistido por IA)"),
            ResolutionStatus::MarkedTodo => write!(f, "Marcado TODO"),
            ResolutionStatus::Skipped => write!(f, "Omitido"),
        }
    }
}

/// Hallazgo individual de migración con su rango exacto de bytes para parcheo quirúrgico.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationFinding {
    pub id: String,
    pub rule_id: String,
    pub target_step: PhpVersion,
    pub bucket: DecisionBucket,
    pub category: RuleCategory,
    pub file: PathBuf,
    pub span: Span,
    pub original_code: String,
    pub suggested_replacement: Option<String>,
    pub explanation: String,
    pub logic_impact: String,
    pub status: ResolutionStatus,
}

/// Nivel de riesgo consolidado de un módulo lógico.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "BAJO"),
            RiskLevel::Medium => write!(f, "MEDIO"),
            RiskLevel::High => write!(f, "ALTO"),
            RiskLevel::Critical => write!(f, "CRÍTICO"),
        }
    }
}

/// Porción o módulo lógico migrable del proyecto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSlice {
    pub id: String,
    pub name: String,
    pub root_path: PathBuf,
    pub files: Vec<PathBuf>,
    pub entrypoints: Vec<PathBuf>,
    pub depends_on_modules: Vec<String>,
    pub db_ops_count: usize,
    pub dynamic_includes_count: usize,
    pub risk_level: RiskLevel,
    pub risk_score: u32,
    pub green_count: usize,
    pub yellow_count: usize,
    pub red_count: usize,
}

/// Resultado consolidado del análisis de todo el proyecto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectAnalysis {
    pub root_path: PathBuf,
    pub detected_php_version: PhpVersion,
    pub version_evidence: Vec<String>,
    pub target_php_version: PhpVersion,
    pub framework: FrameworkKind,
    pub dependencies: Vec<DependencyInfo>,
    pub total_files: usize,
    pub php_files_count: usize,
    pub mixed_html_files_count: usize,
    pub total_lines: usize,
    pub include_dirs: Vec<PathBuf>,
    pub vendor_dirs: Vec<PathBuf>,
    pub security_findings: Vec<SecurityFinding>,
    pub migration_findings: Vec<MigrationFinding>,
    pub modules: Vec<ModuleSlice>,
}

// ============================================================================
// Contratos compartidos del Parser Mixto, Grafo de Lógica, IA y Sandbox
// ============================================================================

/// Tipo de apertura de bloque PHP dentro de un archivo fuente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhpBlockKind {
    Standard,
    ShortEcho,
    ShortOpen,
}

/// Segmento físico del archivo (HTML/CSS/JS puro o código PHP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeBlock {
    pub is_php: bool,
    pub kind: Option<PhpBlockKind>,
    pub span: Span,
}

/// Tipo de sentencia de inclusión de archivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncludeKind {
    Include,
    IncludeOnce,
    Require,
    RequireOnce,
}

impl fmt::Display for IncludeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncludeKind::Include => write!(f, "include"),
            IncludeKind::IncludeOnce => write!(f, "include_once"),
            IncludeKind::Require => write!(f, "require"),
            IncludeKind::RequireOnce => write!(f, "require_once"),
        }
    }
}

/// Sentencia `include` / `require` detectada.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncludeStatement {
    pub kind: IncludeKind,
    pub target_expr: String,
    pub resolved_path: Option<PathBuf>,
    pub is_dynamic: bool,
    pub span: Span,
}

/// Parámetro extraído de una función o método.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamSummary {
    pub name: String,
    pub type_hint: Option<String>,
    pub is_nullable: bool,
    pub has_default: bool,
    pub default_is_null: bool,
    pub span: Span,
    pub type_span: Option<Span>,
}

/// Resumen estructural de una función o método.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub visibility: Option<String>,
    pub is_static: bool,
    pub params: Vec<ParamSummary>,
    pub return_type: Option<String>,
    pub has_return_type_will_change: bool,
    pub signature_span: Span,
    pub span: Span,
    pub body_span: Option<Span>,
}

/// Escritura sobre una propiedad dinámica `$this->prop = ...`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicPropertyWrite {
    pub property_name: String,
    pub span: Span,
}

/// Resumen estructural de una clase PHP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassSummary {
    pub name: String,
    pub extends: Option<String>,
    pub implements: Vec<String>,
    pub declared_properties: Vec<String>,
    pub dynamic_properties: Vec<DynamicPropertyWrite>,
    pub methods: Vec<FunctionSummary>,
    pub has_allow_dynamic_properties: bool,
    pub header_span: Span,
    pub span: Span,
}

/// Argumento individual dentro de una llamada a función o método.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallArg {
    pub text: String,
    pub span: Span,
}

/// Sitio de llamada a función o método.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCallSite {
    pub name: String,
    pub is_method_call: bool,
    pub is_static_call: bool,
    pub args: Vec<CallArg>,
    pub span: Span,
}

/// Interacción detectada con base de datos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbInteraction {
    pub driver: String,
    pub kind: String,
    pub line: usize,
    pub snippet: String,
}

/// Resumen estructural completo de un archivo PHP o PHP+HTML mixto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: PathBuf,
    pub is_mixed_html: bool,
    pub total_lines: usize,
    pub blocks: Vec<CodeBlock>,
    pub namespace: Option<String>,
    pub use_imports: Vec<String>,
    pub includes: Vec<IncludeStatement>,
    pub functions: Vec<FunctionSummary>,
    pub classes: Vec<ClassSummary>,
    pub calls: Vec<FunctionCallSite>,
    pub superglobals: Vec<(String, usize)>,
    pub globals_declared: Vec<String>,
    pub db_interactions: Vec<DbInteraction>,
    pub syntax_version_markers: Vec<(PhpVersion, String)>,
}

/// Respuesta estructurada de la capa de asistencia IA (BYOK).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiResolution {
    pub replacement_code: String,
    pub explanation: String,
    pub logic_safety_notes: String,
}

/// Motor de base de datos soportado por el sandbox Docker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbEngine {
    MySql,
    MariaDb,
    Postgres,
}

impl fmt::Display for DbEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbEngine::MySql => write!(f, "MySQL 8.0"),
            DbEngine::MariaDb => write!(f, "MariaDB 10.11"),
            DbEngine::Postgres => write!(f, "PostgreSQL 16"),
        }
    }
}

/// Estrategia de aislamiento de base de datos para pruebas comparativas origen vs. destino.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbIsolationMode {
    SqlDumpClone {
        dump_path: PathBuf,
        engine: DbEngine,
    },
    ExistingReadOnly {
        host: String,
        port: u16,
        database: String,
        user: String,
    },
    NoDatabase,
}
