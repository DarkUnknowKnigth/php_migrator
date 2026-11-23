//! Módulo de verificación dual en contenedores Docker con aislamiento de base de datos.

pub mod docker;
pub mod verifier;

pub use docker::{
    check_docker_available, generate_docker_compose, write_sandbox_files, SandboxConfig,
};
pub use verifier::{
    normalize_http_body, run_dual_verification, RouteComparison, SandboxReport,
};
