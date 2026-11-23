// SPDX-License-Identifier: GPL-3.0-or-later
//! `php-migrator` — Motor determinista y modular para analizar, mapear y migrar proyectos PHP hacia PHP 8.5.

pub mod ai;
pub mod cli;
pub mod frameworks;
pub mod graph;
pub mod models;
pub mod parser;
pub mod patcher;
pub mod reporter;
pub mod rules;
pub mod sandbox;
pub mod scanner;
