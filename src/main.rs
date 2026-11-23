// SPDX-License-Identifier: GPL-3.0-or-later
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    php_migrator::cli::run().await
}
