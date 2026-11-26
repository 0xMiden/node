use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url, header};
use serde_json::Value;

#[derive(clap::Args)]
pub struct ValidatorConfigOptions {
    /// Base URL of the validator's private admin API.
    #[arg(long, global = true, env = "VALIDATOR_ADMIN_URL", value_name = "URL")]
    admin_url: Option<Url>,

    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(clap::Subcommand)]
enum ConfigCommand {
    /// Print the active and pending validator quorums as JSON.
    Status,
    /// Register a pending validator quorum change.
    Register(ChangeFile),
    /// Cancel the change registered with this file.
    Cancel(ChangeFile),
}

#[derive(clap::Args)]
struct ChangeFile {
    /// JSON file containing the active and pending quorum values.
    file: PathBuf,
}

impl ChangeFile {
    async fn send(self, request: RequestBuilder) -> anyhow::Result<()> {
        let request = request
            .header(header::CONTENT_TYPE, "application/json")
            .body(fs_err::read(self.file)?);
        send(request, StatusCode::NO_CONTENT).await?;
        Ok(())
    }
}

impl ValidatorConfigOptions {
    pub(super) async fn handle(self) -> anyhow::Result<()> {
        let mut url = self.admin_url.context("set --admin-url or VALIDATOR_ADMIN_URL")?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| anyhow::anyhow!("admin URL must be a base URL"))?;
            path.pop_if_empty().extend(["admin", "v1", "validator-config"]);
            if !matches!(self.command, ConfigCommand::Status) {
                path.push("pending");
            }
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(180))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to create validator admin client")?;

        match self.command {
            ConfigCommand::Status => {
                let response = send(client.get(url), StatusCode::OK).await?;
                let status: Value =
                    response.json().await.context("invalid validator configuration status")?;
                println!("{}", serde_json::to_string_pretty(&status)?);
            },
            ConfigCommand::Register(change) => {
                change.send(client.put(url)).await?;
                println!("Registered the pending validator quorum.");
            },
            ConfigCommand::Cancel(change) => {
                change.send(client.delete(url)).await?;
                println!("Cancelled the pending validator quorum change.");
            },
        }
        Ok(())
    }
}

async fn send(request: RequestBuilder, expected: StatusCode) -> anyhow::Result<Response> {
    let response = request.send().await.context("validator admin request failed")?;
    let status = response.status();
    if status != expected {
        let body = response.text().await.context("failed to read validator admin response")?;
        let json = serde_json::from_str::<Value>(&body).ok();
        let message = json.as_ref().and_then(|json| json["error"].as_str()).unwrap_or(body.trim());
        anyhow::bail!("validator admin request returned {status}: {message}");
    }
    Ok(response)
}
