use std::time::Duration;

use anyhow::Context;
use miden_node_store::allowlist::InvitationCode;
use miden_protocol::account::AccountId;
use reqwest::{Client, RequestBuilder};
use url::Url;

pub(crate) struct AdminClient {
    http: Client,
    url: Url,
}

impl AdminClient {
    pub(crate) fn new(url: Url) -> anyhow::Result<Self> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(180))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to create admin client")?;
        Ok(Self { http, url })
    }

    pub(crate) async fn create_invitation(&self, code: &str) -> anyhow::Result<()> {
        let invitation = InvitationCode::new(code).context("invalid invitation code")?;
        let url = self.endpoint("invitations", &invitation.to_hex_digest())?;
        self.send(self.http.put(url).json(&serde_json::json!({}))).await
    }

    pub(crate) async fn allowlist_account(&self, account_id: AccountId) -> anyhow::Result<()> {
        let url = self.endpoint("accounts", &account_id.to_hex())?;
        self.send(self.http.put(url)).await
    }

    fn endpoint(&self, resource: &str, id: &str) -> anyhow::Result<Url> {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("admin URL must be a base URL"))?
            .pop_if_empty()
            .extend(["admin", "allowlist", resource, id]);
        Ok(url)
    }

    async fn send(&self, request: RequestBuilder) -> anyhow::Result<()> {
        let response = request.send().await.context("admin request failed")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.context("failed to read admin error response")?;
            anyhow::bail!("admin request failed ({status}): {body}");
        }
        Ok(())
    }
}
