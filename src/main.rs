use axum::{
    extract::Json,
    http::StatusCode,
    routing::post,
    Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Debug, Deserialize)]
struct TokenRequest {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GmailTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,

    #[serde(default)]
    refresh_token: Option<String>,

    scope: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let app = Router::new()
        .route("/oauth/token", post(exchange_code))
        .route("/oauth/refresh", post(refresh_token));

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string());

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind address");

    println!("Server running on port {}", port);

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn exchange_code(
    Json(request): Json<TokenRequest>,
) -> Result<Json<GmailTokenResponse>, StatusCode> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client = Client::new();

    let response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", request.code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", request.code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if !response.status().is_success() {
        println!(
            "Google token exchange failed: {}",
            response.status()
        );

        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = response
        .json::<GmailTokenResponse>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    Ok(Json(token))
}

async fn refresh_token(
    Json(request): Json<RefreshRequest>,
) -> Result<Json<GmailTokenResponse>, StatusCode> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client = Client::new();

    let response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", request.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if !response.status().is_success() {
        println!(
            "Google token refresh failed: {}",
            response.status()
        );

        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = response
        .json::<GmailTokenResponse>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    Ok(Json(token))
}