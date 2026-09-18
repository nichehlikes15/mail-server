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

#[derive(Debug, Deserialize)]
struct GoogleErrorResponse {
    error: Option<String>,

    #[serde(default)]
    error_description: Option<String>,

    #[serde(default)]
    error_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() {
    println!("========================================");
    println!("Mail OAuth Server starting...");
    println!("========================================");

    println!("[STARTUP] Loading environment variables...");

    dotenvy::dotenv().ok();

    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .expect("GOOGLE_CLIENT_ID is not set");

    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .expect("GOOGLE_CLIENT_SECRET is not set");

    if client_id.trim().is_empty() {
        panic!("GOOGLE_CLIENT_ID is empty");
    }

    if client_secret.trim().is_empty() {
        panic!("GOOGLE_CLIENT_SECRET is empty");
    }

    println!("[STARTUP] GOOGLE_CLIENT_ID is configured");
    println!("[STARTUP] GOOGLE_CLIENT_SECRET is configured");
    println!("[STARTUP] Google OAuth credentials loaded successfully");

    let app = Router::new()
        .route("/oauth/token", post(exchange_code))
        .route("/oauth/refresh", post(refresh_token));

    println!("[STARTUP] OAuth routes registered:");
    println!("[STARTUP]   POST /oauth/token");
    println!("[STARTUP]   POST /oauth/refresh");

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string());

    println!("[STARTUP] Using port: {}", port);
    println!("[STARTUP] Binding server to 0.0.0.0:{}...", port);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind address");

    println!("[STARTUP] Server successfully bound");
    println!("[STARTUP] Mail OAuth Server is ready");
    println!("========================================");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn exchange_code(
    Json(request): Json<TokenRequest>,
) -> Result<Json<GmailTokenResponse>, (StatusCode, Json<OAuthErrorResponse>)> {
    println!();
    println!("========================================");
    println!("[TOKEN] OAuth token exchange requested");
    println!("========================================");

    println!("[TOKEN] Request received successfully");
    println!("[TOKEN] Redirect URI: {}", request.redirect_uri);
    println!(
        "[TOKEN] Authorization code received: {} characters",
        request.code.len()
    );
    println!(
        "[TOKEN] PKCE verifier received: {} characters",
        request.code_verifier.len()
    );

    println!("[TOKEN] Loading Google OAuth credentials...");

    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| {
            internal_error("GOOGLE_CLIENT_ID is not configured")
        })?;

    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| {
            internal_error("GOOGLE_CLIENT_SECRET is not configured")
        })?;

    println!("[TOKEN] GOOGLE_CLIENT_ID loaded");
    println!("[TOKEN] GOOGLE_CLIENT_SECRET loaded");

    println!("[TOKEN] Creating HTTP client...");

    let client = Client::new();

    println!("[TOKEN] HTTP client created");
    println!("[TOKEN] Sending authorization code to Google...");
    println!("[TOKEN] Google endpoint: https://oauth2.googleapis.com/token");
    println!("[TOKEN] Grant type: authorization_code");
    println!("[TOKEN] Redirect URI: {}", request.redirect_uri);

    let response = match client
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
    {
        Ok(response) => response,
        Err(error) => {
            eprintln!("[TOKEN] ERROR: Failed to contact Google");
            eprintln!("[TOKEN] ERROR DETAILS: {}", error);

            return Err((
                StatusCode::BAD_GATEWAY,
                Json(OAuthErrorResponse {
                    error: format!(
                        "Failed to contact Google token endpoint: {}",
                        error
                    ),
                }),
            ));
        }
    };

    let status = response.status();

    println!("[TOKEN] Google responded");
    println!("[TOKEN] Google HTTP status: {}", status);

    if !status.is_success() {
        println!("[TOKEN] Google token exchange FAILED");

        let body = response.text().await.unwrap_or_default();

        println!("[TOKEN] Google response body:");
        println!("{}", body);

        if let Ok(error) =
            serde_json::from_str::<GoogleErrorResponse>(&body)
        {
            println!("[TOKEN] Parsed Google error:");

            if let Some(error_code) = &error.error {
                println!("[TOKEN]   Error code: {}", error_code);
            }

            if let Some(description) = &error.error_description {
                println!(
                    "[TOKEN]   Description: {}",
                    description
                );
            }

            if let Some(uri) = &error.error_uri {
                println!("[TOKEN]   Error URI: {}", uri);
            }

            let message = match (
                error.error,
                error.error_description,
            ) {
                (Some(code), Some(description)) => {
                    format!(
                        "Google OAuth error: {} - {}",
                        code, description
                    )
                }

                (Some(code), None) => {
                    format!("Google OAuth error: {}", code)
                }

                (None, Some(description)) => {
                    format!(
                        "Google OAuth error: {}",
                        description
                    )
                }

                (None, None) => {
                    format!(
                        "Google OAuth error: {}",
                        body
                    )
                }
            };

            return Err((
                StatusCode::BAD_GATEWAY,
                Json(OAuthErrorResponse {
                    error: message,
                }),
            ));
        }

        return Err((
            StatusCode::BAD_GATEWAY,
            Json(OAuthErrorResponse {
                error: format!(
                    "Google OAuth request failed: {}",
                    body
                ),
            }),
        ));
    }

    println!("[TOKEN] Google token exchange succeeded");
    println!("[TOKEN] Parsing Google token response...");

    let token = response
        .json::<GmailTokenResponse>()
        .await
        .map_err(|error| {
            eprintln!(
                "[TOKEN] ERROR: Failed to parse Google token response"
            );
            eprintln!("[TOKEN] ERROR DETAILS: {}", error);

            (
                StatusCode::BAD_GATEWAY,
                Json(OAuthErrorResponse {
                    error: format!(
                        "Failed to parse Google token response: {}",
                        error
                    ),
                }),
            )
        })?;

    println!("[TOKEN] Google token response parsed successfully");
    println!("[TOKEN] Access token received");
    println!(
        "[TOKEN] Access token expires in: {} seconds",
        token.expires_in
    );
    println!("[TOKEN] Token type: {}", token.token_type);
    println!("[TOKEN] Scope: {}", token.scope);

    if token.refresh_token.is_some() {
        println!("[TOKEN] Refresh token received");
    } else {
        println!("[TOKEN] WARNING: No refresh token received");
    }

    println!("[TOKEN] OAuth token exchange completed successfully");
    println!("========================================");

    Ok(Json(token))
}

async fn refresh_token(
    Json(request): Json<RefreshRequest>,
) -> Result<Json<GmailTokenResponse>, (StatusCode, Json<OAuthErrorResponse>)> {
    println!();
    println!("========================================");
    println!("[REFRESH] OAuth token refresh requested");
    println!("========================================");

    println!("[REFRESH] Request received successfully");
    println!(
        "[REFRESH] Refresh token length: {} characters",
        request.refresh_token.len()
    );

    println!("[REFRESH] Loading Google OAuth credentials...");

    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| {
            internal_error("GOOGLE_CLIENT_ID is not configured")
        })?;

    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| {
            internal_error("GOOGLE_CLIENT_SECRET is not configured")
        })?;

    println!("[REFRESH] GOOGLE_CLIENT_ID loaded");
    println!("[REFRESH] GOOGLE_CLIENT_SECRET loaded");

    println!("[REFRESH] Creating HTTP client...");

    let client = Client::new();

    println!("[REFRESH] HTTP client created");
    println!("[REFRESH] Sending refresh request to Google...");
    println!("[REFRESH] Google endpoint: https://oauth2.googleapis.com/token");
    println!("[REFRESH] Grant type: refresh_token");

    let response = match client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", request.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            eprintln!("[REFRESH] ERROR: Failed to contact Google");
            eprintln!("[REFRESH] ERROR DETAILS: {}", error);

            return Err((
                StatusCode::BAD_GATEWAY,
                Json(OAuthErrorResponse {
                    error: format!(
                        "Failed to contact Google token endpoint: {}",
                        error
                    ),
                }),
            ));
        }
    };

    let status = response.status();

    println!("[REFRESH] Google responded");
    println!("[REFRESH] Google HTTP status: {}", status);

    if !status.is_success() {
        println!("[REFRESH] Google token refresh FAILED");

        let body = response.text().await.unwrap_or_default();

        println!("[REFRESH] Google response body:");
        println!("{}", body);

        if let Ok(error) =
            serde_json::from_str::<GoogleErrorResponse>(&body)
        {
            println!("[REFRESH] Parsed Google error:");

            if let Some(error_code) = &error.error {
                println!(
                    "[REFRESH]   Error code: {}",
                    error_code
                );
            }

            if let Some(description) = &error.error_description {
                println!(
                    "[REFRESH]   Description: {}",
                    description
                );
            }

            if let Some(uri) = &error.error_uri {
                println!("[REFRESH]   Error URI: {}", uri);
            }

            let message = match (
                error.error,
                error.error_description,
            ) {
                (Some(code), Some(description)) => {
                    format!(
                        "Google OAuth error: {} - {}",
                        code, description
                    )
                }

                (Some(code), None) => {
                    format!("Google OAuth error: {}", code)
                }

                (None, Some(description)) => {
                    format!(
                        "Google OAuth error: {}",
                        description
                    )
                }

                (None, None) => {
                    format!(
                        "Google OAuth error: {}",
                        body
                    )
                }
            };

            return Err((
                StatusCode::BAD_GATEWAY,
                Json(OAuthErrorResponse {
                    error: message,
                }),
            ));
        }

        return Err((
            StatusCode::BAD_GATEWAY,
            Json(OAuthErrorResponse {
                error: format!(
                    "Google OAuth refresh failed: {}",
                    body
                ),
            }),
        ));
    }

    println!("[REFRESH] Google token refresh succeeded");
    println!("[REFRESH] Parsing Google token response...");

    let token = response
        .json::<GmailTokenResponse>()
        .await
        .map_err(|error| {
            eprintln!(
                "[REFRESH] ERROR: Failed to parse Google response"
            );
            eprintln!(
                "[REFRESH] ERROR DETAILS: {}",
                error
            );

            (
                StatusCode::BAD_GATEWAY,
                Json(OAuthErrorResponse {
                    error: format!(
                        "Failed to parse Google refresh response: {}",
                        error
                    ),
                }),
            )
        })?;

    println!("[REFRESH] Google response parsed successfully");
    println!(
        "[REFRESH] Access token expires in: {} seconds",
        token.expires_in
    );
    println!("[REFRESH] Token type: {}", token.token_type);
    println!("[REFRESH] Scope: {}", token.scope);
    println!("[REFRESH] OAuth token refresh completed successfully");
    println!("========================================");

    Ok(Json(token))
}

fn internal_error(
    message: &str,
) -> (StatusCode, Json<OAuthErrorResponse>) {
    eprintln!("[SERVER] INTERNAL CONFIGURATION ERROR");
    eprintln!("[SERVER] {}", message);

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(OAuthErrorResponse {
            error: message.to_string(),
        }),
    )
}