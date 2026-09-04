use axum::{
    extract::Query,
    http::StatusCode,
    response::Redirect,
    routing::get,
    Router,
};
use reqwest::Client;
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    error: Option<String>
}

#[derive(Deserialize, Debug)]
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
        .route("/login", get(login))
        .route("/auth/google", get(auth_google));

    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind address");

    println!("Server running on http://localhost:3000");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn login() -> Redirect {
    let client_id =
        std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID missing");

    //let redirect = format!(
    //    "https://github.com/login/oauth/authorize?scope=user:email&client_id={}",
    //    client_id
    //);

    let redirect_uri =
        "http://0.0.0.0:3000/auth/google";

    let scope =
        "https://www.googleapis.com/auth/gmail.readonly";

    let redirect = format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
        ?client_id={}\
        &redirect_uri={}\
        &response_type=code\
        &scope={}\
        &access_type=offline\
        &prompt=consent",
        urlencoding::encode(&client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(scope),
    );

    Redirect::to(&redirect)
}

async fn auth_google(Query(params): Query<CallbackQuery>) -> Result<Redirect, StatusCode> {
    let code = match params.code {
        Some(c) => c,
        None => {
            println!("OAuth code missing");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let client = Client::new();

    let client_id = std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID missing");

    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET missing");


    let redirect_uri = "http://0.0.0.0:3000/auth/google";


    println!("Sending Token To Google");

    let token_res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|e| {
            println!("Token request failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    if !token_res.status().is_success() {
        println!("Google token exchange failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token: GmailTokenResponse = token_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    println!("Google OAuth successful!");
    println!("Access Token: {}", token.access_token);
    println!("Token Type: {}", token.token_type);
    println!("Expires In: {}", token.expires_in);
    println!("Scope: {}", token.scope);

    if let Some(refresh_token) = &token.refresh_token {
        println!("Refresh Token: {}", refresh_token);
    } else {
        println!("No refresh token returned");
    }



    /*mvrmwoibrmeo
    let user_res = client
        .get("https://api.github.com/user")
        .header(
            "Authorization",
            format!("token {}", token.access_token),
        )
        .header("User-Agent", "gitpro-webserver")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !user_res.status().is_success() {
        println!("GitHub token invalid");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user: serde_json::Value = user_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let login = user["login"]
        .as_str()
        .unwrap_or("unknown");

    println!("Authenticated GitHub user: {}", login);
    */


    Ok(Redirect::to(&format!(
        "http://127.0.0.1:49152/callback?token={}",
        token.access_token
    )))
}
