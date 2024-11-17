mod qr_code;
mod diceware;
mod api;

use crate::diceware::generate_passphrase;
use crate::qr_code::generate_qr_code;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::{
    extract::Form,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    routing::post,
    Router,
};
use captcha_rs::CaptchaBuilder;
use clap::{value_parser, Arg, ArgAction};
use dashmap::DashMap;
use http::Response;
use include_dir::{include_dir, Dir};
use lazy_static::lazy_static;
use rand::Rng;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::process::exit;
use std::sync::{Arc, RwLock};
use tokio::signal;
use tokio::time::Instant;

static FONTS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/fonts");

lazy_static! {
    static ref REGISTER_HTML: &'static str = include_str!("../web/register.html");
    static ref REG_CASUAL_HTML: &'static str = include_str!("../web/register_casual.html");
    static ref INVITE_HTML: &'static str = include_str!("../web/invite.html");
    static ref INVITE_RES_HTML: &'static str = include_str!("../web/invite_result.html");
    static ref SUCCESS_HTML: &'static str = include_str!("../web/success.html");
    static ref NEXT_HTML: &'static str = include_str!("../web/next.html");
    static ref ERROR_HTML: &'static str = include_str!("../web/error.html");
    static ref SEMANTIC_CSS: &'static str = include_str!("../web/semantic.min.css");
    static ref ADDITIONAL_CSS: &'static str = include_str!("../web/style.css");
    static ref FAVICON: &'static str = include_str!("../web/favicon.svg");
}

#[derive(Deserialize)]
struct RegistrationForm {
    username: String,
    password: String,
    password2: String,
    #[serde(default)]
    captcha: String,
    #[serde(default)]
    session: String,
    #[serde(default)]
    invite: String,
}

#[derive(Deserialize)]
struct RegCasualForm {
    username: String,
    password: String,
    #[serde(default)]
    invite: String,
}

async fn show_register(State(state): State<Arc<RwLock<AppState>>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, Query(params): Query<HashMap<String, String>>) -> Result<impl IntoResponse, StatusCode> {
    let ip = addr.to_string();
    {
        let now = Instant::now();
        let time_window = std::time::Duration::from_secs(60); // 1 minute
        let max_requests = 10;

        // Access the rate limiter state
        let state = state.write().unwrap();
        let limiter = state.rate_limiter.clone();

        let mut request_times = limiter.entry(ip.clone()).or_insert_with(Vec::new);

        // Remove outdated requests
        request_times.retain(|&time| now.duration_since(time) <= time_window);

        if request_times.len() >= max_requests {
            return Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::from(ERROR_HTML.replace("{error}", "Too many requests from your IP. Try again later.")))
                .unwrap());
        }

        // Record the current request time
        request_times.push(now);
    }

    let invite = match params.get("invite") {
        None => String::new(),
        Some(s) => s.to_string()
    };
    let html = if state.read().unwrap().config.casual_mode {
        let username = generate_passphrase(2, '.');
        let passphrase = generate_passphrase(6, '-');
        let state = state.read().unwrap();
        REG_CASUAL_HTML
            .replace("{domain}", &state.config.domain)
            .replace("{username}", &username)
            .replace("{pass}", &passphrase)
            .replace("{invite}", &invite)
    } else {
        let captcha = CaptchaBuilder::new()
            .length(6)
            .width(130)
            .height(38)
            .dark_mode(true)
            .complexity(5) // min: 1, max: 10
            .compression(40) // min: 1, max: 99
            .build();
        let session = random_string(32);
        state.write().unwrap().captcha.insert(session.clone(), captcha.text.to_lowercase());
        let state = state.read().unwrap();
        REGISTER_HTML
            .replace("{domain}", &state.config.domain)
            .replace("{captcha}", &captcha.to_base64())
            .replace("{session}", &session)
            .replace("{invite}", &invite)
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(html))
        .unwrap())
}

async fn show_invite(State(state): State<Arc<RwLock<AppState>>>) -> Result<impl IntoResponse, StatusCode> {
    let pass = state.read().unwrap().config.invite_pass.clone();
    if pass.is_empty() {
        let error = "<p>Set password in config: <code>invite_pass = \"good-password\"</code> and then use this page to generate invite links</p>";
        let html = INVITE_HTML.replace("<!--error-->", error);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(html)
            .unwrap())
    }
    Ok(Response::builder().status(StatusCode::OK).body(INVITE_HTML.to_string()).unwrap())
}

async fn handle_invite(State(state): State<Arc<RwLock<AppState>>>, headers: HeaderMap, Form(params): Form<HashMap<String, String>>) -> Result<impl IntoResponse, StatusCode> {
    let pass = state.read().unwrap().config.invite_pass.clone();
    if pass.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    match params.get("password") {
        None => Err(StatusCode::UNAUTHORIZED),
        Some(password) => {
            if !pass.eq(password) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let random = random_string(24);
            let origin = match extract_origin(&headers) {
                None => return Err(StatusCode::BAD_REQUEST),
                Some(origin) => origin
            };
            let invite_link = format!("{origin}/?invite={}", &random);
            state.write().unwrap().invites.insert(random);
            let html = INVITE_RES_HTML.replace("{link}", &invite_link);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(html)
                .unwrap())
        }
    }
}

fn extract_origin(headers: &HeaderMap) -> Option<String> {
    if headers.contains_key("origin") {
        return Some(String::from_utf8_lossy(headers.get("origin").unwrap().as_bytes()).to_string());
    }
    if headers.contains_key("host") {
        let host = String::from_utf8_lossy(headers.get("host").unwrap().as_bytes()).to_string();
        return Some(format!("https://{host}"));
    }
    None
}

async fn send_favicon() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/svg+xml")
        .header("Cache-Control", "public, max-age=2592000")
        .body(FAVICON.to_string())
        .unwrap()
}

async fn send_next() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .header("Cache-Control", "public, max-age=2592000")
        .body(NEXT_HTML.to_string())
        .unwrap()
}

async fn handle_register(State(state): State<Arc<RwLock<AppState>>>, Form(input): Form<RegistrationForm>) -> Result<impl IntoResponse, StatusCode> {
    if input.password != input.password2 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Passwords do not match."))
            .unwrap());
    }

    if !valid_username(&input.username) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Username contains invalid characters or is too long."))
            .unwrap());
    }

    let username = input.username.clone();
    let password = input.password.clone();
    let config = state.read().unwrap().config.clone();
    println!("Trying to register user {}@{}...", &username, &config.domain);

    if !valid_captcha(&input, &state.read().unwrap().captcha) {
        println!("Wrong captcha");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Wrong captcha, please try harder."))
            .unwrap());
    }

    // Removing the challenge
    state.write().unwrap().captcha.remove(&input.session);

    if !config.invite_pass.is_empty() && !state.read().unwrap().invites.contains(&input.invite) {
        println!("Wrong invite code");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Wrong invite link, get a new one from your inviter."))
            .unwrap());
    }

    // Removing invite code
    if !config.invite_pass.is_empty() {
        state.write().unwrap().invites.remove(&input.invite);
    }

    create_user_by_api(&username, &password, &config).await
}

async fn handle_register_casual(State(state): State<Arc<RwLock<AppState>>>, Form(input): Form<RegCasualForm>) -> Result<impl IntoResponse, StatusCode> {
    if input.password.chars().count() < 8 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Passwords must be at least 8 symbols long."))
            .unwrap());
    }

    if !valid_username(&input.username) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Username contains invalid characters or is too long."))
            .unwrap());
    }

    let username = input.username.clone();
    let password = input.password.clone();
    let config = state.read().unwrap().config.clone();
    println!("Trying to register user {}@{}...", &username, &config.domain);

    if !config.invite_pass.is_empty() && !state.read().unwrap().invites.contains(&input.invite) {
        println!("Wrong invite code");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(ERROR_HTML.replace("{error}", "Wrong invite link, get a new one from your inviter."))
            .unwrap());
    }

    // Removing invite code
    if !config.invite_pass.is_empty() {
        state.write().unwrap().invites.remove(&input.invite);
    }

    create_user_by_api(&username, &password, &config).await
}

fn valid_username(username: &str) -> bool {
    username.chars().count() < 20 && username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

async fn create_user_by_api(username: &str, password: &str, config: &Config) -> Result<Response<String>, StatusCode> {
    let user = api::NewUser::new(
        username.to_string(),
        format!("{}@{}", &username, &config.domain),
        password.to_string(),
        config.group.clone(),
        config.quota
    );
    match api::create_user(&config.url, "admin", &config.credentials, user).await {
        Ok(id) => {
            println!("Created user with Id: {id}");
            let domain = &config.domain;
            let password = urlencoding::encode(&password);
            let url = format!("dclogin://{username}@{domain}/?p={password}&iu={username}&su={username}&v=1");
            let qr = generate_qr_code(&url).unwrap_or_else(|e| e.to_string());
            let html = SUCCESS_HTML.replace("<!--qr-->", &qr).replace("{url}", &url);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(html)
                .unwrap())
        }
        Err(e) => {
            println!("Error: {e}");
            Ok(Response::builder()
                .status(StatusCode::CONFLICT)
                .body(ERROR_HTML.replace("{error}", "This account already exists."))
                .unwrap())
        }
    }
}

fn valid_captcha(form: &RegistrationForm, map: &HashMap<String, String>) -> bool {
    if !map.contains_key(&form.session) {
        return false;
    }
    if let Some(text) = map.get(&form.session) {
        if text.eq(&form.captcha) || form.captcha.to_lowercase().eq(text) {
            return true;
        }
    }
    false
}

async fn serve_semantic_css() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/css"));
    headers.insert("Cache-Control", HeaderValue::from_static("public, max-age=2592000"));
    (headers, *SEMANTIC_CSS)
}

async fn serve_additional_css() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("text/css"));
    headers.insert("Cache-Control", HeaderValue::from_static("public, max-age=3600"));
    (headers, *ADDITIONAL_CSS)
}

async fn serve_font(Path((font, filename)): Path<(String, String)>) -> impl IntoResponse {
    match FONTS_DIR.get_file(format!("{font}/{filename}")) {
        None => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("File not found."))
                .unwrap()
        }
        Some(file) => {
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", HeaderValue::from_static("font/truetype"))
                .header("Cache-Control", HeaderValue::from_static("public, max-age=2592000"))
                .body(Body::from(file.contents()))
                .unwrap()
        }
    }
}

/// Command line arguments
#[derive(Clone, Default, Deserialize)]
struct Config {
    listen: String,
    url: String,
    credentials: String,
    #[serde(default = "default_quota")]
    quota: u64,
    domain: String,
    group: String,
    #[serde(default)]
    invite_pass: String,
    #[serde(default)]
    casual_mode: bool
}

impl Config {
    pub fn load(filename: &str) -> Option<Config> {
        match File::open(filename) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                match toml::from_str(&text) {
                    Ok(settings) => {
                        return Some(settings);
                    }
                    Err(e) => {
                        println!("Error parsing config file: {e}");
                    }
                }
                None
            }
            Err(e) => {
                println!("Error opening config file: {e}");
                None
            }
        }
    }
}

#[derive(Default)]
struct AppState {
    config: Config,
    captcha: HashMap<String, String>,
    invites: HashSet<String>,
    rate_limiter: Arc<DashMap<String, Vec<Instant>>>
}

#[tokio::main]
async fn main() {
    let matches = clap::Command::new("Stalwart Registration")
        .version("1.0")
        .about("Provides Web-UI for self-registration of Stalwart accounts.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .help("Path to config file")
                .value_parser(value_parser!(String))
        )
        .arg(
            Arg::new("generate")
                .short('g')
                .long("generate")
                .help("Generate and print new config file (example)")
                .num_args(0)
                .action(ArgAction::SetTrue)
        )
        .get_matches();

    if matches.get_flag("generate") {
        println!("{}", include_str!("../config_example.toml"));
        return;
    }

    let config = if let Some(c) = matches.get_one::<String>("config") {
        match Config::load(c) {
            None => exit(1),
            Some(config) => config
        }
    } else {
        println!("Error: You must supply config path");
        return;
    };

    let domain = config.domain.clone();
    let listen_addr = config.listen.clone();
    let mut state = AppState::default();
    state.config = config;
    let state = Arc::new(RwLock::new(state));

    let app = Router::new()
        .route("/", get(show_register))
        .route("/register", post(handle_register))
        .route("/register_casual", post(handle_register_casual))
        .route("/invite", get(show_invite))
        .route("/invite", post(handle_invite))
        .route("/favicon.ico", get(send_favicon))
        .route("/semantic.min.css", get(serve_semantic_css))
        .route("/style.css", get(serve_additional_css))
        .route("/next", get(send_next))
        .route("/fonts/:font/:filename", get(serve_font))
        .with_state(state.clone());

    let addr: SocketAddr = listen_addr.parse().unwrap();
    println!("Listening on {} for '{}'", addr, &domain);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// Generates random string of given length
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?".chars().collect();
    let mut rng = rand::thread_rng();
    let mut result = String::with_capacity(length);
    for _ in 0..length {
        let position: usize = rng.gen::<usize>() % chars.len();
        let c: char = *chars.get(position).unwrap();
        result.push(c);
    }
    result
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn default_quota() -> u64 {
    // One GB
    1073741824
}