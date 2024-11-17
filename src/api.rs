use pwhash::sha512_crypt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct User {
    id: u32,
    #[serde(rename = "type")]
    user_type: String,
    pub name: String,
    quota: u64,
    #[serde(rename = "memberOf")]
    member_of: Vec<String>,
    secrets: String,
    pub emails: String,
    #[serde(default)]
    roles: Option<Vec<String>>, // Optional, as not all users have roles
}

// Custom error type to handle API errors
#[derive(Debug)]
enum ApiError {
    FieldAlreadyExists { field: String, value: String },
    Other(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::FieldAlreadyExists { field, value } => {
                write!(f, "Field '{}' with value '{}' already exists", field, value)
            }
            ApiError::Other(message) => write!(f, "{}", message),
        }
    }
}

impl Error for ApiError {}

#[derive(Debug, Serialize)]
pub struct NewUser {
    #[serde(rename = "type")]
    user_type: String,
    quota: u64,
    name: String,
    secrets: Vec<String>,
    emails: Vec<String>,
    urls: Vec<String>,
    #[serde(rename = "memberOf")]
    member_of: Vec<String>,
    roles: Vec<String>,
    lists: Vec<String>,
    members: Vec<String>,
    #[serde(rename = "enabledPermissions")]
    enabled_permissions: Vec<String>,
    #[serde(rename = "disabledPermissions")]
    disabled_permissions: Vec<String>,
}

impl NewUser {
    pub fn new(name: String, email: String, password: String, group: String, quota: u64) -> Self {
        Self {
            user_type: String::from("individual"),
            quota,
            name,
            secrets: vec![sha512_crypt::hash(password).unwrap()],
            emails: vec![email],
            urls: vec![],
            member_of: vec![group],
            roles: vec![String::from("user")],
            lists: vec![],
            members: vec![],
            enabled_permissions: vec![],
            disabled_permissions: vec![],
        }
    }
}

pub async fn create_user(api_url: &str, username: &str, password: &str, user_data: NewUser) -> Result<u32, Box<dyn Error>> {
    let client = Client::new();
    let url = format!("{api_url}/api/principal");

    // Send the POST request with Basic Auth and JSON body
    let response = client
        .post(url)
        .basic_auth(username, Some(password))
        .json(&user_data)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?; // Deserialize as generic JSON to handle both success and error cases

    // Check if the response contains "data" field (success case)
    if let Some(data) = response.get("data").and_then(|d| d.as_u64()) {
        return Ok(data as u32);
    }

    println!("Response: {}", &response.to_string());

    // Check if the response contains "error" field (error case)
    if let Some(error) = response.get("error").and_then(|e| e.as_str()) {
        return if let (Some(field), Some(value)) = (
            response.get("field").and_then(|f| f.as_str()),
            response.get("value").and_then(|v| v.as_str())
        ) {
            // Return specific field error
            Err(Box::new(ApiError::FieldAlreadyExists {
                field: field.to_string(),
                value: value.to_string(),
            }))
        } else {
            // Return a generic error with the error message
            Err(Box::new(ApiError::Other(error.to_string())))
        }
    }

    // If neither "data" nor "error" was found, return a generic error
    Err(Box::new(ApiError::Other("Unexpected API response".to_string())))
}