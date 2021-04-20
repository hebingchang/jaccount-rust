#[macro_use]
extern crate failure;

mod jaccount {
    use oauth2::basic::{BasicClient, BasicTokenResponse};
    use oauth2::reqwest::http_client;
    use oauth2::{AuthorizationCode, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, TokenUrl, AuthorizationRequest};
    use oauth2::url::ParseError;
    use reqwest::Response;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ApiResponse<T> {
        pub errno: i64,
        pub error: String,
        pub total: i64,
        pub next_token: Option<String>,
        pub entities: Vec<T>,
    }

    #[derive(Deserialize)]
    pub struct Profile {
        pub id: String,
        pub account: String,
        pub name: String,
        pub kind: String,
        pub code: String,
        pub user_type: Option<String>,
        pub organize: Organize,
        pub class_no: Option<String>,
        pub gender: String,
        pub email: String,
        pub time_zone: Option<i64>,
        pub mobile: String,
        pub identities: Vec<Identity>,
        pub union_id: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct Organize {
        pub name: String,
        pub id: String,
    }

    #[derive(Deserialize)]
    pub struct Identity {
        pub kind: String,
        pub is_default: Option<bool>,
        pub code: String,
        pub user_type: Option<String>,
        pub organize: Organize,
        pub expire_date: Option<String>,
        pub create_date: Option<i64>,
        pub update_date: Option<i64>,
        pub mgt_organize: Option<Organize>,
        pub status: Option<String>,
        pub class_no: Option<String>,
        pub gjm: Option<String>,
        pub major: Option<Major>,
        pub admission_date: Option<String>,
        pub train_level: Option<String>,
        pub graduate_date: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct Major {
        pub name: String,
        pub id: String,
    }

    #[derive(Deserialize)]
    pub struct Mail {
        pub id: String,
        pub name: String,
        pub status: String,
        pub from: Option<String>,
        pub sender: String,
    }

    pub struct OpenAPI {
        pub access_token: String
    }

    impl OpenAPI {
        async fn _get(&self, path: &str, mut query: Vec<(&str, &str)>) -> Result<Response, reqwest::Error> {
            let client = reqwest::Client::new();
            query.push(("access_token", self.access_token.as_str()));
            client.get(format!("https://api.sjtu.edu.cn{}", path.to_string()))
                .query(query.as_slice())
                .send()
                .await
        }

        pub async fn get_profile(&self) -> Result<Profile, failure::Error> {
            let res = self._get("/v1/me/profile", [].to_vec()).await?;
            let mut body = res.json::<ApiResponse<Profile>>().await?;
            if body.errno != 0 {
                return Err(format_err!("call api error: {} {}", body.errno, body.error));
            }
            let first = body.entities.pop();
            if first.is_none() {
                return Err(format_err!("no profile returned"));
            }
            Ok(first.unwrap())
        }

        pub async fn get_mails(&self) -> Result<Vec<Mail>, failure::Error> {
            let res = self._get("/v1/mails", [].to_vec()).await?;
            let body = res.json::<ApiResponse<Mail>>().await?;
            if body.errno != 0 {
                return Err(format_err!("call api error: {} {}", body.errno, body.error));
            }
            Ok(body.entities)
        }
    }

    pub struct Client {
        _client: BasicClient
    }

    impl Client {
        pub fn new(client_id: &str, client_secret: &str, redirect_uri: &str) -> Result<Client, ParseError> {
            let client = Client {
                _client: BasicClient::new(
                    ClientId::new(client_id.to_string()),
                    Some(ClientSecret::new(client_secret.to_string())),
                    AuthUrl::new("https://jaccount.sjtu.edu.cn/oauth2/authorize".to_string())?,
                    Some(TokenUrl::new("https://jaccount.sjtu.edu.cn/oauth2/token".to_string())?),
                ).set_redirect_url(RedirectUrl::new(redirect_uri.to_string())?)
            };
            Ok(client)
        }

        pub fn authorize_url(&self) -> AuthorizationRequest {
            self._client.authorize_url(CsrfToken::new_random)
        }

        pub fn exchange_code(&self, code: String) -> Result<BasicTokenResponse, failure::Error> {
            let token_result = self._client
                .exchange_code(AuthorizationCode::new(code))
                .request(http_client)?;
            Ok(token_result)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::jaccount::Client;
    use crate::jaccount::OpenAPI;
    use failure;
    use oauth2::{Scope, TokenResponse};
    use std::io::{BufReader, BufRead};
    use std::env;
    use webbrowser;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::str;
    use regex::Regex;
    use lazy_static::lazy_static;
    use std::sync::RwLock;

    lazy_static! {
        static ref ACCESS_TOKEN: RwLock<String> = RwLock::new(String::new());
    }

    fn authorize(url: &str) -> Result<(String, String), failure::Error> {
        webbrowser::open(url)?;
        let listener = TcpListener::bind("127.0.0.1:12345")?;

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        let mut path = String::new();
        for stream in listener.incoming() {
            let stream = stream?;
            let buffer = handle_callback(stream);
            req.parse(buffer.as_ref())?;
            path = req.path.unwrap().to_string();
            break;
        }

        let mut state = String::new();
        let mut code = String::new();
        for m in Regex::new(r"state=([^&]*)")?.find_iter(path.as_str()) {
            state = m.as_str().replace("state=", "")
        }
        for m in Regex::new(r"code=([^&]*)")?.find_iter(path.as_str()) {
            code = m.as_str().replace("code=", "")
        }

        Ok((state, code))
    }

    fn handle_callback(stream: TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut buffer = String::new();
        reader.read_line(&mut buffer).unwrap();
        buffer
    }

    #[test]
    fn test_jaccount() {
        test_auth();
        test_api_me();
        test_api_mail();
    }

    fn test_auth() {
        assert!(!env::var("CLIENT_ID").is_err(), "no client_id provided");
        assert!(!env::var("CLIENT_SECRET").is_err(), "no client_secret provided");
        let client_id = env::var("CLIENT_ID").unwrap();
        let client_secret = env::var("CLIENT_SECRET").unwrap();

        let result = Client::new(
            client_id.as_str(),
            client_secret.as_str(),
            "http://localhost:12345/",
        );
        assert!(!result.is_err(), "create client failed");
        let client = result.unwrap();
        let request = client.authorize_url()
            .add_scope(Scope::new("send_mail".to_string()));
        let (url, csrf_token) = request.url();

        let (state, code) = authorize(url.as_str()).unwrap();
        assert_eq!(state, csrf_token.secret().to_string());

        let result = client.exchange_code(code);
        assert!(result.is_ok(), "exchange code failed");

        let mut access_token = ACCESS_TOKEN.write().unwrap();
        *access_token = result.unwrap().access_token().secret().to_string();
        println!("got access_token: {}", access_token)
    }

    fn test_api_me() {
        let api = OpenAPI {
            access_token: ACCESS_TOKEN.read().unwrap().to_string()
        };
        let result = tokio_test::block_on(api.get_profile());
        assert!(result.is_ok())
    }

    fn test_api_mail() {
        let api = OpenAPI {
            access_token: ACCESS_TOKEN.read().unwrap().to_string()
        };
        let result = tokio_test::block_on(api.get_mails());
        assert!(result.is_ok())
    }
}
