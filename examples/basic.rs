//  http "http://localhost:8080/todos" title=hello "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6InRlY2h5YW5nIn0.9aX8YWnioRfkqMRLCnb_o_jAJOm1jghaIDBehgy1Hzo"
//  http "http://localhost:8080/login" email=a@b.com password=123
//

use axum::{
    async_trait,
    body::{boxed, Full},
    extract::{Extension, FromRequest, RequestParts, TypedHeader},
    handler::Handler,
    headers::authorization::Bearer,
    headers::Authorization,
    http::StatusCode,
    http::{self, header, Request, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    AddExtensionLayer, Json, Router, Server,
};
use jsonwebtoken as jwt;
use jsonwebtoken::Validation;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

const SECRET: &[u8] = b"deadbeef";
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(RustEmbed)]
#[folder = "my-app/build/"]
struct Assets;

struct StaticFile<T>(pub T);

impl<T> IntoResponse for StaticFile<T>
where
    T: Into<String>,
{
    fn into_response(self) -> axum::response::Response {
        let path = self.0.into();
        match Assets::get(path.as_str()) {
            Some(content) => {
                let body = boxed(Full::from(content.data));
                let mime = mime_guess::from_path(path.as_str()).first_or_octet_stream();
                Response::builder()
                    .header(header::CONTENT_TYPE, mime.as_ref())
                    .body(body)
                    .unwrap()
            }
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(boxed(Full::from(format!("File not found: {}", path))))
                .unwrap(),
        }
    }
}

#[derive(Default, Debug, Clone)]
struct TodoStore {
    items: Arc<RwLock<Vec<Todo>>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Todo {
    pub id: usize,
    pub user_id: usize,
    pub title: String,
    pub completed: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateTodo {
    title: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    id: usize,
    name: String,
    exp: usize,
}
#[derive(Serialize, Deserialize, Debug)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum HttpError {
    Auth,     // 500
    Internal, // anything
}

#[tokio::main]
async fn main() {
    let store = TodoStore {
        items: Arc::new(RwLock::new(vec![Todo {
            id: 0,
            user_id: 0,
            title: "Learn rust".to_string(),
            completed: false,
        }])),
    };
    let app = Router::new()
        .route("/", get(index_handler))
        .route(
            "/todos",
            get(todos_handler)
                .post(create_todo_handler)
                .layer(AddExtensionLayer::new(store)),
        )
        .route("/login", post(login_handler))
        .fallback(static_handler.into_service());
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    println!("Listening on http://{}", addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/').to_string();
    StaticFile(path)
}

async fn index_handler() -> impl IntoResponse {
    //StaticFile("index.html")
    static_handler("index.html".parse().unwrap()).await
}

async fn todos_handler(
    claims: Claims,
    Extension(store): Extension<TodoStore>,
) -> Result<Json<Vec<Todo>>, HttpError> {
    let user_id = claims.id;
    match store.items.read() {
        Ok(items) => Ok(Json(
            items
                .iter()
                .filter(|todo| todo.user_id == user_id)
                .map(|todo| todo.clone())
                .collect(),
        )),
        Err(_) => Err(HttpError::Internal),
    }
}
//async fn todos_handler() -> Json<Vec<Todo>> {
//    Json(vec![
//        Todo {
//            id: 1,
//            user_id: 1,
//            title: "todo 1".to_string(),
//            completed: false,
//        },
//        Todo {
//            id: 2,
//            user_id: 2,
//            title: "todo 2".to_string(),
//            completed: false,
//        },
//    ])
//}

async fn create_todo_handler(
    claims: Claims,
    Json(todo): Json<CreateTodo>,
    Extension(store): Extension<TodoStore>,
) -> Result<StatusCode, HttpError> {
    //println!("{:#?}", claims);
    match store.items.write() {
        Ok(mut guard) => {
            let todo = Todo {
                id: get_next_id(),
                user_id: claims.id,
                title: todo.title,
                completed: false,
            };
            guard.push(todo);
            Ok(StatusCode::CREATED)
        }
        Err(_) => Err(HttpError::Internal),
    }
}

async fn login_handler(Json(login): Json<LoginRequest>) -> Json<LoginResponse> {
    // skip login info validation
    let claims = Claims {
        id: 1,
        name: "techyang".to_string(),
        exp: get_ephch() + 14 * 24 * 60 * 60,
    };
    let key = jwt::EncodingKey::from_secret(SECRET);
    let token = jwt::encode(&jwt::Header::default(), &claims, &key).unwrap();

    Json(LoginResponse { token })
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        let (code, msg) = match self {
            HttpError::Auth => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            HttpError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        (code, msg).into_response()
    }
}

#[async_trait]
impl<B> FromRequest<B> for Claims
where
    B: Send,
{
    type Rejection = HttpError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // ...
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| HttpError::Auth)?;
        let key = jwt::DecodingKey::from_secret(SECRET);
        let token =
            jwt::decode::<Claims>(bearer.token(), &key, &Validation::default()).map_err(|e| {
                println!("{:?}", e);
                HttpError::Auth
            })?;

        Ok(token.claims)
    }
}
fn get_ephch() -> usize {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

fn get_next_id() -> usize {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}
