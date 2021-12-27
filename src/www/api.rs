use crate::{Session, Sessions};
use rocket::{
	form::Form,
	http::Status,
	response::{self, Redirect, Responder},
	serde::json::Json,
	tokio::sync::Mutex,
	Request, Route, State,
};
use rocket_sync_db_pools::rusqlite::params;
use std::{io, path::PathBuf};

fn print_bytes(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(2 * bytes.len());
	for b in bytes {
		s += &format!("{:x}", *b);
	}
	s
}

#[async_recursion]
async fn traverse_dir(path: PathBuf) -> io::Result<Vec<String>> {
	let mut files = Vec::new();
	let mut dir = rocket::tokio::fs::read_dir(&path).await?;
	loop {
		match dir.next_entry().await {
			Ok(Some(entry)) => {
				if let Ok(file_type) = entry.file_type().await {
					if file_type.is_dir() {
						files.extend(&mut traverse_dir(entry.path()).await?.iter_mut().map(
							|subentry| {
								format!(
									"{dir}/{subentry}",
									dir = entry.file_name().to_string_lossy().to_string(),
									subentry = subentry,
								)
							},
						));
					} else {
						files.push(
							entry
								.path()
								.strip_prefix(&path)
								.unwrap()
								.to_string_lossy()
								.strip_suffix(".html.hbs")
								.unwrap()
								.to_string(),
						);
					}
				}
			}
			Ok(None) => break,
			Err(_) => continue,
		}
	}
	Ok(files)
}

struct LoginResponder(Session);
impl<'r, 'o: 'r> Responder<'r, 'o> for LoginResponder {
	fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
		use rocket::http::{Cookie, SameSite};

		let mut cookie = Cookie::new(
			Session::COOKIE,
			serde_json::to_string(&self.0).map_err(|_err| Status::InternalServerError)?,
		);
		cookie.set_path("/");
		cookie.set_same_site(SameSite::Strict);
		req.cookies().add_private(cookie);

		Redirect::to("/profile").respond_to(req)
	}
}

#[derive(FromForm)]
struct SignForm<'s> {
	username: &'s str,
	password: &'s str,
}

#[get("/articles")]
async fn articles() -> io::Result<Json<Vec<String>>> {
	let articles = traverse_dir(PathBuf::from("./static/articles")).await?;
	Ok(Json(articles))
}

#[post("/register", data = "<form>")]
async fn register(
	conn: crate::DbConnection,
	sessions: &State<Mutex<Sessions>>,
	form: Form<SignForm<'_>>,
) -> Result<LoginResponder, Status> {
	use sha2::{Digest, Sha256};

	let username = form.username.to_string();
	let password = {
		let mut hasher = Sha256::default();
		hasher.update(form.password.as_bytes());
		hasher.finalize()
	};
	conn.run(move |db| {
		db.execute(
			"INSERT INTO users (username, password) VALUES (?1, ?2)",
			params![username, print_bytes(password.as_slice())],
		)
	})
	.await
	.map_err(|_err| Status::BadRequest)?;
	login(conn, sessions, form).await
}

#[post("/login", data = "<form>")]
async fn login(
	conn: crate::DbConnection,
	sessions: &State<Mutex<Sessions>>,
	form: Form<SignForm<'_>>,
) -> Result<LoginResponder, Status> {
	use rand::{rngs::OsRng, RngCore};
	use sha2::{Digest, Sha256};

	let username = form.username.to_string();
	let password = {
		let mut hasher = Sha256::default();
		hasher.update(form.password.as_bytes());
		hasher.finalize()
	};
	let username: String = conn
		.run(move |db| {
			db.query_row(
				&format!(
					"SELECT username FROM users WHERE username='{username}' AND password='{password}'", // NOTE: SQL injection vulnerable
					username = username,
					password = print_bytes(password.as_slice()),
				),
				[],
				|row| row.get(0),
			)
		})
		.await
		.map_err(|_err| Status::Unauthorized)?;

	let mut sessions = sessions.lock().await;
	let key = format!("{:x}", OsRng::default().next_u64());
	sessions.insert(key.clone(), username.clone());

	Ok(LoginResponder(Session {
		auth_key: key,
		username,
	}))
}

pub(crate) fn routes() -> Vec<Route> {
	routes![articles, register, login]
}
