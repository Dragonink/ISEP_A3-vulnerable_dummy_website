#![warn(clippy::all)]
#![deny(clippy::correctness)]

#[macro_use]
extern crate rocket;
use rocket::{
	http::Status,
	request::{FromRequest, Outcome},
	Request,
};
use rocket_sync_db_pools::{database, rusqlite::Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod web;

#[database("sqlite")]
struct DbConnection(Connection);

#[derive(Serialize, Deserialize)]
struct User {
	pub username: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Session {
	pub auth_key: String,
	pub username: String,
}
impl Session {
	pub const COOKIE: &'static str = "session";
}
#[async_trait]
impl<'r> FromRequest<'r> for Session {
	type Error = ();

	async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		use rocket::{tokio::sync::Mutex, State};

		if let Some(req_session) = req
			.cookies()
			.get_private(Session::COOKIE)
			.and_then(|cookie| serde_json::from_str::<Session>(cookie.value()).ok())
		{
			let sessions = req
				.guard::<&State<Mutex<Sessions>>>()
				.await
				.unwrap()
				.lock()
				.await;
			if let Some(username) = sessions.get(&req_session.auth_key) {
				if username == &req_session.username {
					return Outcome::Success(req_session);
				}
			}
		}
		Outcome::Failure((Status::Unauthorized, ()))
	}
}

type Sessions = HashMap<String, String>;

#[launch]
fn rocket() -> _ {
	use rocket::{shield::Shield, tokio::sync::Mutex};
	use std::collections::HashMap;

	let sessions: Sessions = HashMap::new();

	rocket::build()
		.attach(Shield::new())
		.attach(DbConnection::fairing())
		.manage(Mutex::new(sessions))
		.mount("/", web::static_routes())
		.mount("/api", web::api_routes())
}
