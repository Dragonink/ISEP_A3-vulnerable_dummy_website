#![warn(clippy::all)]
#![deny(clippy::correctness)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate async_recursion;
use rocket::{
	http::Status,
	request::{FromRequest, Outcome},
	Request,
};
use rocket_sync_db_pools::{database, rusqlite::Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod www {
	mod api;
	mod r#static;

	pub(crate) use api::routes as api_routes;
	pub(crate) use r#static::routes as static_routes;
}

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
	pub const COOKIE: &'static str = "__Host-session";
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
	use rocket_dyn_templates::Template;

	let sessions = Sessions::new();

	rocket::build()
		.attach(Shield::new())
		.attach(DbConnection::fairing())
		.attach(Template::fairing())
		.manage(Mutex::new(sessions))
		.mount("/", www::static_routes())
		.mount("/api", www::api_routes())
}
