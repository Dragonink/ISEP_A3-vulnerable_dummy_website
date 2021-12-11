mod api {
	use crate::{Session, Sessions};
	use rocket::{
		form::Form,
		http::Status,
		response::{self, Redirect, Responder},
		tokio::sync::Mutex,
		Request, Route, State,
	};
	use rocket_sync_db_pools::rusqlite::params;

	fn print_bytes(bytes: &[u8]) -> String {
		let mut s = String::new();
		for b in bytes {
			s += &format!("{:x}", *b);
		}
		s
	}

	struct LoginResponder(Session);
	impl<'r, 'o: 'r> Responder<'r, 'o> for LoginResponder {
		fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
			use rocket::http::Cookie;

			let mut cookie = Cookie::new(
				Session::COOKIE,
				serde_json::to_string(&self.0).map_err(|_err| Status::InternalServerError)?,
			);
			cookie.set_secure(Some(true));
			req.cookies().add_private(cookie);

			Redirect::to("/profile").respond_to(req)
		}
	}

	#[derive(FromForm)]
	struct SignForm<'s> {
		username: &'s str,
		password: &'s str,
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
		routes![register, login]
	}
}
pub(crate) use api::routes as api_routes;

mod r#static {
	use crate::{Session, Sessions};
	use either::Either;
	use rocket::{
		fs::NamedFile, http::CookieJar, response::Redirect, tokio::sync::Mutex, Route, State,
	};
	use std::io;

	#[get("/sign")]
	async fn sign(session: Option<Session>) -> Either<io::Result<NamedFile>, Redirect> {
		if session.is_none() {
			Either::Left(NamedFile::open("static/sign.html").await)
		} else {
			Either::Right(Redirect::to("/profile"))
		}
	}

	#[get("/profile")]
	async fn profile(_session: Session) -> io::Result<NamedFile> {
		NamedFile::open("static/profile.html").await
	}

	#[get("/logout")]
	async fn logout(
		sessions: &State<Mutex<Sessions>>,
		jar: &CookieJar<'_>,
		session: Session,
	) -> Redirect {
		use rocket::http::Cookie;

		let mut sessions = sessions.lock().await;
		sessions.remove(&session.auth_key);
		jar.remove_private(Cookie::named(Session::COOKIE));

		Redirect::to("/sign")
	}

	pub(crate) fn routes() -> Vec<Route> {
		routes![sign, profile, logout]
	}
}
pub(crate) use r#static::routes as static_routes;
