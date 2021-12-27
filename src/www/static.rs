use crate::{Session, Sessions};
use either::Either;
use rocket::{
	fs::NamedFile,
	http::{CookieJar, Status},
	response::Redirect,
	tokio::sync::Mutex,
	Route, State,
};
use rocket_dyn_templates::Template;
use serde::Serialize;
use std::{io, path::Path};

#[derive(Serialize)]
struct SessionContext<'s> {
	href: &'static str,
	link: &'s str,
}
impl<'s> SessionContext<'s> {
	pub fn new(path_is_profile: bool, session: Option<&'s Session>) -> Self {
		session
			.map(|session| {
				if path_is_profile {
					Self {
						href: "/signout",
						link: "Sign out",
					}
				} else {
					Self {
						href: "/profile",
						link: &session.username,
					}
				}
			})
			.unwrap_or(Self {
				href: "/sign",
				link: "Sign in/up",
			})
	}
}

#[get("/")]
async fn index(session: Option<Session>) -> Template {
	Template::render("index", SessionContext::new(false, session.as_ref()))
}

#[get("/article?<file>")]
async fn article(
	session: Option<Session>,
	file: &str,
) -> Either<Either<Template, io::Result<NamedFile>>, Status> {
	// NOTE: Path traversal vulnerable
	let path = format!("articles/{}", file);
	let abspath = format!("./static/{}", path);
	if Path::new(&(abspath.clone() + ".html.hbs")).exists() {
		Either::Left(Either::Left(Template::render(
			path,
			SessionContext::new(false, session.as_ref()),
		)))
	} else if Path::new(&abspath).exists() {
		Either::Left(Either::Right(NamedFile::open(abspath).await))
	} else {
		Either::Right(Status::NotFound)
	}
}

#[get("/sign")]
async fn sign(session: Option<Session>) -> Either<io::Result<NamedFile>, Redirect> {
	if session.is_none() {
		Either::Left(NamedFile::open("static/sign.html").await)
	} else {
		Either::Right(Redirect::to("/profile"))
	}
}

#[get("/profile")]
async fn profile(session: Session) -> Template {
	Template::render("profile", SessionContext::new(true, Some(&session)))
}

#[get("/signout")]
async fn signout(
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
	routes![index, article, sign, profile, signout]
}
