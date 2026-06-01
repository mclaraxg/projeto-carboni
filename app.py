from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import closing
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

from security import (
    PASSWORD_POLICY_DESCRIPTION,
    hash_password,
    is_password_strong,
    verify_password,
)


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "auth.db"
LOG_PATH = BASE_DIR / "auth.log"
LOCKOUT_THRESHOLD = 3
LOCKOUT_MINUTES = 5


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")
    app.config["DATABASE"] = str(DATABASE_PATH)

    setup_logging()

    @app.before_request
    def load_current_user() -> None:
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            g.user = get_user_by_id(user_id)

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not username or not email or not password:
                flash("Preencha todos os campos.", "error")
                return render_template("register.html", policy=PASSWORD_POLICY_DESCRIPTION)

            if not is_password_strong(password):
                flash("Senha fraca. " + PASSWORD_POLICY_DESCRIPTION, "error")
                return render_template("register.html", policy=PASSWORD_POLICY_DESCRIPTION)

            if get_user_by_email(email) is not None:
                flash("E-mail já cadastrado.", "error")
                return render_template("register.html", policy=PASSWORD_POLICY_DESCRIPTION)

            salt, password_hash = hash_password(password)
            now = current_utc_iso()

            execute_query(
                """
                INSERT INTO users (username, email, password_salt, password_hash, failed_attempts, locked_until, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, NULL, ?, ?)
                """,
                (username, email, salt, password_hash, now, now),
            )
            logging.info("Cadastro realizado para o usuário %s (%s)", username, email)
            flash("Cadastro realizado com sucesso. Faça login.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", policy=PASSWORD_POLICY_DESCRIPTION)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = get_user_by_email(email)

            if user is None:
                logging.warning("Falha de login para e-mail desconhecido: %s", email)
                flash("Usuário ou senha inválidos.", "error")
                return render_template("login.html")

            if is_locked(user):
                flash("Conta temporariamente bloqueada. Tente novamente mais tarde.", "error")
                logging.warning("Login bloqueado para o usuário %s (%s)", user["username"], user["email"])
                return render_template("login.html")

            if verify_password(password, user["password_salt"], user["password_hash"]):
                reset_login_state(user["id"])
                session["user_id"] = user["id"]
                logging.info("Login autorizado para %s (%s)", user["username"], user["email"])
                flash("Acesso autorizado.", "success")
                return redirect(url_for("dashboard"))

            failed_attempts = int(user["failed_attempts"]) + 1
            locked_until = None
            if failed_attempts >= LOCKOUT_THRESHOLD:
                locked_until_dt = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                locked_until = locked_until_dt.isoformat()
                logging.warning(
                    "Usuário %s (%s) bloqueado por excesso de tentativas",
                    user["username"],
                    user["email"],
                )
            else:
                logging.warning("Falha de login para %s (%s)", user["username"], user["email"])

            update_login_attempts(user["id"], failed_attempts, locked_until)
            flash("Usuário ou senha inválidos.", "error")
            return render_template("login.html")

        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard():
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return render_template("dashboard.html", user=g.user)

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Sessão encerrada.", "success")
        return redirect(url_for("login"))

    @app.route("/demo-reset", methods=["POST"])
    def demo_reset():
        if not session.get("user_id"):
            return redirect(url_for("login"))
        reset_login_state(session["user_id"])
        flash("Estado de bloqueio e falhas redefinido para demonstração.", "success")
        return redirect(url_for("dashboard"))

    init_db()
    return app


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler()],
    )


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def execute_query(query: str, params: tuple = ()) -> None:
    with closing(get_connection()) as connection:
        connection.execute(query, params)
        connection.commit()


def fetch_one(query: str, params: tuple = ()):
    with closing(get_connection()) as connection:
        cursor = connection.execute(query, params)
        return cursor.fetchone()


def init_db() -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def current_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_user_by_email(email: str):
    return fetch_one("SELECT * FROM users WHERE email = ?", (email,))


def get_user_by_id(user_id: int):
    return fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))


def is_locked(user) -> bool:
    locked_until = user["locked_until"]
    if not locked_until:
        return False
    locked_until_dt = datetime.fromisoformat(locked_until)
    return datetime.now(timezone.utc) < locked_until_dt


def update_login_attempts(user_id: int, failed_attempts: int, locked_until: str | None) -> None:
    execute_query(
        """
        UPDATE users
        SET failed_attempts = ?, locked_until = ?, updated_at = ?
        WHERE id = ?
        """,
        (failed_attempts, locked_until, current_utc_iso(), user_id),
    )


def reset_login_state(user_id: int) -> None:
    execute_query(
        """
        UPDATE users
        SET failed_attempts = 0, locked_until = NULL, updated_at = ?
        WHERE id = ?
        """,
        (current_utc_iso(), user_id),
    )


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)