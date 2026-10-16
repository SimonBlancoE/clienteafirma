//! Puente entre los hilos de trabajo y la interfaz: los almacenes y los
//! firmadores piden PIN, contraseñas o confirmaciones desde hilos de fondo y
//! esperan la respuesta del usuario.

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};

use afirma_keystores::{ConfirmRequest, PasswordCallback, PasswordRequest, PasswordResponse};
use eframe::egui;

/// Petición a la interfaz.
pub enum UiRequest {
    Password { request: PasswordRequest, reply: Sender<PasswordResponse> },
    ConfirmSignature { message: String, reply: Sender<bool> },
    Confirm { title: String, message: String, reply: Sender<bool> },
    /// Texto libre (p. ej. la contraseña de un PDF). `None` = cancelado.
    Text { prompt: String, secret: bool, reply: Sender<Option<String>> },
}

/// Extremo que usan los hilos de trabajo.
#[derive(Clone)]
pub struct UiBridge {
    tx: Sender<UiRequest>,
    ctx: egui::Context,
}

impl UiBridge {
    pub fn new(ctx: &egui::Context) -> (UiBridge, Receiver<UiRequest>) {
        let (tx, rx) = channel();
        (UiBridge { tx, ctx: ctx.clone() }, rx)
    }

    fn ask<T>(&self, build: impl FnOnce(Sender<T>) -> UiRequest, default: T) -> T {
        let (reply, rx) = channel();
        if self.tx.send(build(reply)).is_err() {
            return default;
        }
        self.ctx.request_repaint();
        rx.recv().unwrap_or(default)
    }

    /// Pide una contraseña genérica (p. ej. la de un PDF protegido).
    pub fn ask_password(&self, prompt: &str) -> Option<String> {
        let prompt = prompt.to_string();
        self.ask(|reply| UiRequest::Text { prompt, secret: true, reply }, None)
    }

    /// Pregunta sí/no al usuario.
    pub fn confirm(&self, title: impl Into<String>, message: impl Into<String>) -> bool {
        let (title, message) = (title.into(), message.into());
        self.ask(|reply| UiRequest::Confirm { title, message, reply }, false)
    }
}

impl PasswordCallback for UiBridge {
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse {
        let request = request.clone();
        self.ask(|reply| UiRequest::Password { request, reply }, PasswordResponse::Cancelled)
    }

    fn confirm_signature(&self, request: &ConfirmRequest) -> bool {
        let message = request.message.clone();
        self.ask(|reply| UiRequest::ConfirmSignature { message, reply }, false)
    }
}

/// Cola de peticiones pendientes que atiende la interfaz (una cada vez).
pub struct UiInbox {
    rx: Receiver<UiRequest>,
    pub current: Option<UiRequest>,
    /// Texto que el usuario está escribiendo en el diálogo de contraseña.
    pub secret: String,
    pub remember: bool,
}

impl UiInbox {
    pub fn new(rx: Receiver<UiRequest>) -> Self {
        UiInbox { rx, current: None, secret: String::new(), remember: false }
    }

    /// Toma la siguiente petición si no hay ninguna en curso.
    pub fn pump(&mut self) {
        if self.current.is_none() {
            if let Ok(r) = self.rx.try_recv() {
                self.secret.clear();
                self.remember = false;
                self.current = Some(r);
            }
        }
    }
}

/// Estado compartido opcional (para pruebas).
pub type SharedInbox = Mutex<UiInbox>;
