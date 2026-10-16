//! Interfaz gráfica de AutoFirma-rs (egui).

pub mod app;
pub mod cert_picker;
mod demo;
pub mod dialogs;
pub mod flows;
pub mod icons;
pub mod model;
pub mod pages;
pub mod protocol_flow;
pub mod request_view;
pub mod theme;
pub mod visible_sig;
pub mod widgets;

pub use app::AutoFirmaApp;
