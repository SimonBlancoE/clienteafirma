//! Servicios de la aplicación: conectan la interfaz con los motores de
//! firma, los almacenes de certificados y el sistema.

pub mod bridge;
pub mod certs;
pub mod certval;
pub mod config_verifier;
pub mod desktop;
pub mod files;
pub mod instance;
pub mod messages;
pub mod network;
pub mod pdf_pages;
pub mod prefs;
pub mod protocol;
pub mod signing;
pub mod task;
pub mod tools;
pub mod updater;
pub mod verify;
