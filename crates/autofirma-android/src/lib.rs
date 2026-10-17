//! AutoFirma-rs para Android.
//!
//! Biblioteca nativa (`libautofirma_android.so`) de la aplicación Android. La actividad
//! Java (`io.github.autofirma_rs.android.MainActivity`, subclase de `GameActivity`) carga
//! la biblioteca y `android-activity` arranca [`android_main`](crate#arranque) en un hilo
//! propio, donde se ejecuta la interfaz egui con `eframe`. La capa Java solo aporta lo que
//! únicamente existe en el SDK de Android: KeyChain, el selector de documentos (SAF), los
//! intents `afirma://` y el lector NFC. Véase `docs/ANDROID.md`.
//!
//! # Módulos
//!
//! - [`bridge`]: eventos que llegan de Java o de los hilos de trabajo, identificadores de
//!   petición y el rasgo [`Platform`](bridge::Platform) con las llamadas de Rust a Java.
//! - [`screen`]: pantalla principal (estado y dibujo con egui).
//! - [`document`]: análisis de un documento con los firmadores de `afirma-signers`.
//! - [`keychain`]: clave de firma ([`afirma_core::SigningKey`]) de un alias de KeyChain.
//! - `android` (solo `target_os = "android"`): punto de entrada, puente JNI y registro en
//!   logcat.
//!
//! En el anfitrión (Linux, Windows, macOS) solo se compilan los módulos independientes de
//! Android, de modo que `cargo test --workspace` y `cargo clippy --workspace` los
//! comprueban sin el NDK.
//!
//! # Arranque
//!
//! `android_on_create` (hilo principal de Java, dentro de `Activity.onCreate`) inicia el
//! registro en logcat y la verificación TLS de la plataforma; `android_main` (hilo nativo)
//! ejecuta `eframe` hasta que la actividad se destruye y entonces termina el proceso, porque
//! winit no permite crear un segundo bucle de eventos en el mismo proceso.

pub mod bridge;
pub mod document;
pub mod keychain;
pub mod screen;

#[cfg(target_os = "android")]
mod android;

/// Nombre de la aplicación.
pub const APP_NAME: &str = "AutoFirma";

/// Versión del espacio de trabajo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Etiqueta de los mensajes de la aplicación en logcat.
pub const LOG_TAG: &str = "AutoFirma";
