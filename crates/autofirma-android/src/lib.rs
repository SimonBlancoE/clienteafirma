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
//! - [`shell`]: la aplicación (pila de pantallas, diálogos, eventos y acciones).
//! - [`nav`]: pantallas y navegación (botón «Atrás»).
//! - [`ui`]: tema, componentes táctiles, pantallas y diálogos con egui.
//! - [`i18n`]: textos en los seis idiomas del original.
//! - [`prefs`]: preferencias (`afirma.client`) y [`history`]: histórico de firmas.
//! - [`ime`]: teclado en pantalla de GameActivity para los campos de texto de egui.
//! - [`features`]: peticiones sueltas a la plataforma («Ver un certificado», enlaces,
//!   peticiones `afirma://`).
//! - [`flow`]: operaciones de varios pasos: firma local e importación de certificados.
//! - [`local_sign`]: formato, parámetros, firma y nombre del fichero firmado.
//! - [`visible`]: vista previa de la firma visible y conversión del área a puntos PDF.
//! - [`keychain`]: clave de firma ([`afirma_core::SigningKey`]) de un alias de KeyChain,
//!   avisos sobre el certificado y caché de certificado.
//! - [`errors`]: catálogo de errores `AA` del original.
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

/// Marca una clave de los catálogos que llega a [`i18n::tr`] a través de una variable (la
/// prueba `catalogos_completos` comprueba que existe).
macro_rules! k {
    ($key:literal) => {
        $key
    };
}

pub mod bridge;
pub mod errors;
pub mod features;
pub mod flow;
pub mod history;
pub mod i18n;
pub mod ime;
pub mod keychain;
pub mod local_sign;
pub mod nav;
pub mod prefs;
pub mod shell;
pub mod ui;
pub mod visible;

#[cfg(test)]
mod testing;

#[cfg(target_os = "android")]
mod android;

/// Nombre de la aplicación.
pub const APP_NAME: &str = "AutoFirma";

/// Versión del espacio de trabajo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Repositorio del código fuente (`[workspace.package] repository`).
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Etiqueta de los mensajes de la aplicación en logcat.
pub const LOG_TAG: &str = "AutoFirma";
