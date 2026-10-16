//! Integración de AutoFirma-rs con el sistema operativo.
//!
//! Equivalente a `afirma-ui-simple-configurator*`, a los instaladores y a la función
//! «Restaurar instalación» de la AutoFirma Java, más las mejoras para despliegues
//! corporativos silenciosos:
//!
//! * [`prefs`]: modelo tipado de todas las preferencias, capas usuario/sistema/directiva
//!   con bloqueo real, migración desde `java.util.prefs`, `.afconfig` y configuración remota.
//! * [`certs`]: CA local y certificado SSL de `127.0.0.1` (`autofirma.pfx`).
//! * [`trust`]: instalación y retirada de la CA en los almacenes del sistema y de NSS
//!   (Firefox, Chrome/Chromium en Linux).
//! * [`protocol`]: registro del manejador `afirma://`, menús contextuales y asociaciones.
//! * [`browser_policy`]: directivas de Chrome/Edge/Chromium/Firefox para invocar
//!   `afirma://` sin avisos (nuevo respecto a Java) y plantillas `.reg`/`.mobileconfig`.
//! * [`install`]: orquestación de instalación/desinstalación con modo simulación, y
//!   [`restore`] y [`doctor`]; [`cli`] ofrece las subórdenes listas para la aplicación
//!   (`install`, `uninstall`, `restore-config`, `doctor`, `policy-templates`, `configurator`).
//!
//! Todas las operaciones reciben un [`ctx::Context`] que abstrae la raíz del sistema de
//! ficheros, el registro de Windows y la ejecución de mandatos para poder probarlas.

pub mod browser_policy;
pub mod certs;
pub mod cli;
pub mod ctx;
pub mod doctor;
pub mod error;
pub mod exec;
pub mod firefox;
pub mod fsutil;
pub mod install;
pub mod prefs;
pub mod protocol;
pub mod registry;
pub mod restore;
pub mod state;
pub mod trust;
pub mod winpath;

pub use ctx::{AppIdentity, Context, Os};
pub use error::{Result, SystemError};
