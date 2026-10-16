//! Recursos de Windows del ejecutable: icono, información de versión y manifiesto de
//! aplicación (`packaging/windows/autofirma.exe.manifest`):
//!
//! * `asInvoker`: nunca pide elevación (UAC) al abrirse desde el navegador o el menú Inicio;
//!   las operaciones de equipo (`install`/`uninstall --system`) las lanza el MSI, que ya
//!   se ejecuta elevado.
//! * PerMonitorV2: nitidez en pantallas HiDPI y al mover la ventana entre monitores.
//! * Common Controls 6: diálogos nativos (TaskDialog, selector de ficheros) actuales.
//! * `longPathAware`: rutas de más de 260 caracteres (si la directiva del sistema lo permite).
//! * Sin `activeCodePage` UTF-8 a propósito: cambiaría la página de códigos ANSI de las
//!   bibliotecas PKCS#11 de terceros que se cargan en el proceso (tarjetas inteligentes).
//!
//! El manifiesto no lleva comentarios: el analizador de Windows (SxS) es estricto y un XML
//! mal formado impide arrancar el programa (error 14001).
//!
//! Solo actúa cuando el **destino** es Windows (también al compilar de forma cruzada desde
//! Linux con MinGW, donde se usa `x86_64-w64-mingw32-windres`); en Linux y macOS no hace
//! nada. Variables de entorno:
//!
//! * `AUTOFIRMA_SKIP_WINRES=1`: no incrusta recursos (p. ej., sin `windres` disponible).
//! * `AUTOFIRMA_BUILD_NUMBER=<n>`: cuarto componente de `FILEVERSION` (0 por defecto).

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AUTOFIRMA_SKIP_WINRES");
    println!("cargo:rerun-if-env-changed=AUTOFIRMA_BUILD_NUMBER");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if env::var("AUTOFIRMA_SKIP_WINRES").is_ok_and(|v| v == "1") {
        println!(
            "cargo:warning=AUTOFIRMA_SKIP_WINRES=1: el ejecutable no llevará icono, versión ni manifiesto"
        );
        return;
    }

    // Raíz del repositorio sin «..» ni separadores mezclados (rc.exe y windres reciben la
    // ruta tal cual) y sin canonicalize(), que en Windows devuelve rutas \\?\ que rc.exe
    // no admite.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("crates/autofirma está dos niveles por debajo de la raíz");
    let icon = root.join("packaging").join("icons").join("autofirma.ico");
    let manifest = root
        .join("packaging")
        .join("windows")
        .join("autofirma.exe.manifest");
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", manifest.display());

    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let part = |name: &str| -> u64 {
        env::var(name)
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .map_or(0, u64::from)
    };
    let numeric = (part("CARGO_PKG_VERSION_MAJOR") << 48)
        | (part("CARGO_PKG_VERSION_MINOR") << 32)
        | (part("CARGO_PKG_VERSION_PATCH") << 16)
        | part("AUTOFIRMA_BUILD_NUMBER");

    let mut res = winresource::WindowsResource::new();
    res.set_icon(&icon.to_string_lossy())
        .set_manifest_file(&manifest.to_string_lossy())
        // Español (España, alfabetización internacional).
        .set_language(0x0C0A)
        .set_version_info(winresource::VersionInfo::FILEVERSION, numeric)
        .set_version_info(winresource::VersionInfo::PRODUCTVERSION, numeric)
        .set("ProductName", "AutoFirma")
        // Windows muestra FileDescription como nombre de la aplicación (Administrador de
        // tareas, diálogo «Abrir con», avisos de SmartScreen).
        .set("FileDescription", "AutoFirma")
        .set("CompanyName", "AutoFirma-rs")
        .set("LegalCopyright", "AutoFirma-rs (GPL-2.0-or-later OR EUPL-1.1). Basado en Autofirma (C) Gobierno de España")
        .set("OriginalFilename", "autofirma.exe")
        .set("InternalName", "autofirma")
        .set("FileVersion", &version)
        .set("ProductVersion", &version);
    if let Err(e) = res.compile() {
        panic!(
            "No se pudieron compilar los recursos de Windows (icono, versión, manifiesto): {e}. \
             Instale el compilador de recursos (rc.exe del SDK de Windows o windres de MinGW) \
             o defina AUTOFIRMA_SKIP_WINRES=1."
        );
    }
}
