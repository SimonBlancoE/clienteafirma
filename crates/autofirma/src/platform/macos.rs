//! macOS: URL `afirma://` (evento `kAEGetURL`) y ficheros abiertos desde el
//! Finder (`application:openURLs:`).
//!
//! winit no registra delegado de aplicación ni manejador de URL, así que se
//! instalan aquí. El manejador de `kAEGetURL` se registra antes de arrancar la
//! ventana (para no perder la URL con la que el navegador lanza la
//! aplicación) y otra vez al crearla, por si AppKit lo hubiera sustituido.

use std::path::PathBuf;
use std::sync::OnceLock;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, ProtocolObject};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{NSApplication, NSApplicationDelegate};
use objc2_foundation::{NSAppleEventDescriptor, NSAppleEventManager, NSArray, NSObjectProtocol, NSURL};

use super::{Opened, push};

/// `kInternetEventClass` y `kAEGetURL` ('GURL').
const GURL: u32 = u32::from_be_bytes(*b"GURL");
/// `keyDirectObject` ('----').
const KEY_DIRECT_OBJECT: u32 = u32::from_be_bytes(*b"----");

fn push_url(url: &NSURL) {
    if url.isFileURL() {
        if let Some(p) = url.path() {
            push(Opened::File(PathBuf::from(p.to_string())));
        }
    } else if let Some(s) = url.absoluteString() {
        push(Opened::Url(s.to_string()));
    }
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AutoFirmaRsAppDelegate"]
    struct AppDelegate;

    impl AppDelegate {
        #[unsafe(method(handleGetURLEvent:withReplyEvent:))]
        fn handle_get_url(&self, event: &NSAppleEventDescriptor, _reply: &NSAppleEventDescriptor) {
            let param: Option<Retained<NSAppleEventDescriptor>> =
                unsafe { msg_send![event, paramDescriptorForKeyword: KEY_DIRECT_OBJECT] };
            if let Some(text) = param.and_then(|d| d.stringValue()) {
                push(Opened::Url(text.to_string()));
            }
        }
    }

    unsafe impl NSObjectProtocol for AppDelegate {}

    unsafe impl NSApplicationDelegate for AppDelegate {
        #[unsafe(method(application:openURLs:))]
        fn application_open_urls(&self, _application: &NSApplication, urls: &NSArray<NSURL>) {
            for url in urls.iter() {
                push_url(&url);
            }
        }
    }
);

impl AppDelegate {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

/// Delegado único del proceso (AppKit solo guarda una referencia débil).
fn delegate(mtm: MainThreadMarker) -> &'static AppDelegate {
    static DELEGATE: OnceLock<usize> = OnceLock::new();
    let ptr = *DELEGATE.get_or_init(|| Retained::into_raw(AppDelegate::new(mtm)) as usize);
    // SAFETY: el objeto se retuvo arriba y no se libera nunca; solo se usa en
    // el hilo principal (MainThreadMarker).
    unsafe { &*(ptr as *const AppDelegate) }
}

/// Registra el manejador de `kAEGetURL`. Debe llamarse en el hilo principal.
pub fn install_url_handler() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let handler: &AnyObject = delegate(mtm).as_ref();
    let manager = NSAppleEventManager::sharedAppleEventManager();
    unsafe {
        let _: () = msg_send![
            &*manager,
            setEventHandler: handler,
            andSelector: sel!(handleGetURLEvent:withReplyEvent:),
            forEventClass: GURL,
            andEventID: GURL
        ];
    }
}

/// Con la aplicación ya creada: delegado (`application:openURLs:`) y de nuevo
/// el manejador de URL.
pub fn install() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);
    app.setDelegate(Some(ProtocolObject::from_ref(delegate(mtm))));
    install_url_handler();
}
