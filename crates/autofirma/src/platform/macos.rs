//! macOS: URL `afirma://` (evento `kAEGetURL`) y ficheros abiertos desde el
//! Finder (`application:openURLs:`).
//!
//! winit registra su propio delegado de aplicación y comprueba en cada evento
//! que sigue siéndolo (si se sustituye, la aplicación aborta), así que no se
//! cambia: `application:openURLs:` se añade a su clase al recibir
//! `NSApplicationWillFinishLaunchingNotification`, antes de que AppKit entregue
//! los documentos con los que se ha abierto la aplicación. El manejador de
//! `kAEGetURL` (que winit no registra) se instala antes de arrancar la ventana,
//! para no perder la URL con la que el navegador lanza la aplicación, y otra
//! vez al crearla, por si AppKit lo hubiera sustituido.

use std::path::PathBuf;
use std::sync::{Once, OnceLock};

use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Imp, NSObject, Sel};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::NSApplication;
use objc2_foundation::{
    NSAppleEventDescriptor, NSAppleEventManager, NSArray, NSNotification, NSNotificationCenter, NSObjectProtocol,
    NSString, NSURL,
};

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
    /// Receptor del evento de URL y de la notificación de arranque.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AutoFirmaRsEventHandler"]
    struct EventHandler;

    impl EventHandler {
        #[unsafe(method(handleGetURLEvent:withReplyEvent:))]
        fn handle_get_url(&self, event: &NSAppleEventDescriptor, _reply: &NSAppleEventDescriptor) {
            let param: Option<Retained<NSAppleEventDescriptor>> =
                unsafe { msg_send![event, paramDescriptorForKeyword: KEY_DIRECT_OBJECT] };
            if let Some(text) = param.and_then(|d| d.stringValue()) {
                push(Opened::Url(text.to_string()));
            }
        }

        #[unsafe(method(applicationWillFinishLaunching:))]
        fn will_finish_launching(&self, _notification: &NSNotification) {
            extend_app_delegate(self.mtm());
        }
    }

    unsafe impl NSObjectProtocol for EventHandler {}
);

impl EventHandler {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

/// Receptor único del proceso (AppKit y el centro de notificaciones no lo retienen).
fn handler(mtm: MainThreadMarker) -> &'static EventHandler {
    static HANDLER: OnceLock<usize> = OnceLock::new();
    let ptr = *HANDLER.get_or_init(|| Retained::into_raw(EventHandler::new(mtm)) as usize);
    // SAFETY: el objeto se retuvo arriba y no se libera nunca; solo se usa en
    // el hilo principal (MainThreadMarker).
    unsafe { &*(ptr as *const EventHandler) }
}

/// `application:openURLs:` del delegado de la aplicación (ficheros abiertos
/// desde el Finder o arrastrados al icono del Dock).
unsafe extern "C-unwind" fn open_urls(
    _this: *mut AnyObject,
    _cmd: Sel,
    _app: *mut AnyObject,
    urls: *mut NSArray<NSURL>,
) {
    // SAFETY: AppKit pasa un NSArray<NSURL> válido durante la llamada.
    if let Some(urls) = unsafe { urls.as_ref() } {
        for url in urls.iter() {
            push_url(&url);
        }
    }
}

/// Añade `application:openURLs:` a la clase del delegado que ha registrado
/// winit, sin sustituirlo.
fn extend_app_delegate(mtm: MainThreadMarker) {
    let app = NSApplication::sharedApplication(mtm);
    let Some(delegate) = app.delegate() else {
        tracing::warn!("La aplicación no tiene delegado: no se recibirán ficheros del Finder");
        return;
    };
    let obj: &AnyObject = delegate.as_ref();
    let class: &AnyClass = obj.class();
    let sel = sel!(application:openURLs:);
    if class.responds_to(sel) {
        return;
    }
    // SAFETY: la firma de `open_urls` corresponde a la codificación «v@:@@»
    // (void; self, _cmd, NSApplication*, NSArray*).
    let added = unsafe {
        let imp: Imp = std::mem::transmute::<
            unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, *mut NSArray<NSURL>),
            Imp,
        >(open_urls);
        objc2::ffi::class_addMethod(std::ptr::from_ref(class).cast_mut(), sel, imp, c"v@:@@".as_ptr())
    };
    if added.as_bool() {
        // Se vuelve a asignar el mismo delegado por si AppKit guarda qué métodos implementa.
        app.setDelegate(Some(&delegate));
        tracing::debug!("Recepción de ficheros del Finder añadida al delegado de la aplicación");
    } else {
        tracing::warn!("No se ha podido añadir la recepción de ficheros del Finder");
    }
}

/// Registra el manejador de `kAEGetURL` y, una vez, la espera del arranque de
/// la aplicación. Debe llamarse en el hilo principal.
pub fn install_url_handler() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let handler: &AnyObject = handler(mtm).as_ref();
    static OBSERVER: Once = Once::new();
    OBSERVER.call_once(|| {
        let name = NSString::from_str("NSApplicationWillFinishLaunchingNotification");
        // SAFETY: el receptor vive todo el proceso e implementa el selector.
        unsafe {
            NSNotificationCenter::defaultCenter().addObserver_selector_name_object(
                handler,
                sel!(applicationWillFinishLaunching:),
                Some(&name),
                None,
            );
        }
    });
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

/// Con la aplicación ya creada: de nuevo el manejador de URL y, si no llegó a
/// hacerse al arrancar, la recepción de ficheros del Finder.
pub fn install() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    install_url_handler();
    extend_app_delegate(mtm);
}
