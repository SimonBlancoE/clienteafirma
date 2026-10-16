//! Textos de la interfaz del plugin «Validación de certificados»
//! (`plugin.json` y `messages.properties` de
//! `es.gob.afirma.plugin.certvalidation`), idénticos a los de Java (incluidas
//! sus erratas). Los textos del resultado están en
//! [`crate::ValidationResult::dialog_message`].

/// Título del plugin (`plugin.json`).
pub const PLUGIN_TITLE: &str = "Validación de certificados";

/// Descripción del plugin (`plugin.json`, con el marcado HTML original).
pub const PLUGIN_DESCRIPTION: &str = "Plugin para la comprobación del estado de certificados de firma.<br><br>Este plugin permite validar los certificados utilizados para firmar con Autofirma. La validación se realiza mediante mecanismos predefinidos para los certificados de algunos prestadores de servicios de confianza y, en caso de no tener estos mecanismos predefinidos, contra la CRL o el OCSP declarado en el propio certificado.<br><br>Asegúrese de utilizar únicamente certificados emitidos por prestadores de confianza para firmar, ya que un certificado de un origen desconocido podría declarar mecanismos de validación no seguros.";

/// Texto del botón de las pantallas de resultado (`single_result` y
/// `multi_result`).
pub const BUTTON_TITLE: &str = "Validar certificado de firma";

/// Ayuda emergente del botón.
pub const BUTTON_TOOLTIP: &str = "Validar el certificado con el que se ha realizado la firma";

/// Descripción accesible del botón.
pub const BUTTON_ACCESSIBLE_DESCRIPTION: &str = "Valida el certificado utilizado para firmar";

/// Recurso del icono del botón en Java.
pub const BUTTON_ICON_RESOURCE: &str = "es/gob/afirma/plugin/certvalidation/certificate_16.png";

/// `ValidateCertAction.9`: título del diálogo con el resultado.
pub const RESULT_DIALOG_TITLE: &str = "Estado de su certificado";

/// `ValidateCertAction.10`: no hay certificado de firma (con la errata
/// "esá" del original).
pub const NO_SIGNING_CERT: &str = "No esá definido el certificado de firma";

/// `ValidateCertAction.11`: título de los diálogos de error.
pub const ERROR_TITLE: &str = "Error";

/// `ValidateCertAction.12`: no se ha podido crear el validador.
pub const NO_MECHANISM: &str = "No se dispone de ningún mecanismo de validación para el tipo de certificado utilizado";

/// `ValidateCertAction.13`: título del diálogo de espera (modal; al cerrarlo
/// se cancela la validación sin avisar).
pub const WAIT_TITLE: &str = "Validando certificado";

/// `ValidateCertAction.14`: texto del diálogo de espera (con barra de
/// progreso indeterminada).
pub const WAIT_TEXT: &str = "Ejecutando proceso de validación...";
