//! Tabla completa de códigos de error de AutoFirma 1.9.1, generada a partir de
//! `docs/spec/07-core.md` §10.6 (todas las definiciones `new ErrorCode(...)` del
//! código Java). Las descripciones son las cadenas exactas de Java.
//!
//! Si un nombre se repite en varias clases Java, la constante de `ErrorCode`
//! conserva el nombre y la otra lleva el prefijo de su clase.

use super::ErrorCode;

/// `KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED` (afirma-core-keystores)
pub const KEYSTORE_SMARTCARD_LOCKED: ErrorCode = ErrorCode::new(102025, "La tarjeta inteligente esta bloqueada");
/// `ErrorCode.Internal.LIBRARY_NOT_FOUND` (afirma-core)
pub const LIBRARY_NOT_FOUND: ErrorCode = ErrorCode::new(
    200002,
    "No se encuentran dependencias necesarias para la ejecucion de la operacion",
);
/// `ErrorCode.Internal.LOADING_DATA_ERROR` (afirma-core)
pub const LOADING_DATA_ERROR: ErrorCode = ErrorCode::new(200003, "Error durante la carga de datos");
/// `SimpleErrorCode.Internal.CANT_LOAD_HELP` (afirma-simple)
pub const CANT_LOAD_HELP: ErrorCode = ErrorCode::new(200004, "No se ha podido cargar correctamente la ayuda");
/// `SimpleErrorCode.Internal.NOT_VALID_PLUGIN` (afirma-simple)
pub const NOT_VALID_PLUGIN: ErrorCode = ErrorCode::new(200005, "Plugin no valido");
/// `ErrorCode.Internal.ERROR_IMPORT_LANGUAGE` (afirma-core)
pub const ERROR_IMPORT_LANGUAGE: ErrorCode = ErrorCode::new(200006, "Error al importar idioma");
/// `SimpleErrorCode.Internal.ENCRIPTING_SIGNATURE` (afirma-simple)
pub const ENCRIPTING_SIGNATURE: ErrorCode =
    ErrorCode::new(200100, "Error al cifrar la firma para enviarla al servidor intermedio");
/// `SimpleErrorCode.Internal.ENCRIPTING_SIGNING_CERT` (afirma-simple)
pub const ENCRIPTING_SIGNING_CERT: ErrorCode = ErrorCode::new(
    200101,
    "Error al cifrar el certificado de firma para enviarlo al servidor intermedio",
);
/// `ErrorCode.Internal.LOADING_LOCAL_FILE_ERROR` (afirma-core)
pub const LOADING_LOCAL_FILE_ERROR: ErrorCode =
    ErrorCode::new(200102, "Error al cargar el fichero local para realizar la firma");
/// `ErrorCode.Internal.SIGNING_KEY_AUTHENTICATION_ERROR` (afirma-core)
pub const SIGNING_KEY_AUTHENTICATION_ERROR: ErrorCode =
    ErrorCode::new(200108, "No se pudo acceder a la clave de firma");
/// `ErrorCode.Internal.INVALID_SIGNING_KEY` (afirma-core)
pub const INVALID_SIGNING_KEY: ErrorCode = ErrorCode::new(
    200110,
    "La clave de firma no es valida o no es compatible con el algoritmo seleccionado",
);
/// `ErrorCode.Internal.SIGNING_PKCS1_ERROR` (afirma-core)
pub const SIGNING_PKCS1_ERROR: ErrorCode = ErrorCode::new(200111, "Error al generar la firma PKCS#1");
/// `ErrorCode.Internal.INVALID_PKCS1_VALUE` (afirma-core)
pub const INVALID_PKCS1_VALUE: ErrorCode =
    ErrorCode::new(200112, "La firma no se ha generado con el certificado seleccionado");
/// `ErrorCode.Internal.VERIFING_PKCS1_ERROR` (afirma-core)
pub const VERIFING_PKCS1_ERROR: ErrorCode = ErrorCode::new(200113, "No se pudo verificar la firma generada");
/// `ErrorCode.Internal.ENCODING_SIGNING_CERTIFICATE` (afirma-core)
pub const ENCODING_SIGNING_CERTIFICATE: ErrorCode = ErrorCode::new(200114, "Error codificando el certificado de firma");
/// `ErrorCode.Internal.UNKNOWN_SIGNING_ERROR` (afirma-core)
pub const UNKNOWN_SIGNING_ERROR: ErrorCode = ErrorCode::new(200115, "Error desconocido durante la operacion de firma");
/// `SimpleErrorCode.Internal.ENCRIPTING_SIGNATURE_EXTRA_DATA` (afirma-simple)
pub const ENCRIPTING_SIGNATURE_EXTRA_DATA: ErrorCode = ErrorCode::new(
    200116,
    "Error al cifrar la informacion extra de firma para enviarla al servidor intermedio",
);
/// `SimpleErrorCode.Internal.POSTPROCESING_SIGNATURE` (afirma-simple)
pub const POSTPROCESING_SIGNATURE: ErrorCode = ErrorCode::new(200117, "Error en el postproceso de la firma");
/// `ErrorCode.Internal.UNSUPPORTED_HASH_ALGORITHM` (afirma-core)
pub const UNSUPPORTED_HASH_ALGORITHM: ErrorCode =
    ErrorCode::new(200118, "No se soporta un algoritmo de hash establecido internamente");
/// `SimpleErrorCode.Internal.UNKNOWN_SIGNING_BY_SOCKETS_ERROR` (afirma-simple)
pub const UNKNOWN_SIGNING_BY_SOCKETS_ERROR: ErrorCode = ErrorCode::new(
    200118,
    "Error desconocido durante la operacion de firma usando la comunicacion por sockets",
);
/// `SimpleErrorCode.Internal.LOAD_FILE_TO_VIEW` (afirma-simple)
pub const LOAD_FILE_TO_VIEW: ErrorCode =
    ErrorCode::new(200119, "Error al cargar el fichero local para visualizar la firma");
/// `SimpleErrorCode.Internal.ENCRIPTING_SELECTED_CERT` (afirma-simple)
pub const ENCRIPTING_SELECTED_CERT: ErrorCode = ErrorCode::new(
    200200,
    "Error al cifrar el certificado seleccionado para enviarlo al servidor intermedio",
);
/// `SimpleErrorCode.Internal.UNKNOWN_SELECTING_CERT_ERROR` (afirma-simple)
pub const UNKNOWN_SELECTING_CERT_ERROR: ErrorCode = ErrorCode::new(
    200201,
    "Error desconocido durante la operacion de seleccion de certificado",
);
/// `SimpleErrorCode.Internal.CANT_SAVE_FILE` (afirma-simple)
pub const CANT_SAVE_FILE: ErrorCode = ErrorCode::new(200301, "No se ha podido guardar el fichero en disco");
/// `SimpleErrorCode.Internal.UNKNOWN_SAVING_DATA_ERROR` (afirma-simple)
pub const UNKNOWN_SAVING_DATA_ERROR: ErrorCode =
    ErrorCode::new(200305, "Error general durante la operacion de guardado de datos");
/// `SimpleErrorCode.Internal.ENCRIPTING_BATCH_RESULT` (afirma-simple)
pub const ENCRIPTING_BATCH_RESULT: ErrorCode = ErrorCode::new(
    200400,
    "Error al cifrar la informacion de las firmas del lote para enviarla al servidor intermedio",
);
/// `SimpleErrorCode.Internal.ENCRIPTING_BATCH_SIGNING_CERT` (afirma-simple)
pub const ENCRIPTING_BATCH_SIGNING_CERT: ErrorCode = ErrorCode::new(
    200401,
    "Error al cifrar el certificado de firma para enviarlo al servidor intermedio",
);
/// `BatchServiceErrorCode.Internal.INTERNAL_JSON_BATCH_ERROR` (afirma-server-triphase-signer)
pub const BATCHSERVICE_INTERNAL_JSON_BATCH_ERROR: ErrorCode =
    ErrorCode::new(200410, "Error interno al procesar un lote de firmas JSON");
/// `SimpleErrorCode.Internal.INTERNAL_JSON_BATCH_ERROR` (afirma-simple)
pub const SIMPLE_INTERNAL_JSON_BATCH_ERROR: ErrorCode =
    ErrorCode::new(200410, "Error interno al procesar un lote de firmas JSON");
/// `SimpleErrorCode.Internal.INTERNAL_XML_BATCH_ERROR` (afirma-simple)
pub const INTERNAL_XML_BATCH_ERROR: ErrorCode =
    ErrorCode::new(200411, "Error interno al procesar un lote de firmas XML");
/// `SimpleErrorCode.Internal.INTERNAL_LOCAL_BATCH_ERROR` (afirma-simple)
pub const INTERNAL_LOCAL_BATCH_ERROR: ErrorCode =
    ErrorCode::new(200412, "Error interno realizando la firma batch local");
/// `SimpleErrorCode.Internal.UNKNOWN_BATCH_ERROR` (afirma-simple)
pub const UNKNOWN_BATCH_ERROR: ErrorCode = ErrorCode::new(200413, "Error desconocido al procesar un lote de firmas");
/// `SimpleErrorCode.Internal.UNKNOWN_LOADING_DATA_ERROR` (afirma-simple)
pub const UNKNOWN_LOADING_DATA_ERROR: ErrorCode =
    ErrorCode::new(200600, "Error general durante la operacion de carga de fichero");
/// `SimpleErrorCode.Internal.CANT_LOAD_FILE` (afirma-simple)
pub const CANT_LOAD_FILE: ErrorCode = ErrorCode::new(200601, "Error al cargar el fichero local");
/// `SimpleErrorCode.Internal.NEEDS_UPDATED_VERSION` (afirma-simple)
pub const NEEDS_UPDATED_VERSION: ErrorCode = ErrorCode::new(200701, "Se necesita actualizar la aplicacion");
/// `SimpleErrorCode.Internal.NO_DETECTED_PROXIES` (afirma-simple)
pub const NO_DETECTED_PROXIES: ErrorCode = ErrorCode::new(200702, "No se han detectado proxies en el sisema");
/// `SimpleErrorCode.Internal.ERROR_LOAD_TRUSTED_CERT` (afirma-simple)
pub const ERROR_LOAD_TRUSTED_CERT: ErrorCode = ErrorCode::new(200800, "Error al cargar el certificado de confianza");
/// `SimpleErrorCode.Internal.TRUSTSTORE_INCORRECT_INSTALLATION` (afirma-simple)
pub const TRUSTSTORE_INCORRECT_INSTALLATION: ErrorCode = ErrorCode::new(
    200801,
    "El almacen de confianza de Autofirma no se encuentra instalado correctamente",
);
/// `KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR` (afirma-core-keystores)
pub const LOADING_KEYSTORE_INTERNAL_ERROR: ErrorCode =
    ErrorCode::new(201101, "Error generico al cargar el almacen de certificados");
/// `KeyStoreErrorCode.Internal.LOADING_PRIVATE_KEY_ERROR` (afirma-core-keystores)
pub const LOADING_PRIVATE_KEY_ERROR: ErrorCode = ErrorCode::new(201103, "Error al cargar la clave del certificado");
/// `KeyStoreErrorCode.Internal.LOADING_CERTIFICATE_ERROR` (afirma-core-keystores)
pub const LOADING_CERTIFICATE_ERROR: ErrorCode =
    ErrorCode::new(201106, "Error al cargar el certificado suelto o en PKCS#7");
/// `KeyStoreErrorCode.Internal.LOADING_WINDOWS_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_WINDOWS_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(201107, "Error al cargar el almacen de certificados de Windows");
/// `KeyStoreErrorCode.Internal.LOADING_MOZILLA_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_MOZILLA_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(201108, "Error al cargar el almacen de certificados de Mozilla");
/// `KeyStoreErrorCode.Internal.LOADING_APPLE_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_APPLE_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(201109, "Error al cargar el almacen de certificados Apple KeyRing");
/// `KeyStoreErrorCode.Internal.LOADING_PKCS12_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_PKCS12_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(201110, "Error al cargar el almacen de certificados PKCS#12");
/// `KeyStoreErrorCode.Internal.LOADING_JAVA_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_JAVA_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(201111, "Error al cargar el almacen de certificados JKS");
/// `KeyStoreErrorCode.Internal.LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR: ErrorCode = ErrorCode::new(
    201112,
    "Error al cargar el almacen de certificados de claves publicas de Windows",
);
/// `KeyStoreErrorCode.Internal.LOADING_PKCS11_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_PKCS11_KEYSTORE_ERROR: ErrorCode = ErrorCode::new(
    201113,
    "Error al cargar el almacen de certificados a traves del PKCS#11",
);
/// `KeyStoreErrorCode.Internal.LOADING_JMULTICARD_KEYSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_JMULTICARD_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(201114, "Error al cargar el almacen de certificados con JMulticard");
/// `KeyStoreErrorCode.Internal.LOADING_FILE_CERTSTORE_ERROR` (afirma-core-keystores)
pub const LOADING_FILE_CERTSTORE_ERROR: ErrorCode =
    ErrorCode::new(201115, "Error al cargar un certificado desde fichero");
/// `KeyStoreErrorCode.Internal.UNDEFINED_DEFAULT_KEYSTORE` (afirma-core-keystores)
pub const UNDEFINED_DEFAULT_KEYSTORE: ErrorCode = ErrorCode::new(
    201116,
    "No hay definido un almacen de claves por defecto para este sistema operativo",
);
/// `BinaryErrorCode.Internal.UNKWNON_BINARY_SIGNING_ERROR` (afirma-crypto-core-pkcs7)
pub const UNKWNON_BINARY_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(211001, "Error desconocido en la generacion de la firma binaria");
/// `BinaryErrorCode.Internal.INTERNAL_BINARY_SIGNING_ERROR` (afirma-crypto-core-pkcs7)
pub const INTERNAL_BINARY_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(211002, "Error interno en la generacion de la firma binaria");
/// `BinaryErrorCode.Internal.GENERATING_TIMESTAMP_ERROR` (afirma-crypto-core-pkcs7)
pub const GENERATING_TIMESTAMP_ERROR: ErrorCode = ErrorCode::new(211003, "Error generando sello de tiempo binario");
/// `PdfErrorCode.Internal.UNKWNON_PADES_SIGNING_ERROR` (afirma-crypto-pdf-common)
pub const UNKWNON_PADES_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(212001, "Error desconocido en la generacion de la firma PAdES");
/// `PdfErrorCode.Internal.INTERNAL_PADES_SIGNING_ERROR` (afirma-crypto-pdf-common)
pub const INTERNAL_PADES_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(212002, "Error interno en la generacion de la firma PAdES");
/// `PdfErrorCode.Internal.SIGNING_PDF_WITH_UNREGISTER_SIGNATURES` (afirma-crypto-pdf-common)
pub const SIGNING_PDF_WITH_UNREGISTER_SIGNATURES: ErrorCode = ErrorCode::new(
    212003,
    "Se esta intentando firmar una firma PDF con firmas sin registrar",
);
/// `PdfErrorCode.Internal.SIGNING_PDF_WITH_BAD_PASSWORD` (afirma-crypto-pdf-common)
pub const SIGNING_PDF_WITH_BAD_PASSWORD: ErrorCode = ErrorCode::new(212004, "La contrasena del PDF no era correcta");
/// `PdfErrorCode.Internal.SIGNING_PDF_WITHOUT_PASSWORD` (afirma-crypto-pdf-common)
pub const SIGNING_PDF_WITHOUT_PASSWORD: ErrorCode = ErrorCode::new(212005, "El PDF necesita contrasena");
/// `PdfErrorCode.Internal.SIGNING_PDF_WITH_MODIFIED_FORM` (afirma-crypto-pdf-common)
pub const SIGNING_PDF_WITH_MODIFIED_FORM: ErrorCode = ErrorCode::new(
    212006,
    "Se esta intentando firmar un PDF con un formulario modificado despues de una firma anterior",
);
/// `PdfErrorCode.Internal.SIGNING_PDF_WITH_CERTIFIED_SIGN` (afirma-crypto-pdf-common)
pub const SIGNING_PDF_WITH_CERTIFIED_SIGN: ErrorCode = ErrorCode::new(
    212007,
    "Se esta intentando firmar un PDF certificado que no admite nuevas firmas",
);
/// `PdfErrorCode.Internal.SIGNING_PDF_WITH_SUSPICION_OF_PSA` (afirma-crypto-pdf-common)
pub const SIGNING_PDF_WITH_SUSPICION_OF_PSA: ErrorCode = ErrorCode::new(
    212008,
    "Se esta intentando firmar un PDF sospechoso de haber sido modificado tras la firma",
);
/// `XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR` (afirma-crypto-core-xml)
pub const UNKWNON_XML_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(213001, "Error desconocido en la generacion de la firma XML");
/// `XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR` (afirma-crypto-core-xml)
pub const INTERNAL_XML_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(213002, "Error interno en la generacion de la firma XML");
/// `ODFErrorCode.Internal.UNKWNON_ODF_SIGNING_ERROR` (afirma-crypto-odf)
pub const UNKWNON_ODF_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(213003, "Error desconocido en la generacion de la firma ODF");
/// `XMLErrorCode.Internal.UNSUPPORTED_TRANSFORMATION_ALGORITHM` (afirma-crypto-core-xml)
pub const UNSUPPORTED_TRANSFORMATION_ALGORITHM: ErrorCode =
    ErrorCode::new(213004, "El tipo de transformacion declarado no esta soportado");
/// `ODFErrorCode.Internal.INTERNAL_ODF_SIGNING_ERROR` (afirma-crypto-odf)
pub const INTERNAL_ODF_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(213004, "Error interno en la generacion de la firma ODF");
/// `OOXMLErrorCode.Internal.UNKWNON_OOXML_SIGNING_ERROR` (afirma-crypto-ooxml)
pub const UNKWNON_OOXML_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(213005, "Error desconocido en la generacion de la firma OOXML");
/// `OOXMLErrorCode.Internal.INTERNAL_OOXML_SIGNING_ERROR` (afirma-crypto-ooxml)
pub const INTERNAL_OOXML_SIGNING_ERROR: ErrorCode =
    ErrorCode::new(213006, "Error interno en la generacion de la firma OOXML");
/// `ErrorCode.Internal.BUILDING_ASIC_CONTAINER_ERROR` (afirma-core)
pub const BUILDING_ASIC_CONTAINER_ERROR: ErrorCode =
    ErrorCode::new(214001, "Error al construir el contenedor ASiC de la nueva firma");
/// `SimpleErrorCode.Internal.SOCKET_INITIALIZING_ERROR` (afirma-simple)
pub const SOCKET_INITIALIZING_ERROR: ErrorCode = ErrorCode::new(220001, "No se pudo abrir el socket de comunicacion");
/// `SimpleErrorCode.Internal.DECRYPTING_PARAMS_ERROR` (afirma-simple)
pub const DECRYPTING_PARAMS_ERROR: ErrorCode = ErrorCode::new(220002, "Error desencriptando los datos del servidor");
/// `SimpleErrorCode.Internal.ERROR_RECIVED_FROM_CLIENT` (afirma-simple)
pub const ERROR_RECIVED_FROM_CLIENT: ErrorCode =
    ErrorCode::new(220003, "El servicio cliente ya notifico un error durante la peticion");
/// `SimpleErrorCode.Internal.ENCRYPTING_PARAMS_ERROR` (afirma-simple)
pub const ENCRYPTING_PARAMS_ERROR: ErrorCode = ErrorCode::new(220004, "Error encriptando los datos del servidor");
/// `SimpleErrorCode.Internal.LOADING_SSL_KEYSTORE_ERROR` (afirma-simple)
pub const LOADING_SSL_KEYSTORE_ERROR: ErrorCode =
    ErrorCode::new(220008, "No se ha podido cargar el almacen de claves SSL");
/// `SimpleErrorCode.Internal.GENERIC_LANGUAGE_IMPORT_ERROR` (afirma-simple)
pub const GENERIC_LANGUAGE_IMPORT_ERROR: ErrorCode = ErrorCode::new(230100, "Error importando el idioma");
/// `SimpleErrorCode.Internal.CANT_READ_FILE` (afirma-simple)
pub const CANT_READ_FILE: ErrorCode = ErrorCode::new(230101, "No se ha podido leer correctamente el archivo ZIP");
/// `SimpleErrorCode.Internal.CANT_CREATE_DIRECTORY` (afirma-simple)
pub const CANT_CREATE_DIRECTORY: ErrorCode =
    ErrorCode::new(230102, "Se ha producido un error al crear el directorio del idioma");
/// `PluginManagerError.Internal.PLUGIN_ERROR` (afirma-simple-plugins-manager)
pub const PLUGIN_ERROR: ErrorCode = ErrorCode::new(230200, "Error desconocido con el plugin");
/// `PluginManagerError.Internal.UNINSTALL_PLUGIN_ERROR` (afirma-simple-plugins-manager)
pub const UNINSTALL_PLUGIN_ERROR: ErrorCode = ErrorCode::new(230201, "Ocurrio un error al desinstalar el plugin");
/// `PluginManagerError.Internal.ERROR_IN_PLUGIN` (afirma-simple-plugins-manager)
pub const ERROR_IN_PLUGIN: ErrorCode =
    ErrorCode::new(230202, "El propio plugin devolvio un error durante su instalacion");
/// `PluginManagerError.Internal.CANT_REMOVE_LOADED_PLUGIN` (afirma-simple-plugins-manager)
pub const CANT_REMOVE_LOADED_PLUGIN: ErrorCode =
    ErrorCode::new(230203, "Ha ocurrido un error al eliminar el plugin anterior");
/// `PluginManagerError.Internal.PLUGIN_DIRECTORY_ERROR` (afirma-simple-plugins-manager)
pub const PLUGIN_DIRECTORY_ERROR: ErrorCode =
    ErrorCode::new(230204, "El plugin seleccionado ya se encuentra instalado");
/// `PluginManagerError.Internal.PLUGIN_LOAD_ERROR` (afirma-simple-plugins-manager)
pub const PLUGIN_LOAD_ERROR: ErrorCode = ErrorCode::new(230205, "Ha ocurrido un error al intentar cargar el plugin");
/// `PluginManagerError.Internal.INSTALLED_PLUGIN_NOT_FOUND` (afirma-simple-plugins-manager)
pub const INSTALLED_PLUGIN_NOT_FOUND: ErrorCode = ErrorCode::new(
    230206,
    "No se encontraron los ficheros de un plugin previamente instalado",
);
/// `ConfiguratorErrorCode.Internal.IMPORTING_PREFERENCES_ERROR` (afirma-ui-simple-configurator-common)
pub const IMPORTING_PREFERENCES_ERROR: ErrorCode =
    ErrorCode::new(230300, "Error desconocido importando las preferencias");
/// `ConfiguratorErrorCode.Internal.CANT_READ_PREFERENCES_FILE` (afirma-ui-simple-configurator-common)
pub const CANT_READ_PREFERENCES_FILE: ErrorCode = ErrorCode::new(230301, "No se pudo leer el fichero de preferencias");
/// `ConfiguratorErrorCode.Internal.INVALID_XML_PREFERENCES_FILE` (afirma-ui-simple-configurator-common)
pub const INVALID_XML_PREFERENCES_FILE: ErrorCode = ErrorCode::new(230302, "El fichero de preferencia no es un XML");
/// `ConfiguratorErrorCode.Internal.INVALID_FORMAT_PREFERENCES_FILE` (afirma-ui-simple-configurator-common)
pub const INVALID_FORMAT_PREFERENCES_FILE: ErrorCode =
    ErrorCode::new(230303, "El fichero de preferencias no tiene un formato valido");
/// `BinaryErrorCode.ThirdParty.BOUNCYCASTLE_VERSION_NOT_SUPPORTED` (afirma-crypto-core-pkcs7)
pub const BOUNCYCASTLE_VERSION_NOT_SUPPORTED: ErrorCode =
    ErrorCode::new(300001, "Se ha encontrado una version de Spongycastle no soportada");
/// `PdfErrorCode.ThirdParty.ITEXT_VERSION_NOT_SUPPORTED` (afirma-crypto-pdf-common)
pub const ITEXT_VERSION_NOT_SUPPORTED: ErrorCode =
    ErrorCode::new(300002, "Se ha encontrado una version de iText no soportada");
/// `KeyStoreErrorCode.ThirdParty.SUN_MSCAPI_PROVIDER_NOT_FOUND` (afirma-core-keystores)
pub const SUN_MSCAPI_PROVIDER_NOT_FOUND: ErrorCode =
    ErrorCode::new(300003, "No se ha encontrado el proveedor MSCAPI de Sun");
/// `KeyStoreErrorCode.ThirdParty.AFIRMA_MSCAPI_ADDRESBOOK_PROVIDER_NOT_FOUND` (afirma-core-keystores)
pub const AFIRMA_MSCAPI_ADDRESBOOK_PROVIDER_NOT_FOUND: ErrorCode =
    ErrorCode::new(300004, "No se ha encontrado el proveedor MSCAPI del Cliente @firma");
/// `KeyStoreErrorCode.ThirdParty.AFIRMA_SINGLE_CERT_PROVIDER_NOT_FOUND` (afirma-core-keystores)
pub const AFIRMA_SINGLE_CERT_PROVIDER_NOT_FOUND: ErrorCode =
    ErrorCode::new(300005, "No se ha encontrado el proveedor SingleCert del Cliente @firma");
/// `ErrorCode.ThirdParty.INVALID_OPERATION_XML` (afirma-core)
pub const INVALID_OPERATION_XML: ErrorCode = ErrorCode::new(
    300202,
    "La respuesta del servidor intermedio al descargar la informacion no es un XML valido",
);
/// `ErrorCode.ThirdParty.PRESIGN_HTTP_ERROR` (afirma-core)
pub const PRESIGN_HTTP_ERROR: ErrorCode = ErrorCode::new(300400, "El servicio de prefirma devolvio un error HTTP");
/// `ErrorCode.ThirdParty.MALFORMED_PRESIGN_RESPONSE` (afirma-core)
pub const MALFORMED_PRESIGN_RESPONSE: ErrorCode = ErrorCode::new(
    300401,
    "La respuesta del servidor trifasico al hacer la prefirma no es valida",
);
/// `ErrorCode.ThirdParty.PRESIGNS_NOT_FOUND` (afirma-core)
pub const PRESIGNS_NOT_FOUND: ErrorCode =
    ErrorCode::new(300402, "No se han obtenido prefirmas del servicio de prefirma");
/// `ErrorCode.ThirdParty.POSTSIGN_HTTP_ERROR` (afirma-core)
pub const POSTSIGN_HTTP_ERROR: ErrorCode = ErrorCode::new(300404, "El servicio de postfirma devolvio un error HTTP");
/// `ErrorCode.ThirdParty.POSTSIGN_ERROR` (afirma-core)
pub const POSTSIGN_ERROR: ErrorCode = ErrorCode::new(
    300405,
    "La respuesta del servidor trifasico al hacer la postfirma no es valida",
);
/// `ErrorCode.ThirdParty.MALFORMED_POSTSIGN_RESPONSE` (afirma-core)
pub const MALFORMED_POSTSIGN_RESPONSE: ErrorCode = ErrorCode::new(
    300407,
    "El servidor trifasico devolvio una respuesta con texto OK pero no llega el formato correcto",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_1` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_1: ErrorCode = ErrorCode::new(
    300409,
    "ERR-1 en la prefirma: No se ha indicado la operacion a realizar",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_2` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_2: ErrorCode = ErrorCode::new(
    300410,
    "ERR-2 en la prefirma: No se ha indicado el identificador del documento",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_3` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_3: ErrorCode =
    ErrorCode::new(300411, "ERR-3 en la prefirma: No se ha indicado el algoritmo de firma");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_4` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_4: ErrorCode =
    ErrorCode::new(300412, "ERR-4 en la prefirma: No se ha indicado el formato de firma");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_5` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_5: ErrorCode = ErrorCode::new(
    300413,
    "ERR-5 en la prefirma: No se ha indicado el certificado de usuario",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_6` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_6: ErrorCode = ErrorCode::new(
    300414,
    "ERR-6 en la prefirma: El formato de los parametros adicionales suministrados es erroneo",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_7` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_7: ErrorCode = ErrorCode::new(
    300415,
    "ERR-7 en la prefirma: El certificado de usuario no esta en formato X.509",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_8` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_8: ErrorCode =
    ErrorCode::new(300416, "ERR-8 en la prefirma: Formato de firma no soportado");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_9` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_9: ErrorCode =
    ErrorCode::new(300417, "ERR-9 en la prefirma: Error realizando la prefirma");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_10` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_10: ErrorCode =
    ErrorCode::new(300418, "ERR-10 en la prefirma: Error al almacenar el documento");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_11` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_11: ErrorCode =
    ErrorCode::new(300419, "ERR-11 en la prefirma: Operacion desconocida");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_12` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_12: ErrorCode =
    ErrorCode::new(300420, "ERR-12 en la prefirma: Error realizando la postfirma");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_13` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_13: ErrorCode = ErrorCode::new(
    300421,
    "ERR-13 en la prefirma: No se indicado una sub-operacion valida a realizar (firma, cofirma,...)",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_14` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_14: ErrorCode =
    ErrorCode::new(300422, "ERR-14 en la prefirma: Error al recuperar el documento");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_15` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_15: ErrorCode = ErrorCode::new(
    300423,
    "ERR-15 en la prefirma: El formato de los datos de sesion suministrados es erroneo",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_16` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_16: ErrorCode = ErrorCode::new(
    300424,
    "ERR-16 en la prefirma: Error al generar el codigo de verificacion de las firmas",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_17` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_17: ErrorCode = ErrorCode::new(
    300425,
    "ERR-17 en la prefirma: Error al comprobar el codigo de verificacion de las firmas",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_18` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_18: ErrorCode =
    ErrorCode::new(300426, "ERR-18 en la prefirma: Error de integridad en la firma");
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_19` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_19: ErrorCode = ErrorCode::new(
    300427,
    "ERR-19 en la prefirma: El formato de los datos de operacion suministrados es erroneo",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_20` (afirma-core)
pub const TRI_SERVER_PRESIGN_ERROR_20: ErrorCode =
    ErrorCode::new(300428, "ERR-20 en la prefirma: Algoritmo de firma no soportado");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_1` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_1: ErrorCode = ErrorCode::new(
    300430,
    "ERR-1 en la postfirma: No se ha indicado la operacion a realizar",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_2` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_2: ErrorCode = ErrorCode::new(
    300431,
    "ERR-2 en la postfirma: No se ha indicado el identificador del documento",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_3` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_3: ErrorCode =
    ErrorCode::new(300432, "ERR-3 en la postfirma: No se ha indicado el algoritmo de firma");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_4` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_4: ErrorCode =
    ErrorCode::new(300433, "ERR-4 en la postfirma: No se ha indicado el formato de firma");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_5` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_5: ErrorCode = ErrorCode::new(
    300434,
    "ERR-5 en la postfirma: No se ha indicado el certificado de usuario",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_6` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_6: ErrorCode = ErrorCode::new(
    300435,
    "ERR-6 en la postfirma: El formato de los parametros adicionales suministrados es erroneo",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_7` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_7: ErrorCode = ErrorCode::new(
    300436,
    "ERR-7 en la postfirma: El certificado de usuario no esta en formato X.509",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_8` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_8: ErrorCode =
    ErrorCode::new(300437, "ERR-8 en la postfirma: Formato de firma no soportado");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_9` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_9: ErrorCode =
    ErrorCode::new(300438, "ERR-9 en la postfirma: Error realizando la prefirma");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_10` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_10: ErrorCode =
    ErrorCode::new(300439, "ERR-10 en la postfirma: Error al almacenar el documento");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_11` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_11: ErrorCode =
    ErrorCode::new(300440, "ERR-11 en la postfirma: Operacion desconocida");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_12` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_12: ErrorCode =
    ErrorCode::new(300441, "ERR-12 en la postfirma: Error realizando la postfirma");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_13` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_13: ErrorCode = ErrorCode::new(
    300442,
    "ERR-13 en la postfirma: No se indicado una sub-operacion valida a realizar (firma, cofirma,...)",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_14` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_14: ErrorCode =
    ErrorCode::new(300443, "ERR-14 en la postfirma: Error al recuperar el documento");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_15` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_15: ErrorCode = ErrorCode::new(
    300444,
    "ERR-15 en la postfirma: El formato de los datos de sesion suministrados es erroneo",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_16` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_16: ErrorCode = ErrorCode::new(
    300445,
    "ERR-16 en la postfirma: Error al generar el codigo de verificacion de las firmas",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_17` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_17: ErrorCode = ErrorCode::new(
    300446,
    "ERR-17 en la postfirma: Error al comprobar el codigo de verificacion de las firmas",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_18` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_18: ErrorCode =
    ErrorCode::new(300447, "ERR-18 en la postfirma: Error de integridad en la firma");
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_19` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_19: ErrorCode = ErrorCode::new(
    300448,
    "ERR-19 en la postfirma: El formato de los datos de operacion suministrados es erroneo",
);
/// `ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_20` (afirma-core)
pub const TRI_SERVER_POSTSIGN_ERROR_20: ErrorCode =
    ErrorCode::new(300449, "ERR-20 en la postfirma: Algoritmo de firma no soportado");
/// `ErrorCode.ThirdParty.TRI_SERVER_UNKNOWN_PRESIGN_ERROR` (afirma-core)
pub const TRI_SERVER_UNKNOWN_PRESIGN_ERROR: ErrorCode =
    ErrorCode::new(300451, "No se reconoce el error remitido por el servicio de prefirma");
/// `ErrorCode.ThirdParty.TRI_SERVER_UNKNOWN_POSTSIGN_ERROR` (afirma-core)
pub const TRI_SERVER_UNKNOWN_POSTSIGN_ERROR: ErrorCode =
    ErrorCode::new(300452, "No se reconoce el error remitido por el servicio de postfirma");
/// `BatchErrorCode.ThirdParty.JSON_BATCH_PRESIGN_ERROR` (afirma-crypto-batch-client)
pub const JSON_BATCH_PRESIGN_ERROR: ErrorCode =
    ErrorCode::new(300601, "El servicio de prefirma de lotes JSON devolvio un error");
/// `BatchErrorCode.ThirdParty.JSON_BATCH_POSTSIGN_ERROR` (afirma-crypto-batch-client)
pub const JSON_BATCH_POSTSIGN_ERROR: ErrorCode =
    ErrorCode::new(300602, "El servicio de postfirma de lotes JSON devolvio un error");
/// `BatchErrorCode.ThirdParty.XML_BATCH_PRESIGN_ERROR` (afirma-crypto-batch-client)
pub const XML_BATCH_PRESIGN_ERROR: ErrorCode =
    ErrorCode::new(300701, "El servicio de prefirma de lotes XML devolvio un error");
/// `BatchErrorCode.ThirdParty.XML_BATCH_POSTSIGN_ERROR` (afirma-crypto-batch-client)
pub const XML_BATCH_POSTSIGN_ERROR: ErrorCode =
    ErrorCode::new(300702, "El servicio de postfirma de lotes XML devolvio un error");
/// `SimpleErrorCode.Communication.PROXY_CONNECTION` (afirma-simple)
pub const PROXY_CONNECTION: ErrorCode = ErrorCode::new(400002, "Conexion incorrecta con proxy");
/// `ErrorCode.Communication.INVALID_DOMAIN_SSL_CERTIFICATE_ERROR` (afirma-core)
pub const INVALID_DOMAIN_SSL_CERTIFICATE_ERROR: ErrorCode = ErrorCode::new(
    400004,
    "El certificado SSL no esta expedido para el dominio al que pertenece el servidor",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_OPERATION` (afirma-simple)
pub const RECIVING_DATA_OF_SIGN_OPERATION: ErrorCode =
    ErrorCode::new(401100, "Error en la descarga de la operacion de firma");
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_CERT_OPERATION` (afirma-simple)
pub const RECIVING_DATA_OF_CERT_OPERATION: ErrorCode = ErrorCode::new(
    401101,
    "Error en la descarga de la operacion de seleccion de certificado",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_BATCH_OPERATION` (afirma-simple)
pub const RECIVING_DATA_OF_BATCH_OPERATION: ErrorCode =
    ErrorCode::new(401102, "Error en la descarga de la operacion de lote");
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_SAVE_OPERATION` (afirma-simple)
pub const RECIVING_DATA_OF_SAVE_OPERATION: ErrorCode =
    ErrorCode::new(401103, "Error en la descarga de la operacion de guardado de datos");
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_LOAD_OPERATION` (afirma-simple)
pub const RECIVING_DATA_OF_LOAD_OPERATION: ErrorCode =
    ErrorCode::new(401104, "Error en la descarga de la operacion de carga de datos");
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION` (afirma-simple)
pub const RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION: ErrorCode =
    ErrorCode::new(401105, "Error en la descarga de la operacion de firma y guardado");
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_TIMEOUT` (afirma-simple)
pub const RECIVING_DATA_OF_SIGN_TIMEOUT: ErrorCode = ErrorCode::new(
    401106,
    "Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_CERT_TIMEOUT` (afirma-simple)
pub const RECIVING_DATA_OF_CERT_TIMEOUT: ErrorCode = ErrorCode::new(
    401107,
    "Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de seleccion de certificados",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_BATCH_TIMEOUT` (afirma-simple)
pub const RECIVING_DATA_OF_BATCH_TIMEOUT: ErrorCode = ErrorCode::new(
    401108,
    "Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma de lote",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_SAVE_TIMEOUT` (afirma-simple)
pub const RECIVING_DATA_OF_SAVE_TIMEOUT: ErrorCode = ErrorCode::new(
    401109,
    "Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de guardado",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_LOAD_TIMEOUT` (afirma-simple)
pub const RECIVING_DATA_OF_LOAD_TIMEOUT: ErrorCode = ErrorCode::new(
    401110,
    "Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de carga de datos",
);
/// `SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT` (afirma-simple)
pub const RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT: ErrorCode = ErrorCode::new(
    401111,
    "Se excedio el tiempo maximo del servicio de recuperacion de datos del servidor intermedio con los datos de firma y guardado",
);
/// `SimpleErrorCode.Communication.SENDING_RESULT_OPERATION` (afirma-simple)
pub const SENDING_RESULT_OPERATION: ErrorCode =
    ErrorCode::new(401200, "Error en el envio del resultado de la operacion");
/// `SimpleErrorCode.Communication.SENDING_RESULT_TIMEOUT` (afirma-simple)
pub const SENDING_RESULT_TIMEOUT: ErrorCode = ErrorCode::new(
    401201,
    "Se excedio el tiempo maximo de espera en la llamada al servicio de guardado del servidor intermedio",
);
/// `ErrorCode.Communication.PRESIGN_SERVICE_CONNECTION_ERROR` (afirma-core)
pub const PRESIGN_SERVICE_CONNECTION_ERROR: ErrorCode = ErrorCode::new(
    401300,
    "Error de conexion con el servidor trifasico al hacer la prefirma",
);
/// `ErrorCode.Communication.PRESIGN_SERVICE_COMMUNICATION_ERROR` (afirma-core)
pub const PRESIGN_SERVICE_COMMUNICATION_ERROR: ErrorCode = ErrorCode::new(
    401301,
    "Error de comunicacion con el servidor trifasico al hacer la prefirma",
);
/// `ErrorCode.Communication.PRESIGN_SERVICE_TIMEOUT` (afirma-core)
pub const PRESIGN_SERVICE_TIMEOUT: ErrorCode = ErrorCode::new(
    401302,
    "Se excedio el tiempo maximo de espera en la llamada a la prefirma del servidor trifasico",
);
/// `ErrorCode.Communication.POSTSIGN_SERVICE_CONNECTION_ERROR` (afirma-core)
pub const POSTSIGN_SERVICE_CONNECTION_ERROR: ErrorCode = ErrorCode::new(
    401400,
    "Error de conexion con el servidor trifasico al hacer la posfirma",
);
/// `ErrorCode.Communication.POSTSIGN_SERVICE_COMMUNICATION_ERROR` (afirma-core)
pub const POSTSIGN_SERVICE_COMMUNICATION_ERROR: ErrorCode = ErrorCode::new(
    401401,
    "Error de comunicacion con el servidor trifasico al hacer la posfirma",
);
/// `ErrorCode.Communication.POSTSIGN_SERVICE_TIMEOUT` (afirma-core)
pub const POSTSIGN_SERVICE_TIMEOUT: ErrorCode = ErrorCode::new(
    401402,
    "Se excedio el tiempo maximo de espera en la llamada a la postfirma del servidor trifasico",
);
/// `BatchErrorCode.Communication.JSON_BATCH_PRESIGN_CONNECTION_ERROR` (afirma-crypto-batch-client)
pub const JSON_BATCH_PRESIGN_CONNECTION_ERROR: ErrorCode = ErrorCode::new(
    401500,
    "Error de conexion con el servidor trifasico al hacer la prefirma Batch JSON",
);
/// `BatchErrorCode.Communication.JSON_BATCH_PRESIGN_COMMUNICATION_ERROR` (afirma-crypto-batch-client)
pub const JSON_BATCH_PRESIGN_COMMUNICATION_ERROR: ErrorCode = ErrorCode::new(
    401501,
    "Error de comunicacion con el servidor trifasico al hacer la prefirma Batch JSON",
);
/// `BatchErrorCode.Communication.JSON_BATCH_PRESIGN_TIMEOUT` (afirma-crypto-batch-client)
pub const JSON_BATCH_PRESIGN_TIMEOUT: ErrorCode = ErrorCode::new(
    401502,
    "Se excedio el tiempo maximo de espera en la llamada a la prefirma de lote JSON del servidor trifasico",
);
/// `BatchErrorCode.Communication.JSON_BATCH_POSTSIGN_CONNECTION_ERROR` (afirma-crypto-batch-client)
pub const JSON_BATCH_POSTSIGN_CONNECTION_ERROR: ErrorCode = ErrorCode::new(
    401600,
    "Error de conexion con el servidor trifasico al hacer la posfirma Batch JSON",
);
/// `BatchErrorCode.Communication.JSON_BATCH_POSTSIGN_COMMUNICATION_ERROR` (afirma-crypto-batch-client)
pub const JSON_BATCH_POSTSIGN_COMMUNICATION_ERROR: ErrorCode = ErrorCode::new(
    401601,
    "Error de comunicacion con el servidor trifasico al hacer la posfirma Batch JSON",
);
/// `BatchErrorCode.Communication.JSON_BATCH_POSTSIGN_TIMEOUT` (afirma-crypto-batch-client)
pub const JSON_BATCH_POSTSIGN_TIMEOUT: ErrorCode = ErrorCode::new(
    401602,
    "Se excedio el tiempo maximo de espera en la llamada a la postfirma de lote JSON del servidor trifasico",
);
/// `BatchErrorCode.Communication.XML_BATCH_PRESIGN_CONNECTION_ERROR` (afirma-crypto-batch-client)
pub const XML_BATCH_PRESIGN_CONNECTION_ERROR: ErrorCode = ErrorCode::new(
    401700,
    "Error de conexion con el servidor trifasico al hacer la prefirma Batch XML",
);
/// `BatchErrorCode.Communication.XML_BATCH_PRESIGN_COMMUNICATION_ERROR` (afirma-crypto-batch-client)
pub const XML_BATCH_PRESIGN_COMMUNICATION_ERROR: ErrorCode = ErrorCode::new(
    401701,
    "Error de comunicacion con el servidor trifasico al hacer la prefirma Batch XML",
);
/// `BatchErrorCode.Communication.XML_BATCH_PRESIGN_TIMEOUT` (afirma-crypto-batch-client)
pub const XML_BATCH_PRESIGN_TIMEOUT: ErrorCode = ErrorCode::new(
    401702,
    "Se excedio el tiempo maximo de espera en la llamada a la prefirma de lote XML del servidor trifasico",
);
/// `BatchErrorCode.Communication.XML_BATCH_POSTSIGN_CONNECTION_ERROR` (afirma-crypto-batch-client)
pub const XML_BATCH_POSTSIGN_CONNECTION_ERROR: ErrorCode = ErrorCode::new(
    401800,
    "Error de conexion con el servidor trifasico al hacer la posfirma Batch XML",
);
/// `BatchErrorCode.Communication.XML_BATCH_POSTSIGN_COMMUNICATION_ERROR` (afirma-crypto-batch-client)
pub const XML_BATCH_POSTSIGN_COMMUNICATION_ERROR: ErrorCode = ErrorCode::new(
    401801,
    "Error de comunicacion con el servidor trifasico al hacer la posfirma Batch XML",
);
/// `BatchErrorCode.Communication.XML_BATCH_POSTSIGN_TIMEOUT` (afirma-crypto-batch-client)
pub const XML_BATCH_POSTSIGN_TIMEOUT: ErrorCode = ErrorCode::new(
    401802,
    "Se excedio el tiempo maximo de espera en la llamada a la postfirma de lote XML del servidor trifasico",
);
/// `ErrorCode.Communication.TSA_CONNECTION_ERROR` (afirma-core)
pub const TSA_CONNECTION_ERROR: ErrorCode =
    ErrorCode::new(410001, "Error en la comunicacion con la autoridad de sellado de tiempo");
/// `XMLErrorCode.Communication.DERREFERENCING_DATA_ERROR` (afirma-crypto-core-xml)
pub const DERREFERENCING_DATA_ERROR: ErrorCode =
    ErrorCode::new(411001, "No se han podido cargar de una URI los datos para la firma XML");
/// `SimpleErrorCode.Communication.EXTERNAL_REQUEST` (afirma-simple)
pub const EXTERNAL_REQUEST: ErrorCode = ErrorCode::new(420001, "Se ha realizado la peticion desde un puerto externo");
/// `SimpleErrorCode.Communication.SENDING_RESULT_OPERATION_BY_SOCKET` (afirma-simple)
pub const SENDING_RESULT_OPERATION_BY_SOCKET: ErrorCode =
    ErrorCode::new(420501, "Error en el envio del resultado de la operacion por socket");
/// `SimpleErrorCode.Communication.READING_FROM_SOCKET` (afirma-simple)
pub const READING_FROM_SOCKET: ErrorCode = ErrorCode::new(420502, "No se pudieron leer los datos del socket");
/// `ErrorCode.Functional.CANCELLED_OPERATION` (afirma-core)
pub const CANCELLED_OPERATION: ErrorCode = ErrorCode::new(500001, "Operacion cancelada por el usuario");
/// `ErrorCode.Functional.INVALID_SIGNATURE` (afirma-core)
pub const INVALID_SIGNATURE: ErrorCode = ErrorCode::new(500002, "La firma que se trata de procesar es invalida");
/// `ErrorCode.Functional.INCOMPATIBLE_OPERATING_SYSTEM` (afirma-core)
pub const INCOMPATIBLE_OPERATING_SYSTEM: ErrorCode =
    ErrorCode::new(500003, "Sistema operativo no compatible con la operacion");
/// `OOXMLErrorCode.Functional.INCOMPATIBLE_JRE` (afirma-crypto-ooxml)
pub const INCOMPATIBLE_JRE: ErrorCode = ErrorCode::new(500004, "JRE no compatible con la operacion");
/// `SimpleErrorCode.Functional.MINIMUM_VERSION_NON_SATISTIED` (afirma-simple)
pub const MINIMUM_VERSION_NON_SATISTIED: ErrorCode =
    ErrorCode::new(500005, "La web solicito una version posterior de Autofirma");
/// `SimpleErrorCode.Functional.SIGNER_REQUIREMENT_NOT_SUPPORTED` (afirma-simple)
pub const SIGNER_REQUIREMENT_NOT_SUPPORTED: ErrorCode =
    ErrorCode::new(500006, "El firmador hizo una peticion de datos no soportada");
/// `SimpleErrorCode.Functional.VALIDATOR_REQUIREMENT_NOT_SUPPORTED` (afirma-simple)
pub const VALIDATOR_REQUIREMENT_NOT_SUPPORTED: ErrorCode =
    ErrorCode::new(500007, "El validador hizo una peticion de datos no soportada");
/// `ErrorCode.Functional.CERTIFICATE_NEEDED` (afirma-core)
pub const CERTIFICATE_NEEDED: ErrorCode = ErrorCode::new(501001, "Error en la operacion, no hay certificados");
/// `SimpleErrorCode.Functional.NO_CERTS_FOUND_SIGNING` (afirma-simple)
pub const NO_CERTS_FOUND_SIGNING: ErrorCode =
    ErrorCode::new(501001, "No se han encontrado certificados para realizar la seleccion");
/// `ErrorCode.Functional.INVALID_FORMAT_FILE` (afirma-core)
pub const INVALID_FORMAT_FILE: ErrorCode = ErrorCode::new(
    501002,
    "El formato de fichero no es valido para la operacion que se intenta realizar",
);
/// `ErrorCode.Functional.INVALID_SMARTCARD_PIN` (afirma-core)
pub const INVALID_SMARTCARD_PIN: ErrorCode = ErrorCode::new(501003, "El PIN del la tarjeta inteligente es incorrecto");
/// `ErrorCode.Functional.DOCUMENT_TOO_LARGE` (afirma-core)
pub const DOCUMENT_TOO_LARGE: ErrorCode = ErrorCode::new(501005, "El documento supera el tamano maximo permitido");
/// `ErrorCode.Functional.COMPATIBLE_SIGNATURE_NOT_FOUND` (afirma-core)
pub const COMPATIBLE_SIGNATURE_NOT_FOUND: ErrorCode =
    ErrorCode::new(501006, "La firma no es compatible con el formato de firma utilizado");
/// `ErrorCode.Functional.SIGNING_LTS` (afirma-core)
pub const SIGNING_LTS: ErrorCode = ErrorCode::new(
    501007,
    "Se esta intentando firmar una firma longeva que quedara invalidada",
);
/// `ErrorCode.Functional.SIGNING_WITH_POLICY_INCOMPATIBILITY` (afirma-core)
pub const SIGNING_WITH_POLICY_INCOMPATIBILITY: ErrorCode =
    ErrorCode::new(501008, "La firma resultante sera incompatible con la politica de firma");
/// `SimpleErrorCode.Functional.CANT_IDENTIFY_SIGNATURE_FORMAT` (afirma-simple)
pub const CANT_IDENTIFY_SIGNATURE_FORMAT: ErrorCode =
    ErrorCode::new(501009, "No se ha podido identificar un formato de firma para los datos");
/// `SimpleErrorCode.Functional.VISIBLE_SIGNATURE_IS_MANDATORY` (afirma-simple)
pub const VISIBLE_SIGNATURE_IS_MANDATORY: ErrorCode =
    ErrorCode::new(501010, "La operacion marco como obligatoria la firma visible PDF");
/// `XMLErrorCode.Functional.XPATH_NOT_FOUND` (afirma-crypto-core-xml)
pub const XPATH_NOT_FOUND: ErrorCode = ErrorCode::new(
    501011,
    "Una o varias firmas incluidas en el documento no contienen un algoritmo XPath",
);
/// `SimpleErrorCode.Functional.NO_CERTS_FOUND_SELECTING_CERT` (afirma-simple)
pub const NO_CERTS_FOUND_SELECTING_CERT: ErrorCode =
    ErrorCode::new(502001, "No se han encontrado certificados para realizar la seleccion");
/// `SimpleErrorCode.Functional.NO_CERTS_FOUND_SIGNING_BATCH` (afirma-simple)
pub const NO_CERTS_FOUND_SIGNING_BATCH: ErrorCode = ErrorCode::new(
    504001,
    "No se han encontrado certificados para realizar la firma del lote",
);
/// `MassiveErrorCode.Functional.INDIR_NOT_FOUND` (afirma-core-massive)
pub const INDIR_NOT_FOUND: ErrorCode = ErrorCode::new(506001, "El directorio de entrada no existe");
/// `MassiveErrorCode.Functional.ACCESS_TO_DIR_IS_NOT_ALLOWED` (afirma-core-massive)
pub const ACCESS_TO_DIR_IS_NOT_ALLOWED: ErrorCode = ErrorCode::new(506002, "No se tiene acceso al directorio indicado");
/// `ValidationErrorCode.Functional.INCOMPATIBLE_SIGNATURE` (afirma-crypto-validation)
pub const INCOMPATIBLE_SIGNATURE: ErrorCode =
    ErrorCode::new(507001, "El documento no esta firmado o la firma no es compatible");
/// `BinaryErrorCode.Functional.SIGNATURE_DOESNT_CONTAIN_DATA` (afirma-crypto-core-pkcs7)
pub const SIGNATURE_DOESNT_CONTAIN_DATA: ErrorCode = ErrorCode::new(
    510001,
    "La firma no contiene los datos firmados necesarios para la operacion",
);
/// `XMLErrorCode.Functional.XML_DOCUMENT_NEEDED` (afirma-crypto-core-xml)
pub const XML_DOCUMENT_NEEDED: ErrorCode =
    ErrorCode::new(510002, "La firma requiere que los datos sean un documento XML");
/// `ODFErrorCode.Functional.ODF_DOCUMENT_NEEDED` (afirma-crypto-odf)
pub const ODF_DOCUMENT_NEEDED: ErrorCode =
    ErrorCode::new(510003, "La firma requiere que los datos sean un documento ODF");
/// `OOXMLErrorCode.Functional.OOXML_DOCUMENT_NEEDED` (afirma-crypto-ooxml)
pub const OOXML_DOCUMENT_NEEDED: ErrorCode =
    ErrorCode::new(510004, "La firma requiere que los datos sean un documento OOXML");
/// `PdfErrorCode.Functional.PDF_DOCUMENT_NEEDED` (afirma-crypto-pdf-common)
pub const PDF_DOCUMENT_NEEDED: ErrorCode =
    ErrorCode::new(510005, "La firma requiere que los datos sean un documento PDF");
/// `ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE` (afirma-core)
pub const SIGNING_MALFORMED_SIGNATURE: ErrorCode =
    ErrorCode::new(510006, "La firma no es compatible o esta mal formada");
/// `XMLErrorCode.Functional.TRI_SIGNING_SIGNATURE` (afirma-crypto-core-xml)
pub const TRI_SIGNING_SIGNATURE: ErrorCode = ErrorCode::new(
    510007,
    "No se permite firmar una firma XML en el modo de firma trifasica",
);
/// `XAdESErrorCode.Functional.FACTURAE_ALREADY_SIGNED` (afirma-crypto-xades)
pub const FACTURAE_ALREADY_SIGNED: ErrorCode = ErrorCode::new(
    510008,
    "La factura ya tiene una firma electronica y no admite firmas adicionales",
);
/// `XAdESErrorCode.Functional.FACTURAE_NEEDED` (afirma-crypto-xades)
pub const FACTURAE_NEEDED: ErrorCode = ErrorCode::new(510009, "La firma requiere que los datos sean FacturaE");
/// `ErrorCode.Functional.KEYSTORE_LOCKED` (afirma-core)
pub const KEYSTORE_LOCKED: ErrorCode = ErrorCode::new(511003, "El almacen de claves esta bloqueado");
/// `ErrorCode.Functional.SMARTCARD_LOCKED` (afirma-core)
pub const SMARTCARD_LOCKED: ErrorCode = ErrorCode::new(511004, "La tarjeta inteligente esta bloqueada");
/// `SimpleErrorCode.Functional.POLICY_DEFAULT_ERROR` (afirma-simple)
pub const POLICY_DEFAULT_ERROR: ErrorCode = ErrorCode::new(521000, "Ha ocurrido un error configurando la politica");
/// `SimpleErrorCode.Functional.INVALID_POLICY_IDENTIFIER` (afirma-simple)
pub const INVALID_POLICY_IDENTIFIER: ErrorCode =
    ErrorCode::new(521001, "El identificador de politica no puede ser nulo ni vacio");
/// `SimpleErrorCode.Functional.INVALID_POLICY_IDENTIFIER_URI` (afirma-simple)
pub const INVALID_POLICY_IDENTIFIER_URI: ErrorCode = ErrorCode::new(521002, "El identificador debe ser una URI valida");
/// `SimpleErrorCode.Functional.MISSING_DIGEST_ALGORITHM` (afirma-simple)
pub const MISSING_DIGEST_ALGORITHM: ErrorCode = ErrorCode::new(
    521003,
    "Si se indica la huella digital es obligatorio indicar tambien el algoritmo",
);
/// `SimpleErrorCode.Functional.UNREACHABLE_POLICY_IDENTIFIER_URI` (afirma-simple)
pub const UNREACHABLE_POLICY_IDENTIFIER_URI: ErrorCode = ErrorCode::new(
    521004,
    "Si no se especifica la huella digital, el identificador debe ser una URI accesible",
);
/// `SimpleErrorCode.Functional.INVALID_POLICY_IDENTIFIER_HASH_BASE64` (afirma-simple)
pub const INVALID_POLICY_IDENTIFIER_HASH_BASE64: ErrorCode =
    ErrorCode::new(521005, "La huella digital debe estar en formato Base64");
/// `SimpleErrorCode.Functional.INVALID_POLICY_QUALIFIER_URI` (afirma-simple)
pub const INVALID_POLICY_QUALIFIER_URI: ErrorCode = ErrorCode::new(521006, "El calificador debe ser una URI valida");
/// `SimpleErrorCode.Functional.INVALID_POLICY_IDENTIFIER_OID` (afirma-simple)
pub const INVALID_POLICY_IDENTIFIER_OID: ErrorCode =
    ErrorCode::new(521007, "El identificador debe tener un formato OID valido");
/// `SimpleErrorCode.Functional.EMPTY_POLICY_HASH` (afirma-simple)
pub const EMPTY_POLICY_HASH: ErrorCode = ErrorCode::new(521008, "La huella digital no puede ser nula ni vacia");
/// `SimpleErrorCode.Functional.INVALID_POLICY_QUALIFIER_URL` (afirma-simple)
pub const INVALID_POLICY_QUALIFIER_URL: ErrorCode = ErrorCode::new(521009, "El calificador debe ser una URL valida");
/// `SimpleErrorCode.Functional.INVALID_PROXY_CONFIG` (afirma-simple)
pub const INVALID_PROXY_CONFIG: ErrorCode = ErrorCode::new(521010, "La configuracion de proxy no es valida");
/// `ConfiguratorErrorCode.Functional.INVALID_CERTIFICATE_SIGNER` (afirma-ui-simple-configurator-common)
pub const INVALID_CERTIFICATE_SIGNER: ErrorCode = ErrorCode::new(
    522001,
    "El certificado firmante del fichero de configuracion no es valido",
);
/// `ConfiguratorErrorCode.Functional.INVALID_PREFERENCES_FILE_SIGNATURE` (afirma-ui-simple-configurator-common)
pub const INVALID_PREFERENCES_FILE_SIGNATURE: ErrorCode =
    ErrorCode::new(522002, "La firma del fichero de configuracion no es valida");
/// `ConfiguratorErrorCode.Functional.INVALID_PREFERENCES_FILE_SIGNER` (afirma-ui-simple-configurator-common)
pub const INVALID_PREFERENCES_FILE_SIGNER: ErrorCode = ErrorCode::new(
    522003,
    "El certificado firmante del fichero de configuracion no esta autorizado",
);
/// `ConfiguratorErrorCode.Functional.UNSIGNED_PREFERENCES_FILE` (afirma-ui-simple-configurator-common)
pub const UNSIGNED_PREFERENCES_FILE: ErrorCode = ErrorCode::new(
    522004,
    "No se permite la importacion de ficheros de preferencias sin firmar",
);
/// `PluginManagerError.Functional.MALFORMED_PLUGIN_SERVICE` (afirma-simple-plugins-manager)
pub const MALFORMED_PLUGIN_SERVICE: ErrorCode = ErrorCode::new(
    530001,
    "Se han encontrado plugins mal definidos en el fichero importado",
);
/// `PluginManagerError.Functional.NO_PLUGIN_FOUND` (afirma-simple-plugins-manager)
pub const NO_PLUGIN_FOUND: ErrorCode = ErrorCode::new(530002, "No se encontro ningun plugin en los archivos");
/// `PluginManagerError.Functional.MULTIPLE_PLUGINS_FOUND` (afirma-simple-plugins-manager)
pub const MULTIPLE_PLUGINS_FOUND: ErrorCode =
    ErrorCode::new(530003, "No se permite la carga simultanea de varios plugins");
/// `PluginManagerError.Functional.BUTTON_NO_ACTION` (afirma-simple-plugins-manager)
pub const BUTTON_NO_ACTION: ErrorCode = ErrorCode::new(530004, "El plugin no ha definido accion para un boton");
/// `PluginManagerError.Functional.BUTTON_NO_WINDOW` (afirma-simple-plugins-manager)
pub const BUTTON_NO_WINDOW: ErrorCode = ErrorCode::new(
    530005,
    "El plugin no ha definido la ventana en la que debe aparecer un boton",
);
/// `PluginManagerError.Functional.INVALID_ACTION_CLASS` (afirma-simple-plugins-manager)
pub const INVALID_ACTION_CLASS: ErrorCode = ErrorCode::new(530006, "El plugin definio una clase de accion erronea");
/// `SimpleErrorCode.Functional.INVALID_PLUGIN_FILE` (afirma-simple)
pub const INVALID_PLUGIN_FILE: ErrorCode = ErrorCode::new(530007, "El plugin no es valido para ser importado");
/// `PluginManagerError.Functional.ALREADY_INSTALLED_PLUGIN` (afirma-simple-plugins-manager)
pub const ALREADY_INSTALLED_PLUGIN: ErrorCode = ErrorCode::new(530008, "El plugin ya se encuentra instalado");
/// `SimpleErrorCode.Functional.PLUGIN_FILE_NOT_FOUND` (afirma-simple)
pub const PLUGIN_FILE_NOT_FOUND: ErrorCode = ErrorCode::new(530009, "No se ha encontrado el fichero del plugin");
/// `SimpleErrorCode.Request.UNSUPPORTED_OPERATION` (afirma-simple)
pub const UNSUPPORTED_OPERATION: ErrorCode = ErrorCode::new(600002, "La operacion no esta soportada");
/// `ErrorCode.Request.UNSUPPORTED_CIPHER_KEY` (afirma-core)
pub const UNSUPPORTED_CIPHER_KEY: ErrorCode = ErrorCode::new(600009, "La clave de cifrado recibida no esta soportada");
/// `ErrorCode.Request.LOCAL_RETRIEVE_URL` (afirma-core)
pub const LOCAL_RETRIEVE_URL: ErrorCode =
    ErrorCode::new(600010, "La URL del servlet de recuperacion no puede ser local");
/// `KeyStoreErrorCode.Request.UNSUPPORTED_KEYSTORE` (afirma-core-keystores)
pub const UNSUPPORTED_KEYSTORE: ErrorCode = ErrorCode::new(
    600011,
    "El almacen de claves solicitado no es compatible con el entorno de ejecucion",
);
/// `ErrorCode.Request.INVALID_READ_TIMEOUT` (afirma-core)
pub const INVALID_READ_TIMEOUT: ErrorCode =
    ErrorCode::new(600012, "El tiempo de espera de lectura de los servicios no es valido");
/// `ErrorCode.Request.DATA_NOT_FOUND` (afirma-core)
pub const DATA_NOT_FOUND: ErrorCode = ErrorCode::new(
    600100,
    "No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de firma",
);
/// `ErrorCode.Request.RETRIEVE_URL_TO_SIGN_NOT_FOUND` (afirma-core)
pub const RETRIEVE_URL_TO_SIGN_NOT_FOUND: ErrorCode = ErrorCode::new(
    600101,
    "No se ha recibido la URL del servlet para descargar la informacion de la operacion de firma",
);
/// `ErrorCode.Request.STORAGE_URL_TO_SIGN_NOT_FOUND` (afirma-core)
pub const STORAGE_URL_TO_SIGN_NOT_FOUND: ErrorCode = ErrorCode::new(
    600102,
    "No se ha recibido la URL del servlet para guardar la firma en la operacion de firma",
);
/// `ErrorCode.Request.SIGNATURE_FORMAT_NOT_FOUND` (afirma-core)
pub const SIGNATURE_FORMAT_NOT_FOUND: ErrorCode = ErrorCode::new(
    600104,
    "No se ha recibido el formato de firma para la operacion de firma",
);
/// `ErrorCode.Request.UNSUPPORTED_SIGNATURE_FORMAT` (afirma-core)
pub const UNSUPPORTED_SIGNATURE_FORMAT: ErrorCode = ErrorCode::new(
    600105,
    "El formato de firma indicado en la operacion de firma no esta soportado",
);
/// `ErrorCode.Request.SIGNATURE_ALGORITHM_NOT_FOUND` (afirma-core)
pub const SIGNATURE_ALGORITHM_NOT_FOUND: ErrorCode = ErrorCode::new(
    600106,
    "No se ha recibido el algoritmo de firma para la operacion de firma",
);
/// `ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM` (afirma-core)
pub const UNSUPPORTED_SIGNATURE_ALGORITHM: ErrorCode = ErrorCode::new(
    600107,
    "El algoritmo de firma indicado en la operacion de firma no esta soportado",
);
/// `ErrorCode.Request.UNSUPPORTED_COUNTERSIGN_CONFIG` (afirma-core)
pub const UNSUPPORTED_COUNTERSIGN_CONFIG: ErrorCode =
    ErrorCode::new(600110, "No se soporta la configuracion de nodos a contrafirmar");
/// `ErrorCode.Request.UNSUPPORTED_POLICY_HASH_ALGORITHM` (afirma-core)
pub const UNSUPPORTED_POLICY_HASH_ALGORITHM: ErrorCode = ErrorCode::new(
    600111,
    "El algoritmo de huella indicado en la politica de firma no esta soportado",
);
/// `ErrorCode.Request.INVALID_COUNTERSIGNATURE_INDEX` (afirma-core)
pub const INVALID_COUNTERSIGNATURE_INDEX: ErrorCode = ErrorCode::new(
    600112,
    "El numero indicado no se corresponde con la posicion de ninguna contrafirma",
);
/// `ErrorCode.Request.INVALID_TIMESTAMP_HASH_ALGORITHM` (afirma-core)
pub const INVALID_TIMESTAMP_HASH_ALGORITHM: ErrorCode = ErrorCode::new(
    600113,
    "El algoritmo de huella para el sello de tiempo no esta soportado",
);
/// `TriphaseErrorCode.Request.MALFORMED_PRESIGN` (afirma-server-triphase-signer-core)
pub const MALFORMED_PRESIGN: ErrorCode = ErrorCode::new(600114, "La prefirma recibida esta mal formada");
/// `TriServiceErrorCode.Request.CRYPTO_OPERATION_NOT_FOUND` (afirma-server-triphase-signer)
pub const CRYPTO_OPERATION_NOT_FOUND: ErrorCode = ErrorCode::new(
    600115,
    "No se ha recibido el identificador de operacion criptografica para la operacion de firma",
);
/// `ErrorCode.Request.INVALID_RETRIEVE_URL_TO_SIGN` (afirma-core)
pub const INVALID_RETRIEVE_URL_TO_SIGN: ErrorCode = ErrorCode::new(
    600116,
    "La URL del servlet de descarga para la operacion de firma esta mal formado",
);
/// `TriServiceErrorCode.Request.UNSUPPORTED_CRYPTO_OPERATION` (afirma-server-triphase-signer)
pub const UNSUPPORTED_CRYPTO_OPERATION: ErrorCode =
    ErrorCode::new(600116, "El identificador de operacion criptografica no es valido");
/// `ErrorCode.Request.RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL` (afirma-core)
pub const RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL: ErrorCode = ErrorCode::new(
    600117,
    "La URL del servlet de descarga para la operacion de firma no puede ser local",
);
/// `ErrorCode.Request.INVALID_STORAGE_URL_TO_SIGN` (afirma-core)
pub const INVALID_STORAGE_URL_TO_SIGN: ErrorCode = ErrorCode::new(
    600118,
    "La URL del servlet de guardado para la operacion de firma esta mal formada",
);
/// `ErrorCode.Request.LOCAL_STORAGE_URL_TO_SIGN` (afirma-core)
pub const LOCAL_STORAGE_URL_TO_SIGN: ErrorCode = ErrorCode::new(
    600119,
    "La URL del servlet de guardado para la operacion de firma no puede ser local",
);
/// `ErrorCode.Request.INVALID_SESSION_ID_TO_SIGN` (afirma-core)
pub const INVALID_SESSION_ID_TO_SIGN: ErrorCode =
    ErrorCode::new(600120, "El id de sesion recibido para la firma no es valido");
/// `SimpleErrorCode.Request.INVALID_FORMAT_SIGNATURE_PARAM` (afirma-simple)
pub const INVALID_FORMAT_SIGNATURE_PARAM: ErrorCode =
    ErrorCode::new(600121, "Alguna de las propiedades de firma es incorrecta");
/// `ErrorCode.Request.STORAGE_URL_TO_SELECT_CERT_NOT_FOUND` (afirma-core)
pub const STORAGE_URL_TO_SELECT_CERT_NOT_FOUND: ErrorCode = ErrorCode::new(
    600200,
    "No se ha recibido la URL del servlet para guardar el certificado en la operacion de enviar certificado",
);
/// `ErrorCode.Request.INVALID_SESSION_ID_TO_SELECT_CERT` (afirma-core)
pub const INVALID_SESSION_ID_TO_SELECT_CERT: ErrorCode = ErrorCode::new(
    600201,
    "El id de sesion recibido para la seleccion de certificado no es valido",
);
/// `ErrorCode.Request.INVALID_STORAGE_URL_TO_SELECT_CERT` (afirma-core)
pub const INVALID_STORAGE_URL_TO_SELECT_CERT: ErrorCode = ErrorCode::new(
    600202,
    "La URL del servlet de guardado para la operacion de seleccion de certificado esta mal formada",
);
/// `ErrorCode.Request.LOCAL_STORAGE_URL_TO_SELECT_CERT` (afirma-core)
pub const LOCAL_STORAGE_URL_TO_SELECT_CERT: ErrorCode = ErrorCode::new(
    600203,
    "La URL del servlet de guardado para la operacion de seleccion de certificado no puede ser local",
);
/// `ErrorCode.Request.DATA_TO_SAVE_NOT_FOUND` (afirma-core)
pub const DATA_TO_SAVE_NOT_FOUND: ErrorCode = ErrorCode::new(
    600300,
    "No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de guardado",
);
/// `ErrorCode.Request.RETRIEVE_URL_TO_SAVE_NOT_FOUND` (afirma-core)
pub const RETRIEVE_URL_TO_SAVE_NOT_FOUND: ErrorCode = ErrorCode::new(
    600301,
    "No se ha recibido la URL del servlet para descargar la informacion de la operacion de guardado",
);
/// `ErrorCode.Request.STORAGE_URL_TO_SAVE_NOT_FOUND` (afirma-core)
pub const STORAGE_URL_TO_SAVE_NOT_FOUND: ErrorCode = ErrorCode::new(
    600302,
    "No se ha recibido la URL del servlet para guardar la firma en la operacion de guardado",
);
/// `ErrorCode.Request.INVALID_SESSION_ID_TO_SAVE` (afirma-core)
pub const INVALID_SESSION_ID_TO_SAVE: ErrorCode = ErrorCode::new(
    600303,
    "El id de sesion recibido para el guardado de datos no es valido",
);
/// `ErrorCode.Request.INVALID_STORAGE_URL_TO_SAVE` (afirma-core)
pub const INVALID_STORAGE_URL_TO_SAVE: ErrorCode = ErrorCode::new(
    600304,
    "La URL del servlet de guardado para la operacion de guargado esta mal formada",
);
/// `ErrorCode.Request.LOCAL_STORAGE_URL_TO_SAVE` (afirma-core)
pub const LOCAL_STORAGE_URL_TO_SAVE: ErrorCode = ErrorCode::new(
    600305,
    "La URL del servlet de guardado para la operacion de guardado no puede ser local",
);
/// `ErrorCode.Request.FILENAME_TO_SAVE_NOT_FOUND` (afirma-core)
pub const FILENAME_TO_SAVE_NOT_FOUND: ErrorCode = ErrorCode::new(
    600306,
    "No se ha recibido el nombre por defecto para el fichero de datos a guardar",
);
/// `ErrorCode.Request.FILE_EXTENSION_TO_SAVE_NOT_FOUND` (afirma-core)
pub const FILE_EXTENSION_TO_SAVE_NOT_FOUND: ErrorCode = ErrorCode::new(
    600307,
    "No se ha recibido la extension por defecto para el fichero de datos a guardar",
);
/// `ErrorCode.Request.STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND` (afirma-core)
pub const STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND: ErrorCode = ErrorCode::new(
    600402,
    "No se ha recibido la URL del servlet para guardar la firma en la operacion de firma de lotes",
);
/// `ErrorCode.Request.ID_SESSION_TO_SIGN_BATCH_NOT_FOUND` (afirma-core)
pub const ID_SESSION_TO_SIGN_BATCH_NOT_FOUND: ErrorCode = ErrorCode::new(
    600403,
    "No se ha recibido el id del fichero a guardar para la operacion de firma de lotes",
);
/// `ErrorCode.Request.PRESIGN_BATCH_URL_NOT_FOUND` (afirma-core)
pub const PRESIGN_BATCH_URL_NOT_FOUND: ErrorCode =
    ErrorCode::new(600405, "No se ha recibido el URL de prefirma de la firma de lotes");
/// `ErrorCode.Request.POSTSIGN_BATCH_URL_NOT_FOUND` (afirma-core)
pub const POSTSIGN_BATCH_URL_NOT_FOUND: ErrorCode =
    ErrorCode::new(600406, "No se ha recibido el URL de postfirma de la firma de lotes");
/// `ErrorCode.Request.INVALID_SESSION_ID_TO_SIGN_BATCH` (afirma-core)
pub const INVALID_SESSION_ID_TO_SIGN_BATCH: ErrorCode = ErrorCode::new(600410, "El id de sesion recibido no es valido");
/// `ErrorCode.Request.INVALID_STORAGE_URL_TO_SIGN_BATCH` (afirma-core)
pub const INVALID_STORAGE_URL_TO_SIGN_BATCH: ErrorCode = ErrorCode::new(
    600411,
    "La URL del servlet de guardado para la operacion de firma de lotes esta mal formada",
);
/// `ErrorCode.Request.LOCAL_STORAGE_URL_TO_SIGN_BATCH` (afirma-core)
pub const LOCAL_STORAGE_URL_TO_SIGN_BATCH: ErrorCode = ErrorCode::new(
    600412,
    "La URL del servlet de guardado para la operacion de firma de lotes no puede ser local",
);
/// `ErrorCode.Request.INVALID_PRESIGN_BATCH_URL` (afirma-core)
pub const INVALID_PRESIGN_BATCH_URL: ErrorCode =
    ErrorCode::new(600413, "La URL de prefirma de la firma de lotes esta mal formada");
/// `ErrorCode.Request.LOCAL_PRESIGN_BATCH_URL` (afirma-core)
pub const LOCAL_PRESIGN_BATCH_URL: ErrorCode =
    ErrorCode::new(600414, "La URL de prefirma de la firma de lotes no puede ser local");
/// `ErrorCode.Request.INVALID_POSTSIGN_BATCH_URL` (afirma-core)
pub const INVALID_POSTSIGN_BATCH_URL: ErrorCode =
    ErrorCode::new(600415, "La URL de postfirma de la firma de lotes esta mal formada");
/// `ErrorCode.Request.LOCAL_POSTSIGN_BATCH_URL` (afirma-core)
pub const LOCAL_POSTSIGN_BATCH_URL: ErrorCode =
    ErrorCode::new(600416, "La URL de postfirma de la firma de lotes no puede ser local");
/// `BatchErrorCode.Request.INVALID_PARAMS_TO_PRESIGN_JSON_BATCH` (afirma-crypto-batch-client)
pub const INVALID_PARAMS_TO_PRESIGN_JSON_BATCH: ErrorCode = ErrorCode::new(
    600417,
    "El servicio de prefirma de lote JSON informo de un error en los parametros enviados",
);
/// `BatchErrorCode.Request.INVALID_PARAMS_TO_POSTSIGN_JSON_BATCH` (afirma-crypto-batch-client)
pub const INVALID_PARAMS_TO_POSTSIGN_JSON_BATCH: ErrorCode = ErrorCode::new(
    600418,
    "El servicio de postfirma de lote JSON informo de un error en los parametros enviados",
);
/// `BatchErrorCode.Request.MALFORMED_JSON_BATCH` (afirma-crypto-batch-client)
pub const MALFORMED_JSON_BATCH: ErrorCode = ErrorCode::new(600419, "El lote no es un JSON valido o esta mal formado");
/// `SimpleErrorCode.Request.INVALID_FORMAT_SIGN_BATCH_PARAM` (afirma-simple)
pub const INVALID_FORMAT_SIGN_BATCH_PARAM: ErrorCode =
    ErrorCode::new(600420, "Alguna de las propiedades de firma del lote es incorrecta");
/// `BatchErrorCode.Request.INVALID_PARAMS_TO_PRESIGN_XML_BATCH` (afirma-crypto-batch-client)
pub const INVALID_PARAMS_TO_PRESIGN_XML_BATCH: ErrorCode = ErrorCode::new(
    600501,
    "El servicio de prefirma de lote XML informo de un error en los parametros enviados",
);
/// `BatchErrorCode.Request.INVALID_PARAMS_TO_POSTSIGN_XML_BATCH` (afirma-crypto-batch-client)
pub const INVALID_PARAMS_TO_POSTSIGN_XML_BATCH: ErrorCode = ErrorCode::new(
    600502,
    "El servicio de postfirma de lote XML informo de un error en los parametros enviados",
);
/// `BatchErrorCode.Request.MALFORMED_XML_BATCH` (afirma-crypto-batch-client)
pub const MALFORMED_XML_BATCH: ErrorCode = ErrorCode::new(600503, "El lote no es un XML valido o esta mal formado");
/// `MassiveErrorCode.Request.DECODING_HASH_ERROR` (afirma-core-massive)
pub const DECODING_HASH_ERROR: ErrorCode =
    ErrorCode::new(600601, "Se ha proporcionado un hash no valido para la firma explicita");
/// `ErrorCode.Request.INVALID_PARAMS_TO_PRESIGN` (afirma-core)
pub const INVALID_PARAMS_TO_PRESIGN: ErrorCode = ErrorCode::new(
    600701,
    "El servicio de prefirma informo de un error en los parametros enviados",
);
/// `ErrorCode.Request.INVALID_PARAMS_TO_POSTSIGN` (afirma-core)
pub const INVALID_PARAMS_TO_POSTSIGN: ErrorCode = ErrorCode::new(
    600702,
    "El servicio de postfirma informo de un error en los parametros enviados",
);
/// `XMLErrorCode.Request.INVALID_ENCODING_URI` (afirma-crypto-core-xml)
pub const INVALID_ENCODING_URI: ErrorCode = ErrorCode::new(610001, "La URI del algoritmo de codificacion no es valida");
/// `XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI` (afirma-crypto-core-xml)
pub const INVALID_REFERENCES_HASH_ALGORITHM_URI: ErrorCode =
    ErrorCode::new(610002, "La URI del algoritmo de huella de las referencias no es valida");
/// `XMLErrorCode.Request.INVALID_CANONICALIZATION_URI` (afirma-crypto-core-xml)
pub const INVALID_CANONICALIZATION_URI: ErrorCode =
    ErrorCode::new(610003, "La URI del algoritmo de canonicalizacion no es valida");
/// `XMLErrorCode.Request.INVALID_PRECALCULATED_DATA_HASH_ALGORITHM` (afirma-crypto-core-xml)
pub const INVALID_PRECALCULATED_DATA_HASH_ALGORITHM: ErrorCode =
    ErrorCode::new(610004, "El algoritmo de huella de los datos precalculados no es valido");
/// `XMLErrorCode.Request.INVALID_TRANSFORMATION` (afirma-crypto-core-xml)
pub const INVALID_TRANSFORMATION: ErrorCode = ErrorCode::new(610005, "La transformacion no es valida");
/// `XMLErrorCode.Request.INVALID_REFERENCE_URI` (afirma-crypto-core-xml)
pub const INVALID_REFERENCE_URI: ErrorCode = ErrorCode::new(610006, "La URI a los datos firmados no es valida");
/// `XMLErrorCode.Request.INVALID_NODE_SELECTOR_XPATH` (afirma-crypto-core-xml)
pub const INVALID_NODE_SELECTOR_XPATH: ErrorCode =
    ErrorCode::new(610007, "La ruta XPATH para la seleccion de nodo no es valida");
/// `XAdESErrorCode.Request.REFERENCE_HASH_NOT_FOUND` (afirma-crypto-xades)
pub const REFERENCE_HASH_NOT_FOUND: ErrorCode = ErrorCode::new(
    610201,
    "No se ha indicado la huella digital de una referencia a los datos firmados",
);
/// `XAdESErrorCode.Request.INVALID_REFERENCE_HASH` (afirma-crypto-xades)
pub const INVALID_REFERENCE_HASH: ErrorCode =
    ErrorCode::new(610202, "Error al decodificar el hash de los datos referenciados");
/// `XAdESErrorCode.Request.MANIFEST_REFERENCES_NOT_FOUND` (afirma-crypto-xades)
pub const MANIFEST_REFERENCES_NOT_FOUND: ErrorCode =
    ErrorCode::new(610203, "No se han proporcionado referencias para el manifest de firma");
/// `XAdESErrorCode.Request.INVALID_DATA_REFERENCE_URI` (afirma-crypto-xades)
pub const INVALID_DATA_REFERENCE_URI: ErrorCode = ErrorCode::new(610204, "La URI a los datos firmados no es valida");
/// `PdfErrorCode.Request.INVALID_SIGNATURE_POSITION` (afirma-crypto-pdf-common)
pub const INVALID_SIGNATURE_POSITION: ErrorCode =
    ErrorCode::new(610301, "La posicion para la firma visible en la pagina no es valida");
/// `PdfErrorCode.Request.INVALID_SIGNATURE_PAGE` (afirma-crypto-pdf-common)
pub const INVALID_SIGNATURE_PAGE: ErrorCode = ErrorCode::new(610302, "La pagina para la firma visible no es valida");
/// `SimpleErrorCode.Request.UNSUPPORTED_REQUEST_SCHEME` (afirma-simple)
pub const UNSUPPORTED_REQUEST_SCHEME: ErrorCode =
    ErrorCode::new(620009, "El esquema de la URL de invocacion no esta soportado");
/// `SimpleErrorCode.Request.INVALID_SESSION_ID` (afirma-simple)
pub const INVALID_SESSION_ID: ErrorCode =
    ErrorCode::new(620010, "El identificador de sesion del websocket es incorrecto");
/// `SimpleErrorCode.Request.UNSUPPORTED_PROTOCOL_VERSION` (afirma-simple)
pub const UNSUPPORTED_PROTOCOL_VERSION: ErrorCode = ErrorCode::new(
    620011,
    "Version de protocolo de comunicacion con el navegador no soportada",
);
/// `SimpleErrorCode.Request.REQUEST_URI_NOT_FOUND` (afirma-simple)
pub const REQUEST_URI_NOT_FOUND: ErrorCode = ErrorCode::new(620012, "No se ha proporcionado la URI de invocacion");
/// `SimpleErrorCode.Request.PORTS_NOT_FOUND` (afirma-simple)
pub const PORTS_NOT_FOUND: ErrorCode = ErrorCode::new(620013, "No se han proporciona los puertos de conexion");
/// `SimpleErrorCode.Request.MALFORMED_REQUEST_TO_SOCKET` (afirma-simple)
pub const MALFORMED_REQUEST_TO_SOCKET: ErrorCode =
    ErrorCode::new(620016, "Los parametros recibidos en el socket no son correctos");

/// Todos los códigos (para búsquedas por número).
pub const ALL: &[ErrorCode] = &[
    KEYSTORE_SMARTCARD_LOCKED,
    LIBRARY_NOT_FOUND,
    LOADING_DATA_ERROR,
    CANT_LOAD_HELP,
    NOT_VALID_PLUGIN,
    ERROR_IMPORT_LANGUAGE,
    ENCRIPTING_SIGNATURE,
    ENCRIPTING_SIGNING_CERT,
    LOADING_LOCAL_FILE_ERROR,
    SIGNING_KEY_AUTHENTICATION_ERROR,
    INVALID_SIGNING_KEY,
    SIGNING_PKCS1_ERROR,
    INVALID_PKCS1_VALUE,
    VERIFING_PKCS1_ERROR,
    ENCODING_SIGNING_CERTIFICATE,
    UNKNOWN_SIGNING_ERROR,
    ENCRIPTING_SIGNATURE_EXTRA_DATA,
    POSTPROCESING_SIGNATURE,
    UNSUPPORTED_HASH_ALGORITHM,
    UNKNOWN_SIGNING_BY_SOCKETS_ERROR,
    LOAD_FILE_TO_VIEW,
    ENCRIPTING_SELECTED_CERT,
    UNKNOWN_SELECTING_CERT_ERROR,
    CANT_SAVE_FILE,
    UNKNOWN_SAVING_DATA_ERROR,
    ENCRIPTING_BATCH_RESULT,
    ENCRIPTING_BATCH_SIGNING_CERT,
    BATCHSERVICE_INTERNAL_JSON_BATCH_ERROR,
    SIMPLE_INTERNAL_JSON_BATCH_ERROR,
    INTERNAL_XML_BATCH_ERROR,
    INTERNAL_LOCAL_BATCH_ERROR,
    UNKNOWN_BATCH_ERROR,
    UNKNOWN_LOADING_DATA_ERROR,
    CANT_LOAD_FILE,
    NEEDS_UPDATED_VERSION,
    NO_DETECTED_PROXIES,
    ERROR_LOAD_TRUSTED_CERT,
    TRUSTSTORE_INCORRECT_INSTALLATION,
    LOADING_KEYSTORE_INTERNAL_ERROR,
    LOADING_PRIVATE_KEY_ERROR,
    LOADING_CERTIFICATE_ERROR,
    LOADING_WINDOWS_KEYSTORE_ERROR,
    LOADING_MOZILLA_KEYSTORE_ERROR,
    LOADING_APPLE_KEYSTORE_ERROR,
    LOADING_PKCS12_KEYSTORE_ERROR,
    LOADING_JAVA_KEYSTORE_ERROR,
    LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR,
    LOADING_PKCS11_KEYSTORE_ERROR,
    LOADING_JMULTICARD_KEYSTORE_ERROR,
    LOADING_FILE_CERTSTORE_ERROR,
    UNDEFINED_DEFAULT_KEYSTORE,
    UNKWNON_BINARY_SIGNING_ERROR,
    INTERNAL_BINARY_SIGNING_ERROR,
    GENERATING_TIMESTAMP_ERROR,
    UNKWNON_PADES_SIGNING_ERROR,
    INTERNAL_PADES_SIGNING_ERROR,
    SIGNING_PDF_WITH_UNREGISTER_SIGNATURES,
    SIGNING_PDF_WITH_BAD_PASSWORD,
    SIGNING_PDF_WITHOUT_PASSWORD,
    SIGNING_PDF_WITH_MODIFIED_FORM,
    SIGNING_PDF_WITH_CERTIFIED_SIGN,
    SIGNING_PDF_WITH_SUSPICION_OF_PSA,
    UNKWNON_XML_SIGNING_ERROR,
    INTERNAL_XML_SIGNING_ERROR,
    UNKWNON_ODF_SIGNING_ERROR,
    UNSUPPORTED_TRANSFORMATION_ALGORITHM,
    INTERNAL_ODF_SIGNING_ERROR,
    UNKWNON_OOXML_SIGNING_ERROR,
    INTERNAL_OOXML_SIGNING_ERROR,
    BUILDING_ASIC_CONTAINER_ERROR,
    SOCKET_INITIALIZING_ERROR,
    DECRYPTING_PARAMS_ERROR,
    ERROR_RECIVED_FROM_CLIENT,
    ENCRYPTING_PARAMS_ERROR,
    LOADING_SSL_KEYSTORE_ERROR,
    GENERIC_LANGUAGE_IMPORT_ERROR,
    CANT_READ_FILE,
    CANT_CREATE_DIRECTORY,
    PLUGIN_ERROR,
    UNINSTALL_PLUGIN_ERROR,
    ERROR_IN_PLUGIN,
    CANT_REMOVE_LOADED_PLUGIN,
    PLUGIN_DIRECTORY_ERROR,
    PLUGIN_LOAD_ERROR,
    INSTALLED_PLUGIN_NOT_FOUND,
    IMPORTING_PREFERENCES_ERROR,
    CANT_READ_PREFERENCES_FILE,
    INVALID_XML_PREFERENCES_FILE,
    INVALID_FORMAT_PREFERENCES_FILE,
    BOUNCYCASTLE_VERSION_NOT_SUPPORTED,
    ITEXT_VERSION_NOT_SUPPORTED,
    SUN_MSCAPI_PROVIDER_NOT_FOUND,
    AFIRMA_MSCAPI_ADDRESBOOK_PROVIDER_NOT_FOUND,
    AFIRMA_SINGLE_CERT_PROVIDER_NOT_FOUND,
    INVALID_OPERATION_XML,
    PRESIGN_HTTP_ERROR,
    MALFORMED_PRESIGN_RESPONSE,
    PRESIGNS_NOT_FOUND,
    POSTSIGN_HTTP_ERROR,
    POSTSIGN_ERROR,
    MALFORMED_POSTSIGN_RESPONSE,
    TRI_SERVER_PRESIGN_ERROR_1,
    TRI_SERVER_PRESIGN_ERROR_2,
    TRI_SERVER_PRESIGN_ERROR_3,
    TRI_SERVER_PRESIGN_ERROR_4,
    TRI_SERVER_PRESIGN_ERROR_5,
    TRI_SERVER_PRESIGN_ERROR_6,
    TRI_SERVER_PRESIGN_ERROR_7,
    TRI_SERVER_PRESIGN_ERROR_8,
    TRI_SERVER_PRESIGN_ERROR_9,
    TRI_SERVER_PRESIGN_ERROR_10,
    TRI_SERVER_PRESIGN_ERROR_11,
    TRI_SERVER_PRESIGN_ERROR_12,
    TRI_SERVER_PRESIGN_ERROR_13,
    TRI_SERVER_PRESIGN_ERROR_14,
    TRI_SERVER_PRESIGN_ERROR_15,
    TRI_SERVER_PRESIGN_ERROR_16,
    TRI_SERVER_PRESIGN_ERROR_17,
    TRI_SERVER_PRESIGN_ERROR_18,
    TRI_SERVER_PRESIGN_ERROR_19,
    TRI_SERVER_PRESIGN_ERROR_20,
    TRI_SERVER_POSTSIGN_ERROR_1,
    TRI_SERVER_POSTSIGN_ERROR_2,
    TRI_SERVER_POSTSIGN_ERROR_3,
    TRI_SERVER_POSTSIGN_ERROR_4,
    TRI_SERVER_POSTSIGN_ERROR_5,
    TRI_SERVER_POSTSIGN_ERROR_6,
    TRI_SERVER_POSTSIGN_ERROR_7,
    TRI_SERVER_POSTSIGN_ERROR_8,
    TRI_SERVER_POSTSIGN_ERROR_9,
    TRI_SERVER_POSTSIGN_ERROR_10,
    TRI_SERVER_POSTSIGN_ERROR_11,
    TRI_SERVER_POSTSIGN_ERROR_12,
    TRI_SERVER_POSTSIGN_ERROR_13,
    TRI_SERVER_POSTSIGN_ERROR_14,
    TRI_SERVER_POSTSIGN_ERROR_15,
    TRI_SERVER_POSTSIGN_ERROR_16,
    TRI_SERVER_POSTSIGN_ERROR_17,
    TRI_SERVER_POSTSIGN_ERROR_18,
    TRI_SERVER_POSTSIGN_ERROR_19,
    TRI_SERVER_POSTSIGN_ERROR_20,
    TRI_SERVER_UNKNOWN_PRESIGN_ERROR,
    TRI_SERVER_UNKNOWN_POSTSIGN_ERROR,
    JSON_BATCH_PRESIGN_ERROR,
    JSON_BATCH_POSTSIGN_ERROR,
    XML_BATCH_PRESIGN_ERROR,
    XML_BATCH_POSTSIGN_ERROR,
    PROXY_CONNECTION,
    INVALID_DOMAIN_SSL_CERTIFICATE_ERROR,
    RECIVING_DATA_OF_SIGN_OPERATION,
    RECIVING_DATA_OF_CERT_OPERATION,
    RECIVING_DATA_OF_BATCH_OPERATION,
    RECIVING_DATA_OF_SAVE_OPERATION,
    RECIVING_DATA_OF_LOAD_OPERATION,
    RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION,
    RECIVING_DATA_OF_SIGN_TIMEOUT,
    RECIVING_DATA_OF_CERT_TIMEOUT,
    RECIVING_DATA_OF_BATCH_TIMEOUT,
    RECIVING_DATA_OF_SAVE_TIMEOUT,
    RECIVING_DATA_OF_LOAD_TIMEOUT,
    RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT,
    SENDING_RESULT_OPERATION,
    SENDING_RESULT_TIMEOUT,
    PRESIGN_SERVICE_CONNECTION_ERROR,
    PRESIGN_SERVICE_COMMUNICATION_ERROR,
    PRESIGN_SERVICE_TIMEOUT,
    POSTSIGN_SERVICE_CONNECTION_ERROR,
    POSTSIGN_SERVICE_COMMUNICATION_ERROR,
    POSTSIGN_SERVICE_TIMEOUT,
    JSON_BATCH_PRESIGN_CONNECTION_ERROR,
    JSON_BATCH_PRESIGN_COMMUNICATION_ERROR,
    JSON_BATCH_PRESIGN_TIMEOUT,
    JSON_BATCH_POSTSIGN_CONNECTION_ERROR,
    JSON_BATCH_POSTSIGN_COMMUNICATION_ERROR,
    JSON_BATCH_POSTSIGN_TIMEOUT,
    XML_BATCH_PRESIGN_CONNECTION_ERROR,
    XML_BATCH_PRESIGN_COMMUNICATION_ERROR,
    XML_BATCH_PRESIGN_TIMEOUT,
    XML_BATCH_POSTSIGN_CONNECTION_ERROR,
    XML_BATCH_POSTSIGN_COMMUNICATION_ERROR,
    XML_BATCH_POSTSIGN_TIMEOUT,
    TSA_CONNECTION_ERROR,
    DERREFERENCING_DATA_ERROR,
    EXTERNAL_REQUEST,
    SENDING_RESULT_OPERATION_BY_SOCKET,
    READING_FROM_SOCKET,
    CANCELLED_OPERATION,
    INVALID_SIGNATURE,
    INCOMPATIBLE_OPERATING_SYSTEM,
    INCOMPATIBLE_JRE,
    MINIMUM_VERSION_NON_SATISTIED,
    SIGNER_REQUIREMENT_NOT_SUPPORTED,
    VALIDATOR_REQUIREMENT_NOT_SUPPORTED,
    CERTIFICATE_NEEDED,
    NO_CERTS_FOUND_SIGNING,
    INVALID_FORMAT_FILE,
    INVALID_SMARTCARD_PIN,
    DOCUMENT_TOO_LARGE,
    COMPATIBLE_SIGNATURE_NOT_FOUND,
    SIGNING_LTS,
    SIGNING_WITH_POLICY_INCOMPATIBILITY,
    CANT_IDENTIFY_SIGNATURE_FORMAT,
    VISIBLE_SIGNATURE_IS_MANDATORY,
    XPATH_NOT_FOUND,
    NO_CERTS_FOUND_SELECTING_CERT,
    NO_CERTS_FOUND_SIGNING_BATCH,
    INDIR_NOT_FOUND,
    ACCESS_TO_DIR_IS_NOT_ALLOWED,
    INCOMPATIBLE_SIGNATURE,
    SIGNATURE_DOESNT_CONTAIN_DATA,
    XML_DOCUMENT_NEEDED,
    ODF_DOCUMENT_NEEDED,
    OOXML_DOCUMENT_NEEDED,
    PDF_DOCUMENT_NEEDED,
    SIGNING_MALFORMED_SIGNATURE,
    TRI_SIGNING_SIGNATURE,
    FACTURAE_ALREADY_SIGNED,
    FACTURAE_NEEDED,
    KEYSTORE_LOCKED,
    SMARTCARD_LOCKED,
    POLICY_DEFAULT_ERROR,
    INVALID_POLICY_IDENTIFIER,
    INVALID_POLICY_IDENTIFIER_URI,
    MISSING_DIGEST_ALGORITHM,
    UNREACHABLE_POLICY_IDENTIFIER_URI,
    INVALID_POLICY_IDENTIFIER_HASH_BASE64,
    INVALID_POLICY_QUALIFIER_URI,
    INVALID_POLICY_IDENTIFIER_OID,
    EMPTY_POLICY_HASH,
    INVALID_POLICY_QUALIFIER_URL,
    INVALID_PROXY_CONFIG,
    INVALID_CERTIFICATE_SIGNER,
    INVALID_PREFERENCES_FILE_SIGNATURE,
    INVALID_PREFERENCES_FILE_SIGNER,
    UNSIGNED_PREFERENCES_FILE,
    MALFORMED_PLUGIN_SERVICE,
    NO_PLUGIN_FOUND,
    MULTIPLE_PLUGINS_FOUND,
    BUTTON_NO_ACTION,
    BUTTON_NO_WINDOW,
    INVALID_ACTION_CLASS,
    INVALID_PLUGIN_FILE,
    ALREADY_INSTALLED_PLUGIN,
    PLUGIN_FILE_NOT_FOUND,
    UNSUPPORTED_OPERATION,
    UNSUPPORTED_CIPHER_KEY,
    LOCAL_RETRIEVE_URL,
    UNSUPPORTED_KEYSTORE,
    INVALID_READ_TIMEOUT,
    DATA_NOT_FOUND,
    RETRIEVE_URL_TO_SIGN_NOT_FOUND,
    STORAGE_URL_TO_SIGN_NOT_FOUND,
    SIGNATURE_FORMAT_NOT_FOUND,
    UNSUPPORTED_SIGNATURE_FORMAT,
    SIGNATURE_ALGORITHM_NOT_FOUND,
    UNSUPPORTED_SIGNATURE_ALGORITHM,
    UNSUPPORTED_COUNTERSIGN_CONFIG,
    UNSUPPORTED_POLICY_HASH_ALGORITHM,
    INVALID_COUNTERSIGNATURE_INDEX,
    INVALID_TIMESTAMP_HASH_ALGORITHM,
    MALFORMED_PRESIGN,
    CRYPTO_OPERATION_NOT_FOUND,
    INVALID_RETRIEVE_URL_TO_SIGN,
    UNSUPPORTED_CRYPTO_OPERATION,
    RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL,
    INVALID_STORAGE_URL_TO_SIGN,
    LOCAL_STORAGE_URL_TO_SIGN,
    INVALID_SESSION_ID_TO_SIGN,
    INVALID_FORMAT_SIGNATURE_PARAM,
    STORAGE_URL_TO_SELECT_CERT_NOT_FOUND,
    INVALID_SESSION_ID_TO_SELECT_CERT,
    INVALID_STORAGE_URL_TO_SELECT_CERT,
    LOCAL_STORAGE_URL_TO_SELECT_CERT,
    DATA_TO_SAVE_NOT_FOUND,
    RETRIEVE_URL_TO_SAVE_NOT_FOUND,
    STORAGE_URL_TO_SAVE_NOT_FOUND,
    INVALID_SESSION_ID_TO_SAVE,
    INVALID_STORAGE_URL_TO_SAVE,
    LOCAL_STORAGE_URL_TO_SAVE,
    FILENAME_TO_SAVE_NOT_FOUND,
    FILE_EXTENSION_TO_SAVE_NOT_FOUND,
    STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND,
    ID_SESSION_TO_SIGN_BATCH_NOT_FOUND,
    PRESIGN_BATCH_URL_NOT_FOUND,
    POSTSIGN_BATCH_URL_NOT_FOUND,
    INVALID_SESSION_ID_TO_SIGN_BATCH,
    INVALID_STORAGE_URL_TO_SIGN_BATCH,
    LOCAL_STORAGE_URL_TO_SIGN_BATCH,
    INVALID_PRESIGN_BATCH_URL,
    LOCAL_PRESIGN_BATCH_URL,
    INVALID_POSTSIGN_BATCH_URL,
    LOCAL_POSTSIGN_BATCH_URL,
    INVALID_PARAMS_TO_PRESIGN_JSON_BATCH,
    INVALID_PARAMS_TO_POSTSIGN_JSON_BATCH,
    MALFORMED_JSON_BATCH,
    INVALID_FORMAT_SIGN_BATCH_PARAM,
    INVALID_PARAMS_TO_PRESIGN_XML_BATCH,
    INVALID_PARAMS_TO_POSTSIGN_XML_BATCH,
    MALFORMED_XML_BATCH,
    DECODING_HASH_ERROR,
    INVALID_PARAMS_TO_PRESIGN,
    INVALID_PARAMS_TO_POSTSIGN,
    INVALID_ENCODING_URI,
    INVALID_REFERENCES_HASH_ALGORITHM_URI,
    INVALID_CANONICALIZATION_URI,
    INVALID_PRECALCULATED_DATA_HASH_ALGORITHM,
    INVALID_TRANSFORMATION,
    INVALID_REFERENCE_URI,
    INVALID_NODE_SELECTOR_XPATH,
    REFERENCE_HASH_NOT_FOUND,
    INVALID_REFERENCE_HASH,
    MANIFEST_REFERENCES_NOT_FOUND,
    INVALID_DATA_REFERENCE_URI,
    INVALID_SIGNATURE_POSITION,
    INVALID_SIGNATURE_PAGE,
    UNSUPPORTED_REQUEST_SCHEME,
    INVALID_SESSION_ID,
    UNSUPPORTED_PROTOCOL_VERSION,
    REQUEST_URI_NOT_FOUND,
    PORTS_NOT_FOUND,
    MALFORMED_REQUEST_TO_SOCKET,
];

/// Busca un código por su número.
pub fn by_code(code: u32) -> Option<ErrorCode> {
    ALL.iter().copied().find(|c| c.code == code)
}
