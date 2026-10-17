//! Textos de usuario de Autofirma App 1.9 que forman parte de lo que recibe la
//! web (mensajes de error `ERR-NN:=AA… - <texto>`) o de los parámetros de firma
//! (plantilla de la firma visible, nombre de fichero por defecto), en los seis
//! idiomas de la app (`res/values*/strings.xml`, `docs/spec/09-android.md` §9).
//!
//! En la app original los catálogos de error se rellenan al aplicar el idioma de
//! una actividad y están vacíos en un proceso recién creado para `save`
//! (§10 n.º 2, `NullPointerException`). Aquí son tablas estáticas: nunca están
//! vacías.

/// Idioma de la app (`localeConfig`), que decide el texto de los errores que
/// se devuelven a la web.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WebLanguage {
    /// Español (`values`, idioma de referencia).
    #[default]
    Es,
    En,
    Ca,
    Gl,
    Eu,
    /// Valenciano (`values-b+ca+ES+valencia`).
    CaValencia,
}

impl WebLanguage {
    /// Todos los idiomas, en el orden de la pantalla «Idioma».
    pub const ALL: [WebLanguage; 6] = [
        WebLanguage::Es,
        WebLanguage::En,
        WebLanguage::Ca,
        WebLanguage::Gl,
        WebLanguage::Eu,
        WebLanguage::CaValencia,
    ];

    /// Idioma de la etiqueta guardada en `localeConfig` (`es`, `en`, `ca`, `gl`,
    /// `eu`, `ca-ES-valencia`), sin distinguir mayúsculas.
    pub fn from_tag(tag: &str) -> Option<WebLanguage> {
        let t = tag.trim().to_ascii_lowercase().replace('_', "-");
        Some(match t.as_str() {
            "es" => WebLanguage::Es,
            "en" => WebLanguage::En,
            "ca" => WebLanguage::Ca,
            "gl" => WebLanguage::Gl,
            "eu" => WebLanguage::Eu,
            "ca-es-valencia" | "ca-valencia" => WebLanguage::CaValencia,
            _ => return None,
        })
    }

    /// Etiqueta de `localeConfig`.
    pub fn tag(self) -> &'static str {
        match self {
            WebLanguage::Es => "es",
            WebLanguage::En => "en",
            WebLanguage::Ca => "ca",
            WebLanguage::Gl => "gl",
            WebLanguage::Eu => "eu",
            WebLanguage::CaValencia => "ca-ES-valencia",
        }
    }
}

/// Texto de usuario (clave de `strings.xml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserText {
    /// `not_completed_request`: el texto «genérico» de casi todos los errores.
    NotCompletedRequest,
    /// `operation_cancelled`.
    OperationCancelled,
    /// `necessary_pdf_file`.
    NecessaryPdfFile,
    /// `file_read_out_of_memory`.
    FileReadOutOfMemory,
    /// `error_loading_keystore`.
    ErrorLoadingKeystore,
    /// `error_loading_cert`.
    ErrorLoadingCert,
    /// `not_selected_cert`.
    NotSelectedCert,
    /// `error_desc_keystore_empty`.
    ErrorDescKeystoreEmpty,
    /// `error_saving_data`.
    ErrorSavingData,
    /// `error_no_storage_permissions`.
    ErrorNoStoragePermissions,
    /// `error_saving_signature`.
    ErrorSavingSignature,
    /// `pdf_visible_sign_template`: `layer2Text` de la firma visible.
    PdfVisibleSignTemplate,
    /// `default_saved_filename`: nombre propuesto en `save` sin `filename`.
    DefaultSavedFilename,
}

impl UserText {
    /// Clave del recurso en `strings.xml`.
    pub fn key(self) -> &'static str {
        match self {
            UserText::NotCompletedRequest => "not_completed_request",
            UserText::OperationCancelled => "operation_cancelled",
            UserText::NecessaryPdfFile => "necessary_pdf_file",
            UserText::FileReadOutOfMemory => "file_read_out_of_memory",
            UserText::ErrorLoadingKeystore => "error_loading_keystore",
            UserText::ErrorLoadingCert => "error_loading_cert",
            UserText::NotSelectedCert => "not_selected_cert",
            UserText::ErrorDescKeystoreEmpty => "error_desc_keystore_empty",
            UserText::ErrorSavingData => "error_saving_data",
            UserText::ErrorNoStoragePermissions => "error_no_storage_permissions",
            UserText::ErrorSavingSignature => "error_saving_signature",
            UserText::PdfVisibleSignTemplate => "pdf_visible_sign_template",
            UserText::DefaultSavedFilename => "default_saved_filename",
        }
    }

    /// Texto en un idioma.
    pub fn text(self, lang: WebLanguage) -> &'static str {
        use WebLanguage::*;
        match self {
            UserText::NotCompletedRequest => match lang {
                Es => {
                    "Hemos intentado procesar tu solicitud, pero no ha podido ser completada con éxito. Por favor revisa la documentación."
                }
                En => {
                    "We've tried to process your request, but it hasn't been completed successfully. Please check the documentation."
                }
                Ca => {
                    "Hem intentat processar la teva sol·licitud, però no ha pogut ser completada amb èxit. Si us plau revisa la documentació."
                }
                Gl => {
                    "Tentamos procesar a túa solicitude, pero non puido ser completada con éxito. Por favor revisa a documentación."
                }
                Eu => {
                    "Zure eskaera prozesatzen saiatu gara, baina ezin izan da behar bezala bete. Mesedez, berrikusi dokumentazioa."
                }
                CaValencia => {
                    "Hem intentat processar la teua sol·licitud, però no ha pogut ser completada amb èxit. Per favor revisa la documentació."
                }
            },
            UserText::OperationCancelled => match lang {
                Es | Gl => "Operacion cancelada",
                En => "Cancelled operation",
                Ca | CaValencia => "Operacion cancel·lada",
                Eu => "Eragiketa bertan behera geratu da",
            },
            UserText::NecessaryPdfFile => match lang {
                Es => "Para poder realizar esta operación es necesario seleccionar un fichero PDF",
                En => "In order to perform this operation it is necessary to select a PDF file",
                Ca => "Per a poder realitzar aquesta operació és necessari seleccionar un fitxer PDF",
                Gl => "Para poder realizar esta operación é necesario seleccionar un ficheiro PDF",
                Eu => "Eragiketa hau egiteko PDF fitxategi bat hautatu behar da",
                CaValencia => "Per a poder realitzar esta operació és necessari seleccionar un fitxer PDF",
            },
            UserText::FileReadOutOfMemory => match lang {
                Es => {
                    "El fichero seleccionado es demasiado grande y no hay memoria suficiente para completar la operación de lectura"
                }
                En => "The selected file is too large and there is no enough memory to load it",
                Ca => {
                    "El fitxer seleccionat és massa gran i no hi ha memòria suficient per completar l'operació de lectura"
                }
                Gl => {
                    "O ficheiro seleccionado é demasiado grande e non hai memoria suficiente para completar a operación de lectura"
                }
                Eu => {
                    "Hautatutako fitxategia handiegia da, eta ez dago behar adina memoriarik irakurketa-eragiketa osatzeko"
                }
                CaValencia => {
                    "El fitxer seleccionat és massa gran i no hi ha memòria suficient per a completar l'operació de lectura"
                }
            },
            UserText::ErrorLoadingKeystore => match lang {
                Es => "Error al cargar el almacen de certificados",
                En => "Error when loading the certificate store",
                Ca | CaValencia => "Error en carregar l'almacen de certificats",
                Gl => "Erro ao cargar o almacen de certificados",
                Eu => "Errorea gertatu da ziurtagiri-biltegia kargatzean",
            },
            UserText::ErrorLoadingCert => match lang {
                Es => "Error al cargar el certificado",
                En => "Error loading certificate",
                Ca | CaValencia => "Error en carregar el certificat",
                Gl => "Erro ao cargar o certificado",
                Eu => "Errorea gertatu da ziurtagiria kargatzean",
            },
            UserText::NotSelectedCert => match lang {
                Es => "Certificado no seleccionado",
                En => "Unselected certificate",
                Ca | CaValencia => "Certificat no seleccionat",
                Gl => "Certificado non seleccionado",
                Eu => "Ez da hautatu ziurtagiria",
            },
            UserText::ErrorDescKeystoreEmpty => match lang {
                Es => "Para firmar necesitas registrar un certificado digital",
                En => "To sign you need to register a digital certificate.",
                Ca | CaValencia => "Per a signar necessites registrar un certificat digital",
                Gl => "Para asinar necesitas rexistrar un certificado dixital",
                Eu => "Sinatzeko, ziurtagiri digital bat erregistratu behar duzu",
            },
            UserText::ErrorSavingData => match lang {
                Es => "Ocurrió un error al guardar los datos",
                En => "Error while saving data",
                Ca | CaValencia => "Va ocórrer un error en desar les dades",
                Gl => "Ocorreu un erro ao gardar os datos",
                Eu => "Errorea gertatu da datuak gordetzean",
            },
            UserText::ErrorNoStoragePermissions => match lang {
                Es => "El Cliente de firma no tiene permisos de escritura en disco.",
                En => "The Signature Client does not have disk write permissions.",
                Ca => "El Client de signatura no té permisos d'escriptura en disc.",
                Gl => "O Cliente de firma non ten permisos de escritura en disco.",
                Eu => "Bezeroak ez du diskoan idazteko baimenik.",
                CaValencia => "El Client de firma no té permisos d'escriptura en disc.",
            },
            UserText::ErrorSavingSignature => match lang {
                Es => "Ocurrió un error al guardar la firma",
                En => "Error trying to save the signature",
                Ca => "Va ocórrer un error en desar la signatura",
                Gl => "Ocorreu un erro ao gardar a firma",
                Eu => "Errorea gertatu da sinadura gordetzean",
                CaValencia => "Va ocórrer un error en desar la firma",
            },
            UserText::PdfVisibleSignTemplate => match lang {
                Es => {
                    "Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$"
                }
                En => "Signed by $$SUBJECTCN$$ on $$SIGNDATE=dd/MM/yyyy$$ with a certificate issued by $$ISSUERCN$$",
                Ca => "Signat per $$SUBJECTCN$$ el dia $$SIGNDATE=dd/MM/yyyy$$ amb un certificat emès per $$ISSUERCN$$",
                Gl => {
                    "Asinado por $$SUBJECTCN$$ o día $$SIGNDATE=dd/MM/yyyy$$ con certificado expedido por $$ISSUERCN$$"
                }
                Eu => "$$SUBJECTCN$$ k sinatuzuen $$SIGNDATE=dd/MM/yyyy$$ an $$ISSUERCN$$ ek emandako ziurtagiriarekin",
                CaValencia => {
                    "Firmat per $$SUBJECTCN$$ el dia $$SIGNDATE=dd/MM/yyyy$$ amb un certificat emès per $$ISSUERCN$$"
                }
            },
            UserText::DefaultSavedFilename => match lang {
                Es | Gl => "datos",
                En => "data",
                Ca | CaValencia => "dades",
                Eu => "datuak",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        for l in WebLanguage::ALL {
            assert_eq!(WebLanguage::from_tag(l.tag()), Some(l));
        }
        assert_eq!(WebLanguage::from_tag("CA_es_VALENCIA"), Some(WebLanguage::CaValencia));
        assert_eq!(WebLanguage::from_tag("fr"), None);
        assert_eq!(WebLanguage::default(), WebLanguage::Es);
    }

    #[test]
    fn spanish_reference_texts() {
        // El texto español de `operation_cancelled` no lleva tilde (§5.12).
        assert_eq!(
            UserText::OperationCancelled.text(WebLanguage::Es),
            "Operacion cancelada"
        );
        assert!(
            UserText::NotCompletedRequest
                .text(WebLanguage::Es)
                .starts_with("Hemos intentado")
        );
        assert_eq!(UserText::DefaultSavedFilename.text(WebLanguage::En), "data");
        assert_eq!(UserText::NotSelectedCert.key(), "not_selected_cert");
    }
}
