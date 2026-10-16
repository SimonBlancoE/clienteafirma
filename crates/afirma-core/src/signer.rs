//! Interfaz común de los firmadores (equivalente a `AOSigner`) y modelos de
//! información de firma (árbol de firmantes, `AOSignInfo`).

use chrono::{DateTime, Utc};

use crate::error::Result;
use crate::extra_params::ExtraParams;
use crate::key::SigningKey;

/// Objetivo de una contrafirma (`CounterSignTarget`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterSignTarget {
    /// Todos los nodos del árbol de firmantes (`tree`).
    Tree,
    /// Solo las hojas (`leafs`).
    Leafs,
    /// Nodos indicados por su índice en preorden (`nodes`).
    Nodes(Vec<usize>),
    /// Firmantes indicados por su Common Name (`signers`).
    Signers(Vec<String>),
}

impl CounterSignTarget {
    /// Nombre usado en el protocolo y la línea de comandos.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Leafs => "leafs",
            Self::Nodes(_) => "nodes",
            Self::Signers(_) => "signers",
        }
    }

    /// Interpreta el nombre (`tree`, `leafs`, `nodes`, `signers`) sin
    /// distinguir mayúsculas. Para `nodes` y `signers` los objetivos se
    /// añaden después.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "tree" => Some(Self::Tree),
            "leafs" => Some(Self::Leafs),
            "nodes" => Some(Self::Nodes(Vec::new())),
            "signers" => Some(Self::Signers(Vec::new())),
            _ => None,
        }
    }
}

/// Información de un firmante (`AOSimpleSignInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleSignInfo {
    /// Certificados (DER); el primero es el del firmante.
    pub certs: Vec<Vec<u8>>,
    pub signing_time: Option<DateTime<Utc>>,
    /// Algoritmo de firma tal y como lo informa AutoFirma (p. ej.
    /// `SHA256withRSA` en CMS o la URI de `SignatureMethod` en XML).
    pub sign_algorithm: Option<String>,
    /// Valor de firma PKCS#1.
    pub pkcs1: Vec<u8>,
    pub sign_format: Option<String>,
    /// Fechas de los sellos de tiempo de la firma.
    pub timestamping_time: Vec<DateTime<Utc>>,
}

impl SimpleSignInfo {
    /// Common Name del titular del certificado de firma (o el DN completo si
    /// no tiene CN).
    pub fn signer_name(&self) -> String {
        self.certs.first().map(|c| crate::cert::common_name(c)).unwrap_or_default()
    }

    pub fn is_timestamped(&self) -> bool {
        !self.timestamping_time.is_empty()
    }
}

/// Nodo del árbol de firmantes: una firma y sus contrafirmas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignerNode {
    pub info: SimpleSignInfo,
    pub countersigners: Vec<SignerNode>,
}

/// Árbol de firmantes (`AOTreeModel`). La raíz representa los datos
/// (`"Datos"`); sus hijos son las firmas y cofirmas en orden de documento y
/// cada nodo contiene sus contrafirmas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignersTree {
    pub signers: Vec<SignerNode>,
}

impl SignersTree {
    pub const ROOT_LABEL: &'static str = "Datos";

    /// Recorrido en preorden: `(profundidad, nodo)`. Los índices de este
    /// recorrido son los que usa la contrafirma por nodos.
    pub fn preorder(&self) -> Vec<(usize, &SignerNode)> {
        fn walk<'a>(n: &'a SignerNode, depth: usize, out: &mut Vec<(usize, &'a SignerNode)>) {
            out.push((depth, n));
            for c in &n.countersigners {
                walk(c, depth + 1, out);
            }
        }
        let mut out = Vec::new();
        for s in &self.signers {
            walk(s, 0, &mut out);
        }
        out
    }

    /// Representación textual como `AOTreeUtil.showTreeAsString` (con los
    /// nombres de los firmantes).
    pub fn to_text(&self, line_prefix: &str, indent: &str) -> String {
        let mut out = String::new();
        for (depth, node) in self.preorder() {
            out.push('\n');
            out.push_str(line_prefix);
            out.push_str(&indent.repeat(depth));
            out.push_str(&node.info.signer_name());
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }
}

/// Información general de una firma (`AOSignInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignInfo {
    pub format: String,
    pub variant: Option<String>,
    pub url_sign_object: Option<String>,
    pub url_signed_data: Option<String>,
    pub b64_verification_code: Option<String>,
}

/// Firmador de un formato (equivalente a `AOSigner`).
///
/// `algorithm` es el nombre de algoritmo tal y como llega de la web, la línea
/// de comandos o las preferencias (`SHA512withRSA`, `SHA256`...); cada
/// firmador lo normaliza con [`crate::algorithms::compose_signature_algorithm`]
/// según el tipo de la clave.
pub trait Signer: Send + Sync {
    /// Nombre del formato (`CAdES`, `XAdES`, `PAdES`...).
    fn format_name(&self) -> &'static str;

    fn sign(&self, data: &[u8], algorithm: &str, key: &dyn SigningKey, extra: &ExtraParams) -> Result<Vec<u8>>;

    /// Cofirma. `data` son los datos originales cuando la firma no los
    /// contiene (firmas explícitas).
    fn cosign(
        &self,
        data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> Result<Vec<u8>>;

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> Result<Vec<u8>>;

    /// Árbol de firmantes.
    fn signers_structure(&self, sign: &[u8], params: &ExtraParams) -> Result<SignersTree>;

    /// Indica si los datos son una firma de este formato. Nunca falla.
    fn is_sign(&self, data: &[u8], params: &ExtraParams) -> bool;

    /// Indica si los datos pueden firmarse con este formato.
    fn is_valid_data_file(&self, data: &[u8]) -> bool;

    /// Nombre sugerido para el fichero firmado (`inText` se inserta antes de
    /// la extensión de firma).
    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String;

    /// Datos firmados contenidos en la firma (`None` si es explícita).
    fn get_data(&self, sign: &[u8], params: &ExtraParams) -> Result<Option<Vec<u8>>>;

    fn sign_info(&self, sign: &[u8], params: &ExtraParams) -> Result<SignInfo>;
}
