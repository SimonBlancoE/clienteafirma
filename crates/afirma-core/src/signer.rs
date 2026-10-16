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

impl CounterSignTarget {
    /// `CounterSignTarget.getTarget(name)`: recorta y compara sin distinguir
    /// mayúsculas. Errores con los mensajes de Java
    /// (`El objetivo de la contrafirma no puede ser nulo`,
    /// `Objetivo no soportado: <nombre>`).
    pub fn get_target(name: Option<&str>) -> Result<Self> {
        let name = name.ok_or_else(|| crate::AfirmaError::invalid_argument("El objetivo de la contrafirma no puede ser nulo"))?;
        Self::from_name(name).ok_or_else(|| crate::AfirmaError::invalid_argument(format!("Objetivo no soportado: {name}")))
    }
}

impl std::fmt::Display for CounterSignTarget {
    /// `toString()` de Java (`tree`, `leafs`, `nodes`, `signers`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl SimpleSignInfo {
    /// Texto del nodo en el árbol de firmantes (`AOSimpleSignInfo.toString()`):
    /// CN del firmante seguido de ` (TimeStamp: <fecha>)` si tiene sello de
    /// tiempo o ` (<fecha de firma>)` si tiene fecha. Las fechas se escriben
    /// en la zona horaria local con el formato de Java 17+ para `es_ES`
    /// (`16 oct 2026, 13:17`).
    pub fn display_text(&self) -> String {
        self.display_text_in(&chrono::Local)
    }

    /// Como [`SimpleSignInfo::display_text`] en una zona horaria concreta.
    pub fn display_text_in<Tz: chrono::TimeZone>(&self, tz: &Tz) -> String {
        let mut desc = self.signer_name();
        if let Some(ts) = self.timestamping_time.first() {
            desc.push_str(&format!(" (TimeStamp: {})", crate::javafmt::java_default_short_datetime_es(&ts.with_timezone(tz))));
        } else if let Some(t) = &self.signing_time {
            desc.push_str(&format!(" ({})", crate::javafmt::java_default_short_datetime_es(&t.with_timezone(tz))));
        }
        desc
    }
}

impl SignersTree {
    /// `AOTreeUtil.showTreeAsString`: por cada nodo en preorden,
    /// `"\n" + prefijo + sangría×profundidad + texto`. Con
    /// `as_simple_sign_info` el texto es el de
    /// [`SimpleSignInfo::display_text`]; si no, el CN del firmante. Valores
    /// por defecto de Java: prefijo vacío y sangría `\t`.
    pub fn show_tree_as_string(&self, line_prefix: Option<&str>, indent: Option<&str>, as_simple_sign_info: bool) -> String {
        let prefix = line_prefix.unwrap_or("");
        let indent = indent.unwrap_or("\t");
        let mut out = String::new();
        for (depth, node) in self.preorder() {
            out.push('\n');
            out.push_str(prefix);
            out.push_str(&indent.repeat(depth));
            if as_simple_sign_info {
                out.push_str(&node.info.display_text());
            } else {
                out.push_str(&node.info.signer_name());
            }
        }
        out
    }

    /// Número de nodos (firmas y contrafirmas).
    pub fn node_count(&self) -> usize {
        self.preorder().len()
    }

    /// Índices en preorden de las hojas (firmas sin contrafirmas), que son
    /// los objetivos de la contrafirma `leafs`.
    pub fn leaf_indexes(&self) -> Vec<usize> {
        self.preorder().iter().enumerate().filter(|(_, (_, n))| n.countersigners.is_empty()).map(|(i, _)| i).collect()
    }
}

impl SignInfo {
    /// `new AOSignInfo(format)`: `None` → `Desconocido`.
    pub fn new(format: Option<&str>) -> Self {
        SignInfo { format: format.unwrap_or(crate::constants::SIGN_INFO_UNKNOWN_FORMAT).to_string(), ..Default::default() }
    }
}

/// Sello de tiempo de una firma (`AOTimestampInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampInfo {
    /// Certificado de la TSA (DER), si se conoce.
    pub issuer: Option<Vec<u8>>,
    /// Fecha del sello.
    pub date: DateTime<Utc>,
}

impl TimestampInfo {
    /// Crea la información de un sello.
    pub fn new(issuer: Option<Vec<u8>>, date: DateTime<Utc>) -> Self {
        TimestampInfo { issuer, date }
    }

    /// Texto de Java: `Sello de tiempo emitido por '<CN|DESCONOCIDO>' con
    /// fecha <Date.toString()>` (fecha en la zona local con la zona escrita
    /// como `GMT±hh:mm`).
    pub fn display_text(&self) -> String {
        let issuer = self.issuer.as_deref().map(crate::cert::common_name).unwrap_or_else(|| "DESCONOCIDO".to_string());
        format!(
            "Sello de tiempo emitido por '{issuer}' con fecha {}",
            crate::javafmt::java_date_to_string(&self.date.with_timezone(&chrono::Local))
        )
    }

    /// Árbol de sellos de tiempo como lo construye afirma-simple
    /// (`CompleteSignInfo.getTimestampsTree`): un nodo por sello con el
    /// certificado de la TSA y su fecha como fecha de firma.
    pub fn timestamps_tree(timestamps: &[TimestampInfo]) -> SignersTree {
        SignersTree {
            signers: timestamps
                .iter()
                .map(|t| SignerNode {
                    info: SimpleSignInfo {
                        certs: t.issuer.iter().cloned().collect(),
                        signing_time: Some(t.date),
                        ..Default::default()
                    },
                    countersigners: Vec::new(),
                })
                .collect(),
        }
    }
}

impl std::fmt::Display for TimestampInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{FixedOffset, TimeZone};

    fn cert() -> Vec<u8> {
        let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/pki/firmante-rsa.crt")).unwrap();
        crate::cert::decode_certificate(&pem).unwrap()
    }

    fn node(info: SimpleSignInfo, children: Vec<SignerNode>) -> SignerNode {
        SignerNode { info, countersigners: children }
    }

    #[test]
    fn tree_rendering() {
        let c = cert();
        let t = Utc.with_ymd_and_hms(2026, 10, 16, 11, 17, 0).unwrap();
        let signer = SimpleSignInfo { certs: vec![c.clone()], signing_time: Some(t), ..Default::default() };
        let stamped = SimpleSignInfo { certs: vec![c.clone()], timestamping_time: vec![t], signing_time: Some(t), ..Default::default() };
        let tree = SignersTree {
            signers: vec![
                node(signer.clone(), vec![node(stamped.clone(), vec![node(SimpleSignInfo { certs: vec![c.clone()], ..Default::default() }, vec![])])]),
                node(signer.clone(), vec![]),
            ],
        };
        let cn = "ESPAÑOL ESPAÑOL JUAN - 00000000T";
        assert_eq!(tree.show_tree_as_string(None, None, false), format!("\n{cn}\n\t{cn}\n\t\t{cn}\n{cn}"));
        assert_eq!(tree.show_tree_as_string(Some(">"), Some("  "), false), format!("\n>{cn}\n>  {cn}\n>    {cn}\n>{cn}"));
        assert_eq!(tree.to_text("", "\t"), tree.show_tree_as_string(None, None, false));
        let madrid = FixedOffset::east_opt(7200).unwrap();
        assert_eq!(signer.display_text_in(&madrid), format!("{cn} (16 oct 2026, 13:17)"));
        assert_eq!(stamped.display_text_in(&madrid), format!("{cn} (TimeStamp: 16 oct 2026, 13:17)"));
        assert_eq!(tree.node_count(), 4);
        assert_eq!(tree.leaf_indexes(), vec![2, 3]);
        assert!(SignersTree::default().show_tree_as_string(None, None, true).is_empty());
    }

    #[test]
    fn counter_sign_targets_and_infos() {
        assert_eq!(CounterSignTarget::get_target(Some(" LEAFS ")).unwrap(), CounterSignTarget::Leafs);
        assert_eq!(CounterSignTarget::get_target(None).unwrap_err().message, "El objetivo de la contrafirma no puede ser nulo");
        assert_eq!(CounterSignTarget::get_target(Some("todo")).unwrap_err().message, "Objetivo no soportado: todo");
        assert_eq!(CounterSignTarget::Tree.to_string(), "tree");
        assert_eq!(SignInfo::new(None).format, "Desconocido");
        assert_eq!(SignInfo::new(Some("CAdES")).format, "CAdES");
        let t = Utc.with_ymd_and_hms(2026, 10, 16, 11, 17, 0).unwrap();
        let ts = TimestampInfo::new(None, t);
        assert!(ts.to_string().starts_with("Sello de tiempo emitido por 'DESCONOCIDO' con fecha "));
        let ts2 = TimestampInfo::new(Some(cert()), t);
        assert!(ts2.display_text().contains("'ESPAÑOL ESPAÑOL JUAN - 00000000T'"));
        let tree = TimestampInfo::timestamps_tree(&[ts, ts2]);
        assert_eq!(tree.signers.len(), 2);
        assert_eq!(tree.signers[1].info.signing_time, Some(t));
    }
}
