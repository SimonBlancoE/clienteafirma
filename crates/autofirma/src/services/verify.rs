//! Verificación de firmas para la página "Verificar firmas".

use std::path::Path;

use afirma_core::validity::{SignValidity, Validity, ValidityError};
use afirma_core::{ExtraParams, SignerNode};

use crate::i18n::{tr, trf};
use crate::ui::pages::verify::{SignatureDetail, SignatureReport};

/// Analiza y valida un fichero de firma.
pub fn verify_file(path: &Path, params: &ExtraParams) -> Result<SignatureReport, String> {
    let data = std::fs::read(path).map_err(|e| trf("No se ha podido leer el fichero: {0}", &[&e]))?;
    Ok(verify_bytes(&data, path, params))
}

pub fn verify_bytes(data: &[u8], path: &Path, params: &ExtraParams) -> SignatureReport {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let validity = afirma_signers::validate(data, params);
    let detected = afirma_signers::detect(data, params);
    let mut report = SignatureReport {
        path: path.to_path_buf(),
        file_name,
        format: detected
            .as_ref()
            .map(|(k, _)| afirma_core::formats::get_sign_format(*k).to_string())
            .unwrap_or_else(|| tr("Desconocido").into()),
        overall: validity.first().cloned(),
        ..Default::default()
    };
    // Avisos globales (documento modificado, formulario, etc.).
    for v in &validity {
        if let Some(e) = v.error
            && matches!(
                e,
                ValidityError::ModifiedForm
                    | ValidityError::ModifiedDocument
                    | ValidityError::OverlappingSignature
                    | ValidityError::SuspectedSignature
                    | ValidityError::CantValidateExternallyDetached
                    | ValidityError::NoData
                    | ValidityError::SignProfileNotChecked
            )
        {
            let text = capitalize(e.message());
            if !report.global_issues.contains(&text) {
                report.global_issues.push(text);
            }
        }
    }
    let Some((kind, signer)) = detected else {
        if report.overall.is_none() {
            report.overall = Some(SignValidity::ko(ValidityError::UnknownSignatureFormat));
        }
        return report;
    };
    if let Ok(tree) = signer.signers_structure(data, params) {
        for n in &tree.signers {
            flatten(n, 0, &mut report.signatures);
        }
    }
    let embedded = matches!(signer.get_data(data, params), Ok(Some(_)));
    report.has_embedded_data = embedded && kind != afirma_core::formats::SignerKind::Pdf;
    report.data_location = Some(
        match kind {
            afirma_core::formats::SignerKind::Pdf => tr("La firma se encuentra dentro del PDF"),
            afirma_core::formats::SignerKind::Xades | afirma_core::formats::SignerKind::FacturaE => {
                if embedded {
                    tr("La firma contiene los datos")
                } else {
                    tr("La firma no contiene los datos (firma separada)")
                }
            }
            _ if embedded => tr("La firma contiene los datos"),
            _ => tr("La firma no contiene los datos (firma explícita)"),
        }
        .to_string(),
    );
    // Veredicto por firmante: los problemas de certificado se reflejan en
    // cada firma; los globales, en la cabecera.
    let now = chrono::Utc::now();
    for s in &mut report.signatures {
        let mut v = Vec::new();
        if let Some(na) = s.cert_not_after
            && na < now
        {
            v.push(SignValidity::ko(ValidityError::CertificateExpired));
        }
        if v.is_empty() {
            v.push(SignValidity::ok());
        }
        s.validity = v;
    }
    if let Some(o) = &report.overall
        && o.validity == Validity::Ko
        && report.signatures.len() == 1
    {
        report.signatures[0].validity = vec![o.clone()];
    }
    report
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn flatten(node: &SignerNode, depth: usize, out: &mut Vec<SignatureDetail>) {
    let info = &node.info;
    let cert = info.certs.first().and_then(|c| afirma_core::cert::CertInfo::parse(c));
    let now = chrono::Utc::now();
    let cert_status = match &cert {
        Some(c) if c.not_after < now => tr("Certificado caducado.").to_string(),
        Some(c) if c.not_before > now => tr("Certificado aún no válido.").to_string(),
        Some(_) => tr("Correcto. No se ha comprobado la revocación del certificado.").to_string(),
        None => tr("No se ha podido leer el certificado.").to_string(),
    };
    out.push(SignatureDetail {
        depth,
        signer: info.signer_name(),
        signer_id: cert
            .as_ref()
            .and_then(|c| c.subject_serial_number.clone())
            .map(|s| s.trim_start_matches("IDCES-").to_string()),
        issuer: cert.as_ref().map(|c| c.issuer_cn.clone()).unwrap_or_default(),
        cert_not_after: cert.as_ref().map(|c| c.not_after),
        cert_status,
        cert_der: info.certs.first().cloned().unwrap_or_default(),
        profile: None,
        algorithm: info.sign_algorithm.as_deref().map(friendly_algorithm),
        signing_time: info.signing_time,
        timestamps: info.timestamping_time.iter().map(|t| ("TSA".to_string(), *t)).collect(),
        validity: Vec::new(),
        policy: None,
        metadata: Vec::new(),
        certification_level: None,
    });
    for c in &node.countersigners {
        flatten(c, depth + 1, out);
    }
}

/// Convierte URI XMLDSig de algoritmos en nombres legibles.
fn friendly_algorithm(a: &str) -> String {
    afirma_core::algorithms::SignatureAlgorithm::from_xml_uri(a)
        .map(|s| s.java_name())
        .unwrap_or_else(|| a.to_string())
}
