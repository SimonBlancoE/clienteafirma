//! Análisis de un documento abierto con el selector del sistema, con la misma lógica de
//! selección de formato que la aplicación de escritorio (`afirma-signers`).

use afirma_core::formats::DataFileType;
use afirma_signers::{ProposedOperation, analyze_for_desktop};

/// Resumen de un documento para mostrarlo en la interfaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentSummary {
    /// Nombre que da el proveedor de documentos (`OpenableColumns.DISPLAY_NAME`).
    pub name: String,
    pub size: usize,
    /// Tipo de fichero, en palabras.
    pub kind: &'static str,
    /// Formato de firma propuesto (nombre de `AOSignConstants`, p. ej. `PAdES`).
    pub format: String,
    /// Otros formatos que se pueden elegir para este tipo de fichero.
    pub alternatives: Vec<String>,
    /// El fichero ya es una firma (se propone cofirmar o contrafirmar).
    pub already_signed: bool,
}

/// Analiza el contenido de un documento.
pub fn analyze(name: &str, data: &[u8]) -> DocumentSummary {
    let analysis = analyze_for_desktop(data, &|_| None);
    DocumentSummary {
        name: name.to_string(),
        size: data.len(),
        kind: kind_label(analysis.file_type),
        format: analysis.format,
        alternatives: analysis.alternatives,
        already_signed: analysis.operation == ProposedOperation::Multisign,
    }
}

fn kind_label(file_type: DataFileType) -> &'static str {
    match file_type {
        DataFileType::Pdf => "Documento PDF",
        DataFileType::FacturaE => "Factura electrónica (FacturaE)",
        DataFileType::Ooxml => "Documento de Microsoft Office (OOXML)",
        DataFileType::Odf => "Documento de OpenDocument (ODF)",
        DataFileType::SignXades => "Firma XAdES",
        DataFileType::SignCades => "Firma CAdES",
        DataFileType::Xml => "Documento XML",
        DataFileType::Binary => "Fichero binario",
    }
}

/// Tamaño legible (`1,5 MB`), con coma decimal.
pub fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["bytes", "kB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.1} {}", UNITS[unit]).replace('.', ",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(path: &str) -> Vec<u8> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        std::fs::read(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    #[test]
    fn pdf_se_firma_en_pades() {
        let summary = analyze("rotated_pages.pdf", &testdata("pades/rotated_pages.pdf"));
        assert_eq!(summary.kind, "Documento PDF");
        assert_eq!(summary.format, "PAdES");
        assert!(summary.alternatives.contains(&"CAdES".to_string()));
        assert!(!summary.already_signed);
    }

    #[test]
    fn binario_se_firma_en_cades() {
        let summary = analyze("datos.bin", &[0u8, 1, 2, 3, 0xff]);
        assert_eq!(summary.kind, "Fichero binario");
        assert_eq!(summary.format, "CAdES");
        assert_eq!(summary.size, 5);
    }

    #[test]
    fn tamanos_legibles() {
        assert_eq!(human_size(0), "0 bytes");
        assert_eq!(human_size(1023), "1023 bytes");
        assert_eq!(human_size(1536), "1,5 kB");
        assert_eq!(human_size(3 * 1024 * 1024), "3,0 MB");
    }
}
