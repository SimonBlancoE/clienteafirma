# Desviaciones de `afirma-signers` respecto a AutoFirma (Java)

| Tema | Java | AutoFirma-rs | Motivo |
|---|---|---|---|
| Validación de contenedores ASiC-S | `SignValiderFactory` no tiene validador para ASiC: el ZIP se trata como binario y el resultado es "no es una firma" (KO `NO_SIGN`). | Se extrae la firma (`META-INF/signature.p7s` o `META-INF/signatures.xml`) y se valida contra el documento del contenedor. | Permitir verificar en la aplicación las firmas ASiC que la propia AutoFirma genera. No afecta a ningún formato de salida. |
