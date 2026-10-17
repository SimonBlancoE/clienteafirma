//! Activa la prueba cruzada con el simulador Java (`tests/oracle.rs`) solo cuando se indica el
//! directorio de trabajo del oráculo con `AFIRMA_DNIE_ORACLE`.

fn main() {
    println!("cargo::rerun-if-env-changed=AFIRMA_DNIE_ORACLE");
    println!("cargo::rustc-check-cfg=cfg(afirma_dnie_oracle)");
    if std::env::var_os("AFIRMA_DNIE_ORACLE").is_some_and(|v| !v.is_empty()) {
        println!("cargo::rustc-cfg=afirma_dnie_oracle");
    }
}
