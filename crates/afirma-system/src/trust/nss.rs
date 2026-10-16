//! Bases de datos NSS: perfiles de Firefox (todas las variantes, todos los usuarios con
//! privilegios) y la base compartida `~/.pki/nssdb` de Chrome/Chromium/Edge en Linux
//! (incluidas snap y flatpak). Nunca se crean bases que el navegador no haya creado.
//!
//! Operaciones con `certutil` (si existe; en Windows no se usa el `certutil.exe` de
//! Microsoft) o, si no, directamente con `softokn3` vía PKCS#11 ([`super::softokn`]).
//! El éxito se determina por el código de salida (Java consideraba error cualquier salida)
//! y se retiran **todas** las copias del certificado de AutoFirma (Java solo una).

use std::path::{Path, PathBuf};

use super::softokn::{
    CKT_NSS_MUST_VERIFY_TRUST, CKT_NSS_TRUSTED, CKT_NSS_TRUSTED_DELEGATOR, SoftoknSession,
};
use super::{Change, TrustCheck, is_autofirma_cert};
use crate::certs::{CA_CN, CERT_ALIAS, parse_cert_file};
use crate::ctx::{Context, Os, UserHome};
use crate::error::{Result, SystemError};
use crate::exec::Cmd;
use crate::firefox::{self, NssDbKind};
use crate::fsutil;

/// Uso de la base de datos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum NssPurpose {
    /// Perfil de Firefox.
    Firefox,
    /// Base compartida (Chrome/Chromium/Edge/Brave en Linux).
    Shared,
}

/// Base de datos NSS existente.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NssDb {
    pub dir: PathBuf,
    pub kind: NssDbKind,
    pub purpose: NssPurpose,
    pub user: String,
    /// Descripción para mensajes.
    pub description: String,
}

impl NssDb {
    /// Especificación para `certutil -d`.
    pub fn spec(&self) -> String {
        let p = match self.kind {
            NssDbKind::Sql => "sql:",
            NssDbKind::Dbm => "dbm:",
        };
        format!("{p}{}", self.dir.display())
    }

    /// Indicadores de confianza de Java: `C,,` en Firefox y `TCP,TCP,TCP` en la base compartida.
    pub fn trust_flags(&self) -> TrustFlags {
        match self.purpose {
            NssPurpose::Firefox => TrustFlags::parse("C,,"),
            NssPurpose::Shared => TrustFlags::parse("TCP,TCP,TCP"),
        }
    }
}

/// Indicadores de confianza de `certutil` (`SSL,S/MIME,JAR/XPI`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustFlags {
    pub ssl: String,
    pub email: String,
    pub objsign: String,
}

impl TrustFlags {
    /// Interpreta `"C,,"`.
    pub fn parse(s: &str) -> Self {
        let mut it = s.split(',');
        Self {
            ssl: it.next().unwrap_or("").trim().to_string(),
            email: it.next().unwrap_or("").trim().to_string(),
            objsign: it.next().unwrap_or("").trim().to_string(),
        }
    }

    /// Representación de `certutil -t`.
    pub fn as_certutil(&self) -> String {
        format!("{},{},{}", self.ssl, self.email, self.objsign)
    }

    /// `true` si la CA es de confianza para SSL.
    pub fn trusts_ssl_ca(&self) -> bool {
        self.ssl.contains('C') || self.ssl.contains('T')
    }

    fn usage(s: &str) -> super::softokn::TrustValue {
        if s.contains('C') || s.contains('T') {
            CKT_NSS_TRUSTED_DELEGATOR
        } else if s.contains('P') {
            CKT_NSS_TRUSTED
        } else {
            CKT_NSS_MUST_VERIFY_TRUST
        }
    }

    /// Valores de confianza PKCS#11 de NSS: (servidor, correo, código, cliente).
    pub fn pkcs11_trust(
        &self,
    ) -> (
        super::softokn::TrustValue,
        super::softokn::TrustValue,
        super::softokn::TrustValue,
        super::softokn::TrustValue,
    ) {
        let client = if self.ssl.contains('T') {
            CKT_NSS_TRUSTED_DELEGATOR
        } else {
            CKT_NSS_MUST_VERIFY_TRUST
        };
        (
            Self::usage(&self.ssl),
            Self::usage(&self.email),
            Self::usage(&self.objsign),
            client,
        )
    }
}

/// Subdirectorios de bases compartidas (Linux).
pub const SHARED_NSS_DIRS: &[&str] = &[
    ".pki/nssdb",
    "snap/chromium/current/.pki/nssdb",
    ".var/app/com.google.Chrome/.pki/nssdb",
    ".var/app/org.chromium.Chromium/.pki/nssdb",
    ".var/app/com.microsoft.Edge/.pki/nssdb",
    ".var/app/com.brave.Browser/.pki/nssdb",
];

/// Descubre las bases NSS existentes de los usuarios indicados.
pub fn discover(
    ctx: &Context,
    users: &[UserHome],
    firefox_dbs: bool,
    shared_dbs: bool,
) -> Vec<NssDb> {
    let mut out = Vec::new();
    if firefox_dbs {
        for p in firefox::discover_profiles(ctx, users) {
            if let Some(kind) = p.nss_db() {
                out.push(NssDb {
                    description: format!(
                        "Firefox ({:?}) perfil «{}» de {}",
                        p.flavor,
                        p.dir
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        p.user
                    ),
                    dir: p.dir,
                    kind,
                    purpose: NssPurpose::Firefox,
                    user: p.user,
                });
            }
        }
    }
    if shared_dbs && ctx.os == Os::Linux {
        for u in users {
            for sub in SHARED_NSS_DIRS {
                let dir = u.home.join(sub);
                if let Some(kind) = firefox::nss_db_kind(&dir) {
                    out.push(NssDb {
                        description: format!("NSS compartido {sub} de {}", u.name),
                        dir,
                        kind,
                        purpose: NssPurpose::Shared,
                        user: u.name.clone(),
                    });
                }
            }
        }
    }
    out
}

/// Mecanismo de acceso a NSS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Backend {
    /// `certutil` de NSS.
    Certutil(PathBuf),
    /// Módulo `softokn3` vía PKCS#11.
    Softokn(PathBuf),
}

/// Elige el mecanismo disponible: `certutil` de NSS (en Windows solo uno incluido junto al
/// ejecutable, nunca el de Microsoft) o `softokn3`.
pub fn backend(ctx: &Context) -> Option<Backend> {
    let bundled = ctx.app.app_dir.join("nss").join(if ctx.os == Os::Windows {
        "certutil.exe"
    } else {
        "certutil"
    });
    if bundled.is_file() {
        return Some(Backend::Certutil(bundled));
    }
    if ctx.os != Os::Windows
        && let Some(p) = ctx.runner.which("certutil")
    {
        return Some(Backend::Certutil(p));
    }
    super::softokn::find_softokn(ctx).map(Backend::Softokn)
}

/// Entrada de `certutil -L`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedCert {
    pub nickname: String,
    pub trust: TrustFlags,
}

/// Interpreta la salida de `certutil -L`.
pub fn parse_certutil_list(out: &str) -> Vec<ListedCert> {
    let mut v = Vec::new();
    for line in out.lines() {
        let l = line.trim_end();
        if l.is_empty()
            || l.starts_with("Certificate Nickname")
            || l.trim_start().starts_with("SSL,S/MIME")
        {
            continue;
        }
        let Some((nick, trust)) = l.rsplit_once(char::is_whitespace) else {
            continue;
        };
        if trust.matches(',').count() != 2
            || !trust.chars().all(|c| c == ',' || c.is_ascii_alphabetic())
        {
            continue;
        }
        v.push(ListedCert {
            nickname: nick.trim().to_string(),
            trust: TrustFlags::parse(trust),
        });
    }
    v
}

fn certutil(ctx: &Context, bin: &Path, args: &[&str]) -> Result<crate::exec::Output> {
    let mut c = Cmd::new(bin.to_string_lossy().into_owned())
        .args(args.iter().copied())
        .timeout(std::time::Duration::from_secs(30));
    if let Some(dir) = bin.parent().filter(|_| ctx.os != Os::Windows) {
        // certutil incluido junto al ejecutable: sus bibliotecas en el mismo directorio.
        if dir.ends_with("nss") {
            c = c
                .env("LD_LIBRARY_PATH", dir.to_string_lossy().into_owned())
                .env("DYLD_LIBRARY_PATH", dir.to_string_lossy().into_owned());
        }
    }
    ctx.runner.run(&c).map_err(|e| SystemError::Command {
        program: "certutil".into(),
        detail: e.to_string(),
    })
}

fn pem_blocks(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find("-----BEGIN CERTIFICATE-----") {
        let Some(e) = rest[s..].find("-----END CERTIFICATE-----") else {
            break;
        };
        let block = &rest[s..s + e + 25];
        if let Ok(d) = parse_cert_file(block.as_bytes()) {
            out.push(d);
        }
        rest = &rest[s + e + 25..];
    }
    out
}

/// Certificados de AutoFirma en la base (apodo, confianza, DER) vía `certutil`.
fn certutil_autofirma_entries(
    ctx: &Context,
    bin: &Path,
    db: &NssDb,
) -> Result<Vec<(String, TrustFlags, Vec<u8>)>> {
    let spec = db.spec();
    let out = certutil(ctx, bin, &["-L", "-d", &spec])?;
    if !out.success() {
        return Err(SystemError::TrustStore {
            store: db.description.clone(),
            detail: out.message(),
        });
    }
    let mut v = Vec::new();
    for e in parse_certutil_list(&out.stdout) {
        let o = certutil(ctx, bin, &["-L", "-d", &spec, "-n", &e.nickname, "-a"])?;
        for der in pem_blocks(&o.stdout) {
            if e.nickname == CERT_ALIAS || is_autofirma_cert(&der) {
                v.push((e.nickname.clone(), e.trust.clone(), der));
            }
        }
    }
    Ok(v)
}

fn evaluate(entries: &[(TrustFlags, Vec<u8>)], ca_der: &[u8]) -> TrustCheck {
    if entries
        .iter()
        .any(|(t, d)| d == ca_der && t.trusts_ssl_ca())
    {
        return TrustCheck::Trusted;
    }
    if entries.iter().any(|(_, d)| d == ca_der) {
        return TrustCheck::Mismatch("la CA está instalada sin confianza SSL".into());
    }
    if !entries.is_empty() {
        return TrustCheck::Mismatch("hay una CA de AutoFirma distinta (antigua)".into());
    }
    TrustCheck::Missing
}

/// Comprueba la CA en una base.
pub fn check(ctx: &Context, db: &NssDb, backend: &Backend, ca_der: &[u8]) -> TrustCheck {
    let res: Result<TrustCheck> = (|| match backend {
        Backend::Certutil(bin) => {
            let e = certutil_autofirma_entries(ctx, bin, db)?;
            Ok(evaluate(
                &e.into_iter().map(|(_, t, d)| (t, d)).collect::<Vec<_>>(),
                ca_der,
            ))
        }
        Backend::Softokn(lib) => {
            let s = SoftoknSession::open(lib, &db.dir, db.kind)?;
            let mut entries = Vec::new();
            for (_, label, der) in s.certificates()? {
                if label == CERT_ALIAS || is_autofirma_cert(&der) {
                    let tr = s.server_trust(&der)?;
                    let flags = TrustFlags::parse(if tr == Some(CKT_NSS_TRUSTED_DELEGATOR) {
                        "C,,"
                    } else {
                        ",,"
                    });
                    entries.push((flags, der));
                }
            }
            Ok(evaluate(&entries, ca_der))
        }
    })();
    res.unwrap_or_else(|e| TrustCheck::Unknown(e.to_string()))
}

fn remove_with(ctx: &Context, db: &NssDb, backend: &Backend, keep: Option<&[u8]>) -> Result<bool> {
    let mut changed = false;
    match backend {
        Backend::Certutil(bin) => {
            let spec = db.spec();
            // Se repite porque cada -D borra una sola copia del apodo.
            for _ in 0..20 {
                let entries = certutil_autofirma_entries(ctx, bin, db)?;
                let Some((nick, _, _)) =
                    entries.iter().find(|(_, _, d)| keep != Some(d.as_slice()))
                else {
                    break;
                };
                let o = certutil(ctx, bin, &["-D", "-d", &spec, "-n", nick])?;
                if !o.success() {
                    return Err(SystemError::TrustStore {
                        store: db.description.clone(),
                        detail: o.message(),
                    });
                }
                changed = true;
            }
        }
        Backend::Softokn(lib) => {
            let s = SoftoknSession::open(lib, &db.dir, db.kind)?;
            for (h, label, der) in s.certificates()? {
                if (label == CERT_ALIAS || is_autofirma_cert(&der)) && keep != Some(der.as_slice())
                {
                    s.remove(h, &der)?;
                    changed = true;
                }
            }
        }
    }
    Ok(changed)
}

/// Instala la CA (retirando antes las CA de AutoFirma anteriores). Idempotente.
pub fn install(
    ctx: &Context,
    db: &NssDb,
    backend: &Backend,
    ca_der: &[u8],
    ca_file: &Path,
) -> Result<Change> {
    let state = check(ctx, db, backend, ca_der);
    if let TrustCheck::Unknown(e) = &state {
        return Err(SystemError::TrustStore {
            store: db.description.clone(),
            detail: e.clone(),
        });
    }
    let only_ours_ok = state == TrustCheck::Trusted;
    // Retirar CA antiguas (y la propia si estaba sin confianza).
    let removed = remove_with(
        ctx,
        db,
        backend,
        if only_ours_ok { Some(ca_der) } else { None },
    )?;
    if only_ours_ok {
        fix_owner(ctx, db);
        return Ok(if removed {
            Change::Changed
        } else {
            Change::Unchanged
        });
    }
    let flags = db.trust_flags();
    match backend {
        Backend::Certutil(bin) => {
            let spec = db.spec();
            let file = ca_file.to_string_lossy();
            let t = flags.as_certutil();
            let o = certutil(
                ctx,
                bin,
                &["-A", "-d", &spec, "-n", CERT_ALIAS, "-t", &t, "-i", &file],
            )?;
            if !o.success() {
                let msg = if o.stdout.contains("Enter Password") || o.stderr.contains("password") {
                    "la base de datos está protegida con contraseña maestra".to_string()
                } else {
                    o.message()
                };
                return Err(SystemError::TrustStore {
                    store: db.description.clone(),
                    detail: msg,
                });
            }
        }
        Backend::Softokn(lib) => {
            let s = SoftoknSession::open(lib, &db.dir, db.kind)?;
            s.add(ca_der, CERT_ALIAS, &flags)?;
        }
    }
    fix_owner(ctx, db);
    Ok(Change::Changed)
}

/// Retira todas las CA de AutoFirma de la base.
pub fn remove(ctx: &Context, db: &NssDb, backend: &Backend) -> Result<Change> {
    let r = remove_with(ctx, db, backend, None)?;
    fix_owner(ctx, db);
    Ok(if r {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

fn fix_owner(ctx: &Context, db: &NssDb) {
    if ctx.elevated {
        fsutil::restore_owner_in_dir(
            &db.dir,
            &[
                "cert9.db",
                "key4.db",
                "pkcs11.txt",
                "cert8.db",
                "key3.db",
                "secmod.db",
            ],
        );
    }
}

/// Nombre descriptivo del certificado para mensajes.
pub fn ca_display_name() -> &'static str {
    CA_CN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analiza_listado_de_certutil() {
        let out = "\nCertificate Nickname                                         Trust Attributes\n                                                             SSL,S/MIME,JAR/XPI\n\nSocketAutoFirma                                              C,,  \nMi CA con espacios                                           CT,C,C\nbasura sin confianza\n";
        let l = parse_certutil_list(out);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].nickname, "SocketAutoFirma");
        assert!(l[0].trust.trusts_ssl_ca());
        assert_eq!(l[1].nickname, "Mi CA con espacios");
        assert_eq!(l[1].trust.as_certutil(), "CT,C,C");
    }

    #[test]
    fn descubre_solo_bases_existentes() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let home = ctx.paths.home.clone();
        std::fs::create_dir_all(home.join(".pki/nssdb")).unwrap();
        std::fs::write(home.join(".pki/nssdb/cert9.db"), b"x").unwrap();
        std::fs::create_dir_all(home.join("snap/chromium/current/.pki/nssdb")).unwrap(); // vacía: no se usa
        let users = ctx.user_homes(false);
        let dbs = discover(&ctx, &users, true, true);
        assert_eq!(dbs.len(), 1);
        assert_eq!(
            dbs[0].spec(),
            format!("sql:{}", home.join(".pki/nssdb").display())
        );
        assert_eq!(dbs[0].trust_flags().as_certutil(), "TCP,TCP,TCP");
    }
}
