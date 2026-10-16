//! Configuración de proxy (`ProxyConfig`/`ProxyUtil` de afirma-simple).
//!
//! * `NONE`: conexión directa.
//! * `SYSTEM`: proxy del sistema. Se consultan las variables de entorno
//!   (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`), en Windows la
//!   configuración de Internet del registro (con `ProxyOverride`), en macOS
//!   `scutil --proxy` y en escritorios GNOME `gsettings` (modo manual). Los
//!   ficheros PAC/WPAD no están soportados (Java usaba proxy-vole).
//! * `CUSTOM`: servidor, puerto, usuario, contraseña y lista de exclusiones
//!   (formato `http.nonProxyHosts` de Java: patrones separados por `|`, con
//!   `*` al principio o al final, sin distinguir mayúsculas).

use std::sync::OnceLock;

/// Proxy configurado por el usuario (`ProxyConfig` de tipo `CUSTOM`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Contraseña ya descifrada.
    pub password: Option<String>,
    /// Servidores a los que se accede sin proxy.
    pub excluded_hosts: Vec<String>,
}

impl CustomProxy {
    /// Proxy sin autenticación ni exclusiones.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        CustomProxy {
            host: host.into(),
            port,
            username: None,
            password: None,
            excluded_hosts: Vec::new(),
        }
    }

    /// Interpreta la preferencia de exclusiones (`proxyExcludedUrls`,
    /// guardada con `|` como separador; la interfaz usa `,`).
    pub fn parse_excluded_hosts(list: &str) -> Vec<String> {
        list.split(['|', ','])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Indica si el servidor está excluido del uso del proxy.
    pub fn is_excluded(&self, host: &str) -> bool {
        self.excluded_hosts.iter().any(|p| non_proxy_host_matches(host, p))
    }
}

/// Modo de proxy (`ProxyConfig.ConfigType`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// Sin proxy.
    None,
    /// Proxy del sistema (valor por defecto de AutoFirma).
    #[default]
    System,
    /// Proxy configurado manualmente.
    Custom(CustomProxy),
}

impl ProxyMode {
    /// Tipo de proxy según las preferencias (`ProxyUtil.getProxyType` y
    /// `getCustomProxySelector`): `proxyType` (`NONE`, `SYSTEM`, `CUSTOM`;
    /// un valor no válido equivale a `NONE`) o, si no existe, la preferencia
    /// antigua `proxySelected` (`false` → `SYSTEM`; `true` → `CUSTOM` si hay
    /// servidor y puerto, si no `NONE`). Un puerto no numérico se sustituye
    /// por 80.
    pub fn from_preferences(
        proxy_type: Option<&str>,
        proxy_selected: bool,
        host: Option<&str>,
        port: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        excluded_urls: Option<&str>,
    ) -> ProxyMode {
        fn nonblank(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|s| !s.is_empty())
        }
        let kind = match proxy_type {
            None => {
                if !proxy_selected {
                    "SYSTEM"
                } else if nonblank(host).is_some() && nonblank(port).is_some() {
                    "CUSTOM"
                } else {
                    "NONE"
                }
            }
            Some(t) => t,
        };
        match kind {
            "SYSTEM" => ProxyMode::System,
            "CUSTOM" => {
                let Some(h) = host else { return ProxyMode::None };
                let mut proxy = CustomProxy::new(h, port.and_then(|p| p.trim().parse().ok()).unwrap_or(80));
                if nonblank(username).is_some() && nonblank(password).is_some() {
                    proxy.username = username.map(str::to_string);
                    proxy.password = password.map(str::to_string);
                }
                proxy.excluded_hosts = excluded_urls.map(CustomProxy::parse_excluded_hosts).unwrap_or_default();
                ProxyMode::Custom(proxy)
            }
            _ => ProxyMode::None,
        }
    }
}

/// Coincidencia de un servidor con un patrón de exclusión (`nonProxyHosts`
/// de Java: `*` inicial → sufijo, `*` final → prefijo, `.dominio` → sufijo,
/// en otro caso igualdad; sin distinguir mayúsculas). Los rangos CIDR no se
/// admiten.
pub fn non_proxy_host_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    let p = pattern.trim().to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    if let Some(suffix) = p.strip_prefix('*') {
        return host.ends_with(suffix);
    }
    if let Some(prefix) = p.strip_suffix('*') {
        return host.starts_with(prefix);
    }
    if p.starts_with('.') {
        return host.ends_with(&p);
    }
    host == p
}

/// Servidor proxy resuelto para una petición.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyEndpoint {
    pub(crate) fn to_ureq(&self) -> Option<ureq::Proxy> {
        let mut b = ureq::Proxy::builder(ureq::ProxyProtocol::Http)
            .host(&self.host)
            .port(self.port);
        if let Some(u) = &self.username {
            b = b.username(u);
        }
        if let Some(p) = &self.password {
            b = b.password(p);
        }
        b.build().ok()
    }
}

/// Proxy que corresponde a una URL según el modo configurado.
pub(crate) fn resolve_proxy(mode: &ProxyMode, scheme: &str, host: &str) -> Option<ProxyEndpoint> {
    match mode {
        ProxyMode::None => None,
        ProxyMode::Custom(c) => (!c.is_excluded(host)).then(|| ProxyEndpoint {
            host: c.host.clone(),
            port: c.port,
            username: c.username.clone(),
            password: c.password.clone(),
        }),
        ProxyMode::System => system_proxy_for(scheme, host),
    }
}

/// Proxy del sistema para un esquema (`http`/`https`) y servidor.
fn system_proxy_for(scheme: &str, host: &str) -> Option<ProxyEndpoint> {
    if let Some(p) = ureq::Proxy::try_from_env() {
        let uri: Option<ureq::http::Uri> = format!("{scheme}://{host}/").parse().ok();
        if uri.is_some_and(|u| p.is_no_proxy(&u)) {
            return None;
        }
        if !matches!(p.protocol(), ureq::ProxyProtocol::Http | ureq::ProxyProtocol::Https) {
            tracing::warn!(
                "Proxy del sistema no soportado ({}), se conectara directamente",
                p.protocol()
            );
            return None;
        }
        return Some(ProxyEndpoint {
            host: p.host().to_string(),
            port: p.port(),
            username: p.username().map(str::to_string),
            password: p.password().map(str::to_string),
        });
    }
    let platform = platform_proxy().as_ref()?;
    if platform.exclusions.iter().any(|e| non_proxy_host_matches(host, e)) {
        return None;
    }
    let entry = if scheme == "https" {
        platform.https.as_ref().or(platform.http.as_ref())
    } else {
        platform.http.as_ref()
    };
    entry.map(|(h, p)| ProxyEndpoint {
        host: h.clone(),
        port: *p,
        username: None,
        password: None,
    })
}

/// Proxy configurado en el escritorio (macOS o GNOME).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PlatformProxy {
    pub http: Option<(String, u16)>,
    pub https: Option<(String, u16)>,
    pub exclusions: Vec<String>,
}

fn platform_proxy() -> &'static Option<PlatformProxy> {
    static CACHE: OnceLock<Option<PlatformProxy>> = OnceLock::new();
    CACHE.get_or_init(|| {
        if cfg!(target_os = "macos") {
            run("scutil", &["--proxy"]).and_then(|o| parse_scutil_proxy(&o))
        } else if cfg!(all(unix, not(target_os = "macos"))) {
            gnome_proxy()
        } else {
            None
        }
    })
}

/// Proxy del sistema detectado (variables de entorno, registro de Windows,
/// macOS o GNOME) para una URL `https`, como texto `servidor:puerto`. Útil
/// para mostrarlo en la interfaz.
pub fn system_proxy(host: &str) -> Option<String> {
    system_proxy_for("https", host).map(|p| format!("{}:{}", p.host, p.port))
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Interpreta la salida de `scutil --proxy` (macOS).
pub(crate) fn parse_scutil_proxy(output: &str) -> Option<PlatformProxy> {
    let mut values = std::collections::HashMap::new();
    let mut exclusions = Vec::new();
    let mut in_exceptions = false;
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("ExceptionsList") {
            in_exceptions = true;
            continue;
        }
        if in_exceptions {
            if line.starts_with('}') {
                in_exceptions = false;
            } else if let Some((_, v)) = line.split_once(" : ") {
                exclusions.push(v.trim().to_string());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(" : ") {
            values.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let entry = |prefix: &str| -> Option<(String, u16)> {
        if values.get(&format!("{prefix}Enable")).map(String::as_str) != Some("1") {
            return None;
        }
        let host = values.get(&format!("{prefix}Proxy"))?.clone();
        let port = values
            .get(&format!("{prefix}Port"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);
        Some((host, port))
    };
    let p = PlatformProxy {
        http: entry("HTTP"),
        https: entry("HTTPS"),
        exclusions,
    };
    (p.http.is_some() || p.https.is_some()).then_some(p)
}

fn gnome_proxy() -> Option<PlatformProxy> {
    let get = |schema: &str, key: &str| run("gsettings", &["get", schema, key]).map(|s| s.trim().to_string());
    if get("org.gnome.system.proxy", "mode")? != "'manual'" {
        return None;
    }
    let entry = |schema: &str| -> Option<(String, u16)> {
        let host = get(schema, "host")?.trim_matches('\'').to_string();
        if host.is_empty() {
            return None;
        }
        let port = get(schema, "port").and_then(|p| p.parse().ok()).unwrap_or(80);
        Some((host, port))
    };
    let ignore = get("org.gnome.system.proxy", "ignore-hosts").unwrap_or_default();
    Some(parse_gnome(
        entry("org.gnome.system.proxy.http"),
        entry("org.gnome.system.proxy.https"),
        &ignore,
    ))
}

pub(crate) fn parse_gnome(
    http: Option<(String, u16)>,
    https: Option<(String, u16)>,
    ignore_hosts: &str,
) -> PlatformProxy {
    let exclusions = ignore_hosts
        .trim_start_matches("@as ")
        .trim_matches(['[', ']'])
        .split(',')
        .map(|s| s.trim().trim_matches('\'').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    PlatformProxy {
        http,
        https,
        exclusions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusions() {
        assert!(non_proxy_host_matches("www.Gob.es", "*.gob.es"));
        assert!(non_proxy_host_matches("intranet.local", "intranet*"));
        assert!(non_proxy_host_matches("a.local", ".local"));
        assert!(non_proxy_host_matches("Exacto", "exacto"));
        assert!(!non_proxy_host_matches("otro.es", "*.gob.es"));
        assert!(non_proxy_host_matches("x", "*"));
        assert!(!non_proxy_host_matches("x", ""));
        let p = CustomProxy {
            excluded_hosts: CustomProxy::parse_excluded_hosts("localhost|*.interno.es, 10.0.0.1"),
            ..CustomProxy::new("proxy", 3128)
        };
        assert!(p.is_excluded("sede.interno.es"));
        assert!(p.is_excluded("10.0.0.1"));
        assert!(!p.is_excluded("www.google.es"));
        let ep = resolve_proxy(&ProxyMode::Custom(p.clone()), "https", "www.google.es").unwrap();
        assert_eq!((ep.host.as_str(), ep.port), ("proxy", 3128));
        assert!(ep.to_ureq().is_some());
        assert!(resolve_proxy(&ProxyMode::Custom(p), "https", "localhost").is_none());
        assert!(resolve_proxy(&ProxyMode::None, "https", "x").is_none());
    }

    #[test]
    fn preferences() {
        assert_eq!(
            ProxyMode::from_preferences(None, false, None, None, None, None, None),
            ProxyMode::System
        );
        assert_eq!(
            ProxyMode::from_preferences(None, true, Some(" "), Some("8080"), None, None, None),
            ProxyMode::None
        );
        assert_eq!(
            ProxyMode::from_preferences(Some("raro"), false, None, None, None, None, None),
            ProxyMode::None
        );
        let m = ProxyMode::from_preferences(
            Some("CUSTOM"),
            false,
            Some("p"),
            Some("x"),
            Some("u"),
            Some("s"),
            Some("a|b"),
        );
        let ProxyMode::Custom(c) = m else { panic!() };
        assert_eq!(c.port, 80);
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.excluded_hosts, vec!["a", "b"]);
        let m = ProxyMode::from_preferences(None, true, Some("p"), Some("3128"), Some("u"), None, None);
        let ProxyMode::Custom(c) = m else { panic!() };
        assert_eq!((c.port, c.username), (3128, None));
    }

    #[test]
    fn desktop_parsers() {
        let out = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : proxy.empresa.es\n  HTTPSEnable : 1\n  HTTPSPort : 8443\n  HTTPSProxy : sproxy.empresa.es\n}\n";
        let p = parse_scutil_proxy(out).unwrap();
        assert_eq!(p.http, Some(("proxy.empresa.es".into(), 8080)));
        assert_eq!(p.https, Some(("sproxy.empresa.es".into(), 8443)));
        assert_eq!(p.exclusions, vec!["*.local", "169.254/16"]);
        assert!(parse_scutil_proxy("<dictionary> {\n  HTTPEnable : 0\n}").is_none());
        let g = parse_gnome(
            None,
            Some(("p".into(), 3128)),
            "['localhost', '127.0.0.0/8', '*.intra']",
        );
        assert_eq!(g.exclusions, vec!["localhost", "127.0.0.0/8", "*.intra"]);
        assert!(parse_gnome(None, None, "@as []").exclusions.is_empty());
    }
}
