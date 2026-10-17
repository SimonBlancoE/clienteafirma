//! Preferencias de AutoFirma: modelo de claves, capas (directiva → usuario → sistema →
//! valor por defecto), bloqueo real por directiva, almacenes nativos y heredados de Java,
//! importación/exportación `.afconfig`, configuración remota y tarjetas inteligentes.
//!
//! # Capas y resolución
//!
//! * **Directiva obligatoria** ([`policy`]): siempre gana y bloquea la clave (en los dos modos).
//! * **Usuario**: almacén nativo `preferences.json` (migrado una vez desde Java).
//! * **Sistema**: directivas recomendadas + almacén nativo de sistema
//!   (`system-preferences.json`, escrito por el instalador con `-config_path`) + preferencias
//!   de sistema de Java (registro HKLM / `/etc/.java/.systemPrefs` / plist de `/Library`),
//!   o su copia actualizada en el nodo `systempreferences` del usuario cuando
//!   `allowUpdateConfig` es `true` (configuración remota).
//! * **Valor por defecto** ([`keys`]).
//!
//! En [`ResolutionMode::Compat`] se resuelve como Java (usuario → sistema → defecto para
//! todas las claves; `preferencesBlocked` solo deshabilita controles). En
//! [`ResolutionMode::Strict`] (por defecto) `preferencesBlocked=true` **en la capa de
//! sistema** bloquea de verdad las claves bloqueables (se ignoran los valores de usuario)
//! y las claves de administración solo se leen de sistema/directiva.

pub mod afconfig;
pub mod keys;
pub mod legacy;
pub mod policy;
pub mod proxy;
pub mod remote;
pub mod system;
pub mod tree;

use std::collections::BTreeMap;
use std::path::PathBuf;

use afconfig::{AfconfigContent, ConfigError, ConfigSignatureVerifier, SignaturePolicy, SignatureStatus};
use keys::{AuxKey, Key, KeyInfo, PrefValue, Section};
use policy::PolicySet;
use tree::{
    JsonTreeStore, NODE_INTERNAL, NODE_KEYSTORES, NODE_MAIN, NODE_UPDATED_SYSTEM, NODE_UPDATED_SYSTEM_KEYSTORES,
    PrefsFile, PrefsTree,
};

use crate::ctx::Context;
use crate::error::{Result, SystemError};

/// Nombre del fichero nativo de preferencias de usuario.
pub const USER_PREFS_FILE: &str = "preferences.json";

/// Modo de resolución de las capas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum ResolutionMode {
    /// Paridad exacta con Java (bloqueo solo visual, el usuario gana siempre).
    Compat,
    /// Bloqueo real (recomendado).
    #[default]
    Strict,
}

/// Capa de la que procede un valor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Layer {
    /// Directiva obligatoria.
    Policy,
    /// Usuario.
    User,
    /// Sistema (o directiva recomendada).
    System,
    /// Valor por defecto.
    Default,
}

/// Motivo por el que una clave no es editable por el usuario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum LockReason {
    /// Fijada por una directiva obligatoria.
    Policy,
    /// Bloqueada por `preferencesBlocked` en la capa de sistema.
    AdminBlock,
    /// Clave de administración (solo sistema/directiva).
    AdminOnly,
}

/// Origen de una tarjeta inteligente registrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CardOrigin {
    User,
    System,
    Policy,
}

/// Tarjeta inteligente registrada (almacén PKCS#11).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SmartCard {
    pub name: String,
    pub library: String,
    pub origin: CardOrigin,
}

/// Valor efectivo de una clave con su procedencia (para la interfaz y `doctor`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EffectiveValue {
    pub name: &'static str,
    pub value: Option<String>,
    pub layer: Layer,
    pub lock: Option<LockReason>,
}

/// Capa de sistema ya combinada.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SystemLayer {
    /// Valores del nodo principal (incluye las directivas recomendadas).
    pub main: BTreeMap<String, String>,
    /// Valores del nodo interno de sistema.
    pub internal: BTreeMap<String, String>,
    /// Tarjetas del sistema.
    pub smartcards: BTreeMap<String, String>,
    /// Orígenes.
    pub sources: Vec<String>,
    /// `true` si se usa la copia actualizada remota (`systempreferences`).
    pub using_updated_copy: bool,
}

/// Resultado de una importación de usuario.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ImportReport {
    /// Claves aplicadas.
    pub applied: Vec<String>,
    /// Claves omitidas (bloqueadas, de administración o con valor no válido) y motivo.
    pub skipped: Vec<(String, String)>,
    /// Tarjetas añadidas (con el nombre final).
    pub cards_added: Vec<String>,
}

/// Importación de usuario preparada (analizada y con la firma comprobada) a falta de confirmar.
#[derive(Debug, Clone)]
pub struct PreparedImport {
    pub content: AfconfigContent,
    pub signature: SignatureStatus,
}

impl PreparedImport {
    /// Texto del diálogo de confirmación de Java.
    pub fn confirmation_text(&self) -> String {
        afconfig::confirmation_text(&self.signature)
    }
}

/// Gestor de preferencias.
#[derive(Debug, Clone)]
pub struct Preferences {
    mode: ResolutionMode,
    store: JsonTreeStore,
    file: PrefsFile,
    system: SystemLayer,
    policy: PolicySet,
    persist: bool,
}

fn parse_bool(s: Option<&str>) -> Option<bool> {
    s.and_then(bool::parse_pref)
}

/// Tarjetas de un árbol (hijos `n` de `node` con una única entrada nombre → biblioteca).
pub(crate) fn cards_of(tree: &PrefsTree, node: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for child in tree.children(node) {
        if let Some(m) = tree.node(&format!("{node}/{child}"))
            && let Some((k, v)) = m.iter().next()
        {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Construye la capa de sistema a partir de sus fuentes (§4.3.1, con las directivas).
pub fn build_system_layer(
    user: &PrefsTree,
    native: &PrefsTree,
    legacy: &PrefsTree,
    policy: &PolicySet,
    sources: Vec<String>,
) -> SystemLayer {
    let mut main = legacy.node(NODE_MAIN).cloned().unwrap_or_default();
    main.extend(native.node(NODE_MAIN).cloned().unwrap_or_default());
    let mut internal = legacy.node(NODE_INTERNAL).cloned().unwrap_or_default();
    internal.extend(native.node(NODE_INTERNAL).cloned().unwrap_or_default());
    let mut smartcards = cards_of(native, NODE_KEYSTORES);
    if smartcards.is_empty() {
        smartcards = cards_of(legacy, NODE_KEYSTORES);
    }
    let allow_update = parse_bool(
        policy
            .mandatory
            .get(keys::ALLOW_UPDATE_CONFIG.name())
            .map(String::as_str),
    )
    .or_else(|| parse_bool(internal.get(keys::ALLOW_UPDATE_CONFIG.name()).map(String::as_str)))
    .unwrap_or(false);
    let mut using_updated_copy = false;
    if allow_update {
        if user.node_exists(NODE_UPDATED_SYSTEM) {
            main = user.node(NODE_UPDATED_SYSTEM).cloned().unwrap_or_default();
            using_updated_copy = true;
        }
        if user.node_exists(NODE_UPDATED_SYSTEM_KEYSTORES) {
            smartcards = cards_of(user, NODE_UPDATED_SYSTEM_KEYSTORES);
        }
    }
    // Las directivas recomendadas ganan a los ficheros de sistema.
    main.extend(policy.recommended.clone());
    SystemLayer {
        main,
        internal,
        smartcards,
        sources,
        using_updated_copy,
    }
}

/// Ruta del fichero nativo de preferencias de usuario.
pub fn user_prefs_path(ctx: &Context) -> PathBuf {
    ctx.paths.user_config_dir.join(USER_PREFS_FILE)
}

impl Preferences {
    /// Carga las preferencias del sistema y del usuario. Si no existe el almacén nativo de
    /// usuario, se migran (una sola vez) las preferencias Java del usuario.
    pub fn load(ctx: &Context, mode: ResolutionMode) -> Result<Self> {
        let store = JsonTreeStore::new(user_prefs_path(ctx));
        let file = match store.load() {
            Ok(Some(f)) => f,
            Ok(None) => {
                let (legacy, src) = legacy::read_legacy(ctx, legacy::LegacyScope::User);
                let f = PrefsFile {
                    migrated_from: Some(if legacy.is_empty() { "ninguno".into() } else { src }),
                    nodes: legacy,
                    ..Default::default()
                };
                // Como root en el directorio de otro usuario (instalador, sudo) no se
                // crea el fichero: el usuario lo creará al abrir la aplicación.
                if crate::fsutil::root_in_foreign_home(&user_prefs_path(ctx)) {
                    tracing::debug!("migración de preferencias no guardada (root en HOME ajeno)");
                } else if let Err(e) = store.save(&f, Some(0o600)) {
                    tracing::warn!("No se pudo guardar la migración de preferencias: {e}");
                }
                f
            }
            Err(e) => {
                tracing::warn!("{e}");
                PrefsFile {
                    nodes: store.load_tree_lenient(),
                    ..Default::default()
                }
            }
        };
        let native = system::SystemStore::new(ctx).load_tree();
        let (legacy_sys, legacy_src) = legacy::read_legacy(ctx, legacy::LegacyScope::System);
        let policy = policy::load(ctx);
        let mut sources = vec![system::SystemStore::new(ctx).path.display().to_string()];
        if !legacy_sys.is_empty() {
            sources.push(legacy_src);
        }
        sources.extend(policy.sources.iter().cloned());
        let system = build_system_layer(&file.nodes, &native, &legacy_sys, &policy, sources);
        Ok(Self {
            mode,
            store,
            file,
            system,
            policy,
            persist: true,
        })
    }

    /// Construye un gestor en memoria a partir de capas explícitas (pruebas y herramientas).
    pub fn from_layers(mode: ResolutionMode, user: PrefsTree, system: SystemLayer, policy: PolicySet) -> Self {
        Self {
            mode,
            store: JsonTreeStore::new(PathBuf::new()),
            file: PrefsFile {
                nodes: user,
                ..Default::default()
            },
            system,
            policy,
            persist: false,
        }
    }

    /// Modo de resolución.
    pub fn mode(&self) -> ResolutionMode {
        self.mode
    }

    /// Capa de sistema combinada.
    pub fn system_layer(&self) -> &SystemLayer {
        &self.system
    }

    /// Directivas cargadas.
    pub fn policies(&self) -> &PolicySet {
        &self.policy
    }

    /// Árbol de usuario.
    pub fn user_tree(&self) -> &PrefsTree {
        &self.file.nodes
    }

    /// Ruta del almacén de usuario.
    pub fn user_store_path(&self) -> &std::path::Path {
        &self.store.path
    }

    fn user_main(&self, name: &str) -> Option<&str> {
        self.file.nodes.get(NODE_MAIN, name)
    }

    /// `true` si `preferencesBlocked` está activo en la capa de sistema o de directiva
    /// (el usuario no puede desbloquearlo en modo estricto).
    pub fn system_blocked(&self) -> bool {
        let n = keys::PREFERENCES_BLOCKED.name();
        parse_bool(self.policy.mandatory.get(n).map(String::as_str))
            .or_else(|| parse_bool(self.system.main.get(n).map(String::as_str)))
            .unwrap_or(false)
    }

    /// Estado de bloqueo que la interfaz debe aplicar (deshabilitar controles de §4.4.2).
    /// En modo compatible se resuelve como Java (usuario primero).
    pub fn is_blocked(&self) -> bool {
        match self.mode {
            ResolutionMode::Strict => self.system_blocked(),
            ResolutionMode::Compat => self.get_bool(keys::PREFERENCES_BLOCKED.name()),
        }
    }

    /// Motivo de bloqueo de una clave (`None` = editable).
    pub fn lock(&self, name: &str) -> Option<LockReason> {
        if self.policy.mandatory.contains_key(name) {
            return Some(LockReason::Policy);
        }
        let info = keys::info(name)?;
        if info.internal || (self.mode == ResolutionMode::Strict && info.admin_only) {
            return Some(LockReason::AdminOnly);
        }
        if self.mode == ResolutionMode::Strict && info.lockable && self.system_blocked() {
            return Some(LockReason::AdminBlock);
        }
        None
    }

    /// Candidatos de valor en orden de prioridad, con su capa.
    fn chain(&self, name: &str) -> Vec<(Layer, Option<&str>)> {
        if let Some(v) = self.policy.mandatory.get(name) {
            return vec![(Layer::Policy, Some(v.as_str()))];
        }
        let info = keys::info(name);
        let default = (Layer::Default, info.and_then(|i| i.default));
        if let Some(i) = info
            && i.internal
        {
            let sys = (Layer::System, self.system.internal.get(name).map(String::as_str));
            let user = (Layer::User, self.file.nodes.get(NODE_INTERNAL, name));
            if i.system_exclusive || (self.mode == ResolutionMode::Strict && i.admin_only) {
                return vec![sys, default];
            }
            return vec![user, sys, default];
        }
        let sys = (Layer::System, self.system.main.get(name).map(String::as_str));
        let user = (Layer::User, self.user_main(name));
        if self.mode == ResolutionMode::Strict
            && let Some(i) = info
            && (i.admin_only || (i.lockable && self.system_blocked()))
        {
            return vec![sys, default];
        }
        vec![user, sys, default]
    }

    /// Valor efectivo (cadena) de una clave: `get` de Java.
    pub fn get(&self, name: &str) -> Option<String> {
        self.chain(name).into_iter().find_map(|(_, v)| v.map(str::to_string))
    }

    /// Valor efectivo y su capa.
    pub fn get_with_layer(&self, name: &str) -> (Option<String>, Layer) {
        for (l, v) in self.chain(name) {
            if let Some(v) = v {
                return (Some(v.to_string()), l);
            }
        }
        (None, Layer::Default)
    }

    /// Booleano efectivo con la semántica de Java (`getBoolean`): se salta los valores no
    /// booleanos de una capa y usa la siguiente; por defecto `false`.
    pub fn get_bool(&self, name: &str) -> bool {
        self.chain(name)
            .into_iter()
            .find_map(|(_, v)| parse_bool(v))
            .unwrap_or(false)
    }

    /// Valor tipado: el primer valor válido de la cadena de capas, o `None`.
    pub fn value<T: PrefValue>(&self, key: Key<T>) -> Option<T> {
        self.chain(key.name())
            .into_iter()
            .find_map(|(_, v)| v.and_then(T::parse_pref))
    }

    /// Valor de una capa concreta, sin cascada (`get(key, src)` de Java).
    pub fn get_from(&self, name: &str, layer: Layer) -> Option<String> {
        match layer {
            Layer::Policy => self.policy.mandatory.get(name).cloned(),
            Layer::User => self.user_main(name).map(str::to_string),
            Layer::System => self.system.main.get(name).cloned(),
            Layer::Default => keys::default_value(name).map(str::to_string),
        }
    }

    /// Valor de una clave del nodo interno (§4.3.1, `SYSTEM_INTERNAL`).
    pub fn get_internal(&self, name: &str) -> Option<String> {
        self.get(name)
    }

    /// Requisitos de firma de los ficheros de configuración.
    pub fn signature_policy(&self) -> SignaturePolicy {
        SignaturePolicy {
            require_signed: self.get_bool(keys::REQUIRE_SIGNED_PREFERENCES.name()),
            pinned_cert_hash: self
                .get(keys::CERT_HASH_TO_SIGNED_PREFERENCES.name())
                .filter(|s| !s.trim().is_empty()),
        }
    }

    fn check_writable(&self, name: &str) -> Result<()> {
        if self.lock(name).is_some() {
            return Err(SystemError::Locked(name.to_string()));
        }
        Ok(())
    }

    fn validate(name: &str, value: &str) -> Result<()> {
        if let Some(i) = keys::info(name)
            && !i.accepts(value)
        {
            return Err(SystemError::InvalidValue {
                key: name.into(),
                value: value.into(),
            });
        }
        Ok(())
    }

    /// Escribe una preferencia de usuario con la regla de Java de «no ensombrecer»: si el
    /// valor coincide con el del sistema (o el defecto) se borra el valor de usuario.
    pub fn put(&mut self, name: &str, value: &str) -> Result<()> {
        self.check_writable(name)?;
        Self::validate(name, value)?;
        let reference = self
            .system
            .main
            .get(name)
            .cloned()
            .or_else(|| keys::default_value(name).map(str::to_string));
        if reference.as_deref() == Some(value) {
            self.file.nodes.remove(NODE_MAIN, name);
        } else if self.get(name).as_deref() != Some(value) {
            self.file.nodes.put(NODE_MAIN, name, value);
        }
        self.persist()
    }

    /// Escribe una preferencia booleana (misma regla, comparando booleanos).
    pub fn put_bool(&mut self, name: &str, value: bool) -> Result<()> {
        self.check_writable(name)?;
        let reference = parse_bool(self.system.main.get(name).map(String::as_str))
            .unwrap_or_else(|| keys::default_value(name).is_some_and(|d| d == "true"));
        if reference == value {
            self.file.nodes.remove(NODE_MAIN, name);
        } else {
            self.file
                .nodes
                .put(NODE_MAIN, name, if value { "true" } else { "false" });
        }
        self.persist()
    }

    /// Escribe un valor tipado.
    pub fn set<T: PrefValue>(&mut self, key: Key<T>, value: &T) -> Result<()> {
        let s = value.to_pref();
        if matches!(key.info.kind, keys::Kind::Bool) {
            return self.put_bool(key.name(), s == "true");
        }
        self.put(key.name(), &s)
    }

    /// Borra el valor de usuario de una clave (siempre permitido).
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.file.nodes.remove(NODE_MAIN, name);
        self.persist()
    }

    /// Borra todas las claves de usuario del nodo principal (`clearAll`).
    pub fn clear_all(&mut self) -> Result<()> {
        self.file.nodes.0.remove(NODE_MAIN);
        self.persist()
    }

    /// Botón «Restaurar configuración» de la pestaña General (§4.9.3): borra todo el nodo
    /// principal de usuario y las claves sueltas del nodo de almacenes (las tarjetas se conservan).
    pub fn restore_general(&mut self) -> Result<()> {
        self.file.nodes.0.remove(NODE_MAIN);
        self.file.nodes.0.remove(NODE_KEYSTORES);
        self.persist()
    }

    /// Botones «Restaurar configuración» por pestaña (§4.9.8). Devuelve las claves borradas.
    pub fn restore_section(&mut self, section: Section) -> Result<Vec<&'static str>> {
        let (always, unless_blocked) = keys::tab_restore_keys(section);
        let blocked = self.is_blocked() && section != Section::Keystores;
        let mut removed = Vec::new();
        for k in always
            .iter()
            .chain(if blocked { [].iter() } else { unless_blocked.iter() })
        {
            if self.file.nodes.remove(NODE_MAIN, k) {
                removed.push(*k);
            }
        }
        if section == Section::Keystores {
            let children = self.file.nodes.children(NODE_KEYSTORES);
            for c in children {
                self.file.nodes.remove_subtree(&format!("{NODE_KEYSTORES}/{c}"));
            }
        }
        self.persist()?;
        Ok(removed)
    }

    /// Valor de una clave de un nodo auxiliar.
    pub fn get_aux(&self, key: AuxKey) -> Option<String> {
        self.file
            .nodes
            .get(key.node, key.name)
            .map(str::to_string)
            .or_else(|| key.default.map(str::to_string))
    }

    /// Escribe una clave de un nodo auxiliar.
    pub fn put_aux(&mut self, key: AuxKey, value: &str) -> Result<()> {
        self.file.nodes.put(key.node, key.name, value);
        self.persist()
    }

    /// Lee una clave libre de un nodo de usuario (configuración de funciones integradas
    /// como el antiguo complemento de huellas).
    pub fn get_node_value(&self, node: &str, key: &str) -> Option<String> {
        self.file.nodes.get(node, key).map(str::to_string)
    }

    /// Escribe una clave libre de un nodo de usuario.
    pub fn put_node_value(&mut self, node: &str, key: &str, value: &str) -> Result<()> {
        if node == NODE_MAIN {
            return self.put(key, value);
        }
        self.file.nodes.put(node, key, value);
        self.persist()
    }

    /// Valores efectivos de todas las claves conocidas.
    pub fn effective(&self) -> Vec<EffectiveValue> {
        keys::ALL
            .iter()
            .map(|k: &&KeyInfo| {
                let (value, layer) = self.get_with_layer(k.name);
                EffectiveValue {
                    name: k.name,
                    value,
                    layer,
                    lock: self.lock(k.name),
                }
            })
            .collect()
    }

    /// Tarjetas registradas: directiva ∪ sistema ∪ usuario (en caso de nombre repetido gana
    /// la directiva, después el sistema).
    pub fn smart_cards(&self) -> Vec<SmartCard> {
        let mut out: BTreeMap<String, SmartCard> = BTreeMap::new();
        for (n, l) in cards_of(&self.file.nodes, NODE_KEYSTORES) {
            out.insert(
                n.clone(),
                SmartCard {
                    name: n,
                    library: l,
                    origin: CardOrigin::User,
                },
            );
        }
        for (n, l) in &self.system.smartcards {
            out.insert(
                n.clone(),
                SmartCard {
                    name: n.clone(),
                    library: l.clone(),
                    origin: CardOrigin::System,
                },
            );
        }
        for (n, l) in &self.policy.smartcards {
            out.insert(
                n.clone(),
                SmartCard {
                    name: n.clone(),
                    library: l.clone(),
                    origin: CardOrigin::Policy,
                },
            );
        }
        out.into_values().collect()
    }

    /// Registra una tarjeta de usuario (validaciones del diálogo «Agregar tarjeta»).
    pub fn add_smart_card(&mut self, name: &str, library: &str) -> Result<()> {
        if name.trim().is_empty() || library.trim().is_empty() {
            return Err(SystemError::Other("Rellene todos los campos".into()));
        }
        let cards = self.smart_cards();
        if cards.iter().any(|c| c.name == name) {
            return Err(SystemError::Other(
                "El nombre de tarjeta introducido ya se encuentra registrado".into(),
            ));
        }
        if cards.iter().any(|c| c.library == library) {
            return Err(SystemError::Other(
                "El controlador introducido ya se encuentra registrado".into(),
            ));
        }
        self.insert_user_card(name, library);
        self.persist()
    }

    fn insert_user_card(&mut self, name: &str, library: &str) {
        let mut n = 1;
        while self.file.nodes.node_exists(&format!("{NODE_KEYSTORES}/{n}")) {
            n += 1;
        }
        self.file.nodes.put(&format!("{NODE_KEYSTORES}/{n}"), name, library);
    }

    /// Elimina una tarjeta de usuario; `true` si existía.
    pub fn remove_smart_card(&mut self, name: &str) -> Result<bool> {
        for c in self.file.nodes.children(NODE_KEYSTORES) {
            let node = format!("{NODE_KEYSTORES}/{c}");
            if self.file.nodes.node(&node).is_some_and(|m| m.contains_key(name)) {
                self.file.nodes.remove_subtree(&node);
                self.persist()?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Exporta la configuración efectiva como `.afconfig` (§4.10.2): sistema, sobre él el
    /// usuario y sobre ambos las directivas obligatorias; sin claves internas ni valores por defecto.
    pub fn export_afconfig(&self) -> String {
        let mut m = self.system.main.clone();
        if let Some(u) = self.file.nodes.node(NODE_MAIN) {
            m.extend(u.clone());
        }
        m.extend(self.policy.mandatory.clone());
        m.retain(|k, _| !keys::info(k).is_some_and(|i| i.internal));
        let mut cards: BTreeMap<String, String> = BTreeMap::new();
        for c in self.smart_cards() {
            cards.insert(c.name, c.library);
        }
        afconfig::export(&m, &cards)
    }

    /// Analiza un `.afconfig` para importarlo en la capa de usuario y comprueba su firma
    /// según `requireSignedPrerefences` y `certHashToSignedPrerefences`.
    pub fn prepare_import(
        &self,
        data: &[u8],
        verifier: Option<&dyn ConfigSignatureVerifier>,
    ) -> std::result::Result<PreparedImport, ConfigError> {
        let content = afconfig::parse(data)?;
        let signature =
            afconfig::check_signature(data, &content, verifier, &self.signature_policy(), chrono::Utc::now())?;
        Ok(PreparedImport { content, signature })
    }

    /// Aplica una importación ya confirmada (fusión en la capa de usuario, §4.10.3 paso 6).
    pub fn apply_import(&mut self, prepared: &PreparedImport) -> Result<ImportReport> {
        let mut rep = ImportReport::default();
        let was_persist = self.persist;
        self.persist = false;
        if let Some(cards) = &prepared.content.smartcards {
            let mut registered: BTreeMap<String, String> =
                self.smart_cards().into_iter().map(|c| (c.name, c.library)).collect();
            for (name, lib) in cards {
                if registered.values().any(|l| l == lib) {
                    continue;
                }
                let mut final_name = name.clone();
                let mut i = 1;
                while registered.contains_key(&final_name) {
                    final_name = format!("{name}-{i}");
                    i += 1;
                }
                self.insert_user_card(&final_name, lib);
                registered.insert(final_name.clone(), lib.clone());
                rep.cards_added.push(final_name);
            }
        }
        let blocked = self.is_blocked();
        for (k, v) in &prepared.content.prefs {
            if let Some(r) = self.lock(k) {
                rep.skipped.push((k.clone(), format!("{r:?}")));
                continue;
            }
            if blocked && keys::is_protected(k) {
                rep.skipped.push((k.clone(), "protegida".into()));
                continue;
            }
            let res = if matches!(keys::info(k).map(|i| i.kind), Some(keys::Kind::Bool)) {
                match bool::parse_pref(v) {
                    Some(b) => self.put_bool(k, b),
                    None => Err(SystemError::InvalidValue {
                        key: k.clone(),
                        value: v.clone(),
                    }),
                }
            } else {
                self.put(k, v)
            };
            match res {
                Ok(()) => rep.applied.push(k.clone()),
                Err(e) => rep.skipped.push((k.clone(), e.to_string())),
            }
        }
        self.persist = was_persist;
        self.persist()?;
        Ok(rep)
    }

    /// Guarda el almacén de usuario (también se guarda automáticamente en cada escritura).
    pub fn flush(&self) -> Result<()> {
        if self.store.path.as_os_str().is_empty() {
            return Ok(());
        }
        self.store.save(&self.file, Some(0o600))
    }

    fn persist(&self) -> Result<()> {
        if self.persist { self.flush() } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(pairs: &[(&str, &str)]) -> PrefsTree {
        let mut t = PrefsTree::new();
        for (k, v) in pairs {
            t.put(NODE_MAIN, k, v);
        }
        t
    }

    fn sys(pairs: &[(&str, &str)]) -> SystemLayer {
        SystemLayer {
            main: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn resolucion_java_en_modo_compatible() {
        let p = Preferences::from_layers(
            ResolutionMode::Compat,
            tree(&[("signatureHashAlgorithm", "SHA1"), ("preferencesBlocked", "false")]),
            sys(&[
                ("signatureHashAlgorithm", "SHA512"),
                ("preferencesBlocked", "true"),
                ("xadesSignFormat", "XAdES Enveloped"),
            ]),
            PolicySet::default(),
        );
        assert_eq!(
            p.get("signatureHashAlgorithm").as_deref(),
            Some("SHA1"),
            "el usuario gana en Java"
        );
        assert!(!p.is_blocked(), "Java resuelve el bloqueo primero en el usuario");
        assert_eq!(p.get("xadesSignFormat").as_deref(), Some("XAdES Enveloped"));
        assert_eq!(p.get("cadesMultisign").as_deref(), Some("cosign"));
        assert_eq!(p.get("noExiste"), None);
        assert!(p.lock("signatureHashAlgorithm").is_none());
    }

    #[test]
    fn bloqueo_real_en_modo_estricto() {
        let mut p = Preferences::from_layers(
            ResolutionMode::Strict,
            tree(&[
                ("signatureHashAlgorithm", "SHA1"),
                ("preferencesBlocked", "false"),
                ("omitAskOnClose", "true"),
                ("allowPersonalTruststore", "true"),
            ]),
            sys(&[
                ("signatureHashAlgorithm", "SHA512"),
                ("preferencesBlocked", "true"),
                ("allowPersonalTruststore", "false"),
            ]),
            PolicySet::default(),
        );
        assert!(p.is_blocked());
        assert_eq!(p.get("signatureHashAlgorithm").as_deref(), Some("SHA512"));
        assert_eq!(
            p.value(keys::SIGNATURE_HASH_ALGORITHM),
            Some(keys::HashAlgorithm::Sha512)
        );
        assert_eq!(p.lock("signatureHashAlgorithm"), Some(LockReason::AdminBlock));
        assert!(matches!(
            p.put("signatureHashAlgorithm", "SHA1"),
            Err(SystemError::Locked(_))
        ));
        assert!(
            p.get_bool("omitAskOnClose"),
            "las no bloqueables siguen siendo del usuario"
        );
        assert!(
            !p.get_bool("allowPersonalTruststore"),
            "clave de administración solo de sistema"
        );
        // Sin bloqueo de sistema el usuario manda.
        let p2 = Preferences::from_layers(
            ResolutionMode::Strict,
            tree(&[("signatureHashAlgorithm", "SHA1")]),
            sys(&[("signatureHashAlgorithm", "SHA512")]),
            PolicySet::default(),
        );
        assert_eq!(p2.get("signatureHashAlgorithm").as_deref(), Some("SHA1"));
    }

    #[test]
    fn directiva_obligatoria_bloquea_en_ambos_modos() {
        for mode in [ResolutionMode::Compat, ResolutionMode::Strict] {
            let mut pol = PolicySet::default();
            pol.mandatory.insert("secureConnections".into(), "true".into());
            pol.mandatory.insert("default.locale".into(), "eu_ES".into());
            let mut p = Preferences::from_layers(
                mode,
                tree(&[("secureConnections", "false"), ("default.locale", "es_ES")]),
                SystemLayer::default(),
                pol,
            );
            assert!(p.get_bool("secureConnections"));
            assert_eq!(
                p.get_with_layer("default.locale"),
                (Some("eu_ES".into()), Layer::Policy)
            );
            assert_eq!(p.lock("default.locale"), Some(LockReason::Policy));
            assert!(p.put("default.locale", "ca_ES").is_err());
        }
    }

    #[test]
    fn escritura_sin_ensombrecer() {
        let mut p = Preferences::from_layers(
            ResolutionMode::Strict,
            PrefsTree::new(),
            sys(&[("xadesSignFormat", "XAdES Enveloped")]),
            PolicySet::default(),
        );
        p.put("xadesSignFormat", "XAdES Detached").unwrap();
        assert_eq!(p.user_tree().get(NODE_MAIN, "xadesSignFormat"), Some("XAdES Detached"));
        p.put("xadesSignFormat", "XAdES Enveloped").unwrap();
        assert_eq!(
            p.user_tree().get(NODE_MAIN, "xadesSignFormat"),
            None,
            "igual al sistema: se borra"
        );
        p.put_bool("omitAskOnClose", false).unwrap();
        assert_eq!(
            p.user_tree().get(NODE_MAIN, "omitAskOnClose"),
            None,
            "igual al defecto: no se guarda"
        );
        p.put_bool("omitAskOnClose", true).unwrap();
        assert_eq!(p.user_tree().get(NODE_MAIN, "omitAskOnClose"), Some("true"));
        assert!(matches!(
            p.put("xadesSignFormat", "XAdES Raro"),
            Err(SystemError::InvalidValue { .. })
        ));
        p.set(keys::CADES_MULTISIGN, &keys::MultisignOp::CountersignTree)
            .unwrap();
        assert_eq!(p.value(keys::CADES_MULTISIGN), Some(keys::MultisignOp::CountersignTree));
    }

    #[test]
    fn get_bool_salta_valores_no_booleanos() {
        let p = Preferences::from_layers(
            ResolutionMode::Compat,
            tree(&[("confirmToSign", "quizá")]),
            sys(&[("confirmToSign", "false")]),
            PolicySet::default(),
        );
        assert!(!p.get_bool("confirmToSign"));
    }

    #[test]
    fn copia_actualizada_y_tarjetas() {
        let mut user = PrefsTree::new();
        user.put(NODE_UPDATED_SYSTEM, "signatureHashAlgorithm", "SHA384");
        user.put(&format!("{NODE_KEYSTORES}/1"), "Mía", "/usr/lib/mia.so");
        let mut native = PrefsTree::new();
        native.put(NODE_MAIN, "signatureHashAlgorithm", "SHA512");
        native.put(NODE_INTERNAL, "allowUpdateConfig", "true");
        native.put(&format!("{NODE_KEYSTORES}/1"), "Corp", "/usr/lib/corp.so");
        let layer = build_system_layer(&user, &native, &PrefsTree::new(), &PolicySet::default(), vec![]);
        assert!(layer.using_updated_copy);
        let mut p = Preferences::from_layers(ResolutionMode::Strict, user, layer, PolicySet::default());
        assert_eq!(p.get("signatureHashAlgorithm").as_deref(), Some("SHA384"));
        assert!(p.get_bool("allowUpdateConfig"));
        let cards = p.smart_cards();
        assert_eq!(cards.len(), 2);
        assert!(p.add_smart_card("Corp", "/otra.so").is_err());
        assert!(p.add_smart_card("Nueva", "/usr/lib/corp.so").is_err());
        p.add_smart_card("Nueva", "/usr/lib/nueva.so").unwrap();
        assert!(p.user_tree().get(&format!("{NODE_KEYSTORES}/2"), "Nueva").is_some());
        assert!(p.remove_smart_card("Mía").unwrap());
        assert_eq!(p.smart_cards().len(), 2);
    }

    #[test]
    fn importacion_y_exportacion() {
        let mut p = Preferences::from_layers(
            ResolutionMode::Strict,
            PrefsTree::new(),
            sys(&[("preferencesBlocked", "true")]),
            PolicySet::default(),
        );
        let xml = br#"<plist><dict><key>signatureHashAlgorithm</key><string>SHA1</string><key>omitAskOnClose</key><true/><key>smartcards</key><dict><key>T</key><string>/t.so</string></dict></dict></plist>"#;
        let prep = p.prepare_import(xml, None).unwrap();
        assert!(prep.confirmation_text().contains("no esta firmado"));
        let rep = p.apply_import(&prep).unwrap();
        assert_eq!(rep.applied, vec!["omitAskOnClose".to_string()]);
        assert_eq!(rep.skipped.len(), 1);
        assert_eq!(rep.cards_added, vec!["T".to_string()]);
        let exp = p.export_afconfig();
        assert!(exp.contains("<key>omitAskOnClose</key><true/>"));
        assert!(exp.contains("<key>preferencesBlocked</key><true/>"));
        assert!(exp.contains("<key>smartcards</key><dict><key>T</key><string>/t.so</string></dict>"));
    }

    #[test]
    fn restaurar_pestanas() {
        let mut p = Preferences::from_layers(
            ResolutionMode::Strict,
            tree(&[
                ("padesSignReason", "x"),
                ("padesBasicFormat", "adbe.pkcs7.detached"),
                ("omitAskOnClose", "true"),
            ]),
            sys(&[]),
            PolicySet::default(),
        );
        let removed = p.restore_section(Section::Pades).unwrap();
        assert!(removed.contains(&"padesSignReason") && removed.contains(&"padesBasicFormat"));
        assert_eq!(p.get("omitAskOnClose").as_deref(), Some("true"));
        p.restore_general().unwrap();
        assert_eq!(p.get("omitAskOnClose").as_deref(), Some("false"));
    }
}
