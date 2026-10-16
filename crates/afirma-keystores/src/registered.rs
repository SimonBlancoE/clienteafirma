//! Tarjetas inteligentes registradas por el usuario o el administrador
//! (`KeyStorePreferencesManager`, especificación 07 §13.3 y 05 §3.9).
//!
//! Este módulo define solo el modelo y sus reglas; la persistencia
//! (preferencias de Java en `~/.java/.userPrefs/es/gob/afirma/core/keystores`,
//! registro de Windows, plist de macOS) la hace otro crate, que construye un
//! [`RegisteredCards`] y guarda sus cambios.
//!
//! Disposición en Java: nodo de usuario `/es/gob/afirma/core/keystores` con
//! hijos `"1"`, `"2"`… (primer entero libre), cada uno con una única clave
//! `<nombre de tarjeta>` = `<ruta de la biblioteca PKCS#11>`. Nodo de
//! sistema: `/es/gob/afirma/core/systemkeystores` del usuario si existe y
//! `allowUpdateConfig` es verdadero; si no, `/es/gob/afirma/core/keystores`
//! del sistema.

use std::path::PathBuf;

/// Nodo de preferencias de usuario de las tarjetas.
pub const USER_NODE: &str = "/es/gob/afirma/core/keystores";
/// Nodo de usuario que actúa como "sistema" si lo permite `allowUpdateConfig`.
pub const SYSTEM_OVERRIDE_NODE: &str = "/es/gob/afirma/core/systemkeystores";
/// Nodo y clave que permiten usar [`SYSTEM_OVERRIDE_NODE`].
pub const ALLOW_UPDATE_CONFIG_NODE: &str = "/es/gob/afirma/standalone/ui/internalpreferences";
pub const ALLOW_UPDATE_CONFIG_KEY: &str = "allowUpdateConfig";

/// Ámbito de registro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardScope {
    User,
    System,
}

/// Tarjeta registrada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCard {
    /// Nombre (también es el nombre del almacén en el diálogo y en la
    /// preferencia `defaultKeystore`).
    pub name: String,
    /// Biblioteca PKCS#11.
    pub library: PathBuf,
    /// Nodo hijo de Java (`"1"`, `"2"`...), para conservarlo al guardar.
    pub node: String,
    pub scope: CardScope,
}

/// Error de validación del diálogo "Agregar tarjeta" / "Modificar tarjeta".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardRegistrationError {
    #[error("Rellene todos los campos")]
    EmptyFields,
    #[error("El nombre de tarjeta introducido ya se encuentra registrado. Por favor, introduzca otro nombre.")]
    DuplicateName,
    #[error("El controlador introducido ya se encuentra registrado. Por favor, introduzca otro controlador.")]
    DuplicateLibrary,
    #[error("No existe ninguna tarjeta registrada con ese nombre")]
    NotFound,
    #[error("Las tarjetas del sistema no se pueden modificar")]
    SystemCard,
}

/// Conjunto de tarjetas registradas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisteredCards {
    pub user: Vec<RegisteredCard>,
    pub system: Vec<RegisteredCard>,
}

fn same_library(a: &std::path::Path, b: &std::path::Path) -> bool {
    a == b || (cfg!(windows) && a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()))
}

fn next_node(cards: &[RegisteredCard]) -> String {
    (1u32..)
        .map(|n| n.to_string())
        .find(|n| !cards.iter().any(|c| &c.node == n))
        .unwrap_or_else(|| "1".into())
}

impl RegisteredCards {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tarjetas de usuario y después de sistema (orden del menú del
    /// diálogo y del combo de preferencias).
    pub fn all(&self) -> impl Iterator<Item = &RegisteredCard> {
        self.user.iter().chain(self.system.iter())
    }

    /// Mapa nombre → biblioteca de usuario ∪ sistema; con el mismo nombre
    /// prevalece la de sistema (`getAllSmartCardsMap`).
    pub fn all_map(&self) -> Vec<(String, PathBuf)> {
        let mut out: Vec<(String, PathBuf)> = Vec::new();
        for c in self.user.iter().chain(self.system.iter()) {
            match out.iter_mut().find(|(n, _)| *n == c.name) {
                Some(e) => e.1 = c.library.clone(),
                None => out.push((c.name.clone(), c.library.clone())),
            }
        }
        out
    }

    /// Busca por nombre exacto (sistema primero, como `getAllSmartCardsMap`).
    pub fn find(&self, name: &str) -> Option<&RegisteredCard> {
        self.system
            .iter()
            .find(|c| c.name == name)
            .or_else(|| self.user.iter().find(|c| c.name == name))
    }

    /// Indica si la biblioteca ya está registrada en algún ámbito.
    pub fn library_registered(&self, lib: &std::path::Path) -> bool {
        self.all().any(|c| same_library(&c.library, lib))
    }

    /// Nombre único: `nombre`, `nombre-1`, `nombre-2`… (`checkCorrectName`).
    pub fn unique_name(&self, name: &str) -> String {
        if !self.all().any(|c| c.name == name) {
            return name.to_string();
        }
        (1u32..)
            .map(|n| format!("{name}-{n}"))
            .find(|n| !self.all().any(|c| &c.name == n))
            .unwrap_or_else(|| name.to_string())
    }

    /// Registro desde el diálogo de preferencias ("Agregar tarjeta"), con
    /// sus validaciones.
    pub fn add_user(
        &mut self,
        name: &str,
        library: impl Into<PathBuf>,
    ) -> Result<&RegisteredCard, CardRegistrationError> {
        let library = library.into();
        if name.trim().is_empty() || library.as_os_str().is_empty() {
            return Err(CardRegistrationError::EmptyFields);
        }
        if self.all().any(|c| c.name == name) {
            return Err(CardRegistrationError::DuplicateName);
        }
        if self.library_registered(&library) {
            return Err(CardRegistrationError::DuplicateLibrary);
        }
        let node = next_node(&self.user);
        self.user.push(RegisteredCard {
            name: name.to_string(),
            library,
            node,
            scope: CardScope::User,
        });
        Ok(self.user.last().expect("recién añadida"))
    }

    /// "Modificar tarjeta" de usuario. Corrige el fallo de Java que impedía
    /// guardar sin cambiar el nombre (se ignoraba la propia tarjeta al
    /// comprobar duplicados).
    pub fn modify_user(
        &mut self,
        old_name: &str,
        new_name: &str,
        library: impl Into<PathBuf>,
    ) -> Result<(), CardRegistrationError> {
        let library = library.into();
        if new_name.trim().is_empty() || library.as_os_str().is_empty() {
            return Err(CardRegistrationError::EmptyFields);
        }
        if self.system.iter().any(|c| c.name == old_name) && !self.user.iter().any(|c| c.name == old_name) {
            return Err(CardRegistrationError::SystemCard);
        }
        let idx = self
            .user
            .iter()
            .position(|c| c.name == old_name)
            .ok_or(CardRegistrationError::NotFound)?;
        if self.all().enumerate().any(|(i, c)| i != idx && c.name == new_name) {
            return Err(CardRegistrationError::DuplicateName);
        }
        if self
            .all()
            .enumerate()
            .any(|(i, c)| i != idx && same_library(&c.library, &library))
        {
            return Err(CardRegistrationError::DuplicateLibrary);
        }
        let c = &mut self.user[idx];
        c.name = new_name.to_string();
        c.library = library;
        Ok(())
    }

    /// Elimina una tarjeta de usuario (`deleteSmartCardRec`).
    pub fn delete_user(&mut self, name: &str) -> Result<RegisteredCard, CardRegistrationError> {
        let idx = self.user.iter().position(|c| c.name == name).ok_or_else(|| {
            if self.system.iter().any(|c| c.name == name) {
                CardRegistrationError::SystemCard
            } else {
                CardRegistrationError::NotFound
            }
        })?;
        Ok(self.user.remove(idx))
    }

    /// Importación de tarjetas de usuario (`putUserSmartCardsMap`): se omiten
    /// las de bibliotecas ya registradas y se renombran las de nombre
    /// repetido.
    pub fn put_user(&mut self, cards: &[(String, PathBuf)]) {
        for (name, lib) in cards {
            if self.library_registered(lib) {
                continue;
            }
            let name = self.unique_name(name);
            let node = next_node(&self.user);
            self.user.push(RegisteredCard {
                name,
                library: lib.clone(),
                node,
                scope: CardScope::User,
            });
        }
    }

    /// Sustituye las tarjetas de sistema (`putSystemSmartCardsMap`).
    pub fn put_system(&mut self, cards: &[(String, PathBuf)]) {
        self.system.clear();
        for (name, lib) in cards {
            let name = self.unique_name(name);
            let node = next_node(&self.system);
            self.system.push(RegisteredCard {
                name,
                library: lib.clone(),
                node,
                scope: CardScope::System,
            });
        }
    }

    /// "Restaurar" la configuración de almacenes: borra las tarjetas de
    /// usuario.
    pub fn clear_user(&mut self) {
        self.user.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_rules() {
        let mut r = RegisteredCards::new();
        assert_eq!(r.add_user("", "/x.so").unwrap_err(), CardRegistrationError::EmptyFields);
        r.add_user("Mi tarjeta", "/usr/lib/a.so").unwrap();
        assert_eq!(r.user[0].node, "1");
        assert_eq!(
            r.add_user("Mi tarjeta", "/usr/lib/b.so").unwrap_err(),
            CardRegistrationError::DuplicateName
        );
        assert_eq!(
            r.add_user("Otra", "/usr/lib/a.so").unwrap_err(),
            CardRegistrationError::DuplicateLibrary
        );
        r.add_user("Otra", "/usr/lib/b.so").unwrap();
        assert_eq!(r.user[1].node, "2");
        // Modificar sin renombrar funciona (fallo de Java corregido).
        r.modify_user("Mi tarjeta", "Mi tarjeta", "/usr/lib/a2.so").unwrap();
        assert_eq!(r.find("Mi tarjeta").unwrap().library, PathBuf::from("/usr/lib/a2.so"));
        assert_eq!(
            r.modify_user("Mi tarjeta", "Otra", "/usr/lib/a2.so").unwrap_err(),
            CardRegistrationError::DuplicateName
        );
        // Importación: biblioteca repetida se omite, nombre repetido se renombra.
        r.put_user(&[
            ("Otra".into(), "/usr/lib/c.so".into()),
            ("Dup".into(), "/usr/lib/b.so".into()),
        ]);
        assert_eq!(r.user.len(), 3);
        assert_eq!(r.user[2].name, "Otra-1");
        // Sistema prevalece con el mismo nombre en el mapa.
        r.put_system(&[("Sistema".into(), "/opt/s.so".into())]);
        r.system.push(RegisteredCard {
            name: "Otra".into(),
            library: "/opt/o.so".into(),
            node: "9".into(),
            scope: CardScope::System,
        });
        let map = r.all_map();
        assert_eq!(
            map.iter().find(|(n, _)| n == "Otra").unwrap().1,
            PathBuf::from("/opt/o.so")
        );
        assert_eq!(r.find("Otra").unwrap().scope, CardScope::System);
        assert_eq!(r.delete_user("Sistema").unwrap_err(), CardRegistrationError::SystemCard);
        r.delete_user("Otra-1").unwrap();
        assert_eq!(r.user.len(), 2);
        r.clear_user();
        assert!(r.user.is_empty() && r.system.len() == 2);
    }
}
