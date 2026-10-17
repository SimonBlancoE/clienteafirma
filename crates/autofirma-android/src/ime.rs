//! Teclado en pantalla (IME) para los campos de texto de egui.
//!
//! winit 0.30 no trata la entrada de texto de `GameTextInput` (el `InputConnection` de
//! GameActivity): mientras el teclado está activo, GameTextInput se queda con las pulsaciones
//! y con lo que escribe el teclado (`commitText`, `setComposingText`, borrados...) y solo
//! avisa del **estado completo** del editor (texto, selección y región de composición) con
//! `Listener.stateChanged`, que winit descarta. Por eso el puente es por estado, no por
//! eventos de tecla:
//!
//! - `MainActivity` sobrescribe `stateChanged`, `onEditorAction` y
//!   `onSoftwareKeyboardVisibilityChanged` y los pasa a Rust (`NativeBridge`), que los encola
//!   como [`PlatformEvent`](crate::bridge::PlatformEvent) y despierta a egui.
//! - Mientras un campo tiene el foco, el estado del teclado manda: antes de dibujar el campo
//!   se copian el texto y la selección del teclado al `String` del campo y al cursor de egui
//!   ([`ImeController::apply_incoming`]).
//! - Lo que cambia en egui (tocar para mover el cursor, teclas que GameTextInput no trata) se
//!   envía al teclado ([`ImeController::after_field`]), igual que el texto inicial cuando un
//!   campo gana el foco. El teclado se abre y se cierra desde aquí, en el hilo principal de
//!   Java (`imeShow`/`imeHide`), con el tipo de entrada del campo (contraseña sin
//!   sugerencias, numérico, multilínea...). eframe no lo hace: la interfaz quita la salida
//!   `ime` de egui en cada pasada.
//!
//! Los índices de Java son unidades UTF-16; aquí se trabaja con índices de carácter, que son
//! los de egui ([`ImeState::from_java`], [`ImeState::selection_utf16`]).

use std::sync::Arc;

use egui::text::{CCursor, CCursorRange};
use egui::{Context, Id, Response, TextEdit};
use tracing::{info, warn};

use crate::bridge::Platform;

/// Texto y selección del editor del teclado, con índices de carácter (`char`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImeState {
    pub text: String,
    /// Selección (inicio, fin); vacía es la posición del cursor.
    pub selection: (usize, usize),
    /// Región que el teclado está componiendo (palabra subrayada), si la hay.
    pub composing: Option<(usize, usize)>,
}

impl ImeState {
    pub fn new(text: impl Into<String>, selection: (usize, usize)) -> ImeState {
        let text = text.into();
        let len = text.chars().count();
        ImeState {
            selection: (selection.0.min(len), selection.1.min(len)),
            text,
            composing: None,
        }
    }

    /// Estado que envía Java (`gametextinput.State`): índices UTF-16, posiblemente fuera de
    /// rango o -1 (sin selección: el cursor va al final, como hace GameTextInput).
    pub fn from_java(text: String, sel_start: i32, sel_end: i32, comp_start: i32, comp_end: i32) -> ImeState {
        let len = text.chars().count();
        let sel = |i: i32| if i < 0 { len } else { utf16_to_char(&text, i as usize) };
        let selection = (sel(sel_start), sel(sel_end));
        let composing = (comp_start >= 0 && comp_end >= 0 && comp_start != comp_end).then(|| {
            (
                utf16_to_char(&text, comp_start as usize),
                utf16_to_char(&text, comp_end as usize),
            )
        });
        ImeState {
            text,
            selection,
            composing,
        }
    }

    /// Selección en índices UTF-16 para Java.
    pub fn selection_utf16(&self) -> (i32, i32) {
        (
            char_to_utf16(&self.text, self.selection.0) as i32,
            char_to_utf16(&self.text, self.selection.1) as i32,
        )
    }

    /// Selección ordenada (inicio ≤ fin).
    pub fn sorted_selection(&self) -> (usize, usize) {
        let (a, b) = self.selection;
        (a.min(b), a.max(b))
    }

    fn same_content(&self, other: &ImeState) -> bool {
        self.text == other.text && self.sorted_selection() == other.sorted_selection()
    }
}

/// Índice de carácter de un índice UTF-16 (acotado al texto; un índice en medio de un par
/// sustituto cuenta el carácter entero).
pub fn utf16_to_char(text: &str, index: usize) -> usize {
    let mut units = 0;
    for (i, c) in text.chars().enumerate() {
        if units >= index {
            return i;
        }
        units += c.len_utf16();
    }
    text.chars().count()
}

/// Índice UTF-16 de un índice de carácter (acotado al texto).
pub fn char_to_utf16(text: &str, index: usize) -> usize {
    text.chars().take(index).map(char::len_utf16).sum()
}

/// Tipo de campo: decide el teclado (`EditorInfo.inputType`) y qué caracteres admite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// Texto de una línea (motivo y lugar de la firma...).
    Text,
    /// Varias líneas sin autocorrección (lista de dominios).
    MultiLine,
    /// Contraseña (PKCS#12, PDF, PIN del DNIe): sin sugerencias ni aprendizaje.
    Password,
    /// Solo cifras (CAN del DNIe).
    Number,
    /// Solo cifras, ocultas.
    NumberPassword,
}

// Constantes de android.text.InputType y android.view.inputmethod.EditorInfo.
const TYPE_CLASS_TEXT: i32 = 0x1;
const TYPE_CLASS_NUMBER: i32 = 0x2;
const TYPE_TEXT_VARIATION_URI: i32 = 0x10;
const TYPE_TEXT_VARIATION_PASSWORD: i32 = 0x80;
const TYPE_NUMBER_VARIATION_PASSWORD: i32 = 0x10;
const TYPE_TEXT_FLAG_CAP_SENTENCES: i32 = 0x4000;
const TYPE_TEXT_FLAG_MULTI_LINE: i32 = 0x20000;
const TYPE_TEXT_FLAG_NO_SUGGESTIONS: i32 = 0x80000;
const IME_ACTION_NONE: i32 = 0x1;
const IME_ACTION_DONE: i32 = 0x6;
const IME_FLAG_NO_PERSONALIZED_LEARNING: i32 = 0x0100_0000;
const IME_FLAG_NO_FULLSCREEN: i32 = 0x0200_0000;
const IME_FLAG_NO_EXTRACT_UI: i32 = 0x1000_0000;
const IME_FLAG_NO_ENTER_ACTION: i32 = 0x4000_0000;

impl InputKind {
    /// `EditorInfo.inputType`.
    pub fn input_type(self) -> i32 {
        match self {
            InputKind::Text => TYPE_CLASS_TEXT | TYPE_TEXT_FLAG_CAP_SENTENCES,
            InputKind::MultiLine => {
                TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_URI | TYPE_TEXT_FLAG_MULTI_LINE | TYPE_TEXT_FLAG_NO_SUGGESTIONS
            }
            InputKind::Password => TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD | TYPE_TEXT_FLAG_NO_SUGGESTIONS,
            InputKind::Number => TYPE_CLASS_NUMBER,
            InputKind::NumberPassword => TYPE_CLASS_NUMBER | TYPE_NUMBER_VARIATION_PASSWORD,
        }
    }

    /// Acción de la tecla Intro (`EditorInfo.actionId`): «Hecho» en los campos de una línea.
    pub fn action_id(self) -> i32 {
        if self.is_multiline() {
            IME_ACTION_NONE
        } else {
            IME_ACTION_DONE
        }
    }

    /// `EditorInfo.imeOptions`: sin teclado a pantalla completa (taparía la interfaz en
    /// horizontal) y sin aprendizaje en las contraseñas.
    pub fn ime_options(self) -> i32 {
        let mut options = IME_FLAG_NO_FULLSCREEN | IME_FLAG_NO_EXTRACT_UI;
        if self.is_multiline() {
            options |= IME_FLAG_NO_ENTER_ACTION;
        } else {
            options |= IME_ACTION_DONE;
        }
        if self.is_secret() {
            options |= IME_FLAG_NO_PERSONALIZED_LEARNING;
        }
        options
    }

    pub fn is_multiline(self) -> bool {
        self == InputKind::MultiLine
    }

    /// El texto se muestra oculto.
    pub fn is_secret(self) -> bool {
        matches!(self, InputKind::Password | InputKind::NumberPassword)
    }

    /// El campo admite este carácter.
    pub fn accepts(self, c: char) -> bool {
        match self {
            InputKind::Number | InputKind::NumberPassword => c.is_ascii_digit(),
            InputKind::MultiLine => c != '\r',
            InputKind::Text | InputKind::Password => c != '\n' && c != '\r',
        }
    }
}

/// Restricciones de un campo: tipo y longitud máxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub kind: InputKind,
    pub max_chars: Option<usize>,
    /// Un campo secreto que se muestra (icono del ojo).
    pub revealed: bool,
}

impl FieldSpec {
    pub const fn new(kind: InputKind) -> FieldSpec {
        FieldSpec {
            kind,
            max_chars: None,
            revealed: false,
        }
    }

    /// Muestra el texto de un campo secreto.
    pub const fn revealed(mut self, revealed: bool) -> FieldSpec {
        self.revealed = revealed;
        self
    }

    pub const fn max_chars(mut self, max: usize) -> FieldSpec {
        self.max_chars = Some(max);
        self
    }

    /// Quita lo que el campo no admite y ajusta la selección a lo que queda.
    pub fn filter(&self, state: &ImeState) -> ImeState {
        let max = self.max_chars.unwrap_or(usize::MAX);
        let mut text = String::new();
        // Nuevo índice de cada índice antiguo (para mover la selección).
        let mut map = Vec::with_capacity(state.text.len() + 1);
        let mut kept = 0;
        for c in state.text.chars() {
            map.push(kept);
            if self.kind.accepts(c) && kept < max {
                text.push(c);
                kept += 1;
            }
        }
        map.push(kept);
        let remap = |i: usize| map[i.min(map.len() - 1)];
        let composing = state
            .composing
            .map(|(a, b)| (remap(a), remap(b)))
            .filter(|(a, b)| a != b);
        ImeState {
            text,
            selection: (remap(state.selection.0), remap(state.selection.1)),
            composing,
        }
    }
}

/// Lo que pasó en un campo durante la pasada.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FieldEvents {
    /// El texto ha cambiado.
    pub changed: bool,
    /// Se ha pulsado la tecla de acción del teclado («Hecho», Intro en una línea).
    pub submitted: bool,
}

/// Petición para abrir el teclado sobre un campo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImeRequest {
    pub kind: InputKind,
    pub state: ImeState,
}

/// Intervalo en el que se descartan acciones repetidas: GameTextInput avisa de la acción al
/// pulsar y al soltar Intro (`processKeyEvent` no mira si la tecla baja o sube).
const ACTION_DEBOUNCE_SECS: f64 = 0.4;
/// Tras abrir el teclado, los avisos de «teclado oculto» son del cierre anterior.
const VISIBILITY_GRACE_SECS: f64 = 0.6;

/// Sincroniza el teclado de Android con el campo de egui que tiene el foco.
pub struct ImeController {
    platform: Arc<dyn Platform>,
    /// Campo dueño del teclado.
    owner: Option<Id>,
    /// Último estado que conoce el teclado (el que envió o el que se le envió).
    known: Option<ImeState>,
    /// Estado nuevo del teclado que aún no se ha copiado al campo.
    incoming: Option<ImeState>,
    submit: bool,
    last_action: Option<f64>,
    claimed: bool,
    started_at: f64,
    keyboard_visible: bool,
    surrender: bool,
    scroll: bool,
}

impl ImeController {
    pub fn new(platform: Arc<dyn Platform>) -> ImeController {
        ImeController {
            platform,
            owner: None,
            known: None,
            incoming: None,
            submit: false,
            last_action: None,
            claimed: false,
            started_at: f64::NEG_INFINITY,
            keyboard_visible: false,
            surrender: false,
            scroll: false,
        }
    }

    /// Campo que tiene ahora el teclado.
    pub fn owner(&self) -> Option<Id> {
        self.owner
    }

    pub fn keyboard_visible(&self) -> bool {
        self.keyboard_visible
    }

    /// Estado nuevo del editor del teclado (Java `stateChanged`).
    pub fn on_state(&mut self, state: ImeState) {
        if self.owner.is_some() {
            self.incoming = Some(state);
        }
    }

    /// Tecla de acción del teclado (Java `onEditorAction`).
    pub fn on_editor_action(&mut self, now: f64) {
        if self.owner.is_none() || self.last_action.is_some_and(|t| now - t < ACTION_DEBOUNCE_SECS) {
            return;
        }
        self.last_action = Some(now);
        self.submit = true;
        info!("Tecla de acción del teclado");
    }

    /// El teclado se ha mostrado u ocultado (Java `onSoftwareKeyboardVisibilityChanged`).
    /// Si lo oculta el usuario (botón del teclado o Atrás), el campo pierde el foco para que
    /// tocarlo otra vez lo vuelva a abrir.
    pub fn on_visibility(&mut self, visible: bool, now: f64) {
        self.keyboard_visible = visible;
        if visible {
            self.scroll = true;
        } else if self.owner.is_some() && now - self.started_at > VISIBILITY_GRACE_SECS {
            self.surrender = true;
        }
    }

    /// La zona visible ha cambiado (teclado que aparece, giro): hay que volver a mostrar el
    /// campo con el foco.
    pub fn on_viewport_changed(&mut self) {
        if self.owner.is_some() {
            self.scroll = true;
        }
    }

    /// Al empezar cada pasada.
    pub fn begin_frame(&mut self) {
        self.claimed = false;
    }

    /// Al terminar cada pasada: si ningún campo tiene ya el foco (se ha tocado fuera, se ha
    /// cambiado de pantalla...), se cierra el teclado.
    pub fn end_frame(&mut self) {
        if !self.claimed && self.owner.take().is_some() {
            self.known = None;
            self.incoming = None;
            self.submit = false;
            info!("Teclado en pantalla cerrado");
            if let Err(e) = self.platform.ime_hide() {
                warn!("No se pudo cerrar el teclado: {e}");
            }
        }
    }

    /// Antes de dibujar el campo `id`: copia al texto y al cursor lo último que ha escrito el
    /// teclado. Devuelve si el texto ha cambiado.
    pub fn apply_incoming(&mut self, ctx: &Context, id: Id, text: &mut String, spec: FieldSpec) -> bool {
        if self.owner != Some(id) {
            return false;
        }
        let Some(state) = self.incoming.take() else {
            return false;
        };
        let filtered = spec.filter(&state);
        let changed = filtered.text != *text;
        if changed {
            text.clone_from(&filtered.text);
        }
        set_cursor(ctx, id, filtered.sorted_selection());
        if filtered.text == state.text {
            self.known = Some(state);
        } else {
            // Se ha quitado algo que el campo no admite: el teclado tiene que saberlo.
            self.send_update(filtered);
        }
        changed
    }

    /// Después de dibujar el campo `id` (respuesta y cursor del `TextEdit`).
    pub fn after_field(
        &mut self,
        ctx: &Context,
        id: Id,
        response: &Response,
        text: &str,
        cursor: Option<(usize, usize)>,
        spec: FieldSpec,
    ) -> FieldEvents {
        let mut events = FieldEvents::default();
        if !response.has_focus() {
            return events;
        }
        let now = ctx.input(|i| i.time);
        if self.surrender && self.owner == Some(id) {
            // El usuario ha cerrado el teclado: el campo suelta el foco (el teclado ya está
            // cerrado, no hay que pedirlo).
            self.surrender = false;
            self.owner = None;
            self.known = None;
            self.incoming = None;
            info!("Teclado cerrado por el usuario: el campo suelta el foco");
            ctx.memory_mut(|m| m.surrender_focus(id));
            return events;
        }
        self.claimed = true;
        let len = text.chars().count();
        let current = ImeState::new(text, cursor.unwrap_or((len, len)));
        if self.owner != Some(id) {
            self.owner = Some(id);
            self.surrender = false;
            self.incoming = None;
            self.submit = false;
            self.show(spec, current, now);
        } else if response.clicked() && !self.keyboard_visible && now - self.started_at > VISIBILITY_GRACE_SECS {
            // Campo con el foco tocado de nuevo tras cerrar el teclado.
            self.show(spec, current, now);
        } else if !self.known.as_ref().is_some_and(|k| k.same_content(&current)) {
            self.send_update(current);
        }
        if std::mem::take(&mut self.submit) {
            events.submitted = true;
        }
        if std::mem::take(&mut self.scroll) {
            response.scroll_to_me(Some(egui::Align::Center));
        }
        events
    }

    fn show(&mut self, spec: FieldSpec, state: ImeState, now: f64) {
        // Nunca se registra el texto (contraseñas, PIN, CAN).
        info!("Teclado en pantalla abierto ({:?})", spec.kind);
        self.started_at = now;
        self.scroll = true;
        let request = ImeRequest { kind: spec.kind, state };
        if let Err(e) = self.platform.ime_show(&request) {
            warn!("No se pudo abrir el teclado: {e}");
        }
        self.known = Some(request.state);
    }

    fn send_update(&mut self, state: ImeState) {
        if let Err(e) = self.platform.ime_update(&state) {
            warn!("No se pudo actualizar el teclado: {e}");
        }
        self.known = Some(state);
    }
}

/// Pone el cursor (o la selección) de un `TextEdit` de egui.
pub fn set_cursor(ctx: &Context, id: Id, (start, end): (usize, usize)) {
    let mut state = TextEdit::load_state(ctx, id).unwrap_or_default();
    state
        .cursor
        .set_char_range(Some(CCursorRange::two(CCursor::new(start), CCursor::new(end))));
    TextEdit::store_state(ctx, id, state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_utf16() {
        let text = "año 😀 b";
        // a ñ o ␠ 😀(2 unidades) ␠ b
        assert_eq!(char_to_utf16(text, 4), 4);
        assert_eq!(char_to_utf16(text, 5), 6);
        assert_eq!(char_to_utf16(text, 99), 8);
        assert_eq!(utf16_to_char(text, 6), 5);
        assert_eq!(utf16_to_char(text, 5), 5, "a mitad del par sustituto cuenta el emoji");
        assert_eq!(utf16_to_char(text, 99), 7);
        let s = ImeState::from_java(text.to_string(), 8, 6, -1, -1);
        assert_eq!(s.selection, (7, 5));
        assert_eq!(s.sorted_selection(), (5, 7));
        assert_eq!(s.selection_utf16(), (8, 6));
        assert_eq!(s.composing, None);
        let s = ImeState::from_java("hola".into(), -1, -1, 0, 4);
        assert_eq!(s.selection, (4, 4));
        assert_eq!(s.composing, Some((0, 4)));
    }

    #[test]
    fn filtros_de_campo() {
        let can = FieldSpec::new(InputKind::Number).max_chars(6);
        let f = can.filter(&ImeState::new("12a345678", (9, 9)));
        assert_eq!(f.text, "123456");
        assert_eq!(f.selection, (6, 6));
        let f = can.filter(&ImeState::new("1a2", (2, 2)));
        assert_eq!((f.text.as_str(), f.selection), ("12", (1, 1)));
        let line = FieldSpec::new(InputKind::Text).filter(&ImeState::new("a\nb", (3, 3)));
        assert_eq!(line.text, "ab");
        let multi = FieldSpec::new(InputKind::MultiLine).filter(&ImeState::new("a\nb", (3, 3)));
        assert_eq!(multi.text, "a\nb");
    }

    #[test]
    fn tipos_de_teclado() {
        assert_eq!(InputKind::Password.input_type(), 0x80081);
        assert_eq!(InputKind::Number.input_type(), 2);
        assert_eq!(InputKind::NumberPassword.input_type(), 0x12);
        assert_eq!(
            InputKind::MultiLine.input_type() & TYPE_TEXT_FLAG_MULTI_LINE,
            TYPE_TEXT_FLAG_MULTI_LINE
        );
        assert_eq!(InputKind::Text.action_id(), IME_ACTION_DONE);
        assert_eq!(
            InputKind::MultiLine.ime_options() & IME_FLAG_NO_ENTER_ACTION,
            IME_FLAG_NO_ENTER_ACTION
        );
        assert_ne!(InputKind::Password.ime_options() & IME_FLAG_NO_PERSONALIZED_LEARNING, 0);
        assert!(InputKind::NumberPassword.is_secret() && !InputKind::Number.is_secret());
    }
}
