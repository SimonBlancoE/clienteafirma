//! Tareas en segundo plano que informan a la interfaz.

use std::sync::mpsc::{Receiver, TryRecvError, channel};

use eframe::egui;

/// Mensajes de una tarea: progreso intermedio y resultado final.
pub enum JobEvent<P, R> {
    Progress(P),
    Done(R),
}

/// Tarea en curso; la interfaz la consulta en cada fotograma.
pub struct Job<P, R> {
    rx: Receiver<JobEvent<P, R>>,
    finished: bool,
}

impl<P: Send + 'static, R: Send + 'static> Job<P, R> {
    /// Lanza `f` en un hilo. `f` recibe una función para notificar progreso.
    pub fn spawn(ctx: &egui::Context, name: &str, f: impl FnOnce(&dyn Fn(P)) -> R + Send + 'static) -> Self {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        let builder = std::thread::Builder::new().name(name.to_string());
        let _ = builder.spawn(move || {
            let tx_p = tx.clone();
            let ctx_p = ctx.clone();
            let notify = move |p: P| {
                let _ = tx_p.send(JobEvent::Progress(p));
                ctx_p.request_repaint();
            };
            let r = f(&notify);
            let _ = tx.send(JobEvent::Done(r));
            ctx.request_repaint();
        });
        Job { rx, finished: false }
    }

    /// Devuelve los eventos pendientes.
    pub fn poll(&mut self) -> Vec<JobEvent<P, R>> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(ev) => {
                    if matches!(ev, JobEvent::Done(_)) {
                        self.finished = true;
                    }
                    out.push(ev);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.finished = true;
                    break;
                }
            }
        }
        out
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

