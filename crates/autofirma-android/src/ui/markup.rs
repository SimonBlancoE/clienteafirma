//! Textos largos con un marcado mínimo (el de los catálogos): párrafos separados por una
//! línea en blanco, títulos (`## `), elementos de lista (`- `) y negrita (`**así**`).

use egui::text::LayoutJob;
use egui::{Color32, FontId, Label, Response, Ui};

use super::theme::size;
use super::widgets::{Cx, text_format};

/// Bloque del marcado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block<'a> {
    Heading(&'a str),
    Paragraph(&'a str),
    Bullet(&'a str),
}

/// Divide un texto en bloques.
pub fn blocks(text: &str) -> Vec<Block<'_>> {
    let mut out = Vec::new();
    for para in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
        // Inicio (en bytes) del párrafo normal que se está juntando.
        let mut plain: Option<usize> = None;
        let mut offset = 0;
        for line in para.split('\n') {
            let start = offset;
            offset += line.len() + 1;
            let special = line
                .strip_prefix("## ")
                .map(|h| Block::Heading(h.trim()))
                .or_else(|| line.strip_prefix("- ").map(|b| Block::Bullet(b.trim())));
            match special {
                Some(block) => {
                    if let Some(s) = plain.take() {
                        out.push(Block::Paragraph(para[s..start].trim()));
                    }
                    out.push(block);
                }
                None if plain.is_none() => plain = Some(start),
                None => {}
            }
        }
        if let Some(s) = plain {
            out.push(Block::Paragraph(para[s..].trim()));
        }
    }
    out
}

/// Texto con negritas (`**…**`) como `LayoutJob` que se ajusta al ancho.
pub fn rich_job(text: &str, font: FontId, bold: FontId, color: Color32) -> LayoutJob {
    let mut job = LayoutJob::default();
    for (i, part) in text.split("**").enumerate() {
        if part.is_empty() {
            continue;
        }
        let f = if i % 2 == 1 { bold.clone() } else { font.clone() };
        job.append(part, 0.0, text_format(f, color));
    }
    job
}

/// Párrafo con negritas.
pub fn paragraph(ui: &mut Ui, cx: &Cx, text: &str, color: Color32) -> Response {
    let job = rich_job(text, cx.font(size::BODY), cx.bold(size::BODY), color);
    ui.add(Label::new(job).wrap())
}

/// Dibuja un texto largo con su marcado.
pub fn show(ui: &mut Ui, cx: &Cx, text: &str) {
    let p = cx.p;
    for (i, block) in blocks(text).into_iter().enumerate() {
        match block {
            Block::Heading(h) => {
                if i > 0 {
                    ui.add_space(8.0);
                }
                ui.add(Label::new(egui::RichText::new(h).font(cx.bold(size::BODY + 2.0)).color(p.text)).wrap());
            }
            Block::Paragraph(t) => {
                paragraph(ui, cx, t, p.text);
            }
            Block::Bullet(t) => {
                ui.horizontal_top(|ui| {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("•").font(cx.bold(size::BODY)).color(p.primary));
                    ui.add_space(2.0);
                    paragraph(ui, cx, t, p.text);
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloques_del_marcado() {
        let text = "Intro **negrita**.\n\n## Título\n\n- uno\n- dos\nsigue\n\nFinal";
        assert_eq!(
            blocks(text),
            [
                Block::Paragraph("Intro **negrita**."),
                Block::Heading("Título"),
                Block::Bullet("uno"),
                Block::Bullet("dos"),
                Block::Paragraph("sigue"),
                Block::Paragraph("Final"),
            ]
        );
        let job = rich_job("a **b** c", FontId::default(), FontId::monospace(10.0), Color32::RED);
        assert_eq!(job.sections.len(), 3);
        assert_eq!(job.text, "a b c");
    }
}
