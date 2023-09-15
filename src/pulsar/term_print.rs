use anyhow::Result;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use engine_api::dto::{ConfigKV, ModuleConfigKVs};

use pulsar_core::pdk::{ModuleOverview, ModuleStatus};

pub struct TermPrinted;

pub trait TermPrintable {
    fn term_print(&self) -> Result<TermPrinted>;
}

impl TermPrintable for String {
    fn term_print(&self) -> Result<TermPrinted> {
        println!("{self}");
        Ok(TermPrinted)
    }
}

impl TermPrintable for Vec<ModuleOverview> {
    fn term_print(&self) -> Result<TermPrinted> {
        let sorted = {
            let mut tmp = self.clone();
            tmp.sort_by(|a, b| a.name.cmp(&b.name));
            tmp
        };

        let mut table = table();

        table.set_header(vec![
            Cell::new("MODULE").add_attribute(Attribute::Bold),
            Cell::new("VERSION").add_attribute(Attribute::Bold),
            Cell::new("STATUS").add_attribute(Attribute::Bold),
        ]);

        for module in sorted {
            let status_color = match module.status {
                ModuleStatus::Created => Color::White,
                ModuleStatus::Running(ref warnings) if warnings.is_empty() => Color::Green,
                ModuleStatus::Running(_) => Color::Yellow,
                ModuleStatus::Failed(_) => Color::Red,
                ModuleStatus::Stopped => Color::Yellow,
            };

            let status = format!("{}", module.status);

            table.add_row(vec![
                Cell::new(module.name)
                    .fg(Color::Cyan)
                    .add_attribute(Attribute::Bold),
                Cell::new(module.version),
                Cell::new(status)
                    .fg(status_color)
                    .add_attribute(Attribute::Bold),
            ]);
        }

        println!("{table}");
        Ok(TermPrinted)
    }
}

impl TermPrintable for Vec<ConfigKV> {
    fn term_print(&self) -> Result<TermPrinted> {
        let sorted = {
            let mut tmp = self.clone();
            tmp.sort_by(|a, b| a.key.cmp(&b.key));
            tmp
        };

        let mut table = table();

        table.set_header(vec![
            Cell::new("KEY").add_attribute(Attribute::Bold),
            Cell::new("VALUE").add_attribute(Attribute::Bold),
        ]);

        for cfg in sorted {
            table.add_row(vec![
                Cell::new(cfg.key)
                    .fg(Color::Cyan)
                    .add_attribute(Attribute::Bold),
                Cell::new(cfg.value),
            ]);
        }

        println!("{table}");
        Ok(TermPrinted)
    }
}

impl TermPrintable for Vec<ModuleConfigKVs> {
    fn term_print(&self) -> Result<TermPrinted> {
        let sorted = {
            let mut tmp = self.clone();
            tmp.sort_by(|a, b| a.module.cmp(&b.module));
            tmp
        };

        let mut table = table();

        table.set_header(vec![
            Cell::new("MODULE").add_attribute(Attribute::Bold),
            Cell::new("KEY").add_attribute(Attribute::Bold),
            Cell::new("VALUE").add_attribute(Attribute::Bold),
        ]);

        for mut cfgs in sorted.into_iter() {
            cfgs.config.sort_by(|a, b| a.key.cmp(&b.key));

            for cfg in cfgs.config {
                table.add_row(vec![
                    Cell::new(&cfgs.module)
                        .fg(Color::Blue)
                        .add_attribute(Attribute::Bold),
                    Cell::new(cfg.key)
                        .fg(Color::Cyan)
                        .add_attribute(Attribute::Bold),
                    Cell::new(cfg.value),
                ]);
            }
        }

        println!("{table}");
        Ok(TermPrinted)
    }
}

fn table() -> Table {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);

    table
}
