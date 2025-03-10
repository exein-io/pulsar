use std::{collections::HashMap, time::SystemTime};

use anyhow::Context;
use chrono::{DateTime, Utc};
use gethostname::gethostname;
use pulsar_core::pdk::Payload;

const EMAIL_TEMPLATE: &str = include_str!("./template.html.leon");

pub struct Template(leon::Template<'static>);

impl Template {
    pub fn new() -> Result<Self, anyhow::Error> {
        leon::Template::parse(EMAIL_TEMPLATE)
            .context("error parsing the email template")
            .map(Self)
    }

    pub fn render(
        &self,
        timestamp: &SystemTime,
        source: &str,
        image: &str,
        description: &str,
        payload: &Payload,
    ) -> Result<String, anyhow::Error> {
        let hostname = gethostname();
        let datetime: DateTime<Utc> = <DateTime<Utc>>::from(*timestamp);

        let mut values = HashMap::new();

        values.insert("hostname", hostname.to_string_lossy());
        values.insert(
            "timestamp",
            datetime.format("%d/%m/%Y %T").to_string().into(),
        );
        values.insert("threat_source", source.into());
        values.insert("image", image.into());
        values.insert("event_info", payload.to_string().into());
        values.insert("threat_info", description.into());

        self.0
            .render(&values)
            .context("error filling the email template")
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pulsar_core::pdk::Payload;

    use super::Template;

    #[test]
    fn email_template_parse() {
        assert!(Template::new().is_ok())
    }

    #[test]
    fn email_template_fill() {
        let template = Template::new().unwrap();

        let payload = Payload::FileDeleted {
            filename: "/etc/shadow".to_string(),
        };

        assert!(
            template
                .render(
                    &SystemTime::now(),
                    "super-detector",
                    "curl",
                    "accessed sensitive file",
                    &payload,
                )
                .is_ok()
        )
    }
}
