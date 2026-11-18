//! How a field of a pattern is compared: with `==` to a value, or with a
//! matcher. Matchers do what rules do ([`ne`], [`gt`], [`lt`], [`ge`],
//! [`le`], [`starts_with`], [`ends_with`], [`contains`]), and [`satisfies`]
//! does anything else.
//!
//! ```ignore
//! Exec::of(pid).filename("/usr/bin/true").argc(gt(1)).argv(contains("-v"))
//! ```

use std::fmt::Debug;

use next_core::payload::{Argv, FileFlags, Text};

use crate::expect::Field;

pub struct Matcher<T> {
    /// What the field is expected to be, for reports: `> 1`.
    expected: String,
    test: Box<dyn Fn(&T) -> bool>,
}

impl<T> Matcher<T> {
    fn new(expected: String, test: impl Fn(&T) -> bool + 'static) -> Self {
        Self {
            expected,
            test: Box::new(test),
        }
    }
}

/// What a setter takes: a value, compared with `==`, or a matcher.
pub trait IntoMatcher<T> {
    fn into_matcher(self) -> Matcher<T>;
}

impl<T: PartialEq + Debug + 'static> IntoMatcher<T> for T {
    fn into_matcher(self) -> Matcher<T> {
        Matcher::new(format!("{self:?}"), move |found| *found == self)
    }
}

impl<T> IntoMatcher<T> for Matcher<T> {
    fn into_matcher(self) -> Matcher<T> {
        self
    }
}

impl IntoMatcher<Option<Text>> for &str {
    fn into_matcher(self) -> Matcher<Option<Text>> {
        Value::<Option<Text>>::into_value(self).into_matcher()
    }
}

impl IntoMatcher<Option<Text>> for String {
    fn into_matcher(self) -> Matcher<Option<Text>> {
        Value::<Option<Text>>::into_value(self).into_matcher()
    }
}

/// What a matcher compares to: a value, or, for a text, a string, read in
/// full.
pub trait Value<T> {
    fn into_value(self) -> T;
}

impl<T> Value<T> for T {
    fn into_value(self) -> T {
        self
    }
}

impl Value<Option<Text>> for &str {
    fn into_value(self) -> Option<Text> {
        self.to_owned().into_value()
    }
}

impl Value<Option<Text>> for String {
    fn into_value(self) -> Option<Text> {
        Some(Text {
            value: self,
            truncated: false,
        })
    }
}

pub fn ne<T: PartialEq + Debug + 'static>(value: impl Value<T>) -> Matcher<T> {
    let value = value.into_value();
    Matcher::new(format!("not {value:?}"), move |found| *found != value)
}

pub fn gt<T: PartialOrd + Debug + 'static>(value: T) -> Matcher<T> {
    Matcher::new(format!("> {value:?}"), move |found| *found > value)
}

pub fn lt<T: PartialOrd + Debug + 'static>(value: T) -> Matcher<T> {
    Matcher::new(format!("< {value:?}"), move |found| *found < value)
}

pub fn ge<T: PartialOrd + Debug + 'static>(value: T) -> Matcher<T> {
    Matcher::new(format!(">= {value:?}"), move |found| *found >= value)
}

pub fn le<T: PartialOrd + Debug + 'static>(value: T) -> Matcher<T> {
    Matcher::new(format!("<= {value:?}"), move |found| *found <= value)
}

pub fn starts_with<T: AsText>(prefix: &str) -> Matcher<T> {
    let prefix = prefix.to_owned();
    Matcher::new(format!("starting with {prefix:?}"), move |found: &T| {
        found
            .as_text()
            .is_some_and(|text| text.starts_with(&prefix))
    })
}

pub fn ends_with<T: AsText>(suffix: &str) -> Matcher<T> {
    let suffix = suffix.to_owned();
    Matcher::new(format!("ending with {suffix:?}"), move |found: &T| {
        found.as_text().is_some_and(|text| text.ends_with(&suffix))
    })
}

pub fn contains<T: Contains>(item: impl Into<T::Item>) -> Matcher<T> {
    let item = item.into();
    Matcher::new(format!("containing {item:?}"), move |found: &T| {
        found.contains(&item)
    })
}

/// `expected` says what `test` accepts, for reports.
pub fn satisfies<T>(expected: &str, test: impl Fn(&T) -> bool + 'static) -> Matcher<T> {
    Matcher::new(expected.to_owned(), test)
}

/// Fields [`starts_with`] and [`ends_with`] compare.
pub trait AsText {
    /// `None` when there is no text.
    fn as_text(&self) -> Option<&str>;
}

impl AsText for Option<Text> {
    fn as_text(&self) -> Option<&str> {
        self.as_ref().map(|text| text.value.as_str())
    }
}

impl AsText for String {
    fn as_text(&self) -> Option<&str> {
        Some(self)
    }
}

impl AsText for &'static str {
    fn as_text(&self) -> Option<&str> {
        Some(self)
    }
}

/// Fields [`contains`] compares, as rules do.
pub trait Contains {
    type Item: Debug + 'static;

    fn contains(&self, item: &Self::Item) -> bool;
}

/// A substring.
impl Contains for Option<Text> {
    type Item = String;

    fn contains(&self, item: &String) -> bool {
        self.as_text()
            .is_some_and(|text| text.contains(item.as_str()))
    }
}

/// A substring.
impl Contains for String {
    type Item = String;

    fn contains(&self, item: &String) -> bool {
        self.as_str().contains(item.as_str())
    }
}

/// An argument.
impl Contains for Option<Argv> {
    type Item = String;

    fn contains(&self, item: &String) -> bool {
        self.as_ref().is_some_and(|argv| argv.args.contains(item))
    }
}

/// The access mode, or one of the other flags.
impl Contains for FileFlags {
    type Item = FileFlags;

    fn contains(&self, item: &FileFlags) -> bool {
        FileFlags::contains(self, item)
    }
}

/// An element.
impl<T: PartialEq + Debug + 'static> Contains for Vec<T> {
    type Item = T;

    fn contains(&self, item: &T) -> bool {
        self.as_slice().contains(item)
    }
}

/// Adds the field `name` to `fields`, if the pattern sets it.
#[doc(hidden)]
pub fn check<T: Debug>(
    fields: &mut Vec<Field>,
    name: &'static str,
    matcher: &Option<Matcher<T>>,
    found: &T,
) {
    if let Some(matcher) = matcher {
        fields.push(Field {
            name,
            mismatch: (!(matcher.test)(found))
                .then(|| format!("expected {}, found {found:?}", matcher.expected)),
        });
    }
}
