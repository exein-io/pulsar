# Validatron

Validatron is a type checked condition framework to build complex rules for complex types. it's the base of the Pulsar's `rule-engine` module.

### Validations

It's possible to validate rules against a complex type to check if a fields exists on that type and if comparing value matches the relative field type.

It includes macros to generate implementations of the required traits.

### Closures for code generation

For the runtime it compiles rules using closures to generate code. It walks AST nodes and generates closures recursively [^1].

## Status

Now have the base functionalities needed by Pulsar. There are some limitations and a complete DSL is work in progess.

## Contributing

If you're interested in contributing to Validatron: thank you!

We have a [contributing guide](../CONTRIBUTING.md) which will help you getting involved in the Validatron project.

## Building Validatron

Validatron uses a [conventional Cargo build process](https://doc.rust-lang.org/cargo/guide/working-on-an-existing-project.html). 

Validatron uses a [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html), so for some cargo commands, such as `cargo test`, the `--all` is needed to tell cargo to visit all of the crates.


[^1]: Marc Feeley, Guy Lapalme, [Using closures for code generation](https://www.sciencedirect.com/science/article/abs/pii/0096055187900129)