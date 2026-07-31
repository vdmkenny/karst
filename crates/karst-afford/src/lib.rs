//! KARST L11 Affordance.
//!
//! Machines were never in the web's design, so an agent today either scrapes pages
//! written for eyes or you wrap an API in a server in a side protocol. Every wrapper
//! carries its own authentication, its own documentation, and its own drift away from
//! what the service actually does.
//!
//! Here the operations live **inside the signed object**, next to the content, with
//! typed parameters and a declared price. One representation serves every reader:
//!
//! - a person sees a document (L10),
//! - an agent sees the operations it may invoke and what each costs *before* committing,
//! - a device sees the two operations it implements.
//!
//! There is no parallel API surface to drift, no separate key to issue, and no gate to
//! close, because **the capability you already hold is the credential** (L9). Closing
//! the API is not an available move: there is no API, only an object.
//!
//! Every invocation carries its delegation chain, so "which person authorised which
//! machine to do what, within what bound" is answerable from the receipt rather than
//! inferred from logs.

use std::collections::BTreeMap;

use karst_cap::{authorize, CapError, Capability, Caveat, Request};
use karst_doc::Value;
use karst_id::Address;
use karst_object::{Cid, Enc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamType {
    Text,
    Int,
    Bool,
    Money,
    Instant,
    Ref,
}

impl ParamType {
    fn accepts(&self, v: &Value) -> bool {
        matches!(
            (self, v),
            (ParamType::Text, Value::Text(_))
                | (ParamType::Int, Value::Int(_))
                | (ParamType::Bool, Value::Bool(_))
                | (ParamType::Money, Value::Money { .. })
                | (ParamType::Instant, Value::Instant(_))
                | (ParamType::Ref, Value::Ref(_))
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            ParamType::Text => "text",
            ParamType::Int => "int",
            ParamType::Bool => "bool",
            ParamType::Money => "money",
            ParamType::Instant => "instant",
            ParamType::Ref => "ref",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: ParamType,
    pub required: bool,
}

impl Param {
    pub fn required(name: &str, ty: ParamType) -> Self {
        Param {
            name: name.into(),
            ty,
            required: true,
        }
    }
    pub fn optional(name: &str, ty: ParamType) -> Self {
        Param {
            name: name.into(),
            ty,
            required: false,
        }
    }
}

/// One machine-invocable operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Affordance {
    pub name: String,
    pub summary: String,
    pub params: Vec<Param>,
    /// Declared cost in minor units. An agent knows the price before it commits, which
    /// is a field rather than a surprise invoice.
    pub price_minor: u64,
    pub currency: String,
}

/// An object that declares operations alongside whatever else it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub owner: Address,
    pub title: String,
    pub affordances: Vec<Affordance>,
}

impl Resource {
    pub fn cid(&self) -> Cid {
        let mut e = Enc::new();
        e.str("karst.resource.v1")
            .addr(&self.owner)
            .str(&self.title)
            .u64(self.affordances.len() as u64);
        for a in &self.affordances {
            e.str(&a.name)
                .str(&a.summary)
                .u64(a.price_minor)
                .str(&a.currency)
                .u64(a.params.len() as u64);
            for p in &a.params {
                e.str(&p.name).str(p.ty.name()).bool(p.required);
            }
        }
        e.hash()
    }

    pub fn find(&self, name: &str) -> Option<&Affordance> {
        self.affordances.iter().find(|a| a.name == name)
    }

    /// What an agent reads. No scraping, no guessing, no separate documentation that
    /// might be out of date, because this *is* the object.
    pub fn manifest_for_agent(&self) -> String {
        let mut out = format!("resource {} \"{}\"\n", self.cid().short(), self.title);
        out.push_str(&format!("owner {}\n", self.owner.short()));
        for a in &self.affordances {
            out.push_str(&format!(
                "  {} ({}.{:02} {}) : {}\n",
                a.name,
                a.price_minor / 100,
                a.price_minor % 100,
                a.currency,
                a.summary
            ));
            for p in &a.params {
                out.push_str(&format!(
                    "      {}{}: {}\n",
                    p.name,
                    if p.required { "" } else { "?" },
                    p.ty.name()
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvokeError {
    UnknownOperation(String),
    MissingParam(String),
    UnknownParam(String),
    WrongType {
        param: String,
        expected: &'static str,
    },
    /// The capability addresses a different object entirely.
    WrongResource,
    NotAuthorized(CapError),
}

impl core::fmt::Display for InvokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InvokeError::UnknownOperation(op) => write!(f, "no such operation '{op}'"),
            InvokeError::MissingParam(p) => write!(f, "missing required parameter '{p}'"),
            InvokeError::UnknownParam(p) => write!(f, "unexpected parameter '{p}'"),
            InvokeError::WrongType { param, expected } => {
                write!(f, "parameter '{param}' must be {expected}")
            }
            InvokeError::WrongResource => write!(f, "capability is for a different resource"),
            InvokeError::NotAuthorized(e) => write!(f, "not authorized: {e}"),
        }
    }
}

impl std::error::Error for InvokeError {}

/// Proof of what happened, and on whose authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub resource: Cid,
    pub operation: String,
    pub charged_minor: u64,
    pub currency: String,
    pub invoker: Address,
    /// Who authorised whom, from the resource owner down to the invoker.
    pub authority_chain: Vec<(Address, Address)>,
}

impl Receipt {
    pub fn describe(&self) -> String {
        let mut out = format!(
            "{} on {} charged {}.{:02} {}\n",
            self.operation,
            self.resource.short(),
            self.charged_minor / 100,
            self.charged_minor % 100,
            self.currency
        );
        out.push_str("  authority: ");
        let mut parts: Vec<String> = Vec::new();
        if let Some((first, _)) = self.authority_chain.first() {
            parts.push(first.short());
        }
        for (_, to) in &self.authority_chain {
            parts.push(to.short());
        }
        out.push_str(&parts.join(" -> "));
        out.push('\n');
        out
    }
}

pub struct Invocation<'a> {
    pub operation: &'a str,
    pub args: &'a BTreeMap<String, Value>,
    pub at: u64,
    pub use_index: u32,
}

impl Resource {
    /// Invoke an operation. Every check is local: the capability verifies offline
    /// against this object and the owner's address, with no directory and no callback
    /// to an authorization server.
    pub fn invoke(&self, cap: &Capability, inv: Invocation<'_>) -> Result<Receipt, InvokeError> {
        if cap.resource != self.cid() {
            return Err(InvokeError::WrongResource);
        }

        let effective = cap
            .verify(self.owner)
            .map_err(InvokeError::NotAuthorized)?;

        let aff = self
            .find(inv.operation)
            .ok_or_else(|| InvokeError::UnknownOperation(inv.operation.to_string()))?;

        for p in &aff.params {
            match inv.args.get(&p.name) {
                Some(v) => {
                    if !p.ty.accepts(v) {
                        return Err(InvokeError::WrongType {
                            param: p.name.clone(),
                            expected: p.ty.name(),
                        });
                    }
                }
                None if p.required => return Err(InvokeError::MissingParam(p.name.clone())),
                None => {}
            }
        }
        for k in inv.args.keys() {
            if !aff.params.iter().any(|p| &p.name == k) {
                return Err(InvokeError::UnknownParam(k.clone()));
            }
        }

        authorize(
            &effective,
            &Request {
                operation: aff.name.clone(),
                amount: aff.price_minor,
                at: inv.at,
                use_index: inv.use_index,
            },
        )
        .map_err(InvokeError::NotAuthorized)?;

        Ok(Receipt {
            resource: self.cid(),
            operation: aff.name.clone(),
            charged_minor: aff.price_minor,
            currency: aff.currency.clone(),
            invoker: cap.holder().unwrap_or(self.owner),
            authority_chain: cap
                .delegation_chain()
                .map_err(InvokeError::NotAuthorized)?,
        })
    }
}

/// Convenience: the caveat set you would hand an agent for one bounded task.
pub fn agent_budget(operation: &str, max_minor: u64, expires_at: u64, uses: u32) -> Vec<Caveat> {
    vec![
        Caveat::Operation(operation.to_string()),
        Caveat::MaxAmount(max_minor),
        Caveat::ExpiresAt(expires_at),
        Caveat::MaxUses(uses),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_id::Identity;

    fn clinic_resource(owner: Address) -> Resource {
        Resource {
            owner,
            title: "Nephrology clinic, appointments".into(),
            affordances: vec![
                Affordance {
                    name: "book".into(),
                    summary: "Reserve a consultation slot".into(),
                    params: vec![
                        Param::required("slot", ParamType::Instant),
                        Param::optional("note", ParamType::Text),
                    ],
                    price_minor: 4500,
                    currency: "EUR".into(),
                },
                Affordance {
                    name: "cancel".into(),
                    summary: "Release a reserved slot".into(),
                    params: vec![Param::required("booking", ParamType::Ref)],
                    price_minor: 0,
                    currency: "EUR".into(),
                },
            ],
        }
    }

    fn args(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn an_agent_can_invoke_within_its_delegated_budget() {
        let clinic = Identity::generate();
        let person = Identity::generate();
        let agent = Identity::generate();
        let res = clinic_resource(clinic.address());

        let root = Capability::issue(&clinic, res.cid(), person.address(), vec![]);
        let scoped = root
            .attenuate(
                &person,
                agent.address(),
                agent_budget("book", 5000, 100, 1),
            )
            .unwrap();

        let a = args(&[("slot", Value::Instant(42))]);
        let receipt = res
            .invoke(
                &scoped,
                Invocation {
                    operation: "book",
                    args: &a,
                    at: 10,
                    use_index: 0,
                },
            )
            .unwrap();

        assert_eq!(receipt.charged_minor, 4500);
        assert_eq!(receipt.invoker, agent.address());
        assert_eq!(receipt.authority_chain.len(), 2);
    }

    #[test]
    fn the_agent_cannot_reach_an_operation_it_was_not_given() {
        let clinic = Identity::generate();
        let person = Identity::generate();
        let agent = Identity::generate();
        let res = clinic_resource(clinic.address());

        let root = Capability::issue(&clinic, res.cid(), person.address(), vec![]);
        let scoped = root
            .attenuate(&person, agent.address(), agent_budget("book", 5000, 100, 1))
            .unwrap();

        let a = args(&[("booking", Value::Ref(res.cid()))]);
        let err = res
            .invoke(
                &scoped,
                Invocation {
                    operation: "cancel",
                    args: &a,
                    at: 10,
                    use_index: 0,
                },
            )
            .unwrap_err();
        assert!(matches!(err, InvokeError::NotAuthorized(_)));
    }

    #[test]
    fn a_price_above_the_spend_cap_is_refused() {
        let clinic = Identity::generate();
        let person = Identity::generate();
        let agent = Identity::generate();
        let res = clinic_resource(clinic.address());

        let root = Capability::issue(&clinic, res.cid(), person.address(), vec![]);
        // Budget of 10.00 against a 45.00 operation.
        let scoped = root
            .attenuate(&person, agent.address(), agent_budget("book", 1000, 100, 1))
            .unwrap();

        let a = args(&[("slot", Value::Instant(42))]);
        let err = res
            .invoke(
                &scoped,
                Invocation {
                    operation: "book",
                    args: &a,
                    at: 10,
                    use_index: 0,
                },
            )
            .unwrap_err();
        assert!(matches!(err, InvokeError::NotAuthorized(_)));
    }

    #[test]
    fn types_are_checked_so_an_agent_cannot_guess() {
        let clinic = Identity::generate();
        let person = Identity::generate();
        let res = clinic_resource(clinic.address());
        let cap = Capability::issue(&clinic, res.cid(), person.address(), vec![]);

        let wrong = args(&[("slot", Value::Text("next tuesday-ish".into()))]);
        assert_eq!(
            res.invoke(
                &cap,
                Invocation {
                    operation: "book",
                    args: &wrong,
                    at: 0,
                    use_index: 0
                }
            )
            .unwrap_err(),
            InvokeError::WrongType {
                param: "slot".into(),
                expected: "instant"
            }
        );

        let missing = args(&[]);
        assert_eq!(
            res.invoke(
                &cap,
                Invocation {
                    operation: "book",
                    args: &missing,
                    at: 0,
                    use_index: 0
                }
            )
            .unwrap_err(),
            InvokeError::MissingParam("slot".into())
        );
    }

    #[test]
    fn a_capability_for_another_object_does_not_work_here() {
        let clinic = Identity::generate();
        let person = Identity::generate();
        let res = clinic_resource(clinic.address());
        let other = Capability::issue(&clinic, Cid::of(b"something else"), person.address(), vec![]);

        let a = args(&[("slot", Value::Instant(1))]);
        assert_eq!(
            res.invoke(
                &other,
                Invocation {
                    operation: "book",
                    args: &a,
                    at: 0,
                    use_index: 0
                }
            )
            .unwrap_err(),
            InvokeError::WrongResource
        );
    }

    #[test]
    fn the_agent_manifest_states_prices_before_invocation() {
        let clinic = Identity::generate();
        let res = clinic_resource(clinic.address());
        let m = res.manifest_for_agent();
        assert!(m.contains("book (45.00 EUR)"));
        assert!(m.contains("slot: instant"));
        assert!(m.contains("note?: text"));
    }
}
