//! KARST L9 Authority.
//!
//! No ambient authority anywhere in the stack. Every right is an explicit capability
//! that names one permission, can be narrowed before it is passed on, and is never
//! transmitted to a party it was not addressed to.
//!
//! This is the design in *Macaroons: Cookies with Contextual Caveats for Decentralized
//! Authorization in the Cloud* (Birgisson et al., NDSS 2014), with one deliberate
//! change. Macaroons chain nested HMACs, which is compact and fast and requires the
//! verifier to share a secret with the issuer. That reintroduces a party who must be
//! consulted, which is error 03. Here the chain is Ed25519 signatures, so a capability
//! verifies against nothing but itself and the address of the resource owner: no
//! directory, no authority, no network.
//!
//! The property that matters for agents: **a delegation can only ever narrow.** You
//! hand an agent "may book one appointment under fifty euros this week" rather than
//! your account, and a chain link that tries to widen is rejected at verification even
//! though every signature in it is valid.

use core::fmt;

use karst_id::{Address, Identity, Peer, Signature};
use karst_object::{Cid, Enc};

/// A restriction. Absent means unrestricted, so a root grant with no caveats is full
/// authority over the resource and every delegation from it can only subtract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    /// May invoke only this named operation.
    Operation(String),
    /// May not spend more than this, in minor currency units, per invocation.
    MaxAmount(u64),
    /// Invalid at or after this logical time.
    ExpiresAt(u64),
    /// May be used at most this many times.
    MaxUses(u32),
}

impl Caveat {
    fn tag(&self) -> u8 {
        match self {
            Caveat::Operation(_) => 0,
            Caveat::MaxAmount(_) => 1,
            Caveat::ExpiresAt(_) => 2,
            Caveat::MaxUses(_) => 3,
        }
    }

    fn encode(&self, e: &mut Enc) {
        e.u8(self.tag());
        match self {
            Caveat::Operation(op) => {
                e.str(op);
            }
            Caveat::MaxAmount(v) => {
                e.u64(*v);
            }
            Caveat::ExpiresAt(v) => {
                e.u64(*v);
            }
            Caveat::MaxUses(v) => {
                e.u64(*v as u64);
            }
        }
    }

    /// True when `self` is at least as restrictive as `parent`.
    fn implies(&self, parent: &Caveat) -> bool {
        match (self, parent) {
            (Caveat::Operation(a), Caveat::Operation(b)) => a == b,
            (Caveat::MaxAmount(a), Caveat::MaxAmount(b)) => a <= b,
            (Caveat::ExpiresAt(a), Caveat::ExpiresAt(b)) => a <= b,
            (Caveat::MaxUses(a), Caveat::MaxUses(b)) => a <= b,
            _ => false,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Caveat::Operation(op) => format!("operation = {op}"),
            Caveat::MaxAmount(v) => format!("max {}.{:02} per use", v / 100, v % 100),
            Caveat::ExpiresAt(v) => format!("expires at t{v}"),
            Caveat::MaxUses(v) => format!("at most {v} use(s)"),
        }
    }
}

/// Merge two caveat sets, keeping the stricter of each kind. Adding a kind the parent
/// did not have is itself a narrowing.
fn tighten(base: &[Caveat], extra: &[Caveat]) -> Vec<Caveat> {
    let mut out: Vec<Caveat> = base.to_vec();
    for c in extra {
        match out.iter_mut().find(|e| e.tag() == c.tag()) {
            Some(existing) => {
                if c.implies(existing) {
                    *existing = c.clone();
                }
            }
            None => out.push(c.clone()),
        }
    }
    out.sort_by_key(|c| c.tag());
    out
}

/// Every caveat in `parent` must be implied by something in `child`.
fn narrows(child: &[Caveat], parent: &[Caveat]) -> bool {
    parent
        .iter()
        .all(|p| child.iter().any(|c| c.implies(p)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapError {
    EmptyChain,
    /// The first link was not signed by the resource owner.
    NotIssuedByOwner,
    /// A link was signed by someone other than the previous link's audience.
    BrokenDelegation,
    /// A link claimed authority its parent did not have.
    WidenedAuthority,
    BadSignature,
    MalformedKey,
    /// Invocation was refused by a caveat.
    Refused(String),
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapError::EmptyChain => write!(f, "capability has no grants"),
            CapError::NotIssuedByOwner => write!(f, "root grant not signed by resource owner"),
            CapError::BrokenDelegation => write!(f, "delegation chain is not continuous"),
            CapError::WidenedAuthority => {
                write!(f, "delegation claimed more authority than it was given")
            }
            CapError::BadSignature => write!(f, "grant signature did not verify"),
            CapError::MalformedKey => write!(f, "malformed issuer key"),
            CapError::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}

impl std::error::Error for CapError {}

/// One link in a delegation chain.
#[derive(Clone)]
pub struct Grant {
    /// The issuer's public key travels with the grant, so its address is derivable and
    /// the whole thing verifies with no lookup.
    pub issuer_key: [u8; 32],
    pub audience: Address,
    pub caveats: Vec<Caveat>,
    signature: [u8; 64],
}

impl Grant {
    fn signing_bytes(
        resource: &Cid,
        index: u64,
        prev_sig: &[u8; 64],
        issuer_key: &[u8; 32],
        audience: &Address,
        caveats: &[Caveat],
    ) -> Vec<u8> {
        let mut e = Enc::new();
        e.str("karst.grant.v1")
            .cid(resource)
            .u64(index)
            .bytes(prev_sig)
            .bytes(issuer_key)
            .addr(audience)
            .u64(caveats.len() as u64);
        for c in caveats {
            c.encode(&mut e);
        }
        e.finish()
    }

    pub fn issuer(&self) -> Result<Address, CapError> {
        Address::from_key_bytes(&self.issuer_key).map_err(|_| CapError::MalformedKey)
    }
}

/// A capability: a resource plus the chain of grants that leads to its current holder.
#[derive(Clone)]
pub struct Capability {
    pub resource: Cid,
    pub chain: Vec<Grant>,
}

impl Capability {
    /// The resource owner issues root authority to someone.
    pub fn issue(
        owner: &Identity,
        resource: Cid,
        audience: Address,
        caveats: Vec<Caveat>,
    ) -> Self {
        let mut caveats = caveats;
        caveats.sort_by_key(|c| c.tag());
        let zero = [0u8; 64];
        let msg = Grant::signing_bytes(
            &resource,
            0,
            &zero,
            &owner.key_bytes(),
            &audience,
            &caveats,
        );
        let sig = owner.sign(&msg);
        Capability {
            resource,
            chain: vec![Grant {
                issuer_key: owner.key_bytes(),
                audience,
                caveats,
                signature: sig.to_bytes(),
            }],
        }
    }

    /// Delegate onward, narrowing. `extra` can only subtract authority: this is the
    /// operation you use to hand an agent a bounded slice of what you hold.
    pub fn attenuate(
        &self,
        holder: &Identity,
        audience: Address,
        extra: Vec<Caveat>,
    ) -> Result<Capability, CapError> {
        let last = self.chain.last().ok_or(CapError::EmptyChain)?;
        if last.audience != holder.address() {
            return Err(CapError::BrokenDelegation);
        }
        let caveats = tighten(&last.caveats, &extra);
        Ok(self.append(holder, audience, caveats))
    }

    fn append(&self, holder: &Identity, audience: Address, caveats: Vec<Caveat>) -> Capability {
        let last = self.chain.last().expect("chain checked non-empty");
        let msg = Grant::signing_bytes(
            &self.resource,
            self.chain.len() as u64,
            &last.signature,
            &holder.key_bytes(),
            &audience,
            &caveats,
        );
        let sig = holder.sign(&msg);
        let mut chain = self.chain.clone();
        chain.push(Grant {
            issuer_key: holder.key_bytes(),
            audience,
            caveats,
            signature: sig.to_bytes(),
        });
        Capability {
            resource: self.resource,
            chain,
        }
    }

    /// Build a link with arbitrary caveats, correctly signed, ignoring the narrowing
    /// rule. Used only to demonstrate that verification catches a widening attempt whose
    /// signatures are all individually valid.
    #[doc(hidden)]
    pub fn forge_widened(
        &self,
        holder: &Identity,
        audience: Address,
        caveats: Vec<Caveat>,
    ) -> Capability {
        let mut caveats = caveats;
        caveats.sort_by_key(|c| c.tag());
        self.append(holder, audience, caveats)
    }

    /// Verify the whole chain offline and return the effective (tightest) caveats.
    pub fn verify(&self, owner: Address) -> Result<Vec<Caveat>, CapError> {
        if self.chain.is_empty() {
            return Err(CapError::EmptyChain);
        }
        if self.chain[0].issuer()? != owner {
            return Err(CapError::NotIssuedByOwner);
        }

        let mut prev_sig = [0u8; 64];
        let mut effective: Vec<Caveat> = Vec::new();

        for (i, grant) in self.chain.iter().enumerate() {
            if i > 0 {
                let prev = &self.chain[i - 1];
                if grant.issuer()? != prev.audience {
                    return Err(CapError::BrokenDelegation);
                }
                if !narrows(&grant.caveats, &prev.caveats) {
                    return Err(CapError::WidenedAuthority);
                }
            }

            let peer =
                Peer::from_key_bytes(&grant.issuer_key).map_err(|_| CapError::MalformedKey)?;
            let msg = Grant::signing_bytes(
                &self.resource,
                i as u64,
                &prev_sig,
                &grant.issuer_key,
                &grant.audience,
                &grant.caveats,
            );
            peer.verify(&msg, &Signature::from_bytes(&grant.signature))
                .map_err(|_| CapError::BadSignature)?;

            effective = tighten(&effective, &grant.caveats);
            prev_sig = grant.signature;
        }

        Ok(effective)
    }

    /// Who currently holds this capability.
    pub fn holder(&self) -> Option<Address> {
        self.chain.last().map(|g| g.audience)
    }

    /// The accountability trail: who authorised whom, in order.
    pub fn delegation_chain(&self) -> Result<Vec<(Address, Address)>, CapError> {
        self.chain
            .iter()
            .map(|g| Ok((g.issuer()?, g.audience)))
            .collect()
    }
}

/// A concrete attempt to use a capability.
pub struct Request {
    pub operation: String,
    pub amount: u64,
    pub at: u64,
    pub use_index: u32,
}

/// Check a request against effective caveats.
pub fn authorize(effective: &[Caveat], req: &Request) -> Result<(), CapError> {
    for c in effective {
        match c {
            Caveat::Operation(op) if *op != req.operation => {
                return Err(CapError::Refused(format!(
                    "capability permits '{op}', not '{}'",
                    req.operation
                )));
            }
            Caveat::MaxAmount(max) if req.amount > *max => {
                return Err(CapError::Refused(format!(
                    "amount {}.{:02} exceeds cap of {}.{:02}",
                    req.amount / 100,
                    req.amount % 100,
                    max / 100,
                    max % 100
                )));
            }
            Caveat::ExpiresAt(t) if req.at >= *t => {
                return Err(CapError::Refused(format!(
                    "expired at t{t}, now t{}",
                    req.at
                )));
            }
            Caveat::MaxUses(n) if req.use_index >= *n => {
                return Err(CapError::Refused(format!(
                    "already used {n} time(s), which was the limit"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_object::Cid;

    fn setup() -> (Identity, Identity, Identity, Cid) {
        (
            Identity::generate(), // clinic, owns the resource
            Identity::generate(), // person
            Identity::generate(), // their agent
            Cid::of(b"appointments"),
        )
    }

    #[test]
    fn root_grant_verifies_against_the_owner_alone() {
        let (clinic, person, _, res) = setup();
        let cap = Capability::issue(&clinic, res, person.address(), vec![]);
        assert!(cap.verify(clinic.address()).is_ok());
    }

    #[test]
    fn a_capability_from_the_wrong_owner_is_rejected() {
        let (clinic, person, _, res) = setup();
        let stranger = Identity::generate();
        let cap = Capability::issue(&stranger, res, person.address(), vec![]);
        assert_eq!(
            cap.verify(clinic.address()),
            Err(CapError::NotIssuedByOwner)
        );
    }

    #[test]
    fn attenuation_narrows_and_still_verifies() {
        let (clinic, person, agent, res) = setup();
        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(
                &person,
                agent.address(),
                vec![
                    Caveat::Operation("book".into()),
                    Caveat::MaxAmount(5000),
                    Caveat::MaxUses(1),
                ],
            )
            .unwrap();

        let eff = scoped.verify(clinic.address()).unwrap();
        assert!(eff.contains(&Caveat::Operation("book".into())));
        assert!(eff.contains(&Caveat::MaxAmount(5000)));
        assert_eq!(scoped.holder(), Some(agent.address()));
    }

    #[test]
    fn an_agent_cannot_widen_its_own_authority() {
        let (clinic, person, agent, res) = setup();
        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(
                &person,
                agent.address(),
                vec![Caveat::Operation("book".into()), Caveat::MaxAmount(5000)],
            )
            .unwrap();

        // The agent correctly signs a grant to itself claiming a bigger budget and a
        // different operation. Every signature is valid.
        let accomplice = Identity::generate();
        let forged = scoped.forge_widened(
            &agent,
            accomplice.address(),
            vec![
                Caveat::Operation("cancel".into()),
                Caveat::MaxAmount(1_000_000),
            ],
        );

        assert_eq!(
            forged.verify(clinic.address()),
            Err(CapError::WidenedAuthority),
            "valid signatures must not rescue an over-broad delegation"
        );
    }

    #[test]
    fn a_stolen_capability_is_still_bounded() {
        let (clinic, person, agent, res) = setup();
        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(
                &person,
                agent.address(),
                vec![Caveat::Operation("book".into()), Caveat::MaxAmount(5000)],
            )
            .unwrap();

        // Even fully compromised, the caveats travel with the credential.
        let eff = scoped.verify(clinic.address()).unwrap();
        let over = Request {
            operation: "book".into(),
            amount: 900_000,
            at: 0,
            use_index: 0,
        };
        assert!(matches!(
            authorize(&eff, &over),
            Err(CapError::Refused(_))
        ));
    }

    #[test]
    fn caveats_are_enforced_on_operation_amount_expiry_and_uses() {
        let eff = vec![
            Caveat::Operation("book".into()),
            Caveat::MaxAmount(5000),
            Caveat::ExpiresAt(100),
            Caveat::MaxUses(1),
        ];

        let ok = Request {
            operation: "book".into(),
            amount: 4500,
            at: 50,
            use_index: 0,
        };
        assert!(authorize(&eff, &ok).is_ok());

        for bad in [
            Request {
                operation: "cancel".into(),
                amount: 0,
                at: 50,
                use_index: 0,
            },
            Request {
                operation: "book".into(),
                amount: 20_000,
                at: 50,
                use_index: 0,
            },
            Request {
                operation: "book".into(),
                amount: 100,
                at: 100,
                use_index: 0,
            },
            Request {
                operation: "book".into(),
                amount: 100,
                at: 50,
                use_index: 1,
            },
        ] {
            assert!(authorize(&eff, &bad).is_err());
        }
    }

    #[test]
    fn the_chain_records_who_authorised_whom() {
        let (clinic, person, agent, res) = setup();
        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(1)])
            .unwrap();

        let trail = scoped.delegation_chain().unwrap();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0], (clinic.address(), person.address()));
        assert_eq!(trail[1], (person.address(), agent.address()));
    }

    #[test]
    fn tampering_with_a_caveat_breaks_the_signature() {
        let (clinic, person, _, res) = setup();
        let mut cap =
            Capability::issue(&clinic, res, person.address(), vec![Caveat::MaxAmount(100)]);
        cap.chain[0].caveats = vec![Caveat::MaxAmount(999_999)];
        assert_eq!(cap.verify(clinic.address()), Err(CapError::BadSignature));
    }
}
