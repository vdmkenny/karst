//! Authorship agency: human or machine, declared and where possible verified.
//!
//! **This does not detect bots.** Detection is an arms race the detector loses, it
//! punishes unusual writers with false positives, and it is a centralised opinion wearing
//! the costume of a fact. See `docs/07-authorship.md` for why every obvious approach fails.
//!
//! What this does instead: stop asking *what produced this* and ask *who is accountable
//! for it, and what was their relationship to producing it*. That question has a verifiable
//! answer, because an agent already has its own key (L2) and already acts on capabilities
//! attenuated from a person (L9).
//!
//! | Class | Verifiable |
//! |---|---|
//! | [`Agency::Direct`] | **No.** An unfalsifiable claim, permanently. |
//! | [`Agency::Assisted`] | No, but a person's key is on it. |
//! | [`Agency::Delegated`] | **Yes.** Carries the signed capability, verified in full. |
//! | [`Agency::Autonomous`] | **No.** Nothing proves the named operator runs the agent. |
//!
//! So you cannot falsely claim to be *authorised by* someone, and you can always falsely
//! claim to be a person. What the design buys is that the false claim is signed, permanent,
//! and retroactively attributable to everything else that key ever said, and that honest
//! declaration is *more useful* than lying: only a declared agent can present a delegation
//! chain, so only a declared agent can hold authority and act. A bot pretending to be human
//! is confined to speech.

use core::fmt;

use karst_cap::{CapError, Capability};
use karst_id::Address;
use karst_object::{Dec, DecodeError, Enc};

/// How an object came to be, as declared by whoever signed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Agency {
    /// The signing key composed this itself.
    ///
    /// Not verifiable and never will be. A bot may always publish under a fresh key and
    /// declare this. The consequence, rather than the prevention, is the point.
    Direct,

    /// A person composed this with machine assistance and signs it personally. They are
    /// accountable; the tool is named for the reader's benefit.
    Assisted { tool: String },

    /// An agent acted under a specific principal's authority.
    ///
    /// Carries the **actual signed capability**, not a summary of it. An earlier version
    /// stored only `(issuer, audience)` address pairs, which anyone could type out, so a
    /// post could claim any principal at all (issue #28). The evidence now travels with
    /// the claim.
    Delegated {
        /// The address the capability's root grant must be signed by. Verification fails
        /// unless the chain genuinely starts here.
        resource_owner: Address,
        capability: Capability,
    },

    /// An agent acting on its own standing, with no principal authorising this act.
    ///
    /// **Not verifiable.** There is no evidence in this variant that the named operator
    /// runs this agent, and the signer can name anyone. It is a claim, exactly like
    /// [`Agency::Direct`], and [`Agency::is_verifiable`] says so.
    Autonomous { operator: Address },
}

/// Coarse grouping, for policies that do not care about the detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    ClaimedHuman,
    HumanAssisted,
    MachineDelegated,
    Machine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestError {
    /// A `Delegated` claim carried no chain.
    EmptyChain,
    /// The chain does not begin at the declared principal.
    WrongPrincipal,
    /// The chain has a gap: some link's issuer is not the previous audience.
    BrokenChain,
    /// The chain does not end at the key that signed the object.
    NotTerminatedAtSigner,
    /// The underlying capability failed to verify.
    Capability(CapError),
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestError::EmptyChain => write!(f, "delegation claimed with no chain"),
            AttestError::WrongPrincipal => {
                write!(f, "chain does not begin at the declared principal")
            }
            AttestError::BrokenChain => write!(f, "delegation chain has a gap"),
            AttestError::NotTerminatedAtSigner => {
                write!(f, "chain does not end at the signing key")
            }
            AttestError::Capability(e) => write!(f, "capability invalid: {e}"),
        }
    }
}

impl std::error::Error for AttestError {}

impl Agency {
    /// Build a `Delegated` claim from a real capability, keeping the credential itself.
    pub fn from_capability(cap: &Capability, owner: Address) -> Result<Agency, AttestError> {
        cap.verify(owner).map_err(AttestError::Capability)?;
        Ok(Agency::Delegated {
            resource_owner: owner,
            capability: cap.clone(),
        })
    }

    /// The root authority behind a delegated act, if this is one.
    pub fn principal(&self) -> Option<Address> {
        match self {
            Agency::Delegated { capability, .. } => {
                capability.delegation_chain().ok()?.first().map(|l| l.0)
            }
            _ => None,
        }
    }

    /// The party that handed authority to the signer specifically. For a chain of
    /// clinic to person to agent, this is the person: the one who chose to delegate to
    /// this agent, rather than the clinic at the root who never met it.
    pub fn delegator(&self) -> Option<Address> {
        match self {
            Agency::Delegated { capability, .. } => {
                capability.delegation_chain().ok()?.last().map(|l| l.0)
            }
            _ => None,
        }
    }

    /// The full authority trail, for a reader who wants to see every hop.
    pub fn chain(&self) -> Vec<(Address, Address)> {
        match self {
            Agency::Delegated { capability, .. } => {
                capability.delegation_chain().unwrap_or_default()
            }
            _ => Vec::new(),
        }
    }

    pub fn class(&self) -> Class {
        match self {
            Agency::Direct => Class::ClaimedHuman,
            Agency::Assisted { .. } => Class::HumanAssisted,
            Agency::Delegated { .. } => Class::MachineDelegated,
            Agency::Autonomous { .. } => Class::Machine,
        }
    }

    pub fn is_machine(&self) -> bool {
        matches!(
            self,
            Agency::Delegated { .. } | Agency::Autonomous { .. }
        )
    }

    /// Whether this claim can be checked, as opposed to merely asserted.
    ///
    /// Only [`Agency::Delegated`] can. `Autonomous` used to be listed here, which was
    /// wrong: nothing in it proves the named operator runs the agent.
    pub fn is_verifiable(&self) -> bool {
        matches!(self, Agency::Delegated { .. })
    }

    /// Who carries responsibility.
    ///
    /// For a delegated act this is the **immediate delegator**, the party that chose to
    /// hand authority to this specific signer, rather than the root of the chain who may
    /// never have heard of it. Use [`Agency::principal`] and [`Agency::chain`] for the
    /// rest of the trail.
    pub fn accountable(&self, signer: Address) -> Address {
        match self {
            Agency::Direct | Agency::Assisted { .. } => signer,
            Agency::Delegated { .. } => self.delegator().unwrap_or(signer),
            // Nothing here is proven, so the only party we can actually hold to this is
            // whoever signed it.
            Agency::Autonomous { .. } => signer,
        }
    }

    /// Check what can be checked.
    ///
    /// `Direct` and `Assisted` always pass, because there is nothing in them to falsify.
    /// `Autonomous` also passes for the same reason, and reports itself unverifiable.
    ///
    /// `Delegated` is checked properly: every grant signature in the capability, chain
    /// continuity, attenuation at each step, that the root grant came from the declared
    /// resource owner, and that the final audience is the key that signed this object.
    pub fn verify(&self, signer: Address) -> Result<(), AttestError> {
        match self {
            Agency::Direct | Agency::Assisted { .. } | Agency::Autonomous { .. } => Ok(()),
            Agency::Delegated {
                resource_owner,
                capability,
            } => {
                // This does the real work: signatures, continuity, and that authority
                // only ever narrowed.
                capability
                    .verify(*resource_owner)
                    .map_err(AttestError::Capability)?;

                match capability.holder() {
                    None => Err(AttestError::EmptyChain),
                    Some(h) if h != signer => Err(AttestError::NotTerminatedAtSigner),
                    Some(_) => Ok(()),
                }
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Agency::Direct => "human (claimed, unverifiable)".into(),
            Agency::Assisted { tool } => format!("human, assisted by {tool}"),
            Agency::Delegated { .. } => match self.delegator() {
                Some(d) => format!(
                    "agent for {} (chain of {}, signatures verified)",
                    d.short(),
                    self.chain().len()
                ),
                None => "agent (malformed chain)".into(),
            },
            Agency::Autonomous { operator } => {
                format!("autonomous agent, claims operator {} (unverified)", operator.short())
            }
        }
    }

    pub fn encode(&self, e: &mut Enc) {
        match self {
            Agency::Direct => {
                e.u8(0);
            }
            Agency::Assisted { tool } => {
                e.u8(1).str(tool);
            }
            Agency::Delegated {
                resource_owner,
                capability,
            } => {
                e.u8(2).addr(resource_owner);
                capability.encode(e);
            }
            Agency::Autonomous { operator } => {
                e.u8(3).addr(operator);
            }
        }
    }

    pub fn decode(d: &mut Dec<'_>) -> Result<Agency, DecodeError> {
        match d.u8()? {
            0 => Ok(Agency::Direct),
            1 => Ok(Agency::Assisted { tool: d.str()? }),
            2 => {
                let resource_owner = d.addr()?;
                let capability = Capability::decode(d)?;
                Ok(Agency::Delegated {
                    resource_owner,
                    capability,
                })
            }
            3 => Ok(Agency::Autonomous {
                operator: d.addr()?,
            }),
            t => Err(DecodeError::UnknownTag(t)),
        }
    }
}

/// What a board or index will accept. Policy lives here rather than in the protocol,
/// because a rule about who may speak is an opinion, and opinions belong in subscribable
/// views. Three people reading the same posts through different policies see three
/// different boards and all three are correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Take everything, label the machines.
    Everything,
    /// Only content whose author claims to have written it themselves.
    HumanClaimedOnly,
    /// Machines are welcome if a person is answerable for them.
    ExcludeAutonomous,
    /// An agent to agent venue.
    MachineOnly,
}

impl Policy {
    pub fn admits(&self, a: &Agency) -> bool {
        match self {
            Policy::Everything => true,
            Policy::HumanClaimedOnly => !a.is_machine(),
            Policy::ExcludeAutonomous => !matches!(a, Agency::Autonomous { .. }),
            Policy::MachineOnly => a.is_machine(),
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Policy::Everything => "everything, machines labelled",
            Policy::HumanClaimedOnly => "human-claimed authorship only",
            Policy::ExcludeAutonomous => "no autonomous agents",
            Policy::MachineOnly => "agents only",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_cap::{Capability, Caveat};
    use karst_id::Identity;
    use karst_object::Cid;

    fn delegated() -> (Identity, Identity, Identity, Agency) {
        let owner = Identity::generate();
        let person = Identity::generate();
        let agent = Identity::generate();
        let root = Capability::issue(&owner, Cid::of(b"resource"), person.address(), vec![]);
        let scoped = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(1)])
            .unwrap();
        let a = Agency::from_capability(&scoped, owner.address()).unwrap();
        (owner, person, agent, a)
    }

    #[test]
    fn a_delegated_claim_verifies_to_its_principal() {
        let (owner, person, agent, a) = delegated();
        assert!(a.verify(agent.address()).is_ok());
        assert!(a.is_machine());
        assert!(a.is_verifiable());
        assert_eq!(a.principal(), Some(owner.address()));
        // The person chose to delegate to this agent, so the person answers for it.
        assert_eq!(a.accountable(agent.address()), person.address());
        assert_eq!(a.chain().len(), 2);
    }

    /// Regression for issue #28, reported by @matthiasantierens.
    ///
    /// `Delegated` used to hold only `(issuer, audience)` address pairs, and `verify` only
    /// checked that they lined up. An attacker could therefore name any victim as
    /// principal and have the post attributed to them. The variant now carries the signed
    /// capability, so a claim with no grant behind it has nothing to present.
    #[test]
    fn an_attacker_cannot_name_a_victim_as_their_principal() {
        let victim = Identity::generate();
        let attacker = Identity::generate();

        // The exact attack from the report: claim the victim authorised you. There is now
        // no way to express it without a capability the victim actually signed, and the
        // attacker cannot produce one.
        let forged_root = Capability::issue(&attacker, Cid::of(b"resource"), attacker.address(), vec![]);
        let forged = Agency::Delegated {
            resource_owner: victim.address(),
            capability: forged_root,
        };

        assert!(
            forged.verify(attacker.address()).is_err(),
            "a chain not rooted at the victim must be rejected"
        );
    }

    #[test]
    fn a_chain_that_does_not_reach_the_signer_is_caught() {
        let (_owner, _person, _agent, a) = delegated();
        let someone_else = Identity::generate();
        assert_eq!(
            a.verify(someone_else.address()),
            Err(AttestError::NotTerminatedAtSigner)
        );
    }

    #[test]
    fn tampering_with_the_carried_capability_breaks_it() {
        let (owner, person, agent, _) = delegated();
        let root = Capability::issue(&owner, Cid::of(b"resource"), person.address(), vec![]);
        let mut scoped = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxAmount(100)])
            .unwrap();
        // Widen the budget after the fact.
        scoped.chain[1].caveats = vec![Caveat::MaxAmount(999_999)];

        let a = Agency::Delegated {
            resource_owner: owner.address(),
            capability: scoped,
        };
        assert!(a.verify(agent.address()).is_err());
    }

    #[test]
    fn claiming_to_be_human_always_passes_and_that_is_the_known_limit() {
        let bot = Identity::generate();
        assert!(Agency::Direct.verify(bot.address()).is_ok());
        assert!(!Agency::Direct.is_verifiable());
        assert!(!Agency::Direct.is_machine());
    }

    #[test]
    fn autonomous_no_longer_claims_to_be_verifiable() {
        let bot = Identity::generate();
        let victim = Identity::generate();
        let a = Agency::Autonomous { operator: victim.address() };

        assert!(a.is_machine());
        assert!(!a.is_verifiable(), "nothing proves the operator relationship");
        // And it does not launder responsibility onto the named operator.
        assert_eq!(a.accountable(bot.address()), bot.address());
        assert!(a.describe().contains("unverified"));
    }

    #[test]
    fn round_trips_through_the_canonical_encoding() {
        let (_owner, _person, agent, deleg) = delegated();
        let q = Identity::generate().address();
        for a in [
            Agency::Direct,
            Agency::Assisted { tool: "an editor".into() },
            deleg,
            Agency::Autonomous { operator: q },
        ] {
            let mut e = Enc::new();
            a.encode(&mut e);
            let bytes = e.finish();
            let mut d = Dec::new(&bytes);
            let back = Agency::decode(&mut d).unwrap();
            d.end().unwrap();
            assert_eq!(a.class(), back.class());
            assert_eq!(a.describe(), back.describe());
            // Crucially, a decoded delegation still verifies, so the evidence survived.
            if back.is_verifiable() {
                assert!(back.verify(agent.address()).is_ok());
            }
        }
    }

    #[test]
    fn policies_disagree_about_the_same_content_and_all_are_correct() {
        let op = Identity::generate().address();
        let human = Agency::Direct;
        let bot = Agency::Autonomous { operator: op };
        let (_o, _p, _a, deleg) = delegated();

        assert!(Policy::HumanClaimedOnly.admits(&human));
        assert!(!Policy::HumanClaimedOnly.admits(&bot));
        assert!(!Policy::HumanClaimedOnly.admits(&deleg));

        assert!(Policy::ExcludeAutonomous.admits(&deleg));
        assert!(!Policy::ExcludeAutonomous.admits(&bot));

        assert!(Policy::MachineOnly.admits(&bot));
        assert!(!Policy::MachineOnly.admits(&human));

        assert!(Policy::Everything.admits(&bot));
        assert!(Policy::Everything.admits(&human));
    }
}
