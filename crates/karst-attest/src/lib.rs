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
//! | [`Agency::Delegated`] | **Yes.** The chain must verify to the named principal. |
//! | [`Agency::Autonomous`] | **Yes**, as to which operator runs it. |
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

    /// An agent acted under a specific principal's authority. The chain is checkable.
    Delegated {
        principal: Address,
        /// `(issuer, audience)` pairs, from the principal down to the signer.
        chain: Vec<(Address, Address)>,
    },

    /// An agent acting on its own standing, with no principal authorising this act.
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
    /// Derive a verified `Delegated` claim from a real capability. This is the honest
    /// construction: the chain is not asserted, it is taken from a credential that
    /// already verified against the resource owner.
    pub fn from_capability(cap: &Capability, owner: Address) -> Result<Agency, AttestError> {
        cap.verify(owner).map_err(AttestError::Capability)?;
        let chain = cap
            .delegation_chain()
            .map_err(AttestError::Capability)?;
        let principal = chain.first().ok_or(AttestError::EmptyChain)?.0;
        Ok(Agency::Delegated { principal, chain })
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

    /// Whether this claim can be checked at all, as opposed to merely asserted.
    pub fn is_verifiable(&self) -> bool {
        matches!(
            self,
            Agency::Delegated { .. } | Agency::Autonomous { .. }
        )
    }

    /// Who carries responsibility. For a delegated act that is the principal, not the
    /// agent, which is the entire reason to record the chain.
    pub fn accountable(&self, signer: Address) -> Address {
        match self {
            Agency::Direct | Agency::Assisted { .. } => signer,
            Agency::Delegated { principal, .. } => *principal,
            Agency::Autonomous { operator } => *operator,
        }
    }

    /// Check what can be checked. `Direct` and `Assisted` always pass, because there is
    /// nothing in them to falsify. That is not an oversight, it is the limit.
    pub fn verify(&self, signer: Address) -> Result<(), AttestError> {
        match self {
            Agency::Direct | Agency::Assisted { .. } | Agency::Autonomous { .. } => Ok(()),
            Agency::Delegated { principal, chain } => {
                let first = chain.first().ok_or(AttestError::EmptyChain)?;
                if first.0 != *principal {
                    return Err(AttestError::WrongPrincipal);
                }
                for pair in chain.windows(2) {
                    if pair[0].1 != pair[1].0 {
                        return Err(AttestError::BrokenChain);
                    }
                }
                if chain.last().expect("checked non-empty").1 != signer {
                    return Err(AttestError::NotTerminatedAtSigner);
                }
                Ok(())
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Agency::Direct => "human (claimed, unverifiable)".into(),
            Agency::Assisted { tool } => format!("human, assisted by {tool}"),
            Agency::Delegated { principal, chain } => format!(
                "agent under {} (chain of {}, verified)",
                principal.short(),
                chain.len()
            ),
            Agency::Autonomous { operator } => {
                format!("autonomous agent, operator {}", operator.short())
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
            Agency::Delegated { principal, chain } => {
                e.u8(2).addr(principal).u64(chain.len() as u64);
                for (from, to) in chain {
                    e.addr(from).addr(to);
                }
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
                let principal = d.addr()?;
                let n = d.u64()? as usize;
                let mut chain = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let from = d.addr()?;
                    let to = d.addr()?;
                    chain.push((from, to));
                }
                Ok(Agency::Delegated { principal, chain })
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

    #[test]
    fn a_delegated_claim_verifies_to_its_principal() {
        let clinic = Identity::generate();
        let person = Identity::generate();
        let agent = Identity::generate();
        let res = Cid::of(b"resource");

        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(1)])
            .unwrap();

        let a = Agency::from_capability(&scoped, clinic.address()).unwrap();
        assert!(a.verify(agent.address()).is_ok());
        assert!(a.is_machine());
        assert!(a.is_verifiable());
        // Responsibility rests with the clinic that issued the root authority.
        assert_eq!(a.accountable(agent.address()), clinic.address());
    }

    #[test]
    fn a_forged_delegation_claim_is_caught() {
        let real_principal = Identity::generate();
        let liar = Identity::generate();

        // Claim to be acting for someone who never authorised anything.
        let fake = Agency::Delegated {
            principal: real_principal.address(),
            chain: vec![(liar.address(), liar.address())],
        };
        assert_eq!(
            fake.verify(liar.address()),
            Err(AttestError::WrongPrincipal)
        );
    }

    #[test]
    fn a_chain_that_does_not_reach_the_signer_is_caught() {
        let a = Identity::generate();
        let b = Identity::generate();
        let someone_else = Identity::generate();

        let claim = Agency::Delegated {
            principal: a.address(),
            chain: vec![(a.address(), b.address())],
        };
        assert_eq!(
            claim.verify(someone_else.address()),
            Err(AttestError::NotTerminatedAtSigner)
        );
        assert!(claim.verify(b.address()).is_ok());
    }

    #[test]
    fn a_gap_in_the_chain_is_caught() {
        let a = Identity::generate();
        let b = Identity::generate();
        let c = Identity::generate();
        let d = Identity::generate();

        let claim = Agency::Delegated {
            principal: a.address(),
            chain: vec![(a.address(), b.address()), (c.address(), d.address())],
        };
        assert_eq!(claim.verify(d.address()), Err(AttestError::BrokenChain));
    }

    #[test]
    fn claiming_to_be_human_always_passes_and_that_is_the_known_limit() {
        // A bot with a fresh key. Nothing here catches it, by construction.
        let bot = Identity::generate();
        assert!(Agency::Direct.verify(bot.address()).is_ok());
        assert!(!Agency::Direct.is_verifiable());
        assert!(!Agency::Direct.is_machine());
    }

    #[test]
    fn round_trips_through_the_canonical_encoding() {
        let p = Identity::generate().address();
        let q = Identity::generate().address();
        for a in [
            Agency::Direct,
            Agency::Assisted {
                tool: "an editor".into(),
            },
            Agency::Delegated {
                principal: p,
                chain: vec![(p, q)],
            },
            Agency::Autonomous { operator: q },
        ] {
            let mut e = Enc::new();
            a.encode(&mut e);
            let bytes = e.finish();
            let mut d = Dec::new(&bytes);
            let back = Agency::decode(&mut d).unwrap();
            d.end().unwrap();
            assert_eq!(a, back);
        }
    }

    #[test]
    fn policies_disagree_about_the_same_content_and_all_are_correct() {
        let op = Identity::generate().address();
        let human = Agency::Direct;
        let bot = Agency::Autonomous { operator: op };
        let delegated = Agency::Delegated {
            principal: op,
            chain: vec![(op, op)],
        };

        assert!(Policy::HumanClaimedOnly.admits(&human));
        assert!(!Policy::HumanClaimedOnly.admits(&bot));
        assert!(!Policy::HumanClaimedOnly.admits(&delegated));

        assert!(Policy::ExcludeAutonomous.admits(&delegated));
        assert!(!Policy::ExcludeAutonomous.admits(&bot));

        assert!(Policy::MachineOnly.admits(&bot));
        assert!(!Policy::MachineOnly.admits(&human));

        assert!(Policy::Everything.admits(&bot));
        assert!(Policy::Everything.admits(&human));
    }
}
