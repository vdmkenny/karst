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
use std::collections::{BTreeMap, BTreeSet};

use karst_id::{Address, Identity, Peer, Signature};
use karst_object::{Cid, Dec, DecodeError, Enc};

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

    pub fn decode(d: &mut Dec<'_>) -> Result<Caveat, DecodeError> {
        match d.u8()? {
            0 => Ok(Caveat::Operation(d.str()?)),
            1 => Ok(Caveat::MaxAmount(d.u64()?)),
            2 => Ok(Caveat::ExpiresAt(d.u64()?)),
            3 => {
                let v = d.u64()?;
                Ok(Caveat::MaxUses(
                    u32::try_from(v).map_err(|_| DecodeError::Truncated)?,
                ))
            }
            t => Err(DecodeError::UnknownTag(t)),
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
    /// The presenter is not the party this capability was delegated to.
    NotTheHolder,
    /// This nonce has already been retired by the verifier.
    Replayed,
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
            CapError::NotTheHolder => {
                write!(f, "presenter does not hold the key this was delegated to")
            }
            CapError::Replayed => write!(f, "invocation nonce has already been used"),
            CapError::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}

impl std::error::Error for CapError {}

/// One link in a delegation chain.
#[derive(Clone, Debug, PartialEq, Eq)]
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

    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.issuer_key)
            .addr(&self.audience)
            .u64(self.caveats.len() as u64);
        for c in &self.caveats {
            c.encode(e);
        }
        e.bytes(&self.signature);
    }

    fn decode(d: &mut Dec<'_>) -> Result<Grant, DecodeError> {
        let issuer_key: [u8; 32] = d
            .bytes()?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let audience = d.addr()?;
        let n = d.u64()? as usize;
        if n > 64 {
            return Err(DecodeError::UnknownTag(0));
        }
        let mut caveats = Vec::with_capacity(n);
        for _ in 0..n {
            caveats.push(Caveat::decode(d)?);
        }
        let signature: [u8; 64] = d
            .bytes()?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(Grant {
            issuer_key,
            audience,
            caveats,
            signature,
        })
    }
}

/// A capability: a resource plus the chain of grants that leads to its current holder.
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// A stable name for this exact capability, used to key verifier-side usage state and
    /// to bind a signed invocation to the credential it exercises.
    pub fn id(&self) -> Cid {
        let mut e = Enc::new();
        e.str("karst.capability.v1")
            .cid(&self.resource)
            .u64(self.chain.len() as u64);
        for g in &self.chain {
            g.encode(&mut e);
        }
        e.hash()
    }

    /// Serialise, signatures and all, so a capability can travel inside another object.
    ///
    /// This is what makes an authorship claim checkable rather than merely asserted: the
    /// evidence goes with the claim instead of being reduced to a list of addresses
    /// anyone could type out (issue #28).
    pub fn encode(&self, e: &mut Enc) {
        e.cid(&self.resource).u64(self.chain.len() as u64);
        for g in &self.chain {
            g.encode(e);
        }
    }

    pub fn decode(d: &mut Dec<'_>) -> Result<Capability, DecodeError> {
        let resource = d.cid()?;
        let n = d.u64()? as usize;
        if n > 64 {
            return Err(DecodeError::UnknownTag(0));
        }
        let mut chain = Vec::with_capacity(n);
        for _ in 0..n {
            chain.push(Grant::decode(d)?);
        }
        Ok(Capability { resource, chain })
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
///
/// Note the absence of a use counter. An earlier version took one from the caller, which
/// meant a one-use capability could be replayed forever by always sending index zero
/// (issue #29). Usage is now counted by the verifier in a [`UseLedger`], where the caller
/// cannot reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub operation: String,
    pub amount: u64,
    pub at: u64,
    /// Replay protection. The verifier refuses a nonce it has already retired.
    pub nonce: [u8; 16],
    /// Binds the invocation to its exact arguments, so a signature over this request
    /// cannot be reused with different ones.
    pub args_digest: Cid,
}

impl Request {
    fn signing_bytes(&self, cap_id: &Cid, resource: &Cid) -> Vec<u8> {
        let mut e = Enc::new();
        e.str("karst.invoke.v1")
            .cid(cap_id)
            .cid(resource)
            .str(&self.operation)
            .u64(self.amount)
            .u64(self.at)
            .bytes(&self.nonce)
            .cid(&self.args_digest);
        e.finish()
    }
}

/// An invocation signed by the capability holder.
///
/// A capability on its own is a bearer token: anyone who copies it can spend it (issue
/// #30). Requiring the holder to sign the request, and checking that signature against the
/// final grant's audience, means possession of the token is not enough. You need the key it
/// was issued to.
#[derive(Clone)]
pub struct SignedInvocation {
    pub request: Request,
    /// The presenter's public key. Its hash must equal the capability's final audience.
    pub invoker_key: [u8; 32],
    signature: [u8; 64],
}

impl SignedInvocation {
    pub fn sign(holder: &Identity, cap: &Capability, request: Request) -> Self {
        let msg = request.signing_bytes(&cap.id(), &cap.resource);
        let sig = holder.sign(&msg);
        SignedInvocation {
            request,
            invoker_key: holder.key_bytes(),
            signature: sig.to_bytes(),
        }
    }

    /// Prove the presenter holds the key this capability was delegated to.
    ///
    /// Returns the verified presenter's address, which is what a receipt should attribute
    /// the action to, rather than whoever the capability merely names.
    pub fn verify_possession(&self, cap: &Capability) -> Result<Address, CapError> {
        let peer =
            Peer::from_key_bytes(&self.invoker_key).map_err(|_| CapError::MalformedKey)?;

        let audience = cap.holder().ok_or(CapError::EmptyChain)?;
        if peer.address() != audience {
            return Err(CapError::NotTheHolder);
        }

        let msg = self.request.signing_bytes(&cap.id(), &cap.resource);
        peer.verify(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| CapError::BadSignature)?;
        Ok(peer.address())
    }
}

/// Verifier-owned usage state.
///
/// The caller never sees this and cannot assert anything about it, which is the entire
/// point. `&mut self` makes consumption atomic for a single verifier.
///
/// **The honest limit.** This enforces a use count *at one verifier*. A capability
/// presented to two disconnected offline verifiers will be accepted by both, because
/// neither can know about the other without talking to it, and requiring them to talk
/// reintroduces exactly the always-online authority this stack exists to remove. So
/// [`Caveat::MaxUses`] means "at most n times per verifier", not "at most n times in the
/// universe", and anything that needs the stronger guarantee has to name a single verifier
/// or accept consensus latency. Documented rather than papered over.
#[derive(Default)]
pub struct UseLedger {
    consumed: BTreeMap<Cid, u32>,
    retired_nonces: BTreeSet<[u8; 16]>,
}

impl UseLedger {
    pub fn new() -> Self {
        UseLedger::default()
    }

    /// How many times this verifier has seen this capability used.
    pub fn uses(&self, cap_id: &Cid) -> u32 {
        self.consumed.get(cap_id).copied().unwrap_or(0)
    }

    /// Retire a nonce and take one use, or refuse. Atomic: nothing is recorded unless the
    /// whole thing succeeds.
    pub fn consume(
        &mut self,
        cap_id: Cid,
        nonce: [u8; 16],
        max_uses: Option<u32>,
    ) -> Result<u32, CapError> {
        if self.retired_nonces.contains(&nonce) {
            return Err(CapError::Replayed);
        }
        let used = self.uses(&cap_id);
        if let Some(max) = max_uses {
            if used >= max {
                return Err(CapError::Refused(format!(
                    "already used {used} of {max} permitted time(s)"
                )));
            }
        }
        self.retired_nonces.insert(nonce);
        let now = used + 1;
        self.consumed.insert(cap_id, now);
        Ok(now)
    }
}

/// Check a request against effective caveats and consume one use.
///
/// Takes the ledger by mutable reference because authorising and consuming must be one
/// step. Checking first and consuming later is where replay windows come from.
pub fn authorize(
    effective: &[Caveat],
    req: &Request,
    cap_id: Cid,
    ledger: &mut UseLedger,
) -> Result<(), CapError> {
    let mut max_uses = None;

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
            Caveat::MaxUses(n) => max_uses = Some(*n),
            _ => {}
        }
    }

    ledger.consume(cap_id, req.nonce, max_uses)?;
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

    fn req(op: &str, amount: u64, at: u64, nonce: u8) -> Request {
        Request {
            operation: op.into(),
            amount,
            at,
            nonce: [nonce; 16],
            args_digest: Cid::of(b"args"),
        }
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
        let mut ledger = UseLedger::new();
        assert!(matches!(
            authorize(&eff, &req("book", 900_000, 0, 1), scoped.id(), &mut ledger),
            Err(CapError::Refused(_))
        ));
    }

    #[test]
    fn caveats_are_enforced_on_operation_amount_and_expiry() {
        let eff = vec![
            Caveat::Operation("book".into()),
            Caveat::MaxAmount(5000),
            Caveat::ExpiresAt(100),
        ];
        let id = Cid::of(b"cap");

        let mut l = UseLedger::new();
        assert!(authorize(&eff, &req("book", 4500, 50, 0), id, &mut l).is_ok());

        for (i, bad) in [
            req("cancel", 0, 50, 10),
            req("book", 20_000, 50, 11),
            req("book", 100, 100, 12),
        ]
        .into_iter()
        .enumerate()
        {
            let mut l = UseLedger::new();
            assert!(
                authorize(&eff, &bad, id, &mut l).is_err(),
                "case {i} should have been refused"
            );
        }
    }

    /// Regression for issue #29, reported by @matthiasantierens.
    ///
    /// `MaxUses` was checked against a `use_index` the caller supplied, so a one-use
    /// capability could be spent forever by always sending zero. Usage now lives in a
    /// ledger the caller cannot reach.
    #[test]
    fn a_one_use_capability_cannot_be_replayed_by_a_lying_caller() {
        let eff = vec![Caveat::MaxUses(1)];
        let id = Cid::of(b"cap");
        let mut ledger = UseLedger::new();

        assert!(authorize(&eff, &req("book", 0, 0, 1), id, &mut ledger).is_ok());

        // The adversarial client repeats the call with a fresh nonce and no memory of
        // having spent anything. There is no field it can lie about that helps.
        for n in 2..6u8 {
            assert!(
                authorize(&eff, &req("book", 0, 0, n), id, &mut ledger).is_err(),
                "replay {n} was accepted"
            );
        }
        assert_eq!(ledger.uses(&id), 1);
    }

    #[test]
    fn an_identical_invocation_is_rejected_as_a_replay() {
        let eff = vec![Caveat::MaxUses(10)];
        let id = Cid::of(b"cap");
        let mut ledger = UseLedger::new();

        let r = req("book", 0, 0, 7);
        assert!(authorize(&eff, &r, id, &mut ledger).is_ok());
        assert_eq!(
            authorize(&eff, &r, id, &mut ledger),
            Err(CapError::Replayed)
        );
        // A refused call consumes nothing.
        assert_eq!(ledger.uses(&id), 1);
    }

    #[test]
    fn a_refused_invocation_does_not_burn_a_use() {
        let eff = vec![Caveat::Operation("book".into()), Caveat::MaxUses(1)];
        let id = Cid::of(b"cap");
        let mut ledger = UseLedger::new();

        assert!(authorize(&eff, &req("cancel", 0, 0, 1), id, &mut ledger).is_err());
        assert_eq!(ledger.uses(&id), 0, "a rejected call must be free");
        assert!(authorize(&eff, &req("book", 0, 0, 2), id, &mut ledger).is_ok());
    }

    #[test]
    fn ledgers_are_per_verifier_and_the_docs_say_so() {
        // Two disconnected verifiers each accept the same one-use capability. This is a
        // real limit of offline verification, not an oversight, and UseLedger documents it.
        let eff = vec![Caveat::MaxUses(1)];
        let id = Cid::of(b"cap");
        let mut a = UseLedger::new();
        let mut b = UseLedger::new();

        assert!(authorize(&eff, &req("book", 0, 0, 1), id, &mut a).is_ok());
        assert!(authorize(&eff, &req("book", 0, 0, 1), id, &mut b).is_ok());
    }

    /// Regression for issue #30, reported by @matthiasantierens.
    ///
    /// A capability was a pure bearer token: copying it was enough to spend it. The holder
    /// now signs the request, and the signature is checked against the final audience.
    #[test]
    fn a_copied_capability_is_useless_without_the_holders_key() {
        let (clinic, person, agent, res) = setup();
        let thief = Identity::generate();

        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(5)])
            .unwrap();

        // The rightful holder can exercise it.
        let good = SignedInvocation::sign(&agent, &scoped, req("book", 100, 0, 1));
        assert_eq!(good.verify_possession(&scoped).unwrap(), agent.address());

        // Someone who copied the bytes cannot.
        let stolen = SignedInvocation::sign(&thief, &scoped, req("book", 100, 0, 2));
        assert_eq!(
            stolen.verify_possession(&scoped),
            Err(CapError::NotTheHolder)
        );
    }

    #[test]
    fn a_signed_invocation_cannot_be_moved_to_another_capability_or_argument_set() {
        let (clinic, person, agent, res) = setup();
        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let a = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(5)])
            .unwrap();
        let b = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(1)])
            .unwrap();
        assert_ne!(a.id(), b.id());

        let signed = SignedInvocation::sign(&agent, &a, req("book", 100, 0, 1));
        assert!(signed.verify_possession(&a).is_ok());
        assert_eq!(
            signed.verify_possession(&b),
            Err(CapError::BadSignature),
            "a signature bound to one capability must not travel to another"
        );

        // Swapping the arguments out from under a valid signature also fails.
        let mut tampered = signed.clone();
        tampered.request.args_digest = Cid::of(b"different args");
        assert_eq!(
            tampered.verify_possession(&a),
            Err(CapError::BadSignature)
        );
    }

    #[test]
    fn a_capability_round_trips_through_the_canonical_encoding() {
        let (clinic, person, agent, res) = setup();
        let root = Capability::issue(&clinic, res, person.address(), vec![]);
        let scoped = root
            .attenuate(
                &person,
                agent.address(),
                vec![Caveat::Operation("book".into()), Caveat::MaxAmount(5000)],
            )
            .unwrap();

        let mut e = Enc::new();
        scoped.encode(&mut e);
        let bytes = e.finish();

        let mut d = Dec::new(&bytes);
        let back = Capability::decode(&mut d).unwrap();
        d.end().unwrap();

        assert_eq!(back.id(), scoped.id());
        assert_eq!(back.verify(clinic.address()).unwrap(), scoped.verify(clinic.address()).unwrap());
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
