#![cfg(test)]

//! Lineage graph bounds (#333).
//!
//! A lineage record is an edge from registered evidence to a derivative. These
//! tests pin both directions of that edge, the depth the edge implies, and the
//! fact that a rejected edge costs a parent nothing:
//!
//! 1. A derivative names at least one parent and at most `MAX_LINEAGE_FANOUT`.
//! 2. A parent is charged for at most `MAX_LINEAGE_FANOUT` derivatives.
//! 3. Depth is derived from the parents, never trusted from the caller, and is
//!    capped at `MAX_LINEAGE_DEPTH`.
//! 4. An edge only ever points at evidence that exists: no self-reference, no
//!    repeated parent, no unknown parent, and no digest that is already
//!    recorded.
//! 5. A rejected edge leaves every parent's budget untouched.

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

/// A parent set from a list of seed bytes.
fn parents(env: &Env, seeds: &[u8]) -> soroban_sdk::Vec<BytesN<32>> {
    let mut out = soroban_sdk::Vec::new(env);
    for seed in seeds.iter() {
        out.push_back(bytes32(env, *seed));
    }
    out
}

/// A registry with an admin and one registered source proof, returning the
/// client, the actor, and the digest of the registered evidence.
fn setup(env: &Env) -> (HarpocratesRegistryClient<'_>, Address, BytesN<32>) {
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.init(&admin);

    let actor = Address::generate(env);
    let evidence = bytes32(env, 0xE1);
    client.register_source(&actor, &bytes32(env, 0xE2), &bytes32(env, 0xE3), &evidence);
    (client, actor, evidence)
}

/// Record one derivative with a single parent, returning its depth.
fn derive(
    client: &HarpocratesRegistryClient<'_>,
    env: &Env,
    actor: &Address,
    parent: &BytesN<32>,
    output: u8,
    depth: u32,
) -> u32 {
    let record = client.register_lineage(
        actor,
        &one_parent(env, parent),
        &bytes32(env, output.wrapping_add(1)),
        &Symbol::new(env, "crop"),
        &bytes32(env, output),
        &depth,
    );
    record.depth
}

/// A single-parent vector built from an explicit digest.
fn one_parent(env: &Env, parent: &BytesN<32>) -> soroban_sdk::Vec<BytesN<32>> {
    let mut out = soroban_sdk::Vec::new(env);
    out.push_back(parent.clone());
    out
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn registers_lineage_with_bounded_validation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 1);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &parent);

    let lineage = client.register_lineage(
        &actor,
        &one_parent(&env, &parent),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 5),
        &1,
    );

    assert_eq!(lineage.output_digest, bytes32(&env, 5));
    assert_eq!(lineage.depth, 1);
    assert_eq!(lineage.actor, actor);
    assert_eq!(client.get_lineage(&bytes32(&env, 5)).unwrap(), lineage);
    assert_eq!(client.get_lineage_child_count(&parent), 1);
}

#[test]
fn accepts_a_parent_set_exactly_at_the_fanout_cap() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // One registered proof plus the siblings the cap allows.
    let mut seeds: std::vec::Vec<u8> = std::vec![0xE1];
    for i in 1..MAX_LINEAGE_FANOUT {
        let extra = 0x20 + i as u8;
        client.register_source(
            &actor,
            &bytes32(&env, extra),
            &bytes32(&env, extra.wrapping_add(1)),
            &bytes32(&env, extra.wrapping_add(2)),
        );
        seeds.push(extra.wrapping_add(2));
    }
    assert_eq!(seeds.len(), MAX_LINEAGE_FANOUT as usize);
    let parents = parents(&env, &seeds);

    let record = client.register_lineage(
        &actor,
        &parents,
        &bytes32(&env, 0x30),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x31),
        &1,
    );

    assert_eq!(record.parent_proof_ids.len(), MAX_LINEAGE_FANOUT);
    assert_eq!(record.depth, 1);
    // Every distinct parent was charged exactly once.
    for seed in seeds.iter() {
        assert_eq!(client.get_lineage_child_count(&bytes32(&env, *seed)), 1);
    }
    assert_eq!(client.get_lineage_child_count(&evidence), 1);
}

#[test]
fn derives_depth_from_the_deepest_parent() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // A shallow parent and a deeper one: the derivative sits one below the
    // deeper of the two.
    assert_eq!(derive(&client, &env, &actor, &evidence, 0x40, 1), 1);
    let deep = bytes32(&env, 0x40);
    assert_eq!(derive(&client, &env, &actor, &deep, 0x41, 2), 2);

    let mut mixed = soroban_sdk::Vec::new(&env);
    mixed.push_back(evidence.clone());
    mixed.push_back(bytes32(&env, 0x41));

    let record = client.register_lineage(
        &actor,
        &mixed,
        &bytes32(&env, 0x42),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x43),
        &3,
    );
    assert_eq!(record.depth, 3);
}

// ---------------------------------------------------------------------------
// Fan-out: parents per derivative
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #60)")]
fn rejects_excessive_fanout() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    let parents = soroban_sdk::Vec::from_array(
        &env,
        [
            bytes32(&env, 1),
            bytes32(&env, 2),
            bytes32(&env, 3),
            bytes32(&env, 4),
            bytes32(&env, 5),
        ],
    );

    client.register_lineage(
        &actor,
        &parents,
        &bytes32(&env, 6),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 7),
        &1,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #57)")]
fn rejects_an_empty_parent_set() {
    let env = Env::default();
    let (client, actor, _) = setup(&env);

    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::new(&env),
        &bytes32(&env, 0x50),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x51),
        &1,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #57)")]
fn rejects_a_repeated_parent() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // Naming the same parent twice is one edge, not two, and is refused so the
    // fan-out cap always counts distinct parents.
    client.register_lineage(
        &actor,
        &parents(&env, &[0xE1, 0xE1]),
        &bytes32(&env, 0x52),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x53),
        &1,
    );
    let _ = evidence;
}

// ---------------------------------------------------------------------------
// Fan-out: derivatives per parent
// ---------------------------------------------------------------------------

#[test]
fn enforces_the_per_parent_fanout_cap() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    for i in 0..MAX_LINEAGE_FANOUT {
        let output = 0x60 + i as u8;
        client.register_lineage(
            &actor,
            &one_parent(&env, &evidence),
            &bytes32(&env, output),
            &Symbol::new(&env, "crop"),
            &bytes32(&env, output.wrapping_add(1)),
            &1,
        );
    }
    assert_eq!(
        client.get_lineage_child_count(&evidence),
        MAX_LINEAGE_FANOUT
    );

    // One more derivative of the same parent is refused.
    let overflow = client.try_register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x7F),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x80),
        &1,
    );
    assert!(overflow.is_err());
    assert_eq!(
        client.get_lineage_child_count(&evidence),
        MAX_LINEAGE_FANOUT
    );
}

#[test]
fn a_parent_budget_is_shared_by_every_derivative_that_names_it() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // A second parent that is already at its cap must not be able to ride along
    // with a parent that still has room.
    let sibling = bytes32(&env, 0x90);
    client.register_source(&actor, &bytes32(&env, 0x91), &bytes32(&env, 0x92), &sibling);
    for i in 0..MAX_LINEAGE_FANOUT {
        let output = 0x93 + i as u8;
        client.register_lineage(
            &actor,
            &one_parent(&env, &sibling),
            &bytes32(&env, output),
            &Symbol::new(&env, "crop"),
            &bytes32(&env, output.wrapping_add(0x10)),
            &1,
        );
    }

    let mut both = soroban_sdk::Vec::new(&env);
    both.push_back(evidence.clone());
    both.push_back(sibling.clone());
    let result = client.try_register_lineage(
        &actor,
        &both,
        &bytes32(&env, 0xA0),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0xA1),
        &1,
    );
    assert!(result.is_err());

    // The saturated sibling aborted the edge, so the available parent was not
    // charged for a derivative that was never recorded.
    assert_eq!(client.get_lineage_child_count(&evidence), 0);
    assert_eq!(client.get_lineage_child_count(&sibling), MAX_LINEAGE_FANOUT);
}

#[test]
fn a_rejected_edge_does_not_spend_a_parent_budget() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // A repeated parent is rejected before any budget is charged.
    let repeated = client.try_register_lineage(
        &actor,
        &parents(&env, &[0xE1, 0xE1]),
        &bytes32(&env, 0xB0),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0xB1),
        &1,
    );
    assert!(repeated.is_err());
    assert_eq!(client.get_lineage_child_count(&evidence), 0);

    // A forged depth is rejected the same way.
    let forged = client.try_register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0xB2),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0xB3),
        &0,
    );
    assert!(forged.is_err());
    assert_eq!(client.get_lineage_child_count(&evidence), 0);

    // The full budget is still available afterwards.
    for i in 0..MAX_LINEAGE_FANOUT {
        let output = 0xB4 + i as u8;
        client.register_lineage(
            &actor,
            &one_parent(&env, &evidence),
            &bytes32(&env, output),
            &Symbol::new(&env, "crop"),
            &bytes32(&env, output.wrapping_add(0x20)),
            &1,
        );
    }
    assert_eq!(
        client.get_lineage_child_count(&evidence),
        MAX_LINEAGE_FANOUT
    );
}

// ---------------------------------------------------------------------------
// Depth
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #59)")]
fn rejects_a_derivative_beyond_the_depth_cap() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // evidence(0) -> 1 -> 2 -> 3 -> 4 is the deepest legal chain.
    let mut parent = evidence;
    for depth in 1..=MAX_LINEAGE_DEPTH {
        let output = 0xC0 + depth as u8;
        assert_eq!(derive(&client, &env, &actor, &parent, output, depth), depth);
        parent = bytes32(&env, output);
    }

    // One more step would sit at MAX_LINEAGE_DEPTH + 1.
    client.register_lineage(
        &actor,
        &one_parent(&env, &parent),
        &bytes32(&env, 0xDF),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0xE0),
        &(MAX_LINEAGE_DEPTH + 1),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #69)")]
fn rejects_a_forged_shallow_depth() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // Build a real two-level chain, then claim a derivative of the second level
    // is only one deep. The registry believes the graph, not the caller.
    assert_eq!(derive(&client, &env, &actor, &evidence, 0xD0, 1), 1);
    assert_eq!(
        derive(&client, &env, &actor, &bytes32(&env, 0xD0), 0xD1, 2),
        2
    );

    client.register_lineage(
        &actor,
        &one_parent(&env, &bytes32(&env, 0xD1)),
        &bytes32(&env, 0xD2),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0xD3),
        &1,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #69)")]
fn rejects_an_overstated_depth() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    client.register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0xD4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0xD5),
        &MAX_LINEAGE_DEPTH,
    );
}

// ---------------------------------------------------------------------------
// Edge integrity
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #58)")]
fn rejects_self_referential_lineage() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    client.register_lineage(
        &actor,
        &one_parent(&env, &bytes32(&env, 1)),
        &bytes32(&env, 2),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 1),
        &1,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #57)")]
fn rejects_an_unknown_parent() {
    let env = Env::default();
    let (client, actor, _) = setup(&env);

    client.register_lineage(
        &actor,
        &parents(&env, &[0xFA, 0xFB]),
        &bytes32(&env, 0xFC),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0xFD),
        &1,
    );
}

#[test]
fn rejects_registration_of_an_existing_output_digest() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    let original = client.register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x10),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x11),
        &1,
    );

    // A second registration for the same output digest is refused, so a
    // recorded derivation cannot be rewritten by another actor. The parent here
    // is a real, unrelated artefact, so nothing but the duplicate-output guard
    // can reject this edge.
    let replayed = client.try_register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x12),
        &Symbol::new(&env, "blur"),
        &bytes32(&env, 0x11),
        &1,
    );
    assert!(replayed.is_err());

    assert_eq!(client.get_lineage(&bytes32(&env, 0x11)).unwrap(), original);
    // The refused attempt did not create a second edge from the parent.
    assert_eq!(client.get_lineage_child_count(&evidence), 1);
}

#[test]
fn a_derivative_is_itself_a_valid_parent() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    client.register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x70),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x71),
        &1,
    );

    let child = client.register_lineage(
        &actor,
        &one_parent(&env, &bytes32(&env, 0x71)),
        &bytes32(&env, 0x72),
        &Symbol::new(&env, "blur"),
        &bytes32(&env, 0x73),
        &2,
    );

    assert_eq!(child.depth, 2);
    assert_eq!(client.get_lineage_child_count(&bytes32(&env, 0x71)), 1);
    // The evidence keeps the one edge it was charged for.
    assert_eq!(client.get_lineage_child_count(&evidence), 1);
}
