//! The [`CorpusIDManager`] is responsible for keeping track of active [`CorpusID`]s. It lets the corpus map a
//! [`CorpusID`] to its corresponding corpus index to allow for a vector-based corpus storage. It is the only component
//! that should be able to create new [`CorpusID`]s.

use alloc::{string::String, vec::Vec};
use core::fmt::{Display, Error as FormatError, Formatter};

use serde::{Deserialize, Serialize};

use super::Corpus;
use crate::{
    bolts::rands::Rand,
    state::{HasCorpus, HasRand},
    Error,
};

/// Creates a new [`CorpusID`]. [`CorpusID`]s are globally unique for a corpus and monotonically increasing.
/// They should only ever be created by a [`CorpusIDManager`], everything else must acquire them from one.
/// [`CorpusID`]s allow us to track a testcase uniquely even when corpora can have testcases be removed or replaced.
/// Two different testcases should never have the same [`CorpusID`].
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CorpusID {
    id: usize,
}
impl Display for CorpusID {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        write!(f, "CorpusID[#{}]", self.id)
    }
}

/// A [`CorpusIDManager`] is responsible for keeping track of active [`CorpusID`]s. It creates new ones, ensures that
/// they are unique, and maps them to their corresponding indices in the corpus. The `active_ids` field
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CorpusIDManager {
    next: usize,
    active_ids_: Vec<CorpusID>,
}

impl CorpusIDManager {
    /// Creates a new [`CorpusIDManager`].
    #[must_use]
    pub fn new() -> Self {
        CorpusIDManager::default()
    }

    /// Get a slice of the currently active [`CorpusID`]s. The length of this slice should always match the `count()` of
    /// the corpus.
    #[must_use]
    pub fn active_ids(&self) -> &[CorpusID] {
        // should always be sorted, since it only increasing values are ever appended!
        // debug_assert!(self.active_ids_.is_sorted());
        &self.active_ids_
    }

    /// Allocate the next [`CorpusID`] and return it. This returns a [`CorpusID`] with an identifer larger than all
    /// previously issued [`CorpusID`]s. This new [`CorpusID`] is immediately added to the `active_ids`.
    pub(super) fn provide_next(&mut self) -> Result<CorpusID, Error> {
        let id = self.next;
        self.next = id
            .checked_add(1)
            .ok_or_else(|| Error::illegal_state(String::from("Detected Integer overflow")))?;
        let id = CorpusID { id };
        self.active_ids_.push(id);
        Ok(id)
    }

    /// Invalidate the given [`CorpusID`]. This will cause any future operations and lookups for this [`CorpusID`] to
    /// fail. If the id was valid, returns the index where it was found;
    #[must_use]
    pub(crate) fn remove_id(&mut self, id: CorpusID) -> Option<usize> {
        // debug_assert!(self.active_ids_.is_sorted());
        let idx = self.active_ids_.binary_search(&id).ok()?;
        self.active_ids_.remove(idx);
        Some(idx)
    }

    /// Get the corpus index for the given [`CorpusID`]. Should only ever be called by a [`Corpus`].
    #[must_use]
    pub(crate) fn active_index_for(&self, id: CorpusID) -> Option<usize> {
        // debug_assert!(self.active_ids_.is_sorted());
        self.active_ids_.binary_search(&id).ok()
    }

    /// Get the [`CorpusID`] at the given index. If the index is out of bounds, returns `None`.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<CorpusID> {
        self.active_ids_.get(idx).copied()
    }

    /// Get the id of the first (oldest) active [`CorpusID`].
    #[must_use]
    pub fn first_id(&self) -> Option<CorpusID> {
        self.active_ids_.first().copied()
    }

    /// Gets the "next" (least less old) active [`CorpusID`]. This is like incrementing the index.
    #[must_use]
    pub fn find_next(&self, id: CorpusID) -> Option<CorpusID> {
        // it should ALWAYS be sorted since it only ever gets appended to with larger values (next ids)
        // debug_assert!(self.active_ids_.is_sorted());

        // TODO: change to binary search
        self.active_ids_.iter().find(|x| x.id > id.id).copied()
    }
}

/// Return a random entry from the corpus of a given state. This function is mainly for encapsulation to make the borrow
/// checker happy and keep the random index creation confined to one spot.
pub(crate) fn random_corpus_entry<S>(state: &mut S) -> Option<(usize, CorpusID)>
where
    S: HasCorpus + HasRand,
{
    let num = state.corpus().count();
    if num == 0 {
        return None;
    }
    let idx = state.rand_mut().below(num.try_into().unwrap()) as usize;
    let id = state
        .corpus()
        .id_manager()
        .get(idx)
        .expect("this should never fail, our random value should always be inbounds");
    Some((idx, id))
}