//! The queue corpus scheduler implements an AFL-like queue mechanism

use alloc::borrow::ToOwned;
use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusId},
    inputs::UsesInput,
    schedulers::Scheduler,
    state::{HasCorpus, UsesState},
    Error,
};

/// Walk the corpus in a queue-like fashion
#[derive(Debug, Clone)]
pub struct QueueScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> UsesState for QueueScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> Scheduler for QueueScheduler<S>
where
    S: HasCorpus,
{
    /// Gets the next entry in the queue
    fn next(&self, state: &mut Self::State) -> Result<CorpusId, Error> {
        let id_manager = state.corpus().id_manager();
        let first_id = id_manager
            .first_id()
            .ok_or_else(|| Error::empty("No entries in corpus".to_owned()))?;
        let next_id = state
            .corpus()
            .current()
            .and_then(|cur| id_manager.find_next(cur))
            .unwrap_or(first_id);
        *state.corpus_mut().current_mut() = Some(next_id);
        Ok(next_id)
    }
}

impl<S> QueueScheduler<S> {
    /// Creates a new `QueueScheduler`
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> Default for QueueScheduler<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::{
        bolts::rands::StdRand,
        corpus::{Corpus, OnDiskCorpus, Testcase},
        feedbacks::ConstFeedback,
        inputs::bytes::BytesInput,
        schedulers::{QueueScheduler, Scheduler},
        state::{HasCorpus, StdState},
    };

    #[test]
    fn test_queuecorpus() {
        let rand = StdRand::with_seed(4);
        let scheduler = QueueScheduler::new();

        let mut q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/path")).unwrap();
        let t = Testcase::with_filename(
            BytesInput::new(vec![0_u8; 4]),
            "target/.test/fancy/path/fancyfile".into(),
        );
        q.add(t).unwrap();

        let objective_q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/objective/path"))
                .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(rand, q, objective_q, &mut feedback, &mut objective).unwrap();

        let next_idx = scheduler.next(&mut state).unwrap();
        let filename = state
            .corpus()
            .get(next_idx)
            .unwrap()
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .clone();

        assert_eq!(filename, "target/.test/fancy/path/fancyfile");

        fs::remove_dir_all("target/.test/fancy").unwrap();
    }
}
