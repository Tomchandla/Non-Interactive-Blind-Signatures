use crate::zk::vole_rain_then_mayo::parameters::VOLERainThenMAYOParameters;

/// Defines the intermediate proof state, that is described by the output of
/// `prove`. Primarily used to initialize the proof state before it is converted
/// to the final proof.
#[derive(Clone)]
pub struct VOLERainThenMAYOProofState {
    pub proof: Vec<u8>,
    pub random_seed: Vec<u8>,
}

/// Just a capture for the [`VOLERainThenMAYOProof`] type.
pub struct VOLERainThenMAYOProof {
    pub proof: Vec<u8>,
}

impl From<VOLERainThenMAYOProofState> for VOLERainThenMAYOProof {
    /// Extracts the proof from a [`VOLERainThenMAYOProofState`] after `prove` was called.
    fn from(value: VOLERainThenMAYOProofState) -> Self {
        VOLERainThenMAYOProof { proof: value.proof }
    }
}

impl VOLERainThenMAYOProofState {
    /// Initiates a state and allocates sufficient space in memory based on the provided
    /// [`VOLERainThenMAYOParameters`].
    pub fn init(p: &VOLERainThenMAYOParameters) -> Self {
        let proof = vec![0u8; p.proof_size];
        let random_seed = vec![0u8; p.random_seed_size];

        VOLERainThenMAYOProofState { proof, random_seed }
    }
}
