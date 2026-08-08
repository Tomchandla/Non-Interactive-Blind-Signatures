use crate::zk::vole_rain_then_mayo::parameters::VOLERainThenMAYOParameters;

#[derive(Clone)]
pub struct VOLERainThenMAYOProofState {
    pub proof: Vec<u8>,
    pub random_seed: Vec<u8>,
}

pub struct VOLERainThenMAYOProof {
    pub proof: Vec<u8>,
}

impl From<VOLERainThenMAYOProofState> for VOLERainThenMAYOProof {
    fn from(value: VOLERainThenMAYOProofState) -> Self {
        VOLERainThenMAYOProof { proof: value.proof }
    }
}

impl VOLERainThenMAYOProofState {
    pub fn init(p: &VOLERainThenMAYOParameters) -> Self {
        let proof = vec![0u8; p.proof_size];
        let random_seed = vec![0u8; p.random_seed_size];

        VOLERainThenMAYOProofState { proof, random_seed }
    }
}
