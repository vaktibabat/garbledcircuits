use protobuf::MessageField;
use std::{cell::RefCell, rc::Rc};

use crate::{
    backend::garbler_backend::protos::{GarbledCircuitSend, GarbledNodeSend},
    crypto::aes_ctr::AesCtr,
    garbling::{GarbledCircuit, GarbledNode},
};

const KEY_SIZE: usize = 32;

/// From the receiver's POV, a gate is defined by its ciphertexts and its children
#[derive(Clone)]
pub struct GarbledGateRecv {
    c_00: Option<Vec<u8>>,
    c_01: Option<Vec<u8>>,
    c_10: Option<Vec<u8>>,
    c_11: Option<Vec<u8>>,
    pub left: Option<Rc<RefCell<GarbledNodeRecv>>>,
    pub right: Option<Rc<RefCell<GarbledNodeRecv>>>,
}

/// A node in the circuit can be either an input or a gate (like `Circuit` and `GarbledCircuit`)
#[derive(Clone)]
pub enum GarbledNodeRecv {
    Input(usize),
    Gate(GarbledGateRecv),
}

/// A garbled circuit from the receiver's POV 
pub struct GarbledCircuitRecv {
    pub(crate) out: GarbledNodeRecv,
    pub(crate) n: usize,
}

impl GarbledGateRecv {
    pub fn c_00(&self) -> Option<Vec<u8>> {
        self.c_00.clone()
    }

    pub fn c_01(&self) -> Option<Vec<u8>> {
        self.c_01.clone()
    }

    pub fn c_10(&self) -> Option<Vec<u8>> {
        self.c_10.clone()
    }

    pub fn c_11(&self) -> Option<Vec<u8>> {
        self.c_11.clone()
    }
}

impl GarbledNodeRecv {
    /// Evaluate the garbled circuit based on a vector of input keys
    pub fn eval(&self, inputs: &Vec<[u8; KEY_SIZE]>) -> [u8; KEY_SIZE] {
        match self {
            Self::Input(idx) => inputs[*idx],
            Self::Gate(gate) => {
                // Construct ciphers based on the keys coming from our left and right children
                // (this is done by recursively calling `eval` on our children)
                let left_out = gate.left.as_ref().unwrap().borrow().eval(inputs);
                let right_out = gate.right.as_ref().unwrap().borrow().eval(inputs);
                let left_cipher = AesCtr::new(&left_out);
                let right_cipher = AesCtr::new(&right_out);
                // The correct key is appended with 32 zeros
                let suffix = [0u8; KEY_SIZE];
                // Decrypt each of this gate's ciphertexts based on the two ciphers we constructed
                // Only one decryption will be valid
                let d_00 =
                    right_cipher.decrypt(&left_cipher.decrypt(gate.c_00.as_ref().unwrap(), 0), 0);
                let d_01 =
                    right_cipher.decrypt(&left_cipher.decrypt(gate.c_01.as_ref().unwrap(), 0), 0);
                let d_10 =
                    right_cipher.decrypt(&left_cipher.decrypt(gate.c_10.as_ref().unwrap(), 0), 0);
                let d_11 =
                    right_cipher.decrypt(&left_cipher.decrypt(gate.c_11.as_ref().unwrap(), 0), 0);

                // Get this gate's output key by checking which decryption ends with the correct suffix
                if d_00.ends_with(&suffix) {
                    d_00[0..KEY_SIZE].try_into().unwrap()
                } else if d_01.ends_with(&suffix) {
                    d_01[0..KEY_SIZE].try_into().unwrap()
                } else if d_10.ends_with(&suffix) {
                    d_10[0..KEY_SIZE].try_into().unwrap()
                } else {
                    d_11[0..KEY_SIZE].try_into().unwrap()
                }
            }
        }
    }
}

impl GarbledCircuitRecv {
    pub fn eval(&self, inputs: &Vec<[u8; KEY_SIZE]>) -> [u8; KEY_SIZE] {
        self.out.eval(inputs)
    }

    pub fn n(&self) -> usize {
        self.n
    }
}

// Convert from the node protobuf sent to us over the network to a `GarbledInputRecv`
impl From<GarbledNodeSend> for GarbledNodeRecv {
    fn from(value: GarbledNodeSend) -> Self {
        if let MessageField(Some(input)) = value.input {
            GarbledNodeRecv::Input(input.idx as usize)
        } else {
            let gate = value.gate.unwrap();

            GarbledNodeRecv::Gate(GarbledGateRecv {
                c_00: Some(gate.c_00),
                c_01: Some(gate.c_01),
                c_10: Some(gate.c_10),
                c_11: Some(gate.c_11),
                left: Some(Rc::new(RefCell::new(gate.left.unwrap().into()))),
                right: Some(Rc::new(RefCell::new(gate.right.unwrap().into()))),
            })
        }
    }
}

impl From<GarbledCircuitSend> for GarbledCircuitRecv {
    fn from(value: GarbledCircuitSend) -> Self {
        let n = value.n as usize;
        let out = value.out.unwrap().into();

        GarbledCircuitRecv { out, n }
    }
}

// Used by the garbler to "dumb down" garbled nodes into a form the receiver can understand
impl From<GarbledNode> for GarbledNodeRecv {
    fn from(value: GarbledNode) -> Self {
        match value {
            GarbledNode::Input(idx) => GarbledNodeRecv::Input(idx),
            GarbledNode::Gate(gate) => {
                let gate = gate.borrow().clone();

                GarbledNodeRecv::Gate(GarbledGateRecv {
                    c_00: Some(gate.c_00()),
                    c_01: Some(gate.c_01()),
                    c_10: Some(gate.c_10()),
                    c_11: Some(gate.c_11()),
                    left: Some(Rc::new(RefCell::new(
                        gate.left.clone().unwrap().borrow().clone().into(),
                    ))),
                    right: Some(Rc::new(RefCell::new(
                        gate.right.clone().unwrap().borrow().clone().into(),
                    ))),
                })
            }
        }
    }
}

impl From<GarbledCircuit> for GarbledCircuitRecv {
    fn from(value: GarbledCircuit) -> Self {
        GarbledCircuitRecv {
            out: value.out().into(),
            n: value.n(),
        }
    }
}
