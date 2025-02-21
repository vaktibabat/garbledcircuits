use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::{
    circuit::{Circuit, Node},
    crypto::aes_ctr::AesCtr,
};

const KEY_SIZE: usize = 32;

#[derive(Clone, Debug)]
pub struct GarbledWire {
    on_key: [u8; KEY_SIZE],
    off_key: [u8; KEY_SIZE],
}

#[derive(Debug, Clone)]
/// A garbled gate (from the garbler's POV, i.e. we know the gate's keys and operation unlike the receiver)
pub struct GarbledGate {
    c_00: Option<Vec<u8>>,
    c_01: Option<Vec<u8>>,
    c_10: Option<Vec<u8>>,
    c_11: Option<Vec<u8>>,
    pub left: Option<Rc<RefCell<GarbledNode>>>,
    pub right: Option<Rc<RefCell<GarbledNode>>>,
    left_wire: Option<GarbledWire>,
    right_wire: Option<GarbledWire>,
    parent_wire: Option<GarbledWire>,
    op: Option<u8>,
}

#[derive(Debug, Clone)]
/// Possible nodes in a GarbledCircuit (analogous to `Node` in a regular Circuit)
pub enum GarbledNode {
    Input(usize),
    Gate(Rc<RefCell<GarbledGate>>),
}

/// A garbled circuit from the garbler's POV
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    out: GarbledNode,
    input_wires: HashMap<usize, GarbledWire>,
    n: usize,
}

impl GarbledWire {
    /// Generate a new wire with random on and off keys
    fn new() -> GarbledWire {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut on_key = [0u8; KEY_SIZE];
        let mut off_key = [0u8; KEY_SIZE];

        rng.fill(&mut on_key);
        rng.fill(&mut off_key);

        GarbledWire {
            on_key,
            off_key,
        }
    }

    /// We have to generate the out wire in a manner that allows the receiver
    /// to detect whether the gate output true or false. To do this,
    /// we set the on key to only 1s, and the off key to only 0s
    fn out_wire() -> Self {
        GarbledWire {
            on_key: [1u8; KEY_SIZE],
            off_key: [0u8; KEY_SIZE],
        }
    }

    pub fn off_key(&self) -> [u8; KEY_SIZE] {
        self.off_key
    }

    pub fn on_key(&self) -> [u8; KEY_SIZE] {
        self.on_key
    }
}

impl Default for GarbledWire {
    fn default() -> Self {
        Self::new()
    }
}

impl GarbledGate {
    /// Generate a new gate from the gate's parent, and the new gate's operation
    fn new(parent_wire: Option<GarbledWire>, op: u8) -> Self {
        GarbledGate {
            c_00: None,
            c_01: None,
            c_10: None,
            c_11: None,
            left: None,
            right: None,
            left_wire: None,
            right_wire: None,
            parent_wire,
            op: Some(op),
        }
    }

    /// Assign ciphertexts to this gate based on its encrypted inputs
    fn assign_ciphertexts(&mut self) {
        let op = self.op.unwrap();
        // Get the bits of the operation
        let vals = ((op & 1) != 0, (op & 2) != 0, (op & 4) != 0, (op & 8) != 0);
        // Encrypt the output wire's keys
        let out_on_key = self.parent_wire.as_ref().unwrap().on_key;
        let out_off_key = self.parent_wire.as_ref().unwrap().off_key;
        // Each bit in the operation determines whether we encrypt the output wire's on key or off key
        let (out_00, out_01, out_10, out_11) = (
            if vals.0 { out_on_key } else { out_off_key },
            if vals.1 { out_on_key } else { out_off_key },
            if vals.2 { out_on_key } else { out_off_key },
            if vals.3 { out_on_key } else { out_off_key },
        );
        let left_off_cipher = AesCtr::new(&self.left_wire.as_ref().unwrap().off_key);
        let left_on_cipher = AesCtr::new(&self.left_wire.as_ref().unwrap().on_key);
        let right_off_cipher = AesCtr::new(&self.right_wire.as_ref().unwrap().off_key);
        let right_on_cipher = AesCtr::new(&self.right_wire.as_ref().unwrap().on_key);
        // We append zeros to the ciphertexts so that the receiver will be able
        // to distinguish between valid decryptions and gibberish
        // (since the decrypted keys are, by definition, random sequences of bytes, indistinguishable from gibberish)
        let zeros = [0u8; KEY_SIZE];
        self.c_00 = Some(left_off_cipher.encrypt(
            &right_off_cipher.encrypt([out_00, zeros].as_flattened(), 0),
            0,
        ));
        self.c_01 = Some(left_off_cipher.encrypt(
            &right_on_cipher.encrypt([out_01, zeros].as_flattened(), 0),
            0,
        ));
        self.c_10 = Some(left_on_cipher.encrypt(
            &right_off_cipher.encrypt([out_10, zeros].as_flattened(), 0),
            0,
        ));
        self.c_11 = Some(left_on_cipher.encrypt(
            &right_on_cipher.encrypt([out_11, zeros].as_flattened(), 0),
            0,
        ));
    }

    pub fn c_00(&self) -> Vec<u8> {
        self.c_00.as_ref().unwrap().clone()
    }

    pub fn c_01(&self) -> Vec<u8> {
        self.c_01.as_ref().unwrap().clone()
    }

    pub fn c_10(&self) -> Vec<u8> {
        self.c_10.as_ref().unwrap().clone()
    }

    pub fn c_11(&self) -> Vec<u8> {
        self.c_11.as_ref().unwrap().clone()
    }
}

impl GarbledNode {
    /// Recursively garble a circuit
    fn garble(
        node: Node,
        parent_wire: Option<GarbledWire>,
        input_wires: &HashMap<usize, GarbledWire>,
    ) -> Option<Rc<RefCell<GarbledNode>>> {
        match node {
            // If this node is an input node, just transform it to a `GarbledInput::Input`
            // with the same input index
            Node::Input(idx) => Some(Rc::new(RefCell::new(GarbledNode::Input(idx)))),
            Node::Gate(op, left, right) => {
                // Construct the gate we'll output
                let out_node = Rc::new(RefCell::new(GarbledGate::new(parent_wire, op)));
                // If our left child is an Input node, get the wire connecting us to the left child
                // by looking up the input node's index in the input wires
                // Otherwise, create a new wire
                let left_wire = if let Node::Input(idx) = *left {
                    input_wires.get(&idx).unwrap().clone()
                } else {
                    GarbledWire::new()
                };
                // Same goes for the right child
                let right_wire = if let Node::Input(idx) = *right {
                    input_wires.get(&idx).unwrap().clone()
                } else {
                    GarbledWire::new()
                };
                // Call recursively on our children; the left and right children's parent wires are
                // left_wire and right_wire, respectively
                let left_child = GarbledNode::garble(*left, Some(left_wire.clone()), input_wires);
                let right_child = GarbledNode::garble(*right, Some(right_wire.clone()), input_wires);
        
                // Set our children to the left and right children we just created
                if let Some(ref left_c) = left_child {
                    out_node.borrow_mut().left = Some(left_c.clone());
                    out_node.borrow_mut().left_wire = Some(left_wire);
                }
                if let Some(ref right_c) = right_child {
                    out_node.borrow_mut().right = Some(right_c.clone());
                    out_node.borrow_mut().right_wire = Some(right_wire);
                }
        
                // Create the ciphertexts for this node
                out_node.borrow_mut().assign_ciphertexts();
        
                Some(Rc::new(RefCell::new(GarbledNode::Gate(out_node))))
            }
        }
    }
}

impl From<Circuit> for GarbledCircuit {
    /// Garble a circuit
    fn from(value: Circuit) -> Self {
        // Generate the input wire keys
        let n = value.n();
        let mut input_wires = HashMap::new();

        for i in 0..n {
            input_wires.insert(i, GarbledWire::new());
        }

        // Garble the output node (this garbled the entire circuit)
        let garbled_out =
            GarbledNode::garble(value.out(), Some(GarbledWire::out_wire()), &input_wires);
        let garbled_out = garbled_out.as_ref().unwrap().borrow();

        GarbledCircuit::new(garbled_out.clone(), input_wires, n)
    }
}

impl GarbledCircuit {
    pub fn new(
        out: GarbledNode,
        input_wires: HashMap<usize, GarbledWire>,
        n: usize,
    ) -> GarbledCircuit {
        GarbledCircuit {
            out,
            input_wires,
            n,
        }
    }

    pub fn input_keys(&self) -> HashMap<usize, GarbledWire> {
        self.input_wires.clone()
    }

    pub fn out(&self) -> GarbledNode {
        self.out.clone()
    }

    pub fn n(&self) -> usize {
        self.n
    }
}
