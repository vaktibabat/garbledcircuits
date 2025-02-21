/// A node in the circuit
#[derive(Debug, Clone)]
pub enum Node {
    /// An input node through which the inputs to the circuit are passed; the usize indicates the input id
    Input(usize),
    /// A logic gate represented with a 4-bit integer -- since the truth table has 4 rows, we can
    /// save for each gate the output column read as a 4-bit integer (frop top to botoom). For example, OR is represented as 0111
    /// We also save the boxed left and right inputs to this gate
    Gate(u8, Box<Node>, Box<Node>),
}

/// The circuit is represented as a binary tree
pub struct Circuit {
    out: Node,
    /// Number of inputs to the circuit
    n: usize,
}

impl Node {
    pub fn eval(&self, input: &Vec<bool>) -> bool {
        match self {
            Node::Input(idx) => input[*idx],
            Node::Gate(op, left, right) => {
                // Index into the gate's operation based on the inputs
                let (left_val, right_val) = (left.eval(input), right.eval(input));

                (op & (1 << (2 * left_val as usize + right_val as usize))) != 0
            }
        }
    }

    // How many inputs does this circuit have?
    fn inputs(&self) -> Vec<usize> {
        match self {
            Node::Input(idx) => vec![*idx],
            Node::Gate(_, left, right) => {
                let mut left_inputs = left.inputs();
                let mut right_inputs = right.inputs();
                let mut inputs = vec![];

                inputs.append(&mut left_inputs);
                inputs.append(&mut right_inputs);

                inputs
            }
        }
    }

    pub fn n_inputs(&self) -> usize {
        let mut inputs = self.inputs();

        // We may have repetitions (in case some inputs are connected to multiple gates)
        // in which case we have to dedup them
        inputs.sort();
        inputs.dedup();

        inputs.len()
    }
}

impl Circuit {
    pub fn new(out: Node) -> Circuit {
        let n = out.n_inputs();

        Circuit { out, n }
    }

    pub fn eval(&self, input: &Vec<bool>) -> bool {
        self.out.eval(input)
    }

    pub fn out(&self) -> Node {
        self.out.clone()
    }

    pub fn n(&self) -> usize {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::{Circuit, Node};

    // Some useful gates
    const AND_GATE: u8 = 0b1000u8;
    const OR_GATE: u8 = 0b1110u8;
    const XOR_GATE: u8 = 0b0110u8;

    #[test]
    pub fn and_gate_test() {
        let x = Node::Input(0);
        let y = Node::Input(1);
        let out = Node::Gate(AND_GATE, Box::new(x), Box::new(y));
        let circuit = Circuit::new(out);

        assert_eq!(circuit.eval(&vec![false, false]), false);
        assert_eq!(circuit.eval(&vec![false, true]), false);
        assert_eq!(circuit.eval(&vec![true, false]), false);
        assert_eq!(circuit.eval(&vec![true, true]), true);
    }

    #[test]
    pub fn or_gate_test() {
        let x = Node::Input(0);
        let y = Node::Input(1);
        let out = Node::Gate(OR_GATE, Box::new(x), Box::new(y));
        let circuit = Circuit::new(out);

        assert_eq!(circuit.eval(&vec![false, false]), false);
        assert_eq!(circuit.eval(&vec![false, true]), true);
        assert_eq!(circuit.eval(&vec![true, false]), true);
        assert_eq!(circuit.eval(&vec![true, true]), true);
    }

    #[test]
    pub fn xor_gate_test() {
        let x = Node::Input(0);
        let y = Node::Input(1);
        let out = Node::Gate(XOR_GATE, Box::new(x), Box::new(y));
        let circuit = Circuit::new(out);

        assert_eq!(circuit.eval(&vec![false, false]), false);
        assert_eq!(circuit.eval(&vec![false, true]), true);
        assert_eq!(circuit.eval(&vec![true, false]), true);
        assert_eq!(circuit.eval(&vec![true, true]), false);
    }

    #[test]
    pub fn complex_circuit_test() {
        // x & ((x | y) ^ z)
        let x = Node::Input(0);
        let y = Node::Input(1);
        let z = Node::Input(2);
        let or = Node::Gate(OR_GATE, Box::new(x.clone()), Box::new(y));
        let xor = Node::Gate(XOR_GATE, Box::new(or), Box::new(z));
        let out = Node::Gate(AND_GATE, Box::new(x), Box::new(xor));
        let circuit = Circuit::new(out);

        assert_eq!(circuit.eval(&vec![false, false, false]), false);
        assert_eq!(circuit.eval(&vec![false, false, true]), false);
        assert_eq!(circuit.eval(&vec![false, true, false]), false);
        assert_eq!(circuit.eval(&vec![false, true, true]), false);
        assert_eq!(circuit.eval(&vec![true, false, false]), true);
        assert_eq!(circuit.eval(&vec![true, false, true]), false);
        assert_eq!(circuit.eval(&vec![true, true, false]), true);
        assert_eq!(circuit.eval(&vec![true, true, true]), false);
    }
}
