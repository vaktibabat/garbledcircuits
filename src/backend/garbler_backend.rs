use std::{io, net::TcpStream};

use crate::{
    backend::receiver_backend::GarbledNodeRecv,
    circuit::{self, Circuit},
    garbling::GarbledCircuit,
    message::MessageStream,
};
use protobuf::MessageField;
use protos::{GarbledCircuitSend, GarbledNodeSend, GarblerKeys, Gate, Input};

use super::receiver_backend::GarbledCircuitRecv;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

const AND_GATE: u8 = 0b1000u8;
const OR_GATE: u8 = 0b1110u8;
const XNOR_GATE: u8 = 0b1001u8;
/// $x \wedge \neg y$
/// Truth table (top to bottom):
/// F F T F
const MY_GATE: u8 = 0b0100u8;

// Convert a garbled node to the garbled node protobuf
impl From<GarbledNodeRecv> for GarbledNodeSend {
    fn from(value: GarbledNodeRecv) -> Self {
        let mut input_send = GarbledNodeSend::new();

        match value {
            GarbledNodeRecv::Input(idx) => {
                // Extract the input index from the message
                let mut input_msg = Input::new();
                input_msg.idx = idx as i64;
                input_send.input = MessageField::some(input_msg);

                input_send
            }
            GarbledNodeRecv::Gate(gate) => {
                // Extract the gate data
                let mut gate_msg = Gate::new();
                gate_msg.c_00 = gate.c_00().unwrap();
                gate_msg.c_01 = gate.c_01().unwrap();
                gate_msg.c_10 = gate.c_10().unwrap();
                gate_msg.c_11 = gate.c_11().unwrap();
                gate_msg.left =
                    MessageField::some(GarbledNodeSend::from(gate.left.unwrap().borrow().clone()));
                gate_msg.right = MessageField::some(GarbledNodeSend::from(
                    gate.right.unwrap().borrow().clone(),
                ));
                input_send.gate = MessageField::some(gate_msg);

                input_send
            }
        }
    }
}

/// Send the keys corresponding to our input to the receiver
/// Note that since we don't tell the receiver which keys correspond to which bit value (on/off),
/// the receiver can't learn anything about our inputs
pub fn send_input_keys(
    stream: &mut TcpStream,
    circuit: &GarbledCircuit,
    net_worth: usize,
) -> Result<(), io::Error> {
    // Extract the keys we need to send based on the garbler's net worth
    let mut keys_msg = GarblerKeys::new();
    let mut keys = vec![];
    let key_map = circuit.input_keys();

    for key_idx in 0..circuit.n() / 2 {
        let wire = key_map.get(&key_idx).unwrap();

        keys.push(
            // Is the current bit set or not?
            if (net_worth & (1 << key_idx)) != 0 {
                wire.on_key().to_vec()
            } else {
                wire.off_key().to_vec()
            },
        );
    }

    keys_msg.keys = keys;

    MessageStream::<GarblerKeys>::send_msg(stream, keys_msg)?;

    Ok(())
}

/// Send the garbled circuit to the receiver
pub fn send_garbled_circuit(
    stream: &mut TcpStream,
    garbled_circuit: GarbledCircuit,
) -> Result<(), io::Error> {
    let n = garbled_circuit.n();
    // "dumb down" the circuit to a form the receiver can understand
    let recv_circuit: GarbledCircuitRecv = garbled_circuit.into();
    let out_msg: GarbledNodeSend = recv_circuit.out.into();
    // Send the garbled circuit to the receiver
    let mut garbled_circuit_msg = GarbledCircuitSend::new();
    garbled_circuit_msg.n = n as i64;
    garbled_circuit_msg.out = MessageField::some(out_msg);
    MessageStream::<GarbledCircuitSend>::send_msg(stream, garbled_circuit_msg)?;

    Ok(())
}

/// Construct a digital comparison circuit 
/// where each input is of size n bits
pub fn construct_circuit(n: usize) -> GarbledCircuit {
    let a_vals: Vec<circuit::Node> = (0..n).map(circuit::Node::Input).collect();
    let b_vals: Vec<circuit::Node> = (0..n).map(|i| circuit::Node::Input(n + i)).collect();
    let xs: Vec<circuit::Node> = (0..n).map(|i| circuit::Node::Gate(XNOR_GATE, Box::new(a_vals[i].clone()), Box::new(b_vals[i].clone()))).collect();
    // The AND comparison gates
    let mut out: Option<circuit::Node> = None;

    for i in (0..n).rev() {
        let mut cmp_hat = circuit::Node::Gate(MY_GATE, Box::new(a_vals[i].clone()), Box::new(b_vals[i].clone()));

        for x in xs.iter().take(n).skip(i+1) {
            cmp_hat = circuit::Node::Gate(AND_GATE, Box::new(cmp_hat.clone()), Box::new(x.clone()));
        }

        if out.is_some() {
            out = Some(circuit::Node::Gate(OR_GATE, Box::new(out.unwrap().clone()), Box::new(cmp_hat.clone())));
        } else {
            out = Some(cmp_hat);
        }
    }

    let circuit = Circuit::new(out.unwrap());

    circuit.into()
}