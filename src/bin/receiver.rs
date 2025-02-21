use std::{
    env,
    io::{self, stdin, stdout, Write},
    net::TcpStream,
};

use millionaire::{
    backend::{garbler_backend::protos::{
        EvalResult, GarbledCircuitSend, GarblerKeys, OtBlindedIdx, OtEncMessages, RsaPubkey, Xs
    }, receiver_backend::GarbledCircuitRecv},
    crypto::rsa::PublicKey,
    message::MessageStream,
    ot::ObTransferReceiver,
};
use num_bigint::BigUint;

fn get_net_worth() -> usize {
    let mut input = String::new();

    print!("How much $ do you have? (in millions): ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).expect("Failed to read line");
    input = input.trim().to_lowercase();

    input.parse::<usize>().unwrap()
}

fn connect(net_worth: usize, params: (String, u16)) -> Result<bool, io::Error> {
    let mut stream = TcpStream::connect(format!("{}:{}", params.0, params.1))?;
    // The garbler should have sent us the garbled circuit
    let circuit = MessageStream::<GarbledCircuitSend>::receive_msg(&mut stream)?;
    let circuit_recv: GarbledCircuitRecv = circuit.into();
    // What are the garbler's keys in the circuit?
    let keys_msg = MessageStream::<GarblerKeys>::receive_msg(&mut stream)?;
    let mut circuit_inputs = keys_msg.keys;
    // Using OT, get our (the receiver's) keys
    // First, the garbler should have sent us their RSA public key
    let garbler_pubkey = MessageStream::<RsaPubkey>::receive_msg(&mut stream)?;
    let pubkey = PublicKey {
        e: BigUint::from_bytes_be(&garbler_pubkey.e),
        n: BigUint::from_bytes_be(&garbler_pubkey.n),
    };
    let n = circuit_recv.n();

    // We have n / 2 inputs
    for i in 0..n / 2 {
        let curr_bit = ((net_worth & (1 << i)) != 0) as usize;

        let xs = MessageStream::<Xs>::receive_msg(&mut stream)?;
        let (x_0, x_1) = (
            BigUint::from_bytes_be(&xs.x_0),
            BigUint::from_bytes_be(&xs.x_1),
        ); 
        let receiver = ObTransferReceiver::new(pubkey.clone(), (x_0, x_1));
        // Blind the index we want & send it to the garbler
        let v = receiver.blind_idx(curr_bit);
        let mut blinded_idx = OtBlindedIdx::new();
        blinded_idx.v = v.to_bytes_be();

        MessageStream::<OtBlindedIdx>::send_msg(&mut stream, blinded_idx)?;
        // We should now get the encrypted messages
        let m_primes_msg = MessageStream::<OtEncMessages>::receive_msg(&mut stream)?;
        let (m_prime_0, m_prime_1) = (
            BigUint::from_bytes_be(&m_primes_msg.m_prime_0),
            BigUint::from_bytes_be(&m_primes_msg.m_prime_1),
        );
        // Get our key
        circuit_inputs.push(
            receiver
                .derive_msg((m_prime_0, m_prime_1), curr_bit)
                .to_bytes_be(),
        );
    }

    // Evaluate the garbled circuit
    let circuit_inputs: Vec<[u8; 32]> = circuit_inputs
        .iter()
        .map(|x| x.as_slice().try_into().unwrap())
        .collect();

    let result = circuit_recv.eval(&circuit_inputs);

    // Send the result to the garbler
    let mut msg = EvalResult::new();

    msg.result = result[0] != 0;

    MessageStream::<EvalResult>::send_msg(&mut stream, msg)?;

    // Print the result
    if result[0] != 0    {
        println!("The garbler is richer!");
    } else {
        println!("The receiver is richer!");
    }

    Ok(true)
}

fn main() {
    let net_worth = get_net_worth();
    let args: Vec<String> = env::args().collect();
    let (ip, port) = (
        args.get(1).unwrap(),
        args.get(2).unwrap().parse::<u16>().unwrap(),
    );

    connect(net_worth, (ip.to_string(), port)).unwrap();
}
