use millionaire::{
    backend::garbler_backend::{
        construct_circuit, protos::{EvalResult, OtBlindedIdx, OtEncMessages, RsaPubkey, Xs}, send_garbled_circuit, send_input_keys
    },
    crypto::rsa::Keypair,
    message::MessageStream,
    ot::ObTransferSender,
};
use num_bigint::BigUint;
use std::{
    env,
    io::{self, stdin, stdout, Write},
    net::TcpListener,
};

fn get_net_worth() -> usize {
    let mut input = String::new();

    print!("How much $ do you have? (in millions): ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).expect("Failed to read line");
    input = input.trim().to_lowercase();

    input.parse::<usize>().unwrap()
}

fn listen(net_worth: usize, params: (String, u16)) -> Result<bool, io::Error> {
    let listener = TcpListener::bind(format!("{}:{}", params.0, params.1)).unwrap();
    let circuit = construct_circuit(10);
    let input_keys = circuit.input_keys();
    let keypair = Keypair::new(None, None);

    println!("Keypair generated");

    if let Some(stream) = listener.incoming().next() {
        let mut stream = stream.unwrap();
        // Send the client the circuit
        send_garbled_circuit(&mut stream, circuit.clone())?;
        // Send the receiver our input keys
        send_input_keys(&mut stream, &circuit, net_worth)?;
        // Send the receiver our RSA public key
        let mut pubkey_msg = RsaPubkey::new();
        pubkey_msg.e = keypair.public.e.to_bytes_be();
        pubkey_msg.n = keypair.public.n.to_bytes_be();

        MessageStream::<RsaPubkey>::send_msg(&mut stream, pubkey_msg)?;
        // Proceed with n/2 rounds of OT to send the receiver its keys
        for i in circuit.n() / 2..circuit.n() {
            let wire = input_keys.get(&i).unwrap();
            let msgs = (
                BigUint::from_bytes_be(&wire.off_key()),
                BigUint::from_bytes_be(&wire.on_key()),
            );
            let sender = ObTransferSender::new(msgs, keypair.clone());
            // Send the x values
            let mut xs = Xs::new();
            let xs_bigints = sender.xs();
            xs.x_0 = xs_bigints.0.to_bytes_be();
            xs.x_1 = xs_bigints.1.to_bytes_be();

            MessageStream::<Xs>::send_msg(&mut stream, xs)?;
            // Receive the blinded index from the message
            let blinded_idx = MessageStream::<OtBlindedIdx>::receive_msg(&mut stream)?;
            // Respond with the m_primes
            let m_primes = sender.gen_combined(BigUint::from_bytes_be(&blinded_idx.v));
            let mut m_primes_msg = OtEncMessages::new();
            m_primes_msg.m_prime_0 = m_primes.0.to_bytes_be();
            m_primes_msg.m_prime_1 = m_primes.1.to_bytes_be();

            MessageStream::<OtEncMessages>::send_msg(&mut stream, m_primes_msg)?;
        }

        let result = MessageStream::<EvalResult>::receive_msg(&mut stream)?;

        if result.result {
            println!("The garbler is richer!");
        } else {
            println!("The receiver is richer!");
        }
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
    // Start the garbling server
    listen(net_worth, (ip.to_string(), port)).unwrap();
}
