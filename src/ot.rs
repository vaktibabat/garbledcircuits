use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use crate::crypto::rsa::{Keypair, PublicKey};

/// Oblivious transfer
/// Alice (the Sender) has two messages m_0 and m_1. Bob (the Receiver) wants to receive
/// message m_b, without Alice finding out which message he received
pub struct ObTransferSender {
    msgs: (BigUint, BigUint),
    /// RSA keypair
    keypair: Keypair,
    /// Random messages
    xs: (BigUint, BigUint),
}

/// OT from the receiver's POV
pub struct ObTransferReceiver {
    /// The xs sent by the sender
    xs: (BigUint, BigUint),
    /// Used to blind the message index
    k: BigUint,
    /// Sender's pubkey
    sender_pubkey: PublicKey,
}

impl ObTransferSender {
    /// Generate a new sender
    pub fn new(msgs: (BigUint, BigUint), keypair: Keypair) -> ObTransferSender {
        // The x's are two random messages smaller than the RSA modulus
        let xs = (
            thread_rng().gen_biguint_below(&keypair.public.n),
            thread_rng().gen_biguint_below(&keypair.public.n),
        );

        ObTransferSender {
            msgs,
            keypair,
            xs,
        }
    }

    /// Generate the combined messages that allow the receiver to derive the message they want
    /// v is the blinded x the receiver wants
    pub fn gen_combined(&self, v: BigUint) -> (BigUint, BigUint) {
        let n = &self.keypair.public.n;
        let (x_0, x_1) = &self.xs;
        let (k_0, k_1) = (
            self.keypair.private.decrypt(&((&v + (n - x_0)) % n)),
            self.keypair.private.decrypt(&((&v + (n - x_1)) % n)),
        );
        // Combine with the secret messages
        let (m_0, m_1) = &self.msgs;

        ((m_0 + k_0) % n, (m_1 + k_1) % n)
    }

    pub fn msgs(&self) -> (BigUint, BigUint) {
        self.msgs.clone()
    }

    pub fn keypair(&self) -> Keypair {
        self.keypair.clone()
    }

    pub fn xs(&self) -> (BigUint, BigUint) {
        self.xs.clone()
    }
}

impl ObTransferReceiver {
    pub fn new(sender_pubkey: PublicKey, xs: (BigUint, BigUint)) -> ObTransferReceiver {
        let k = thread_rng().gen_biguint_below(&sender_pubkey.n);

        ObTransferReceiver {
            xs,
            k,
            sender_pubkey,
        }
    }

    /// Generate the blinded x_b given the index b
    pub fn blind_idx(&self, b: usize) -> BigUint {
        ((if b == 0 {
            &self.xs.0
        } else {
            &self.xs.1
        }) + self.k.modpow(&self.sender_pubkey.e, &self.sender_pubkey.n))
            % &self.sender_pubkey.n
    }

    /// Derive the selected message from the sender's reply
    pub fn derive_msg(&self, m_primes: (BigUint, BigUint), b: usize) -> BigUint {
        ((if b == 0 { m_primes.0 } else { m_primes.1 }) + (&self.sender_pubkey.n - &self.k))
            % &self.sender_pubkey.n
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::rsa::Keypair;

    use super::{ObTransferReceiver, ObTransferSender};

    #[test]
    fn oblivious_transfer_test() {
        let sender_pubkey = Keypair::new(None, None);
        // The sender has two messages
        let sender = ObTransferSender::new((123u64.into(), 456u64.into()), sender_pubkey.clone());
        // Receiver wants to get one of the messages, w/o the sender knowing which message
        // was sent
        // First of all, we need to get the sender's public parameters (in real usage, these would be sent over the network)
        let xs = sender.xs();
        let receiver = ObTransferReceiver::new(sender_pubkey.public, xs);
        // In this case, the receiver wants to get message 0 (123), so he blinds x_0
        let v = receiver.blind_idx(0);
        // The receiver then sends v to the sender, and the sender responds with m_prime_0 and m_prime_1
        // from which m_b can be derived
        let m_primes = sender.gen_combined(v);
        // The receiver then uses these to extract the desired message
        let extracted_msg = receiver.derive_msg(m_primes, 0);
        // The extracted message should be equal to the original one
        assert_eq!(extracted_msg, sender.msgs().0);
    }
}
