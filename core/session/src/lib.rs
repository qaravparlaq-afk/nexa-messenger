//! M v1 session-establishment primitive.
#![forbid(unsafe_code)]

use hkdf::Hkdf;
use nexa_identity::{IdentityKey, OneTimePrekey, SignedPrekey, SignedPrekeyRecord};
use nexa_protocol::{PreKeyBundle, ProtocolVersion, PROTOCOL_VERSION};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"M/SESSION/v1";
const ROOT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError { ProtocolVersion, InvalidSignedPrekey, InvalidPeerIdentity, InvalidSharedSecret, KeyDerivation }
pub struct InitiatorEphemeral { secret: Zeroizing<[u8; 32]>, pub public_key: [u8; 32] }
impl InitiatorEphemeral { pub fn generate() -> Self { let secret=StaticSecret::random_from_rng(rand_core::OsRng); Self{public_key:PublicKey::from(&secret).to_bytes(),secret:Zeroizing::new(secret.to_bytes())} } }
pub struct SessionRoot(Zeroizing<[u8; ROOT_LEN]>);
impl SessionRoot { pub fn as_bytes(&self)->&[u8;ROOT_LEN]{&self.0} }
pub struct InitiatorSession{pub root:SessionRoot,pub peer_device_id:[u8;16],pub used_one_time_prekey_id:Option<u32>}
pub struct ResponderSession{pub root:SessionRoot,pub peer_device_id:[u8;16],pub used_one_time_prekey_id:Option<u32>}

pub fn initiate(own_identity:&IdentityKey,own_device_id:[u8;16],own_ephemeral:&InitiatorEphemeral,bundle:&PreKeyBundle,signed_prekey_record:&SignedPrekeyRecord,one_time_prekey_public:Option<(u32,[u8;32])>)->Result<InitiatorSession,SessionError>{
    if bundle.protocol_version.0!=PROTOCOL_VERSION{return Err(SessionError::ProtocolVersion);}
    let peer_identity=ed25519_dalek::VerifyingKey::from_bytes(&bundle.identity_signing_key).map_err(|_|SessionError::InvalidPeerIdentity)?;
    if bundle.identity_agreement_key!=signed_prekey_record.agreement_public_key||!signed_prekey_record.verify(&peer_identity)||signed_prekey_record.key_id!=bundle.signed_prekey_id||signed_prekey_record.public_key!=bundle.signed_prekey{return Err(SessionError::InvalidSignedPrekey);}
    let own_ephemeral_secret=StaticSecret::from(*own_ephemeral.secret);
    let dh1=own_identity.agreement_diffie_hellman(&bundle.signed_prekey);
    let dh2=own_ephemeral_secret.diffie_hellman(&PublicKey::from(bundle.identity_agreement_key)).to_bytes();
    let dh3=own_ephemeral_secret.diffie_hellman(&PublicKey::from(bundle.signed_prekey)).to_bytes();
    if is_zero(&dh1)||is_zero(&dh2)||is_zero(&dh3){return Err(SessionError::InvalidSharedSecret);}
    let mut ikm=Vec::with_capacity(128);ikm.extend_from_slice(&dh1);ikm.extend_from_slice(&dh2);ikm.extend_from_slice(&dh3);
    let used_id=if let Some((id,public))=one_time_prekey_public{let dh4=own_ephemeral_secret.diffie_hellman(&PublicKey::from(public)).to_bytes();if is_zero(&dh4){return Err(SessionError::InvalidSharedSecret);}ikm.extend_from_slice(&dh4);Some(id)}else{None};
    let root=derive_root(&ikm,&own_device_id,&bundle.device_id,&own_ephemeral.public_key).ok_or(SessionError::KeyDerivation)?;ikm.zeroize();Ok(InitiatorSession{root,peer_device_id:bundle.device_id,used_one_time_prekey_id:used_id})
}

pub fn respond(own_identity:&IdentityKey,own_signed_prekey:&SignedPrekey,own_one_time_prekey:Option<(u32,OneTimePrekey)>,own_device_id:[u8;16],peer_device_id:[u8;16],peer_identity_agreement_key:[u8;32],peer_ephemeral_public:[u8;32])->Result<ResponderSession,SessionError>{
    let dh1=own_signed_prekey.diffie_hellman(&peer_identity_agreement_key);let dh2=own_identity.agreement_diffie_hellman(&peer_ephemeral_public);let dh3=own_signed_prekey.diffie_hellman(&peer_ephemeral_public);if is_zero(&dh1)||is_zero(&dh2)||is_zero(&dh3){return Err(SessionError::InvalidSharedSecret);}
    let mut ikm=Vec::with_capacity(128);ikm.extend_from_slice(&dh1);ikm.extend_from_slice(&dh2);ikm.extend_from_slice(&dh3);let used_id=if let Some((id,otp))=own_one_time_prekey{let dh4=otp.diffie_hellman(&peer_ephemeral_public);if is_zero(&dh4){return Err(SessionError::InvalidSharedSecret);}ikm.extend_from_slice(&dh4);Some(id)}else{None};let root=derive_root(&ikm,&peer_device_id,&own_device_id,&peer_ephemeral_public).ok_or(SessionError::KeyDerivation)?;ikm.zeroize();Ok(ResponderSession{root,peer_device_id,used_one_time_prekey_id:used_id})
}
fn derive_root(ikm:&[u8],initiator_device_id:&[u8;16],responder_device_id:&[u8;16],ephemeral_public:&[u8;32])->Option<SessionRoot>{if ikm.iter().all(|b|*b==0){return None;}let hk=Hkdf::<Sha256>::new(Some(DOMAIN),ikm);let mut info=Vec::with_capacity(70);info.extend_from_slice(&ProtocolVersion(PROTOCOL_VERSION).0.to_be_bytes());info.extend_from_slice(initiator_device_id);info.extend_from_slice(responder_device_id);info.extend_from_slice(ephemeral_public);let mut out=Zeroizing::new([0u8;ROOT_LEN]);hk.expand(&info,out.as_mut()).ok()?;Some(SessionRoot(out))}
fn is_zero(value:&[u8;32])->bool{value.iter().all(|b|*b==0)}

#[cfg(test)]
mod tests{
 use super::*;use nexa_identity::{prekeys::publishable_signed_prekey,IdentityKey};
 fn setup()->(IdentityKey,IdentityKey,SignedPrekey,SignedPrekeyRecord,PreKeyBundle){let a=IdentityKey::generate();let b=IdentityKey::generate();let spk=SignedPrekey::generate();let record=publishable_signed_prekey(&b,1,&spk);let bundle=PreKeyBundle{protocol_version:ProtocolVersion(PROTOCOL_VERSION),device_id:[7;16],identity_signing_key:b.public_key().to_bytes(),identity_agreement_key:b.agreement_public_key(),signed_prekey_id:record.key_id,signed_prekey:record.public_key,signed_prekey_signature:record.signature,one_time_prekeys:vec![]};(a,b,spk,record,bundle)}
 #[test]fn initiator_and_responder_derive_same_root(){let(a,b,spk,record,bundle)=setup();let eph=InitiatorEphemeral::generate();let i=initiate(&a,[8;16],&eph,&bundle,&record,None).unwrap();let r=respond(&b,&spk,None,[7;16],[8;16],a.agreement_public_key(),eph.public_key).unwrap();assert_eq!(i.root.as_bytes(),r.root.as_bytes());}
 #[test]fn tampered_agreement_key_rejects_session(){let(a,_,spk,record,mut bundle)=setup();bundle.identity_agreement_key[0]^=1;let eph=InitiatorEphemeral::generate();assert!(matches!(initiate(&a,[8;16],&eph,&bundle,&record,None),Err(SessionError::InvalidSignedPrekey)));let _=spk;}
 #[test]fn one_time_prekey_must_be_the_same_key_on_both_sides(){let(a,b,spk,record,mut bundle)=setup();let otp=OneTimePrekey::generate(9);let otp_public=otp.public_key();bundle.one_time_prekeys.push(nexa_protocol::OneTimePrekeyPublic{key_id:9,public_key:otp_public});let eph=InitiatorEphemeral::generate();let i=initiate(&a,[8;16],&eph,&bundle,&record,Some((9,otp_public))).unwrap();let r=respond(&b,&spk,Some((9,otp)),[7;16],[8;16],a.agreement_public_key(),eph.public_key).unwrap();assert_eq!(i.root.as_bytes(),r.root.as_bytes());assert_eq!(i.used_one_time_prekey_id,r.used_one_time_prekey_id);}
}
