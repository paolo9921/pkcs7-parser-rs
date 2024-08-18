/*
Verification of the signature
Verification of the validity period
Checking the revocation status
Verification of trust (certificate path)

*/


use bcder::OctetString;
#[allow(dead_code)]
use bcder::{Oid, Tag, Mode};
use bcder::decode::{self, Constructed, DecodeError};
use std::fs::File;
use std::io::Read;

//use chrono::{NaiveDateTime, TimeZone, Utc};
//use ring::signature::{self, UnparsedPublicKey};

pub struct Pkcs7 {
    pub content_type: Oid,
    pub content: Vec<Certificate>,
    //pub signatures: Vec<Signature>,
}

pub struct Signature {
    pub algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
}

pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}
pub struct TbsCertificate {
    pub version: Option<u8>,
    pub serial_number: String,
    pub signature_algorithm: AlgorithmIdentifier,
    pub issuer: Vec<u8>,
    pub validity: Validity,
    pub subject: Vec<u8>,
    pub subject_public_key_info: SubjectPublicKeyInfo,
}
pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Option<Vec<u8>>,
}
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
}
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: Vec<u8>,
}
/* 
#[derive(Debug)]
enum VerifyError {
    UnsupportedAlgorithm,
    InvalidSignature,
    CertificateExpired,
    UntrustedCertificate,
}
impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for VerifyError {}

*/

impl Pkcs7 {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = Oid::take_from(cons)?;
            //println!("Parsed content_type: {:?}", content_type);

            let content = cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    
                    // parse SignedData
                    let cms_version = cons.capture_one().expect("cms version");
                    let digest_algo_id = cons.capture_one().expect("digest_algo_id");
                    //println!("digest_algo_id {:?}",digest_algo_id);
                    //let encap_content_info = cons.capture_one().expect("encap_content_info");
                    //println!("encap_content {:?}",encap_content_info);
                    
                    // we need the e_content_octet to calculate the digest of the message
                    /*let e_content_octet = cons.take_sequence(|cons|{
                        let content_type = Oid::take_from(cons)?;
                        println!("content_type {:?}",content_type);
                        let e_content_octet = OctetString::take_opt_from(cons);
                    
                        Ok(e_content_octet)
                    });
                    
                    println!("e_content_octet: {:?}",e_content_octet);*/

                    let encap_content_info = cons.take_sequence(|eContCons|{
                        let e_content_type = Oid::take_from(eContCons)?;
                        println!("econtenttype {}",e_content_type);
                        Ok(e_content_type)
                    });
                    println!("Parsed content_info_type: {:?}", encap_content_info);
                    
                    
                    
                    // Parse CertificateSet
                    let cert_set = cons.take_constructed_if(Tag::CTX_0, |cons| {

                        let a = cons.skip_one();
                        //println!("a {:?}",a);
                        let mut certificates = Vec::new();                        

                        // Read the CertificateChoices
                        while let Ok(cert) = Certificate::take_from(cons) {
                            //println!("Parsed certificate: {:?}", cert.to_string());
                            certificates.push(cert);
                        }

                        Ok(certificates)
                    })?;
                    println!("Parsed all certificates");
                    let signer_infos = cons.capture_all();
                    Ok(cert_set)
                })
            })?;

            Ok(Pkcs7 {
                content_type,
                content,
            })
        })
    }

    pub fn to_string(&self) -> String {
        let mut content_string = String::new();
        for x in &self.content {
            content_string.push_str(&format!("{}\n", x.to_string()));
        }

        format!(
            "Pkcs7 {{\n  content_type: {},\n  content: \n{}\n}}",
            self.content_type.to_string(),
            content_string,
        )
    }
}

/*impl Signature {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let algorithm = AlgorithmIdentifier::take_from(cons)?;
            let signature = cons.take_value(|_, content| {
                let sign = content.as_primitive().map_err(|e| {
                    DecodeError::content(format!("Expected primitive content: {}", e), decode::Pos::default())
                })?;
                let sign_bytes = sign.slice_all()?.to_vec();
                Ok(sign_bytes)
            })?;
            _=cons.skip_all();
            Ok(Signature {
                algorithm,
                signature,
            })
        })
    }
}*/

impl Certificate {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let tbs_certificate = TbsCertificate::take_from(cons)?;
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let signature_value = cons.take_value(|_,content| {
                let sign = content.as_primitive().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let mut sign_bytes = sign.slice_all()?.to_vec();
                sign_bytes.drain(0..1);
                //let hex_bytes = hex::encode(&sign_bytes);
                _=sign.skip_all();
                Ok(sign_bytes)
            })?;

            //println!("parsing certificate, sig : {:?}",signature_algorithm.to_string());
            Ok(Certificate {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
            
        })
    }
    

    pub fn to_string(&self) -> String {
        format!(
            "Certificate {{\n  tbs_certificate: {},\n  signature_algorithm: {},\n  signature_value: {:?}\n}}",
            self.tbs_certificate.to_string(),
            self.signature_algorithm.to_string(),
            self.signature_value,
        )
    }

    /*pub fn verify(&self, trusted_root_cert: &[Certificate]) -> Result<(), Box<dyn std::error::Error>> {

        self.verify_signature()?;

        self.verify_validity()?;

        //self.verify_trust(trusted_root_cert)?;

        Ok(())
    }


    fn verify_signature(&self) -> Result<(), Box<dyn std::error::Error>> {
        let tbs_cert_bytes = self.tbs_certificate.encode_to_der()?;
        println!("tbs_bytes {:?}",tbs_cert_bytes);
        let sig_bytes = hex::decode(&self.signature_value)?;

        let alg_oid = self.signature_algorithm.algorithm;
        let alg = match alg_oid.to_string().as_str() {
            "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256,
            _ => return Err(Box::new(VerifyError::UnsupportedAlgorithm)),
        };

        let public_key_bytes = hex::decode(&self.tbs_certificate.subject_public_key_info.subject_public_key)?;
        let public_key = UnparsedPublicKey::new(alg, &public_key_bytes);

        public_key.verify(&tbs_cert_bytes, &sig_bytes).map_err(|_| Box::new(VerifyError::InvalidSignature))?;


        Ok(())
    }

    fn verify_validity(&self) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now();
        let n_now = now.format(("%y%m%d%H%M%SZ"));

        let format = "%y%m%d%H%M%SZ";
        let not_before_date = NaiveDateTime::parse_from_str(&self.tbs_certificate.validity.not_before, format).expect("Failed formatting date");
        let not_after_date = NaiveDateTime::parse_from_str(&self.tbs_certificate.validity.not_after, format).expect("Failed formatting date");
        let now_date = NaiveDateTime::parse_from_str(&n_now.to_string(), format).expect("Failed formatting date");

        if now_date < not_before_date || now_date > not_after_date {
            return Err(Box::new(VerifyError::CertificateExpired));
        }

        Ok(())
    }*/

}

impl TbsCertificate {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            
            //version = optional field
            let version = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                cons.take_primitive_if(Tag::INTEGER, |content| {
                    content.to_u8()
                })
                //println!("[tbs] version {:?}",version);
            })?;
            
            let serial_number = cons.take_primitive(|_,content| {
                let bytes = content.slice_all()?.to_vec();     
                let hex_bytes = hex::encode(&bytes); 
                _ = content.skip_all();
                //println!("[tbs] Serial Number Bytes: {:?}", serial_number);
                Ok(hex_bytes)
            })?;
            
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;

            // only byte vec, for more detailed issuer, take it as a SEQUENCE and parse...
            let issuer = cons.take_value_if(Tag::SEQUENCE, |content| {
                let constructed_content = content.as_constructed().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let issuer_bytes = constructed_content.capture_all()?;
                let issuer_vec = issuer_bytes.to_vec();

                Ok(issuer_vec)
            })?;

            //asn1 format YYMMDDHHMMSSZ
            let validity = Validity::take_from(cons)?;

            //same as issuer
            let subject = cons.take_value_if(Tag::SEQUENCE, |content| {
                let constructed_content = content.as_constructed().map_err(|e|{
                    DecodeError::content(format!("Expected constructed content: {}", e), decode::Pos::default())
                })?;
                
                let issuer_bytes = constructed_content.capture_all()?;
                let subject_vec = issuer_bytes.to_vec();
                //println!("sub {:?}",subject_vec);
                Ok(subject_vec)
            })?;

            let subject_public_key_info = SubjectPublicKeyInfo::take_from(cons)?;

            _ = cons.skip_all();
            
            Ok(TbsCertificate {
                version,
                serial_number,
                signature_algorithm,
                issuer,
                validity,
                subject,
                subject_public_key_info,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "TbsCertificate {{\n    version: {:?},\n    serial_number: {:?},\n    signature_algorithm: {},\n    issuer: {:?},\n    validity: {},\n    subject: {:?},\n    subject_public_key_info: {}\n  }}",
            self.version,
            self.serial_number,
            self.signature_algorithm.to_string(),
            self.issuer,
            self.validity.to_string(),
            self.subject,
            self.subject_public_key_info.to_string()
        )
    }
  

}

impl AlgorithmIdentifier {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let algorithm = Oid::take_from(cons)?;
            let parameters = None; //not needed
            _= cons.skip_all();
             
            Ok(AlgorithmIdentifier {
                algorithm,
                parameters,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "AlgorithmIdentifier {{\n    algorithm: {},\n    parameters: {:?}\n  }}",
            self.algorithm.to_string(),
            self.parameters
        )
    }
}

impl Validity {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {

            let not_before = cons.take_primitive(|_,content| {
                let bytes = content.slice_all()?;
                
                let time_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())
                })?;
                _=content.skip_all();
                Ok(time_str)
            })?;
 
            println!("#########notbefore: {}",not_before);
            let not_after = cons.take_primitive(|_,content| {
                let bytes = content.slice_all()?;
                
                let time_str = String::from_utf8(bytes.to_vec()).map_err(|_| {
                    DecodeError::content("Invalid UTF-8 sequence", decode::Pos::default())
                })?;
                _=content.skip_all();
                Ok(time_str)
            })?;

            Ok(Validity {
                not_before,
                not_after,
            })
        })
    }
    pub fn to_string(&self) -> String {
        format!(
            "Validity {{\n    not_before: {},\n    not_after: {}\n  }}",
            self.not_before,
            self.not_after
        )
    }
}

impl SubjectPublicKeyInfo {
    pub fn take_from<S: decode::Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            
            let algorithm = AlgorithmIdentifier::take_from(cons)?;

            let subject_public_key = cons.take_primitive(|_, content| {
                let mut key_bytes = content.slice_all()?.to_vec();
                _= content.skip_all();

                //remove first 9 -> Tag, sequence, ecc; last 5 -> exp
                if key_bytes.len() > 14 {
                    key_bytes.drain(0..9);
                    key_bytes.truncate(key_bytes.len()-5); //exp
                }
                else {
                    println!("Failed to load pub Key");
                    }
                
                Ok(key_bytes)
                //let hex_bytes = hex::encode(&key_bytes);
                //Ok(hex_bytes)
            })?;
            _ = cons.skip_all();
            
            //println!("subpubkey {:?}", subject_public_key);

            Ok(SubjectPublicKeyInfo {
                algorithm,
                subject_public_key,
            })
        })
    }  
    pub fn to_string(&self) -> String {
        format!(
            "SubjectPublicKeyInfo {{\n    algorithm: {},\n    subject_public_key: {:?}\n  }}",
            self.algorithm.to_string(),
            self.subject_public_key
        )
    }     
}

/* load single x509 file

fn load_certificate(path: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let pem = pem::parse(buffer)?;
    let bytes = pem.contents();

    let cert = Constructed::decode(bytes, Mode::Der, |constructed| {
        Certificate::take_from(constructed)
    }).map_err(|err| {
        eprintln!("Error decoding certificate: {:?}", err);
        Box::new(err) as Box<dyn std::error::Error>
    })?;
    
    Ok(cert)/* 
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let cert = X509::from_der(&buffer)?;
    Ok(cert)*/
}
*/

fn load_pkcs7(path: &str) -> Result<Pkcs7, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let pem = pem::parse(buffer)?;
    let bytes = pem.contents();

    let pkcs7 = Constructed::decode(bytes, Mode::Der, |constructed| {
        Pkcs7::take_from(constructed)
    }).map_err(|err| {
        eprintln!("Error decoding PKCS#7: {:?}", err);
        Box::new(err) as Box<dyn std::error::Error>
    })?;

    Ok(pkcs7)
}

use std::time::{SystemTime, UNIX_EPOCH};


fn main() {
    match load_pkcs7("../rchain.p7b") {
        Ok(pkcs7) => {
            println!("PKCS#7 file loaded successfully!");
            println!("{:?}",pkcs7.content[0].tbs_certificate.validity.not_after);
            let a = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            println!("now {}", a)

        },
        Err(e) => println!("Failed to load PKCS#7 file: {}", e),
    }
}
    


