//! Parse/reencode actual public fixtures using the unchanged Rust wire codec.
use fhe_prio3::{messages::{self,Report},packed::{WireFormat,Expect}};
use serde_json::{Value,json};
use std::{fs,path::PathBuf};
fn main(){
 let args:Vec<_>=std::env::args().collect();assert!(args.len()==3||args.len()==4);
 let params:Value=serde_json::from_str(&fs::read_to_string(&args[1]).unwrap()).unwrap();
 let q=params["q"].as_array().unwrap().iter().map(|x|x.as_u64().unwrap()).collect::<Vec<_>>();
 let root=PathBuf::from(&args[2]);let pk=fs::read(root.join("public_key.bin")).unwrap();
 let format=WireFormat::new(65537,32768,q.clone(),&pk).unwrap();
 let bytes=fs::read(root.join("report.bin")).unwrap();let report:Report=messages::decode(&bytes).unwrap();
 assert_eq!(report.task_id,[0xE9;32]);assert_eq!(report.group,0);assert_eq!(report.chunks.len(),1);assert!(report.auth.is_none());
 assert_eq!(report.report_id,Report::compute_id(&report.task_id,report.group,&report.chunks));
 assert_eq!(messages::encode(&report).unwrap(),bytes);
 let(meta,residues)=format.parse(&report.chunks[0],Expect::Any).unwrap();
 assert_eq!(meta.level,0);assert_eq!(meta.num_elements,2);assert_eq!(meta.num_towers as usize,q.len());
 assert_eq!(format.encode_raw(&meta,&residues).unwrap(),report.chunks[0]);
 for offset in [0,4,5,6,13,24]{let mut bad=report.chunks[0].clone();bad[offset]^=0x80;assert!(format.parse(&bad,Expect::Exactly(meta)).is_err());}
 let mut short=report.chunks[0].clone();short.pop();assert!(format.parse(&short,Expect::Exactly(meta)).is_err());
 let output=root.join("aggregate.bin");let mut output_bytes=None;
 if output.exists(){
  let wire=fs::read(output).unwrap();let chunks:Vec<Vec<u8>>=messages::decode(&wire).unwrap();
  assert_eq!(chunks.len(),1);assert_eq!(messages::encode(&chunks).unwrap(),wire);
  let(m,v)=format.parse(&chunks[0],Expect::Any).unwrap();assert_eq!(m.level,23);
  assert_eq!(format.encode_raw(&m,&v).unwrap(),chunks[0]);
  assert!(format.parse(&chunks[0],Expect::Exactly(meta)).is_err());output_bytes=Some(wire.len());
 }else{assert!(args.len()!=4,"aggregate required but not yet available");}
 println!("{}",json!({"status":if output_bytes.is_some(){"FULL_CODEC_PASS"}else{"REPORT_CODEC_PASS"},"report_bytes":bytes.len(),"collector_output_bytes":output_bytes,"aggregate_checked":output_bytes.is_some(),"negative_parser_cases":7,"scope":"unchanged Rust wire parsing and byte-exact reencoding; no encrypted/security proof rerun"}));
}
