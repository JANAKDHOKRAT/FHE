#include "data.h"
#include "lazer.h"
#include "params.h"
#include <time.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static size_t g_prooflen;

void
prover (uint8_t *proof, polyvec_t s, polymat_t A, polyvec_t t,
        const uint8_t pp[32])
{
  lin_prover_state_t prover;
  lin_prover_init (prover, pp, params);
  lin_prover_set_statement (prover, A, t);
  lin_prover_set_witness (prover, s);
  lin_prover_prove (prover, proof, &g_prooflen, NULL);
  lin_prover_clear (prover);
}

int
verifier (const uint8_t *proof, polymat_t A, polyvec_t t, const uint8_t pp[32])
{
  lin_verifier_state_t verifier;
  lin_verifier_init (verifier, pp, params);
  lin_verifier_set_statement (verifier, A, t);
  int accept = lin_verifier_verify (verifier, proof, NULL);
  lin_verifier_clear (verifier);
  return accept;
}

int
main (void)
{
  lazer_init ();

  INT_T (p, 1);
  int_set_i64 (p, 3329);            // Kyber1024 prime modulus
  POLYRING_T (Rp, p, 256);      // Kyber1024 degree 256 ring
  const uint8_t pp[32] = { 0 }; // toy public randomness

  polymat_t A, A1, Id; // A=A1||Id
  polyvec_t s;         // secret
  polyvec_t t;         // t=As

  polymat_alloc (A, Rp, 4, 8);
  polyvec_alloc (s, Rp, 8);
  polyvec_alloc (t, Rp, 4);

  printf ("load statement As=t, s small ... ");
  
  polymat_get_submat (A1, A, 0, 0, 4, 4, 1, 1);
  polymat_set_i64 (A1, A1_);
  polymat_get_submat (Id, A, 0, 4, 4, 4, 1, 1);
  polymat_set_one (Id);
  polyvec_set_coeffvec_i64 (s, s_);
  polyvec_set_coeffvec_i64 (t, t_);
  polyvec_neg_self (t);
  
  printf ("[OK]\n");

  printf ("prover generates PoK of s: As-t=0, s small ... ");
  
  uint8_t proof[50000]; // some upper bound on proof size
  double tp=0,tv=0; int accept=1; int runs=20;
  for(int i=0;i<runs;i++){
    double a=now(); prover (proof, s, A, t, pp); double b=now();
    int ok = verifier (proof, A, t, pp); double c=now();
    tp+=b-a; tv+=c-b; accept&=ok;
  }
  printf ("[OK]\n");
  printf ("runs %d: proof %zu bytes, prover mean %.1f ms, verifier mean %.1f ms, all accepted %d\n", runs, g_prooflen, 1000*tp/runs, 1000*tv/runs, accept);
  printf ("verifier verifies proof ... %s\n", accept ? "[OK]" : "[FAILED]");

  polymat_free (A);
  polyvec_free (s);
  polyvec_free (t);
  return 0;
}
