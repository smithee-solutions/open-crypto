/*
  eac-crypto_symkey_stubs - stub versions of symmetric key crypto routines
*/


#include <string.h>
#include <stdlib.h>


#include <aes.h>


#include <eac-encode.h>
#include <eac-crypto_tiny-crypto.h>


int eac_crypto_encrypt_add
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key,
  EAC_ENCODE_OBJECT *input,
  EAC_ENCODE_OBJECT *output)

{ /* eac_crypto_encrypt_add for tiny-AES-c */

  OB_CRYPTO_CONTEXT_TINY_CRYPTO *internal;
  int status;
  unsigned char tmp [1024];


  status = ST_OK;
// check internal, check tmp long enough, check even number of cipherblocks
  internal = (OB_CRYPTO_CONTEXT_TINY_CRYPTO *)(key->internal);
  memcpy(tmp, input->raw, input->raw_lth);
  AES_CBC_encrypt_buffer(&(internal->aes_context), tmp, input->raw_lth);
  memcpy(output->raw, tmp, input->raw_lth);
  output->raw_lth = input->raw_lth;

  return(status);

} /* eac_crypto_encrypt_add for tiny-AES-c */


/*
  for tiny-AES-c there is no 'final' so it's a no-op
*/

int eac_crypto_encrypt_final
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key,
  EAC_ENCODE_OBJECT *tag)

{ /* eac_crypto_encrypt_final for tiny-AES-c */

 return(ST_OK);

} /* eac_crypto_encrypt_final for tiny-AES-c */


// raw of a key is the key material
// aux of a key is the IV

int eac_crypto_encrypt_init
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key,
  EAC_ENCODE_OBJECT *session)

{ /* eac_crypto_encrypt_init for tiny-AES-c */

  OB_CRYPTO_CONTEXT_TINY_CRYPTO *internal;
  int status;


  status = ST_OK;
  internal = (OB_CRYPTO_CONTEXT_TINY_CRYPTO *)(key->internal);
  AES_init_ctx(&(internal->aes_context), key->raw);
  AES_ctx_set_iv(&(internal->aes_context), key->aux);
  return(status);

} /* eac_crypto_encrypt_init for tiny-AES-c */


int eac_crypto_internal_allocate
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *object)

{ /* eac_crypto_internal_object */

  int status;


  status = ST_OK;
  object->internal = malloc(sizeof(OB_CRYPTO_CONTEXT_TINY_CRYPTO));
  if (object->internal EQUALS NULL)
    status = STEAC_MALLOC;
  return(status);

} /* eac_crypto_internal_allocate */


int eac_crypto_set_key
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key)

{ /* eac_crypto_set_key */

  int status;


  status = ST_OK;
  if ((key->key_parameters [0] EQUALS EAC_CRYPTO_AES) &&
    (key->key_parameters [2] EQUALS EAC_KEY_AES_MODE_CBC))
  {
    status = ST_OK;  // no operation, key material came in in raw, stays there.
  };
  if ((key->key_parameters [0] EQUALS EAC_CRYPTO_AES) &&
    (key->key_parameters [2] EQUALS EAC_KEY_AES_MODE_GCM))
  {
    status = -3;
  };

  return(status);

} /* eac_crypto_set_key */


