/*
  eac crypto routines for AES-GCM based on 'SharedAES-GCM'
*/

#include <stdio.h>
#include <stdlib.h>

#include <gcm/gcm.h>
#include <eac-encode.h>
#include <eac-crypto_gcm.h>


char log_message [8192];


int valid_buffer
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *bufobj)

{
  int valid;


  valid = 0;

  // if marked initialized, it's valid - trust the caller.
  if (bufobj->state_flags & EACOBJ_STATE_INIT)
    valid = 1;

  // if either 'encoded' or 'raw' is a pointer it's valid

  if ((unsigned long int)(bufobj->encoded) != 0)
  {
    valid = 1;
    if (ctx->verbosity > 3)
      if (!(bufobj->enc_lth))
        fprintf(stderr, "object 0x%lX encoded buffer but no length\n", (unsigned long)(bufobj));
  };
  if ((unsigned long int)(bufobj->raw) != 0)
  {
    valid = 1;
    if (ctx->verbosity > 3)
      if (!(bufobj->raw_lth))
        fprintf(stderr, "object 0x%lX raw buffer but no length\n", (unsigned long)(bufobj));
  };
  return(valid);
}


/*
  raw is input
  encoded is output
*/

int eac_crypto_encrypt_add
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key,
  EAC_ENCODE_OBJECT *input,
  EAC_ENCODE_OBJECT *output)

{ /* eac_crypto_encrypt_add */

  OB_CRYPTO_CONTEXT_GCM *internal;
  int status;
  int status_crypto;


  status = ST_OK;
  if (!(ctx->eac_log))
    status = STEAC_NO_LOGGER;
  if (!(key->internal))
    status = STEAC_MALLOC;
  if (!valid_buffer(ctx, input))
    status = STEAC_BUFFER;
  if (!valid_buffer(ctx, output))
    status = STEAC_BUFFER;
  if (status EQUALS ST_OK)
  {
    internal = key->internal;
    status_crypto = gcm_update(&(internal->gcm_ctx), 
      input->raw_lth, input->raw, output->encoded);
    if (status_crypto != 0)
      status = STEAC_ENCRYPT_ERROR;
  };
  return(status);

} /* eac_crypto_encrypt_add */


/*
  tbs is the otherwise INPUT object, this will use the ENCODED
  buffer in the input for the tag.
*/
int eac_crypto_encrypt_final
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key,
  EAC_ENCODE_OBJECT *tbs)

{
  OB_CRYPTO_CONTEXT_GCM *internal;
  int status;
  int status_crypto;


  status = ST_OK;
  if (!(ctx->eac_log))
    status = STEAC_NO_LOGGER;
  if (!(key->internal))
    status = STEAC_MALLOC;
  if (!valid_buffer(ctx, tbs))
    status = STEAC_BUFFER;
  if (status EQUALS ST_OK)
  {
    internal = key->internal;
    status_crypto = gcm_finish(&(internal->gcm_ctx), tbs->encoded, tbs->enc_lth);
    if (status_crypto != 0)
      status = STEAC_ENCRYPT_ERROR;
  };
  return(status);
}

/*
  iv is in key -> aux

  the input object contains the plaintext and/or to-be-mac'd (additional)
  data
*/
int eac_crypto_encrypt_init
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key,
  EAC_ENCODE_OBJECT *tbmac)

{ /* eac_crypto_encrypt_init */

  OB_CRYPTO_CONTEXT_GCM *internal;
  int status;
  int status_crypto;


  status = ST_OK;
  if (!(ctx->eac_log))
    status = STEAC_NO_LOGGER;
//  if (key->internal) // initialized here, not before status = STEAC_MALLOC;
  if (!valid_buffer(ctx, tbmac))
    status = STEAC_BUFFER;
  if (status EQUALS ST_OK)
  {
//  key->internal = malloc(sizeof(OB_CRYPTO_CONTEXT_GCM));
    if (key->internal EQUALS NULL)
      status = STEAC_MALLOC;
  };
  if (status EQUALS ST_OK)
  {
    internal = key->internal;
aes_init_keygen_tables();
    status_crypto = gcm_start(&(internal->gcm_ctx), ENCRYPT, key->aux, key->aux_lth, tbmac->raw, tbmac->raw_lth);
    if (status_crypto != 0)
      status = STEAC_ENCRYPT_ERROR;
  };
  return(status);

} /* eac_crypto_encrypt_init */


/*
  for AES-GCM param 1 is key length (must be 128)
  param 2 is tag length
  raw is the key
*/

int eac_crypto_set_key
  (EAC_ENCODE_CONTEXT *ctx,
  EAC_ENCODE_OBJECT *key)

{ /* eac_crypto_set_key */

  OB_CRYPTO_CONTEXT_GCM *internal;
  int status;
  int status_crypto;


  status = ST_OK;
  if (ctx->verbosity > 3)
  {
    sprintf(log_message, "set_key key length %d. octets\n", key->raw_lth);
    (ctx->eac_log)(log_message);
  };
  if (!(ctx->eac_log))
    status = STEAC_NO_LOGGER;
//  if (key->internal) status = STEAC_MALLOC; // the malloc happens here
  if (!valid_buffer(ctx, key))
    status = STEAC_BUFFER;

  if (status EQUALS ST_OK)
  {
    key->internal = malloc(sizeof(OB_CRYPTO_CONTEXT_GCM));
    if (key->internal EQUALS NULL)
      status = STEAC_MALLOC;
  };
  if (status EQUALS ST_OK)
  {
    internal = key->internal;
    memset(internal, 0, sizeof(OB_CRYPTO_CONTEXT_GCM));

    // apparently this just returns if already done so sprinkling them around?
    aes_init_keygen_tables();

    status_crypto = gcm_setkey(&(internal->gcm_ctx), key->raw, key->raw_lth);
    if (status_crypto != 0)
      status = STEAC_CRYPTO_INIT;
  };
  if (status EQUALS ST_OK)
    key->state_flags = key->state_flags | EACOBJ_STATE_INIT;
  return(status);

} /* eac_crypto_set_key */

