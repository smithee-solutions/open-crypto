/*
  eac-crypto_gcm - implementation-specific data structures for AES-GCM

  the "internal" field of the generic eac-encode key data structure points to this.

  (C)Copyright 2024 Smithee Solutions LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


typedef struct ob_crypto_context_gcm
{
  gcm_context gcm_ctx;
  unsigned char key [128/8];
  unsigned char iv [128/8];
} OB_CRYPTO_CONTEXT_GCM;

