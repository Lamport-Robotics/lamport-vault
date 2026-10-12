/** Splitting a staged signature into `write_sig` chunks. */

/** Largest chunk that keeps a `write_sig` transaction under the 1232-byte packet limit with room to spare. */
export const MAX_CHUNK_BYTES = 900;

export interface SigChunk {
  readonly offset: number;
  readonly bytes: Uint8Array;
}

/** Sequential chunks covering `sig`; the program requires each `offset == filled`. */
export function chunkSignature(sig: Uint8Array, chunkSize = MAX_CHUNK_BYTES): SigChunk[] {
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_BYTES) {
    throw new RangeError(`chunkSize must be in 1..${MAX_CHUNK_BYTES}`);
  }
  const chunks: SigChunk[] = [];
  for (let offset = 0; offset < sig.length; offset += chunkSize) {
    chunks.push({ offset, bytes: sig.slice(offset, Math.min(sig.length, offset + chunkSize)) });
  }
  return chunks;
}
