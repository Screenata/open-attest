export async function verifyEd25519Signature(
  publicKeyBase64: string,
  signatureBase64: string,
  data: Uint8Array,
): Promise<boolean> {
  try {
    const publicKeyBytes = base64ToBytes(publicKeyBase64);
    const signatureBytes = base64ToBytes(signatureBase64);

    const key = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );

    return await crypto.subtle.verify('Ed25519', key, signatureBytes, data);
  } catch {
    return false;
  }
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
