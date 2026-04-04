import { describe, it, expect } from 'vitest';
import { verifyEd25519Signature } from '../src/crypto';
import { generateEd25519Keypair, signPayload } from './helpers';

describe('Ed25519 crypto', () => {
  it('should verify a valid signature', async () => {
    const { publicKeyBase64, privateKey } = await generateEd25519Keypair();
    const message = '{"hello":"world"}';
    const signature = await signPayload(privateKey, message);
    const data = new TextEncoder().encode(message);

    const result = await verifyEd25519Signature(publicKeyBase64, signature, data);
    expect(result).toBe(true);
  });

  it('should reject an invalid signature', async () => {
    const { publicKeyBase64 } = await generateEd25519Keypair();
    const { privateKey: otherKey } = await generateEd25519Keypair();
    const message = '{"hello":"world"}';
    const signature = await signPayload(otherKey, message);
    const data = new TextEncoder().encode(message);

    const result = await verifyEd25519Signature(publicKeyBase64, signature, data);
    expect(result).toBe(false);
  });

  it('should reject when data is tampered', async () => {
    const { publicKeyBase64, privateKey } = await generateEd25519Keypair();
    const message = '{"hello":"world"}';
    const signature = await signPayload(privateKey, message);
    const data = new TextEncoder().encode('{"hello":"tampered"}');

    const result = await verifyEd25519Signature(publicKeyBase64, signature, data);
    expect(result).toBe(false);
  });

  it('should return false for invalid base64', async () => {
    const data = new TextEncoder().encode('test');
    const result = await verifyEd25519Signature('not-valid-base64!!!', 'also-invalid!!!', data);
    expect(result).toBe(false);
  });
});
