import type { StoredTotpCredential, TotpCredentialStore } from "./stores.js";
import type { UserId } from "./types.js";

export interface EncryptedTotpCredentialStoreOptions {
  store: TotpCredentialStore;
  key: Uint8Array;
  ivBytes?: number;
}

export class EncryptedTotpCredentialStore implements TotpCredentialStore {
  private readonly store: TotpCredentialStore;
  private readonly key: Uint8Array;
  private readonly ivBytes: number;

  constructor(options: EncryptedTotpCredentialStoreOptions) {
    this.store = options.store;
    this.key = options.key;
    this.ivBytes = options.ivBytes ?? 12;
  }

  public async setTotpCredential(
    credential: StoredTotpCredential,
  ): Promise<void> {
    await this.store.setTotpCredential({
      ...credential,
      key: await encryptAesGcm(credential.key, this.key, this.ivBytes),
    });
  }

  public async getTotpCredential(
    userId: UserId,
  ): Promise<StoredTotpCredential | null> {
    const credential = await this.store.getTotpCredential(userId);
    if (credential === null) {
      return null;
    }
    return {
      ...credential,
      key: await decryptAesGcm(credential.key, this.key, this.ivBytes),
    };
  }

  public async deleteTotpCredential(userId: UserId): Promise<void> {
    await this.store.deleteTotpCredential(userId);
  }
}

export async function encryptAesGcm(
  data: Uint8Array,
  key: Uint8Array,
  ivBytes = 12,
): Promise<Uint8Array> {
  const iv = new Uint8Array(ivBytes);
  crypto.getRandomValues(iv);
  const cryptoKey = await importAesGcmKey(key);
  const dataBuffer = toArrayBuffer(data);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, dataBuffer),
  );
  const output = new Uint8Array(iv.length + encrypted.length);
  output.set(iv, 0);
  output.set(encrypted, iv.length);
  return output;
}

export async function decryptAesGcm(
  encrypted: Uint8Array,
  key: Uint8Array,
  ivBytes = 12,
): Promise<Uint8Array> {
  const iv = encrypted.slice(0, ivBytes);
  const data = encrypted.slice(ivBytes);
  const cryptoKey = await importAesGcmKey(key);
  const dataBuffer = toArrayBuffer(data);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, dataBuffer),
  );
}

async function importAesGcmKey(key: Uint8Array): Promise<CryptoKey> {
  if (![16, 24, 32].includes(key.byteLength)) {
    throw new Error("AES-GCM key must be 16, 24, or 32 bytes.");
  }
  const keyBuffer = toArrayBuffer(key);
  return crypto.subtle.importKey("raw", keyBuffer, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
