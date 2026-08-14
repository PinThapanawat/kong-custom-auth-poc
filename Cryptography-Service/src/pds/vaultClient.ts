import * as crypto from "node:crypto";
import NodeVault from "node-vault";

// Startup key material provisioning against HashiCorp Vault (dev mode).
// Replaces the old `initKeys()` (regenerated an ephemeral RSA keypair on
// every process restart) with a read-or-generate-and-persist pattern: keys
// now survive `Cryptography-Service` restarts as long as the Vault dev container
// itself stays up. Vault dev mode is in-memory and loses everything on its
// *own* restart — that caveat just moves one layer down, it isn't solved by
// this change, and is documented as a POC simplification (production Vault
// would use a real storage backend + AppRole auth scoped to only these
// three `pds/*` paths, not a shared root token).

const VAULT_ADDR = process.env.VAULT_ADDR ?? "http://vault:8200";
const VAULT_TOKEN = process.env.VAULT_TOKEN ?? "";

const vault = NodeVault({ apiVersion: "v1", endpoint: VAULT_ADDR, token: VAULT_TOKEN });

export interface EcKeyPair {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
}

function isNotFound(err: unknown): boolean {
  const statusCode = (err as { response?: { statusCode?: number } } | undefined)?.response?.statusCode;
  return statusCode === 404;
}

async function ensureEcKeyPair(vaultPath: string): Promise<EcKeyPair> {
  try {
    const { data } = await vault.read(vaultPath);
    const privateKey = crypto.createPrivateKey(data.data.privateKeyPem);
    const publicKey = crypto.createPublicKey(data.data.publicKeyPem);
    console.log(`Vault: loaded existing keypair from ${vaultPath}`);
    return { privateKey, publicKey };
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }

  console.log(`Vault: no keypair at ${vaultPath}, generating a new one`);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  await vault.write(vaultPath, { data: { privateKeyPem, publicKeyPem } });
  return { privateKey, publicKey };
}

async function ensureSekWrapKek(): Promise<Buffer> {
  const vaultPath = "secret/data/pds/sek-wrap-kek";
  try {
    const { data } = await vault.read(vaultPath);
    console.log("Vault: loaded existing SEK-wrap KEK");
    return Buffer.from(data.data.key, "base64");
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }

  console.log("Vault: no SEK-wrap KEK found, generating a new one");
  const kek = crypto.randomBytes(32);
  await vault.write(vaultPath, { data: { key: kek.toString("base64") } });
  return kek;
}

export interface PdsKeyMaterial {
  pdsEncKeyPair: EcKeyPair; // ECDH-ES+A256KW identity (Category 1 request decrypt / response encrypt)
  pdsSignKeyPair: EcKeyPair; // ECDSA signing: deviceJwt, sessionJwt, response envelopes
  sekWrapKek: Buffer; // RFC 3394 AESWrap key-encryption-key for SEKs at rest in Postgres
}

export async function loadPdsKeyMaterial(): Promise<PdsKeyMaterial> {
  const [pdsEncKeyPair, pdsSignKeyPair, sekWrapKek] = await Promise.all([
    ensureEcKeyPair("secret/data/pds/ec-enc-keypair"),
    ensureEcKeyPair("secret/data/pds/ec-sign-keypair"),
    ensureSekWrapKek()
  ]);
  return { pdsEncKeyPair, pdsSignKeyPair, sekWrapKek };
}
