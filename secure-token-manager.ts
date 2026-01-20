// ============================================
// ============================================

import {
  KMSClient,
  GenerateDataKeyCommand,
  DecryptCommand,
} from "@aws-sdk/client-kms";
import { createClient } from "redis";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

interface EncryptionContext {
  client_id: string;
  api_provider: string;
  action: string;
}

interface TokenPayload {
  ct: string; // ciphertext
  n: string; // nonce
  ek: string; // encrypted key
  client: string;
  provider: string;
}

class SecureTokenManager {
  private kms: KMSClient;
  private redis: ReturnType<typeof createClient>;
  private dataKeyCache: Map<string, any>;

  constructor() {
    this.kms = new KMSClient({ region: "us-east-1" });
    this.redis = createClient({
      url: "rediss://your-elasticache.amazonaws.com:6379",
      password: process.env.REDIS_AUTH_TOKEN,
    });
    this.dataKeyCache = new Map();
  }

  // ============================================

  async storeToken(
    clientId: string,
    apiProvider: string,
    token: string,
    kmsKeyId: string,
  ): Promise<void> {
    const encryptionContext: EncryptionContext = {
      client_id: clientId,
      api_provider: apiProvider,
      action: "store",
    };

    // Gerar/recuperar data key (com cache)
    const cacheKey = `${kmsKeyId}:${clientId}`;

    if (!this.dataKeyCache.has(cacheKey)) {
      const command = new GenerateDataKeyCommand({
        KeyId: kmsKeyId,
        KeySpec: "AES_256",
        EncryptionContext: encryptionContext,
      });

      const response = await this.kms.send(command);
      this.dataKeyCache.set(cacheKey, response);
    }

    const dataKey = this.dataKeyCache.get(cacheKey);

    const nonce = randomBytes(12);
    const cipher = createCipheriv(
      "aes-256-gcm",
      dataKey.Plaintext!.slice(0, 32),
      nonce,
    );

    // AAD (Additional Authenticated Data)
    const aad = Buffer.from(`${clientId}:${apiProvider}`);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
      cipher.update(token, "utf8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    const payload: TokenPayload = {
      ct: Buffer.concat([ciphertext, authTag]).toString("base64"),
      n: nonce.toString("base64"),
      ek: dataKey.CiphertextBlob!.toString("base64"),
      client: clientId,
      provider: apiProvider,
    };

    // Salvar no Redis com TTL
    const redisKey = `token:${apiProvider}:${clientId}`;
    await this.redis.setEx(
      redisKey,
      840, // 14 minutos
      JSON.stringify(payload),
    );
  }

  // ============================================
  // ============================================

  async getToken(
    clientId: string,
    apiProvider: string,
  ): Promise<string | null> {
    const redisKey = `token:${apiProvider}:${clientId}`;
    const encryptedPayload = await this.redis.get(redisKey);

    if (!encryptedPayload) {
      return null;
    }

    const payload: TokenPayload = JSON.parse(encryptedPayload);

    // Encryption context (DEVE ser idêntico ao usado na criptografia)
    const encryptionContext: EncryptionContext = {
      client_id: clientId,
      api_provider: apiProvider,
      action: "store",
    };

    // ESTA CHAMADA É REGISTRADA NO CLOUDTRAIL!
    const command = new DecryptCommand({
      CiphertextBlob: Buffer.from(payload.ek, "base64"),
      EncryptionContext: encryptionContext,
    });

    const response = await this.kms.send(command);
    const plaintextKey = response.Plaintext!;

    // Separar ciphertext e authTag
    const ctWithTag = Buffer.from(payload.ct, "base64");
    const ciphertext = ctWithTag.slice(0, -16);
    const authTag = ctWithTag.slice(-16);

    const decipher = createDecipheriv(
      "aes-256-gcm",
      plaintextKey.slice(0, 32),
      Buffer.from(payload.n, "base64"),
    );

    // AAD (deve ser idêntico ao usado na criptografia)
    const aad = Buffer.from(`${payload.client}:${payload.provider}`);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);

    const token = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");

    return token;
  }

  // ============================================
  // Métodos auxiliares
  // ============================================

  async connect(): Promise<void> {
    await this.redis.connect();
  }

  async disconnect(): Promise<void> {
    await this.redis.disconnect();
  }
}

// ============================================
// Exemplo de uso
// ============================================

async function main() {
  const tokenManager = new SecureTokenManager();
  await tokenManager.connect();

  try {
    // Armazenar token
    await tokenManager.storeToken(
      "cliente_123",
      "api_provider_x",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    );

    console.log("Token armazenado com sucesso!");

    // Recuperar token
    const token = await tokenManager.getToken("cliente_123", "api_provider_x");

    console.log("Token recuperado:", token);
  } finally {
    await tokenManager.disconnect();
  }
}

// Executar apenas se for o arquivo principal
if (require.main === module) {
  main().catch(console.error);
}

export { SecureTokenManager, EncryptionContext, TokenPayload };
