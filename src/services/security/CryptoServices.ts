import crypto, {
  createCipheriv,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  randomFillSync,
  scryptSync,
} from 'crypto';
import config from '../../configs/config';

export interface Decipheriv {
  salt: string;
  iv: string;
  data: string;
}

export class Crypto {
  static cipheriv = async (
    text: unknown,
    password: string
  ): Promise<Decipheriv> => {
    try {
      const salt = randomFillSync(new Uint8Array(16));
      const iv = randomFillSync(new Uint8Array(Number(config.IV_LENGTH)));

      const key = scryptSync(password, salt, Number(config.KEY_LENGTH));

      const cipher = createCipheriv(String(config.ALGORITHM), key, iv);
      let encrypted = cipher.update(JSON.stringify(text), 'utf8', 'hex');
      encrypted += cipher.final('hex');

      return {
        salt: Buffer.from(salt).toString('hex'),
        iv: Buffer.from(iv).toString('hex'),
        data: encrypted,
      };
    } catch (error: unknown) {
      throw new Error(
        `Encryption failed using scrypt: ${(error as Error).message}`
      );
    }
  };

  static decipheriv = async <T = unknown>(
    data: Decipheriv,
    password: string
  ): Promise<T> => {
    try {
      const salt = new Uint8Array(Buffer.from(data.salt, 'hex'));
      const iv = new Uint8Array(Buffer.from(data.iv, 'hex'));
      const key = scryptSync(password, salt, Number(config.KEY_LENGTH));
      const decipher = createDecipheriv(String(config.ALGORITHM), key, iv);

      let decrypted = decipher.update(data.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return JSON.parse(decrypted);
    } catch (error: unknown) {
      throw new Error(
        `Encryption failed using scrypt: ${(error as Error).message}`
      );
    }
  };

  static hmac = (payload: string, key: string = config.HMAC_SECRET) => {
    return createHmac('sha256', key).update(payload).digest('hex');
  };

  static hash = (payload: string) => {
    return crypto.createHash('sha256').update(payload).digest('hex');
  };

  static randomHexString(length = 32): string {
    return randomBytes(length).toString('hex');
  }

  static generateRSAKeyPair() {
    return generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  }

  static encryptWithPublicKey(plaintext: string, publicKey: string): string {
    return publicEncrypt(publicKey, Buffer.from(plaintext, 'utf8')).toString(
      'base64'
    );
  }

  static decryptWithPrivateKey(ciphertext: string, privateKey: string): string {
    return privateDecrypt(
      privateKey,
      Buffer.from(ciphertext, 'base64')
    ).toString('utf8');
  }

  static safeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  }
}
