// src/shims/crypto.ts
import * as c from 'crypto-browserify';

export const createHash  = c.createHash;
export const createHmac  = c.createHmac;
export const randomBytes = c.randomBytes;
export const pbkdf2      = c.pbkdf2;
export const pbkdf2Sync  = c.pbkdf2Sync;

export default { createHash, createHmac, randomBytes, pbkdf2, pbkdf2Sync };