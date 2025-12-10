import crypto from "crypto";
import { decode as cborDecode } from "cbor-x";

export function base64urlEncode(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function base64urlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = 4 - (s.length % 4);
  if (pad !== 4) s += "=".repeat(pad);
  return Buffer.from(s, "base64");
}

export function signup(user) {
  const challenge = crypto.randomBytes(32);

  const options = {
    rp: {
      id: "localhost",
      name: "Example RP",
    },
    user: {
      id: base64urlEncode(user.id),
      name: user.email,
      displayName: user.email,
    },
    challenge: base64urlEncode(challenge),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    timeout: 60000,
    attestation: "none",
  };

  return { options, challenge };
}

export function checkSignup(user, credentialResponse) {
  if (!user) throw new Error("Unknown user");
  if (!user.currentChallenge) throw new Error("No registration in progress");

  const clientDataJSON = base64urlDecode(
    credentialResponse.response.clientDataJSON,
  );
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));

  if (clientData.type !== "webauthn.create")
    throw new Error("Invalid clientData type");

  if (clientData.challenge !== base64urlEncode(user.currentChallenge))
    throw new Error("Challenge mismatch");

  // if (clientData.origin !== expectedOrigin) throw new Error("Origin mismatch");

  const attestationBuffer = base64urlDecode(
    credentialResponse.response.attestationObject,
  );

  const { authData, publicKeyPem } = parseAttestation(attestationBuffer);

  const credential = {
    id: credentialResponse.id,
    publicKey: publicKeyPem,
    counter: 0,
  };

  return { ok: true, credential };
}

function parseAttestation(attestationObjectBuffer) {
  const obj = cborDecode(attestationObjectBuffer);

  let authData = obj.authData;
  if (!authData) throw new Error("attestationObject missing authData");

  authData = Buffer.isBuffer(authData) ? authData : Buffer.from(authData);

  const publicKeyCose = extractCosePublicKey(authData);

  const publicKeyPem = coseToPEMPublicKey(publicKeyCose);

  return { authData, publicKeyPem };
}

function extractCosePublicKey(authData) {
  const buf = Buffer.isBuffer(authData) ? authData : Buffer.from(authData);

  let offset = 32 + 1 + 4 + 16; // rpIdHash + flags + counter + aaguid

  if (buf.length < offset + 2) {
    throw new Error("authData too short when reading credential id length");
  }

  const credIdLen = buf.readUInt16BE(offset);
  offset += 2;

  if (buf.length < offset + credIdLen) {
    throw new Error("authData too short for credId");
  }

  offset += credIdLen;

  const coseSlice = buf.slice(offset);

  const coseKey = cborDecode(coseSlice);

  return coseKey;
}

function coseToPEMPublicKey(coseKey) {
  const get = (mapLike, k) => {
    if (mapLike instanceof Map) return mapLike.get(k);

    if (Object.prototype.hasOwnProperty.call(mapLike, k)) return mapLike[k];
    if (Object.prototype.hasOwnProperty.call(mapLike, String(k)))
      return mapLike[String(k)];
    return undefined;
  };

  const x = get(coseKey, -2) || get(coseKey, -1 + 1);
  const y = get(coseKey, -3);

  const xBuf = x ? Buffer.from(x) : null;
  const yBuf = y ? Buffer.from(y) : null;

  if (!xBuf || !yBuf) {
    const altX = get(coseKey, -1) || get(coseKey, 2);
    const altY = get(coseKey, -2) || get(coseKey, 3);
    if (altX && altY) {
      return coseToPEMPublicKey({ [-2]: altX, [-3]: altY });
    }
    throw new Error("COSE public key missing x/y coordinates");
  }

  const uncompressed = Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);

  const der = wrapEcPublicKey(uncompressed);
  const pem = `-----BEGIN PUBLIC KEY-----\n${der.toString("base64")}\n-----END PUBLIC KEY-----`;
  return pem;
}

function wrapEcPublicKey(uncompressed) {
  const oidSeq = Buffer.from([
    0x30,
    0x59, // SEQ (89)
    0x30,
    0x13, // SEQ (19)
    0x06,
    0x07, // OID (7)
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01, // 1.2.840.10045.2.1
    0x06,
    0x08, // OID (8)
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x03,
    0x01,
    0x07, // 1.2.840.10045.3.1.7
    0x03,
    0x42,
    0x00, // BIT STRING (66 bytes) with 0 unused bits
  ]);

  const algOid = Buffer.from([
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  ]);

  const bitString = Buffer.concat([
    Buffer.from([0x03]),
    Buffer.from([uncompressed.length + 1]), // length of bitstring payload
    Buffer.from([0x00]), // number of unused bits
    uncompressed,
  ]);

  const fullSeq = Buffer.concat([
    Buffer.from([0x30]), // SEQUENCE
    Buffer.from([algOid.length + bitString.length]), // total length
    algOid,
    bitString,
  ]);

  return fullSeq;
}

export function generateLogin(user) {
  if (!user || user.credentials.length === 0)
    throw new Error("Unknown user or no credentials registered");

  const challenge = crypto.randomBytes(32);

  const allowCredentials = user.credentials.map((c) => ({
    type: "public-key",
    id: c.id,
  }));

  return {
    challenge,
    options: {
      challenge: base64urlEncode(challenge),
      rpId: "localhost",
      allowCredentials,
      userVerification: "preferred",
      timeout: 60000,
    },
  };
}

export function checkLogin(user, credentialResponse) {
  if (!user || !user.currentLoginChallenge)
    throw new Error("No login challenge active");

  const clientDataJSON = base64urlDecode(
    credentialResponse.response.clientDataJSON,
  );
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));

  if (clientData.type !== "webauthn.get")
    throw new Error("Invalid clientData type");

  if (clientData.challenge !== base64urlEncode(user.currentLoginChallenge))
    throw new Error("Challenge mismatch");

  // if (clientData.origin !== expectedOrigin) throw new Error("Origin mismatch");

  const authData = base64urlDecode(
    credentialResponse.response.authenticatorData,
  );
  const signature = base64urlDecode(credentialResponse.response.signature);

  const cred = user.credentials.find((c) => c.id === credentialResponse.id);
  if (!cred) throw new Error("Unknown credential");

  const clientDataHash = crypto
    .createHash("sha256")
    .update(clientDataJSON)
    .digest();
  const signedData = Buffer.concat([authData, clientDataHash]);

  const verifier = crypto.createVerify("SHA256");
  verifier.update(signedData);
  verifier.end();

  const valid = verifier.verify(cred.publicKey, signature);

  return valid;
}
