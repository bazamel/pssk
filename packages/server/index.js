import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

export function signup(user) {
  return generateRegistrationOptions({
    rpName: "Example RP",
    rpID: "localhost",
    userID: user.id,
    userName: user.email,
    userDisplayName: user.email,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 60000,
  });
}

export async function checkSignup(user, credentialResponse) {
  if (!user) throw new Error("Unknown user");
  if (!user.currentChallenge) throw new Error("No registration in progress");

  const verification = await verifyRegistrationResponse({
    response: credentialResponse,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: "http://localhost:4321", // adjust for your site
    expectedRPID: "localhost",
    requireUserVerification: false,
  });

  const { verified, registrationInfo } = verification;
  if (!verified) throw new Error("Failed to verify registration");

  const { credential } = registrationInfo;

  const newCredential = {
    id: credential.id,
    publicKey: credential.publicKey,
    counter: credential.counter ?? 0,
  };

  return {
    ok: true,
    credential: newCredential,
  };
}

export function generateLogin(user) {
  if (!user || !user.credentials || user.credentials.length === 0)
    throw new Error("Unknown user or no credentials registered");

  return generateAuthenticationOptions({
    rpID: "localhost",
    allowCredentials: user.credentials.map((c) => ({
      id: c.id,
      type: "public-key",
    })),
    userVerification: "preferred",
    timeout: 60000,
  });
}

export async function checkLogin(user, credentialResponse) {
  if (!user || !user.currentLoginChallenge)
    throw new Error("No login in progress");

  const verification = await verifyAuthenticationResponse({
    response: credentialResponse,
    expectedChallenge: user.currentLoginChallenge,
    expectedOrigin: "http://localhost:4321",
    expectedRPID: "localhost",
    requireUserVerification: false,
    credential: (() => {
      const cred = user.credentials.find((c) => c.id === credentialResponse.id);
      if (!cred) throw new Error("Unknown credential");

      const newCredential = {
        id: cred.id,
        publicKey: cred.publicKey,
        counter: cred.counter ?? 0,
      };

      return newCredential;
    })(),
  });

  const { verified, authenticationInfo } = verification;
  if (!verified) return false;

  return true;
}
