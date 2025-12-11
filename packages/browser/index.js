const bufferToBase64Url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const base64UrlToBuffer = (s) =>
  Uint8Array.from(
    atob(
      s
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(s.length + ((4 - (s.length % 4)) % 4), "="),
    ),
    (c) => c.charCodeAt(0),
  ).buffer;

export async function signup(endpoint, email) {
  const optionsResp = await fetch(endpoint + "/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const options = await optionsResp.json().then((res) => res.options);

  options.challenge = base64UrlToBuffer(options.challenge);
  options.user.id = base64UrlToBuffer(options.user.id);

  const credential = await navigator.credentials.create({ publicKey: options });

  const result = {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64Url(
        credential.response.attestationObject,
      ),
    },
  };

  const checkResp = await fetch(endpoint + "/check-signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, credential: result }),
  });

  return await checkResp.json();
}

export async function login(endpoint, email) {
  const resp = await fetch(endpoint + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const options = await resp.json().then((res) => res.options);

  options.challenge = base64UrlToBuffer(options.challenge);
  options.allowCredentials = options.allowCredentials.map((c) => ({
    type: c.type,
    id: base64UrlToBuffer(c.id),
  }));

  const assertion = await navigator.credentials.get({ publicKey: options });

  const data = {
    id: assertion.id,
    rawId: bufferToBase64Url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64Url(
        assertion.response.authenticatorData,
      ),
      signature: bufferToBase64Url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64Url(assertion.response.userHandle)
        : null,
    },
  };

  const check = await fetch(endpoint + "/check-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, credential: data }),
  });

  const result = await check.json();
  return result;
}
