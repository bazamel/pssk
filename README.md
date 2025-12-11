**Project status:** this is a work-in-progress. Do not use in production.

# pssk 

`pssk` is a Javascript library for passkey authentication via the standard Web Authentication API (WebAuthn) and @simplewebauthn/server.

## How it works

### Signup

1. Client → Server: "Start registration"
2. Server → Client: creationOptions (with challenge)
3. Client → WebAuthn → Client: credential
4. Client → Server: credential response
5. Server verifies + stores public key

### Login

1. Client → Server: "Start login"
2. Server → Client: requestOptions (with challenge)
3. Client → WebAuthn → Client: assertion
4. Client → Server: signed assertion
5. Server verifies signature → login success

## Usage

***client.js***
```js
import { signup, login } from "@packages/index.js";

const ENDPOINT = "http://localhost:3000";

async function handleSignup() {
    const res = await signup(ENDPOINT, "basunako@gmail.com");
    
    if(res.ok) {
      console.log('signed up!')
    }
}

async function handleLogin() {
    const res = await login(ENDPOINT, "basunako@gmail.com");
    
    if(res.ok) {
      console.log('logged in!')
    }
}
```
 
***server.js***
```js
app.post("/signup", async (c) => {
  const { email } = await c.req.json();

  const res = signup(email);

  return c.json({ ok: true, options: res });
});

app.post("/check-signup", async (c) => {
  const { email, credential } = await c.req.json();

  const res = checkSignup(email, credential, "http://localhost:4321");

  return c.json({ ok: true });
});

app.post("/login", async (c) => {
  const { email } = await c.req.json();

  const res = generateLogin(email);

  return c.json({ ok: true, options: res });
});

app.post("/check-login", async (c) => {
  const { email, credential } = await c.req.json();

  const res = checkLogin(email, credential, "http://localhost:4321");

  return c.json({ ok: true });
});
```

## local testing

Run the webpage at `http://localhost:4321`:
```bash
npm run dev
```

Run the server at `http://localhost:3000`:
```bash
cd server 
npm run start
```

Go to `http://localhost:4321` and click the `signup` button, then the `login` button.
