import {
  signup,
  checkSignup,
  generateLogin,
  checkLogin,
} from "../packages/server/index.js";

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";

const app = new Hono();

app.use(cors("*"));

let USERS = new Map();

function getOrCreateUser(email) {
  if (!USERS.has(email)) {
    USERS.set(email, {
      id: crypto.randomBytes(32),
      email: email,
      credentials: [],
    });
  }
  return USERS.get(email);
}

app.post("/signup", async (c) => {
  const { email } = await c.req.json();

  const user = getOrCreateUser(email);

  const res = signup(user);

  user.currentChallenge = res.challenge;

  return c.json({ ok: true, options: res.options });
});
app.post("/check-signup", async (c) => {
  const { email, credential } = await c.req.json();

  const user = USERS.get(email);

  const res = checkSignup(user, credential);

  if (!res.ok) throw new Error("bad credential");

  user.credentials.push(res.credential);
  delete user.currentChallenge;

  return c.json({ ok: true });
});

app.post("/login", async (c) => {
  const { email } = await c.req.json();

  const user = USERS.get(email);

  const res = generateLogin(user);

  user.currentLoginChallenge = res.challenge;

  return c.json({ ok: true, options: res.options });
});

app.post("/check-login", async (c) => {
  const { email, credential } = await c.req.json();

  const user = USERS.get(email);

  const res = checkLogin(user, credential);

  delete user.currentLoginChallenge;

  return c.json({ ok: true });
});

serve(app);
