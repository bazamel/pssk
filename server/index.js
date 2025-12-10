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

serve(app);
