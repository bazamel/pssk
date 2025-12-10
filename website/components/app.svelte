<script>
    import { signup, login } from "@packages/index.js";

    const ENDPOINT = "http://localhost:3000";

    async function handleSignup() {
        const res = await signup(ENDPOINT, "basunako@gmail.com");

        if (res.ok) {
            console.log("signed up!");
        }
    }

    async function handleLogin() {
        const res = await login(ENDPOINT, "basunako@gmail.com");

        if (res.ok) {
            console.log("logged in!");
        }
    }
</script>

<div class="flex flex-col gap-10">
    <button class="p-2 bg-green-800" onclick={handleSignup}>signup</button>
    <button class="p-2 bg-blue-800" onclick={handleLogin}>login</button>
</div>
