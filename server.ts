import { serve } from "@hono/node-server";
import {
	createFederation,
	exportJwk,
	generateCryptoKeyPair,
	importJwk,
	Follow,
	Person,
	MemoryKvStore,
} from "@fedify/fedify";
import { behindProxy } from "x-forwarded-fetch";
import { configure, getConsoleSink } from "@logtape/logtape";
import { openKv } from "@deno/kv";

const kv = await openKv("kv.db");

await configure({
	sinks: { console: getConsoleSink() },
	filters: {},
	loggers: [{ category: "fedify", sinks: ["console"], lowestLevel: "info" }],
});

const federation = createFederation<void>({
	kv: new MemoryKvStore(),
});

federation
	.setActorDispatcher("/users/{identifier}", async (ctx, identifier) => {
		if (identifier !== "me") return null; // Other than "me" is not found.
		return new Person({
			id: ctx.getActorUri(identifier),
			name: "Me", // Display name
			summary: "This is me!", // Bio
			preferredUsername: identifier, // Bare handle
			url: new URL("/", ctx.url),
			inbox: ctx.getInboxUri(identifier), // Inbox URI
		});
	})
	.setKeyPairsDispatcher(async (ctx, identifier) => {
		if (identifier != "me") return []; // Other than "me" is not found.
		const entry = await kv.get<{
			privateKey: JsonWebKey;
			publicKey: JsonWebKey;
		}>(["key"]);
		if (entry == null || entry.value == null) {
			// Generate a new key pair at the first time:
			const { privateKey, publicKey } =
				await generateCryptoKeyPair("RSASSA-PKCS1-v1_5");
			// Store the generated key pair to the Deno KV database in JWK format:
			await kv.set(["key"], {
				privateKey: await exportJwk(privateKey),
				publicKey: await exportJwk(publicKey),
			});
			return [{ privateKey, publicKey }];
		}
		// Load the key pair from the Deno KV database:
		const privateKey = await importJwk(entry.value.privateKey, "private");
		const publicKey = await importJwk(entry.value.publicKey, "public");
		return [{ privateKey, publicKey }];
	});

federation
	.setInboxListeners("/users/{identifier}/inbox", "/inbox")
	.on(Follow, async (ctx, follow) => {
		if (
			follow.id == null ||
			follow.actorId == null ||
			follow.objectId == null
		) {
			return;
		}
		const parsed = ctx.parseUri(follow.objectId);
		if (parsed?.type !== "actor" || parsed.identifier !== "me") return;
		const follower = await follow.getActor(ctx);
		console.debug(follower);
	});

serve({
	port: 8000,
	fetch: behindProxy((request) =>
		federation.fetch(request, { contextData: undefined }),
	),
});

// curl https://1f0c-121-136-244-64.ngrok-free.app/.well-known/webfinger?resource=acct:me@1f0c-121-136-244-64.ngrok-free.app
// curl -H"Accept: application/activity+json" https://1f0c-121-136-244-64.ngrok-free.app/users/me
