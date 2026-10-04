# grow private relay template

This deployable Worker gives one grow user their own ephemeral signaling,
encrypted short-invitation store, and short-lived Cloudflare TURN credentials.
It never receives message bodies or conversation history.

This repository contains only the standalone relay Worker, not the grow app,
its database, user content, or production configuration.

Use the **Deploy to Cloudflare** button in grow. Cloudflare will ask for:

1. the TURN Token ID and API token from **Realtime → TURN**;
2. the private `OWNER_KEY` generated inside grow; and
3. an optional friendly relay name.

After deployment, paste the resulting `https://…workers.dev` address back into
grow. Do not share the `OWNER_KEY` or TURN API token.

[Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/ryoi/grow-og-relay-template/tree/main)

The default browser origins are `https://og.grow.ryoi.ai` and
`https://sottli.ryoi.ai`. Add an origin only for a frontend you control; do not
use a wildcard. This template creates a separate personal relay, not a copy
of the application's database or managed service.

## Local verification

Install dependencies with `npm install`, then run `npm run typecheck` and
`npx wrangler deploy --dry-run`. A dry run does not deploy a Worker or validate
your provider credentials. Never commit real setup keys or TURN tokens.
The example secret file intentionally contains only empty values.

## Deployment and privacy

Cloudflare deployment creates resources in your account. Review the provider's
current Workers, Durable Objects and Realtime TURN limits and charges before
deploying. The template does not select or purchase a plan for you.

Signaling and encrypted short invitations expire; chat message bodies do not
pass through this Worker. Ordinary Cloudflare operational metadata is separate
from message content. The template enables sampled provider observability.

## License

This standalone relay template is licensed under [MIT](LICENSE). This license
covers only the files in this template repository, not the grow application,
its private source, user data or production infrastructure.
