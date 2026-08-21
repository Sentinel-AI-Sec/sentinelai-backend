# Billing

Subscriptions through Stripe Checkout. Four endpoints, one of which can grant a paid plan.

---

## 0. The shape of it

```
GET  /v1/billing/subscription   what this tenant is on now        [Authorize]
POST /v1/billing/checkout       start a Checkout Session          [Authorize(admin)]
POST /v1/billing/portal         open Stripe's billing portal      [Authorize(admin)]
POST /v1/billing/webhook        Stripe -> us                      [AllowAnonymous]
```

**The browser never touches a card.** It asks this API for a Checkout Session and follows the
redirect to a Stripe-hosted page; Stripe redirects it back. No card number, payment method id or
publishable key ever enters our origin, which keeps the whole application out of PCI scope. There
is no Stripe.js, and `environment.ts` deliberately has no `publishableKey` field to invite one.

**The redirect back is a cue, not a receipt.** Anyone can type the success URL. Only the webhook —
verified against this deployment's signing secret — moves a tenant's entitlement. The UI treats its
return from Stripe purely as a reason to re-read `GET /v1/billing/subscription`.

**Billing belongs to the tenant, not the user.** `Tenant.PlanTier` is already what the rest of the
product reads to decide what an account may do, and the webhook keeps it in step with the
subscription row. Nothing outside billing has to understand Stripe's status vocabulary.

---

## 1. Configuration

Section `Billing` (`src/SentinelAI.Api/appsettings.json`).

| Key | What it is | Secret? |
|---|---|---|
| `Billing:SecretKey` | Stripe secret API key, `sk_...` | **Yes** |
| `Billing:WebhookSecret` | Signing secret for this endpoint, `whsec_...` | **Yes** |
| `Billing:Prices:<plan>:<Monthly\|Annual>` | Stripe **Price** id, `price_...` | No |
| `Billing:FreePlanId` | Tier written to `Tenant.PlanTier` when nothing is paid for. Defaults to `free` | No |
| `Billing:AllowedReturnOrigins` | Origins Stripe may return a browser to. Falls back to `Cors:AllowedOrigins` | No |

The two secrets are supplied the same way every other credential is — Key Vault
(`stripe-secret-key`, `stripe-webhook-secret`), environment variables, or user-secrets. **Never the
committed file.**

**Either secret being empty means billing is off.** The endpoints answer `503` with a reason and
the UI renders its "not configured" state. That is the default, and it is how the offline demo, a
fresh clone and the integration suite all run — an API that refused to boot without a Stripe
account would make every other endpoint hostage to a commercial integration.

### Prices are the allowlist

`POST /v1/billing/checkout` takes a **plan id and a period**, never a price id, and resolves the
price against this table. That is not a convenience — it removes a check rather than performing
one. Price ids are public (they appear in every payment link), so a price arriving in a request
body would be an attacker-supplied identifier this endpoint would have to validate before acting
on. Resolving name → price against configuration means the set of purchasable things is exactly
what an operator wrote down.

The reverse lookup is what makes the webhook honest: the plan a tenant is granted comes from the
price Stripe actually billed, resolved back through the same table. An unrecognised price grants
nothing.

Keep the plan keys in step with the UI's `core/billing/plans.ts`. The UI holds display prices and
copy; it holds no price ids at all.

---

## 2. Local development

```bash
# 1. Test-mode keys from https://dashboard.stripe.com/test/apikeys
dotnet user-secrets set "Billing:SecretKey" "sk_test_..." --project src/SentinelAI.Api

# 2. Two test-mode Prices on one Product, monthly and annual
dotnet user-secrets set "Billing:Prices:team:Monthly" "price_..." --project src/SentinelAI.Api
dotnet user-secrets set "Billing:Prices:team:Annual"  "price_..." --project src/SentinelAI.Api

# 3. Forward webhooks to the running API. This prints the whsec_ to use.
stripe listen --forward-to https://localhost:7001/v1/billing/webhook

dotnet user-secrets set "Billing:WebhookSecret" "whsec_..." --project src/SentinelAI.Api

# 4. Where Stripe may send the browser back to (ng serve)
dotnet user-secrets set "Billing:AllowedReturnOrigins:0" "http://localhost:4200" --project src/SentinelAI.Api
```

Then `dotnet ef database update` for the `Subscriptions` table, and buy something with card
`4242 4242 4242 4242`, any future expiry, any CVC.

> The `whsec_` from `stripe listen` is **not** the one in the Stripe dashboard. They are different
> secrets for different endpoints, and using the dashboard's against the CLI forwarder fails every
> signature — which this API reports as `400`, correctly.

To drive a specific case without paying: `stripe trigger customer.subscription.deleted`,
`stripe trigger invoice.payment_failed`.

---

## 3. The webhook

`POST /v1/billing/webhook` is the only unauthenticated write in the API and the only thing that can
grant a paid plan. Three properties hold it up.

**The signature is its authentication.** An HMAC over the exact request body, keyed with
`Billing:WebhookSecret`, plus a 300-second recency tolerance that rejects a delivery captured off
the wire and replayed later. There is no configuration that skips it; an empty secret refuses every
delivery rather than accepting unverified ones. The body is read as raw text for this reason —
binding it to a model and re-serializing would change whitespace and key order, and nothing would
verify.

**It runs with no tenant.** `SentinelDbContext` filters every `ITenantOwned` entity to
`CurrentTenantId`, and `Subscription` is one — which is what stops any authenticated caller reading
another organisation's plan. Stripe authenticates a signature, not a tenant, so the filter resolves
to `Guid.Empty` and matches nothing. Query filters do not affect writes, so a handler using the
ordinary repository would read back no row, decide there was nothing to do, and answer `200` —
Stripe would mark the delivery handled and never retry, customers would pay, and every one of them
would stay on the free tier with no error anywhere. `IBillingSubscriptionStore` is the one narrow,
reviewable place that steps around the filter, keyed only by a Stripe customer id.

`AssumableCallerContext` — the mechanism the scan worker uses for the same problem — deliberately
refuses inside an HTTP request, and a webhook is one. Hence the separate type.

**Almost every failure answers `200`.** Stripe reads a non-2xx as "retry", backs off for up to three
days, and then disables the endpoint — taking the deliveries that matter with it. An unrecognised
customer, an ignored event type and an already-applied event are all logged and acknowledged. The
one exception is a signature that does not verify: retrying will not fix a forged or misconfigured
delivery, and `200` would hide a wrong secret behind a green dashboard.

### Events handled

| Stripe event | Effect |
|---|---|
| `checkout.session.completed` | Links the Stripe subscription id to the tenant. Sets no status. |
| `customer.subscription.created/updated/deleted` | Writes the whole current state. Stripe's own `status` says which of the three happened. |
| `invoice.payment_failed` | Moves an entitled subscription to `past_due`. |

Everything else is acknowledged and ignored.

### Ordering

Stripe delivers at least once and does not guarantee order, and each subscription event carries the
**whole** subscription rather than a delta — so a redelivered or overtaken event does not merely
repeat work, it rewrites the row with a state that has since been superseded. `Subscription.LastEventAt`
holds the `created` timestamp of the last state-bearing event applied; anything older is
acknowledged and dropped. Without it, a customer who upgrades can appear minutes later to be back
on the plan they left, with Stripe showing the right answer the whole time.

> **The comparison is strictly older (`<`), and tightening it to `<=` breaks checkout silently.**
>
> Stripe stamps `created` to the **second**, and a single purchase fires eight or nine events
> inside the same second — `invoice.paid`, `customer.subscription.created`,
> `invoice.payment_succeeded` and the rest. Rejecting equal timestamps therefore lets exactly one
> event per second through: whichever arrives first claims the watermark and every sibling is
> discarded as stale.
>
> This is not hypothetical. A live test-mode purchase delivered `invoice.paid` ahead of
> `customer.subscription.created`, so the event carrying the price was dropped and the account read
> as a completed payment against no plan — while all eight deliveries logged a satisfied `200` and
> the Stripe dashboard showed everything green. Nothing about the failure looks like a failure.
>
> What `<` gives up is ordering *within* one second, which second-resolution timestamps cannot
> express anyway. What it keeps is the guard that matters: a retry redelivered seconds or minutes
> later cannot walk the row backwards.
>
> For the same reason, an event that changed nothing must not advance the watermark —
> `checkout.session.completed` deliberately does not, and neither should any future handler that
> writes no state.

### API version drift

`EventUtility.ConstructEvent` is called with `throwOnApiVersionMismatch: false`. That comparison is
not a security check — the HMAC has already been verified when it runs. Left on, it throws whenever
the Stripe **account's** default API version differs from the one this build of Stripe.net pins;
the account version moves when Stripe upgrades it or when somebody clicks upgrade in the dashboard,
and the result would be `400` on every genuine delivery until the NuGet package was bumped. See the
comment in `StripeEventReader` for the full argument.

---

## 4. Entitlement

`BillingEntitlement.TierFor` is the single place a status becomes a tier.

| Status | Entitled? |
|---|---|
| `active`, `trialing`, `past_due` | Yes — the plan |
| `incomplete`, `canceled`, `none` | No — `Billing:FreePlanId` |

**`past_due` keeps the plan on purpose.** It is a card that failed once while Stripe is still
retrying, not a lapsed account; locking a paying customer out of a security product over an expired
card, hours before the replacement charge succeeds, is the wrong call. Stripe ends its own retry
cycle and sends `canceled`, which is the event that removes the entitlement — and the one the
customer has already been emailed about.

`cancel_at_period_end` is not consulted: the customer has paid through `CurrentPeriodEnd` and stays
entitled until Stripe actually ends the subscription.

---

## 5. Return URLs

`successUrl`, `cancelUrl` and `returnUrl` arrive in the request body, because the origin the
customer started from differs between `ng serve` and the deployed app and the API cannot know which
one this browser is on. That makes them attacker-controlled input on a redirect — an open redirect
unless checked.

`BillingSettings.IsAllowedReturnUrl` compares the **origin** (`scheme://host[:port]`) against
`Billing:AllowedReturnOrigins`, falling back to `Cors:AllowedOrigins`. The path is not pinned: it
carries the SPA's own screen state, and coupling this API to another repository's routing table is a
change that would break checkout silently. An empty allowlist refuses everything, exactly as the
CORS policy does.

---

## 6. Account deletion

`TenantPurgeService` cancels the tenant's Stripe subscription **before** deleting its rows — the
same ordering, and the same reasoning, as purging stored bundles: afterwards there is no record that
a subscription existed and nothing in this product would ever look at it again.

A Stripe failure there is logged at **error** with the subscription id and the deletion continues.
SEC-35's promise is that an account can be deleted; making that conditional on a third party being
reachable would leave a customer unable to delete their own data during a Stripe outage. The other
outcome — a card charged for an account that no longer exists — is fixable by hand in the dashboard
in under a minute, and that log line is the only trace that survives the purge.

---

## 7. Tests

| What | Where |
|---|---|
| The four endpoints over HTTP, with a **real** HMAC signature | `Integration.Tests/Billing/BillingEndpointTests.cs` |
| The allowlist, the origin check, the entitlement table, the wire shape | `Application.Tests/Billing/BillingRulesTests.cs` |
| Subscription rows and Stripe cancellation on account deletion | `Integration.Tests/Retention/AccountDeletionTests.cs` |

`IBillingGateway` is faked; `IBillingEventReader` deliberately is not. The signature check is the
only authentication on the only endpoint that can grant a paid plan, so a test that stubbed it out
would be a test that the endpoint works when authentication is disabled.

---

## 8. Deploying it

Everything in §2 is a developer machine. A deployed instance differs in three ways that each
produce a *working-looking* system that does not take payments, so they are worth stating.

### The connection string lives in two places, and they are not the same place

| Where | Who reads it |
|---|---|
| GitHub secret `AZURE_SQL_CONNECTION_STRING` | **only** the `Apply migrations` step in `ci.yml` |
| Container App secret `sql-default-connection` | the running process |

`az containerapp update` in the deploy job passes `--image` and nothing else — existing environment
variables and secrets are carried across revisions untouched, which is deliberate and is why none
of them appear in the workflow. So updating the GitHub secret alone migrates one database while the
app keeps serving from another, and both halves report success. Change both, or neither.

> The GitHub secret is still named `AZURE_SQL_CONNECTION_STRING` while pointing at MonsterASP
> (`db64146.public.databaseasp.net`). Renaming it means editing `ci.yml` in the same commit.

### The Stripe config is not in the image

`Billing:SecretKey` and the price table are configuration, so a fresh deployment has none and
answers `503` — the UI's "billing is not configured on this deployment" state. The container app
carries them as:

| Env var | Source |
|---|---|
| `Billing__SecretKey` | secret ref `stripe-secret-key` |
| `Billing__WebhookSecret` | secret ref `stripe-webhook-secret` |
| `Billing__Prices__team__Monthly` | `price_...` (public id, plain value) |
| `Billing__Prices__team__Annual` | `price_...` (public id, plain value) |

`Billing__AllowedReturnOrigins` is left unset on purpose: it falls back to `Cors:AllowedOrigins`,
which already has to name the console's origin for the browser to reach the API at all. One list.

Set them with `az containerapp update --set-env-vars`, which adds and updates. **Not
`--replace-env-vars`** — that substitutes the whole list, and every model key, the JWT key and the
connection string go with it.

`BillingSettings` is built once at registration (`DependencyInjection`), so a changed secret needs a
new revision before it is read. Azure says as much when you set one.

### `stripe listen` does not sign a deployed app's webhooks

The `whsec_` the CLI prints belongs to the CLI's own listener and signs only what that process
forwards. A deployed app needs a real endpoint registered against its public URL, and the signing
secret is returned **once**, at creation — there is no way to read it back afterwards.

```bash
# The five events HandleBillingWebhookCommandHandler acts on. `secret` in the response is the
# whsec_ to configure — capture it here or create the endpoint again.
curl -s -u "$STRIPE_SECRET_KEY:" https://api.stripe.com/v1/webhook_endpoints \
  -d "url=https://<app-fqdn>/v1/billing/webhook" \
  -d "description=SentinelAI deployed API" \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=customer.subscription.created" \
  -d "enabled_events[]=customer.subscription.updated" \
  -d "enabled_events[]=customer.subscription.deleted" \
  -d "enabled_events[]=invoice.payment_failed"
```

The Stripe CLI can do the same with `stripe webhook_endpoints create --url ... --enabled-events ...`
— note it takes a repeated `--enabled-events` flag, not the `-d "enabled_events[]="` form the raw
API uses.

Register it as `https://` directly. Stripe does **not** follow redirects on webhook delivery, and
`UseHttpsRedirection` is on outside Development — an `http://` endpoint records every delivery as a
failure and retries until it gives up. No test catches this.

### Checking a deployment without spending anything

```
GET  /v1/health              -> 200
POST /v1/billing/checkout    -> 401 unauthenticated, NOT 503   # 503 = Stripe config missing
POST /v1/billing/webhook     -> 400 on a bogus Stripe-Signature # 400 = verification running
```

The middle line is the useful one: `401` and `503` are the difference between "billing is wired up"
and "the UI will tell every customer it is not".
