import { AgentSpendBudget } from '../../src/shared-budget.js'

/**
 * A sealed-agent stand-in for the shared daily budget (brief item 21, D-048), answering the
 * payer's real wire requests:
 *
 *   POST /v1/spend/reserve {amount}            -> {ok, reservationId, remaining}
 *   POST /v1/spend/release {reservationId, used}
 *
 * What the payer may reserve is budget - reservedForFees - used - open reservations, so fee
 * settlement keeps priority. `used` of a release is what counts as spent; the rest of the
 * reservation goes back.
 */
export function fakeAgentBudget(options: { budget: bigint; reservedForFees?: bigint }) {
  const state = {
    budget: options.budget,
    reservedForFees: options.reservedForFees ?? 0n,
    used: 0n,
    reservations: new Map<string, bigint>(),
    /** Throw a network error on every call. */
    down: false,
    /** Answer every call with this HTTP status and no body. */
    status: undefined as number | undefined,
    /** Fail this many release calls with HTTP 500 before accepting. */
    failReleases: 0,
  }
  const calls: { path: string; body: Record<string, string> }[] = []
  let next = 0
  const available = () => {
    let held = 0n
    for (const amount of state.reservations.values()) held += amount
    const left = state.budget - state.reservedForFees - state.used - held
    return left > 0n ? left : 0n
  }
  const fake = {
    state,
    calls,
    onCall: undefined as ((path: string) => void) | undefined,
    available,
    /** The `used` value of every release, in order. */
    releases: () => calls.filter((c) => c.path === '/v1/spend/release').map((c) => BigInt(c.body.used!)),
    fetch: async (url: string, init: RequestInit): Promise<Response> => {
      if (state.down) throw new TypeError('fetch failed: connect ECONNREFUSED 172.30.0.3:7070')
      const path = new URL(url).pathname
      const body = JSON.parse(String(init.body)) as Record<string, string>
      calls.push({ path, body })
      fake.onCall?.(path)
      if (state.status !== undefined) return new Response(null, { status: state.status })
      if (path === '/v1/spend/reserve') {
        if (typeof body.amount !== 'string' || !/^\d+$/.test(body.amount)) return Response.json({ error: 'amount must be a decimal string' }, { status: 400 })
        const amount = BigInt(body.amount)
        if (amount > available()) return Response.json({ ok: false, remaining: available().toString() }, { status: 409 })
        const reservationId = `r${++next}`
        state.reservations.set(reservationId, amount)
        return Response.json({ ok: true, reservationId, remaining: available().toString() })
      }
      if (path === '/v1/spend/release') {
        if (state.failReleases > 0) {
          state.failReleases--
          return Response.json({ error: 'busy' }, { status: 500 })
        }
        const amount = state.reservations.get(body.reservationId ?? '')
        if (amount === undefined) return Response.json({ error: 'unknown reservation' }, { status: 404 })
        const used = BigInt(body.used ?? 'x')
        if (used > amount) return Response.json({ error: 'used exceeds the reservation' }, { status: 400 })
        state.reservations.delete(body.reservationId!)
        state.used += used
        return new Response(null, { status: 204 })
      }
      return Response.json({ error: 'not found' }, { status: 404 })
    },
    budget: undefined as unknown as AgentSpendBudget,
  }
  fake.budget = new AgentSpendBudget({ agentUrl: 'http://sealed-agent:7070', fetch: fake.fetch, retryDelaysMs: [5, 5, 5] })
  return fake
}
