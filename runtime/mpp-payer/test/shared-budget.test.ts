import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { AgentSpendBudget, BudgetUnavailableError } from '../src/shared-budget.js'
import { SpendLimitError } from '../src/spend-guard.js'
import { fakeAgentBudget } from './helpers/fake-agent-budget.js'

const until = async (check: () => boolean, ms = 2_000) => {
  const deadline = Date.now() + ms
  while (!check()) {
    if (Date.now() > deadline) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 5))
  }
}

describe('shared spend budget client (sealed-agent /v1/spend/reserve and /release)', () => {
  // A real HTTP listener, so the request line, headers and JSON bodies are what the agent receives.
  const seen: { method?: string; url?: string; type?: string; body: string }[] = []
  let reply: (url: string) => { status: number; body?: string } = () => ({ status: 404 })
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => (body += chunk))
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, type: req.headers['content-type'], body })
      const r = reply(req.url ?? '')
      res.writeHead(r.status, { 'content-type': 'application/json' })
      res.end(r.body ?? '')
    })
  })
  let agentUrl = ''
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
    agentUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  })
  afterAll(() => server.close())

  it('sends decimal-string amounts and reads the reservation', async () => {
    seen.length = 0
    reply = (url) =>
      url === '/v1/spend/reserve' ? { status: 200, body: JSON.stringify({ ok: true, reservationId: 'res-1', remaining: '1499640' }) } : { status: 204 }
    const budget = new AgentSpendBudget({ agentUrl, now: () => 1_000 })
    const reservation = await budget.reserve(500_360n)
    expect(reservation).toEqual({ id: 'res-1', amount: 500_360n, remaining: 1_499_640n })
    await budget.release(reservation, 500_360n)
    expect(seen).toEqual([
      { method: 'POST', url: '/v1/spend/reserve', type: 'application/json', body: '{"amount":"500360"}' },
      { method: 'POST', url: '/v1/spend/release', type: 'application/json', body: '{"reservationId":"res-1","used":"500360"}' },
    ])
    expect(budget.state()).toEqual({ remaining: '1499640', checkedAt: 1_000, pendingReleases: 0, lastError: undefined })
  })

  it('turns ok:false into a shared SpendLimitError and accepts a numeric remaining', async () => {
    reply = () => ({ status: 409, body: JSON.stringify({ ok: false, remaining: 1200 }) })
    const error = await new AgentSpendBudget({ agentUrl }).reserve(5_000n).catch((e) => e)
    expect(error).toBeInstanceOf(SpendLimitError)
    expect(error).toMatchObject({ scope: 'shared', requested: 5_000n, remaining: 1_200n })
    reply = () => ({ status: 200, body: JSON.stringify({ ok: false }) })
    expect(await new AgentSpendBudget({ agentUrl }).reserve(5_000n).catch((e) => e)).toMatchObject({ scope: 'shared', remaining: 0n })
    // The agent's reason is kept when it is not plain lack of budget.
    reply = () => ({ status: 200, body: JSON.stringify({ ok: false, remaining: '9', reason: 'too_many_reservations' }) })
    const busy = await new AgentSpendBudget({ agentUrl }).reserve(5n).catch((e) => e)
    expect(busy).toMatchObject({ scope: 'shared', reason: 'too_many_reservations' })
    expect(busy.message).toMatch(/too_many_reservations/)
    reply = () => ({ status: 200, body: JSON.stringify({ ok: false, remaining: '1', reason: 'budget' }) })
    expect(await new AgentSpendBudget({ agentUrl }).reserve(5n).catch((e) => e)).toMatchObject({ reason: undefined })
  })

  it.each([
    ['not ready', { status: 503, body: '{"error":"not ready"}' }, /HTTP 503: not ready/],
    ['a caller other than the payer', { status: 403, body: '{"error":"spend budget is for sealed-mpp-payer only"}' }, /HTTP 403/],
    ['an agent without the endpoint', { status: 404, body: '{"error":"not found"}' }, /HTTP 404/],
    ['a bad request', { status: 400, body: '{"error":"amount"}' }, /HTTP 400/],
    ['no reservation id', { status: 200, body: '{"ok":true}' }, /unexpected reserve response/],
    ['an oversized reservation id', { status: 200, body: JSON.stringify({ ok: true, reservationId: 'x'.repeat(129) }) }, /unexpected/],
    ['a non-JSON body', { status: 200, body: 'ok' }, /unexpected/],
    ['a 409 without a verdict', { status: 409, body: '{}' }, /unexpected/],
  ])('fails closed on %s', async (_name, response, message) => {
    reply = () => response
    const error = await new AgentSpendBudget({ agentUrl }).reserve(1n).catch((e) => e)
    expect(error).toBeInstanceOf(BudgetUnavailableError)
    expect(error.message).toMatch(message)
  })

  it('fails closed when the agent is unreachable or slow', async () => {
    const down = new AgentSpendBudget({ agentUrl: 'http://127.0.0.1:1' })
    await expect(down.reserve(1n)).rejects.toThrow(/unreachable/)
    expect(down.state().lastError).toBeDefined()
    const slow = new AgentSpendBudget({ agentUrl, timeoutMs: 20, fetch: (_url, init) => new Promise((_, reject) => init.signal?.addEventListener('abort', () => reject(new Error('timeout')))) })
    await expect(slow.reserve(1n)).rejects.toThrow(BudgetUnavailableError)
    await expect(slow.reserve(0n)).rejects.toThrow(/non-positive/)
  })

  it('retries a failed release in the background and never reports more than was reserved', async () => {
    const agent = fakeAgentBudget({ budget: 10_000n })
    const reservation = await agent.budget.reserve(4_000n)
    agent.state.failReleases = 2
    await agent.budget.release(reservation, 9_999n)
    expect(agent.budget.state().pendingReleases).toBe(1)
    // Until the release lands, the whole reservation stays counted: the payer can only spend less.
    expect(agent.available()).toBe(6_000n)
    await until(() => agent.budget.state().pendingReleases === 0)
    expect(agent.releases()).toEqual([4_000n, 4_000n, 4_000n])
    expect(agent.state.used).toBe(4_000n)
    expect(agent.available()).toBe(6_000n)
  })

  it('gives up after the last retry and treats an unknown reservation as released', async () => {
    const agent = fakeAgentBudget({ budget: 10_000n })
    const logs: string[] = []
    const budget = new AgentSpendBudget({ agentUrl: 'http://sealed-agent:7070', fetch: agent.fetch, retryDelaysMs: [1], log: (e) => logs.push(String(e.event)) })
    const reservation = await budget.reserve(100n)
    agent.state.failReleases = 5
    await budget.release(reservation, 0n)
    await until(() => budget.state().pendingReleases === 0)
    expect(logs).toContain('spend_release_abandoned')
    agent.state.failReleases = 0
    await budget.release({ id: 'gone', amount: 1n }, 0n)
    expect(budget.state().pendingReleases).toBe(0)
    budget.stop()
  })
})
