import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:net'
import { http, createClient, custom, publicActions, walletActions } from 'viem'
import { tempo as tempoChain } from 'viem/chains'
import { tempoActions } from 'viem/tempo'

export const PATHUSD = '0x20c0000000000000000000000000000000000000' as const
/** anvil dev accounts 3..9 default to pathUSD as fee token and hold u64::MAX of each local USD token. */
export const DEV_KEYS = {
  3: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
  4: '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a',
  5: '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba',
} as const

export function anvilAvailable(): boolean {
  const res = spawnSync('anvil', ['--version'], { stdio: 'ignore' })
  return res.status === 0
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer()
    s.listen(0, '127.0.0.1', () => {
      const a = s.address()
      s.close(() => (a && typeof a === 'object' ? resolve(a.port) : reject(new Error('no port'))))
    })
  })
}

export type LocalTempo = { rpcUrl: string; client: ReturnType<typeof localClient>; stop: () => void }

/**
 * Local Tempo node: `anvil --network tempo` with chain id 4217 and one-second blocks (so block
 * timestamps track wall time, which expiring-nonce transactions need).
 */
export async function startLocalTempo(): Promise<LocalTempo> {
  const port = await freePort()
  const proc: ChildProcess = spawn(
    'anvil',
    ['--network', 'tempo', '--hardfork', process.env.SEALED_ANVIL_HARDFORK ?? 'T12', '--chain-id', '4217', '--block-time', '1', '--port', String(port), '--silent'],
    { stdio: 'ignore' },
  )
  const rpcUrl = `http://127.0.0.1:${port}`
  const deadline = Date.now() + 15_000
  for (;;) {
    try {
      const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' })
      if (res.ok) break
    } catch {}
    if (Date.now() > deadline) {
      proc.kill()
      throw new Error('anvil did not start')
    }
    await new Promise((r) => setTimeout(r, 200))
  }
  await new Promise((r) => setTimeout(r, 1500))
  return { rpcUrl, client: localClient(rpcUrl), stop: () => proc.kill() }
}

/**
 * viem Tempo client for the local node. Foundry 1.7.1's anvil accepts `eth_sendRawTransactionSync`
 * with the raw transaction only, so the optional timeout parameter viem sends is dropped here.
 */
export function localClient(rpcUrl: string) {
  const chain = tempoChain.extend({ feeToken: PATHUSD })
  const base = http(rpcUrl)({ chain })
  const transport = custom({
    async request({ method, params }: { method: string; params?: unknown }) {
      const p = method === 'eth_sendRawTransactionSync' && Array.isArray(params) ? [params[0]] : params
      return base.request({ method, params: p } as never)
    },
  })
  return createClient({ chain, transport }).extend(publicActions).extend(walletActions).extend(tempoActions())
}

export async function balanceOf(client: ReturnType<typeof localClient>, account: `0x${string}`): Promise<bigint> {
  return client.readContract({
    address: PATHUSD,
    abi: [{ type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] }],
    functionName: 'balanceOf',
    args: [account],
  }) as Promise<bigint>
}
