/** OpenAI chat-completion helpers: SSE framing and folding a chunk stream into one completion. */

type ToolCallDelta = { index?: number; id?: string; type?: string; function?: { name?: string; arguments?: string } }

type Chunk = {
  id?: string
  created?: number
  model?: string
  system_fingerprint?: string
  choices?: {
    index?: number
    delta?: { role?: string; content?: string | null; reasoning_content?: string | null; tool_calls?: ToolCallDelta[] }
    finish_reason?: string | null
  }[]
  usage?: Record<string, unknown> | null
  error?: unknown
}

export function sseFrame(data: string): string {
  return `data: ${data}\n\n`
}

type ChoiceState = {
  content: string
  reasoning: string
  finish: string | null
  tools: Map<number, { id?: string; type: string; name: string; arguments: string }>
}

/** Folds streamed chunks (raw JSON strings) into a non-streaming chat.completion object. */
export class CompletionAccumulator {
  private id = ''
  private created = 0
  private model = ''
  private fingerprint: string | undefined
  private usage: Record<string, unknown> | undefined
  private readonly choices = new Map<number, ChoiceState>()
  error: unknown

  add(data: string): void {
    let chunk: Chunk
    try {
      chunk = JSON.parse(data) as Chunk
    } catch {
      return
    }
    if (chunk.error !== undefined) this.error = chunk.error
    if (chunk.id) this.id = chunk.id
    if (chunk.created) this.created = chunk.created
    if (chunk.model) this.model = chunk.model
    if (chunk.system_fingerprint) this.fingerprint = chunk.system_fingerprint
    if (chunk.usage) this.usage = chunk.usage
    for (const choice of chunk.choices ?? []) {
      const index = choice.index ?? 0
      let state = this.choices.get(index)
      if (!state) {
        state = { content: '', reasoning: '', finish: null, tools: new Map() }
        this.choices.set(index, state)
      }
      const delta = choice.delta ?? {}
      if (typeof delta.content === 'string') state.content += delta.content
      if (typeof delta.reasoning_content === 'string') state.reasoning += delta.reasoning_content
      for (const call of delta.tool_calls ?? []) {
        const i = call.index ?? 0
        const tool = state.tools.get(i) ?? { type: 'function', name: '', arguments: '' }
        if (call.id) tool.id = call.id
        if (call.type) tool.type = call.type
        if (call.function?.name) tool.name += call.function.name
        if (call.function?.arguments) tool.arguments += call.function.arguments
        state.tools.set(i, tool)
      }
      if (choice.finish_reason) state.finish = choice.finish_reason
    }
  }

  result(fallbackModel: string): Record<string, unknown> {
    const choices = [...this.choices.entries()]
      .sort(([a], [b]) => a - b)
      .map(([index, s]) => {
        const message: Record<string, unknown> = { role: 'assistant', content: s.content }
        if (s.reasoning) message.reasoning_content = s.reasoning
        if (s.tools.size > 0) {
          message.tool_calls = [...s.tools.entries()]
            .sort(([a], [b]) => a - b)
            .map(([, t]) => ({ id: t.id, type: t.type, function: { name: t.name, arguments: t.arguments } }))
          if (!s.content) message.content = null
        }
        return { index, message, finish_reason: s.finish ?? 'stop' }
      })
    return {
      id: this.id || `chatcmpl-${Date.now()}`,
      object: 'chat.completion',
      created: this.created || Math.floor(Date.now() / 1000),
      model: this.model || fallbackModel,
      ...(this.fingerprint ? { system_fingerprint: this.fingerprint } : {}),
      choices,
      ...(this.usage ? { usage: this.usage } : {}),
    }
  }
}
