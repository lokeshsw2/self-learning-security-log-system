import { useEffect, useState } from "react"
import { toast } from "sonner"
import { KeyRound, Play, ShieldCheck, Square, Wrench } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ErrorNote, Mono, useLoad } from "@/components/common"
import { api, ago, fmt, type Json, type LearnRun, type Role } from "@/lib/api"

const AGENTS: { role: Role; label: string; note: string }[] = [
  { role: "source-naming", label: "Name sources", note: "vendor and product from content" },
  { role: "grouping-repair", label: "Fix grouping", note: "merge, split or remask groups" },
  { role: "parser-gen", label: "Write parsers", note: "field extraction per group" },
  { role: "ocsf-mapping", label: "Map to OCSF", note: "class and attributes per group" },
  { role: "longtail", label: "Long tail", note: "rare lines, batched" },
]
const LABEL = Object.fromEntries(AGENTS.map((a) => [a.role, a.label])) as Record<Role, string>

const usd = (n: number) => "$" + n.toFixed(n < 1 ? 3 : 2)
const MODEL_NAME: Record<string, string> = {
  "claude-sonnet-5-5": "Claude Sonnet 5.5",
  "claude-opus-5-5": "Claude Opus 5.5",
  "claude-haiku-5-5": "Claude Haiku 5.5",
}
const modelName = (id: string) => MODEL_NAME[id] ?? id

export function LearnPanel({ onChange }: { onChange?: () => void }) {
  const { data, error, reload } = useLoad(() => api.learn(), [])
  const [roles, setRoles] = useState<Role[]>(AGENTS.map((a) => a.role))
  const [limit, setLimit] = useState("5")
  const [budget, setBudget] = useState("2")
  const [busy, setBusy] = useState(false)
  const [model, setModel] = useState<string | null>(null)
  const chosen = model ?? data?.default_model ?? "claude-sonnet-5-5"
  const running = !!data?.run?.running

  useEffect(() => {
    const t = setInterval(reload, running ? 1500 : 10000)
    return () => clearInterval(t)
  }, [reload, running])

  // refresh the queue below when a run ends
  const [wasRunning, setWasRunning] = useState(false)
  useEffect(() => {
    if (wasRunning && !running) onChange?.()
    setWasRunning(running)
  }, [running]) // eslint-disable-line react-hooks/exhaustive-deps

  async function start() {
    setBusy(true)
    try {
      await api.startLearn(roles, Number(limit) || 5, Number(budget) || 2, chosen)
      toast.success("Learning run started")
      reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function runAudit() {
    setBusy(true)
    try {
      const r = await api.audit()
      const n = Number(r.groups_failing)
      toast(n ? `${n} groups produce wrong events; sent back to the agents` : "Every group checked out")
      reload()
      onChange?.()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function stop() {
    await api.stopLearn()
    toast("Stopping after the current model call")
    reload()
  }

  const toggle = (r: Role, on: boolean) => setRoles(on ? [...roles, r] : roles.filter((x) => x !== r))
  const selectedWaiting = data ? roles.reduce((a, r) => a + (data.waiting[r] ?? 0), 0) : 0

  return (
    <Card>
      <CardHeader>
        <CardTitle>Learn: run the AI agents</CardTitle>
        <CardDescription>
          Each waiting item gets a short, bounded conversation with Claude. The agents can only call the rule tools, and
          code checks every rule before it is saved. Lines the new rules parse go to ClickHouse.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <ErrorNote error={error} />}
        {data && !data.key_configured && (
          <Alert>
            <KeyRound />
            <AlertTitle>No API key on the server</AlertTitle>
            <AlertDescription>
              Restart the server with the key in its environment:{" "}
              <Mono>ANTHROPIC_API_KEY=sk-ant-… .venv/bin/python -m logparser.web --db work/app.db</Mono>. The key stays on
              the server; the browser never sees it.
            </AlertDescription>
          </Alert>
        )}

        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {AGENTS.map((a) => (
            <label
              key={a.role}
              className="flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 has-[[data-checked]]:border-primary/50 has-[[data-checked]]:bg-muted/40"
            >
              <Checkbox
                checked={roles.includes(a.role)}
                onCheckedChange={(v) => toggle(a.role, !!v)}
                disabled={running}
                className="mt-0.5"
              />
              <span className="grid gap-0.5">
                <span className="text-sm font-medium">{a.label}</span>
                <span className="text-xs text-muted-foreground">{a.note}</span>
                <span className="text-xs tabular-nums">{data ? fmt(data.waiting[a.role]) : "–"} waiting</span>
              </span>
            </label>
          ))}
        </div>

        <div className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label>Model</Label>
            <Select value={chosen} onValueChange={(v) => setModel(String(v))} disabled={running}>
              <SelectTrigger className="w-64">
                <SelectValue>{(v: string) => modelName(v)}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {(data?.models ?? []).map((m) => (
                  <SelectItem key={m.id} value={m.id}>
                    {modelName(m.id)}{" "}
                    <span className="text-xs text-muted-foreground">
                      ${m.input} / ${m.output} per M tokens
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="learn-limit">Items per agent</Label>
            <Input id="learn-limit" type="number" min={1} max={200} value={limit} onChange={(e) => setLimit(e.target.value)}
              disabled={running} className="w-32" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="learn-budget">Budget (USD)</Label>
            <Input id="learn-budget" type="number" min={0.1} max={100} step={0.5} value={budget}
              onChange={(e) => setBudget(e.target.value)} disabled={running} className="w-32" />
          </div>
          {running ? (
            <Button variant="destructive" onClick={stop}><Square /> Stop</Button>
          ) : (
            <Button onClick={start} disabled={busy || !roles.length || !data?.key_configured || selectedWaiting === 0}>
              <Play /> Start learning
            </Button>
          )}
          <Button variant="outline" onClick={runAudit} disabled={busy || running}>
            <ShieldCheck /> Run self-audit
          </Button>
          <span className="pb-2 text-xs text-muted-foreground">
            {selectedWaiting === 0 && !running
              ? "Nothing waiting for the selected agents."
              : "Spend is estimated from list prices; the run stops starting new items at the budget."}
          </span>
        </div>

        {data?.last_audit && (!data.run || data.last_audit.at > data.run.started) && (
          <div className="rounded-lg border p-3">
            <SummaryLine tag="audit" s={data.last_audit} />
            <p className="mt-1 text-xs text-muted-foreground">
              Code only, no AI and no cost. Wrong groups wait in the agents' queues below; Start learning fixes them.
            </p>
          </div>
        )}
        {data?.run && <RunView run={data.run} />}
      </CardContent>
    </Card>
  )
}

// one line per step of a run: an agent, the self-audit, or a fix round
function SummaryLine({ tag, s }: { tag: string; s: Record<string, Json> }) {
  if (tag.startsWith("audit")) {
    const failing = Number(s.groups_failing)
    const routed = Object.entries((s.routed ?? {}) as Record<string, number>)
    const checks = Object.entries((s.by_check ?? {}) as Record<string, number>)
    return (
      <div className="flex flex-wrap items-center gap-1.5 text-sm">
        <Badge variant={failing ? "destructive" : "secondary"}>
          <ShieldCheck /> {tag === "audit" ? "Self-audit" : `Self-audit, round ${tag.split(" ")[1]}`}
        </Badge>
        <span className="text-muted-foreground">
          {fmt(Number(s.groups_checked))} groups, {fmt(Number(s.lines_checked))} lines checked against their own text:
        </span>
        {failing === 0 ? (
          <span>all correct</span>
        ) : (
          <>
            <span>{fmt(failing)} groups wrong</span>
            {checks.map(([c, n]) => <Badge key={c} variant="outline" className="font-normal">{c}: {fmt(n)} lines</Badge>)}
            {routed.map(([q, n]) => (
              <Badge key={q} variant="outline" className="font-normal">
                {q === "human-review" ? `${fmt(n)} to human review` : `${fmt(n)} sent back to the agent`}
              </Badge>
            ))}
          </>
        )}
      </div>
    )
  }
  const fix = tag.match(/^fix (\d+): (.+)$/)
  const role = (fix ? fix[2] : tag) as Role
  const text =
    "skipped" in s
      ? String(s.skipped)
      : role === "longtail"
        ? `${fmt(Number(s.saved))} saved${s.stopped ? `, ${s.stopped}` : ""}`
        : `${fmt(Number(s.saved))} of ${fmt(Number(s.items))} saved`
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-sm">
      <Badge variant="outline" className="font-normal">
        {fix ? <Wrench /> : null}
        {fix ? `Fix round ${fix[1]} · ` : ""}
        {LABEL[role] ?? role}
      </Badge>
      <span className="text-muted-foreground">{text}</span>
    </div>
  )
}

function RunView({ run }: { run: LearnRun }) {
  const pct = Math.min(100, (100 * run.spent_usd) / run.budget_usd)
  const saved = run.results.filter((r) => r.saved).length
  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {run.running ? <Badge>running</Badge> : <Badge variant="secondary">finished</Badge>}
        <span className="text-muted-foreground">started {ago(run.started)} · {modelName(run.model)}</span>
        <span>· {fmt(run.results.length)} items done, {fmt(saved)} saved</span>
        {run.current && (
          <span className="text-muted-foreground">
            · now: {LABEL[run.current.role]} <Mono>{run.current.key}</Mono> (call {run.current.iteration})
          </span>
        )}
      </div>
      <div className="grid gap-1">
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>Estimated spend</span>
          <span className="tabular-nums">{usd(run.spent_usd)} of {usd(run.budget_usd)}</span>
        </div>
        <Progress value={pct} />
      </div>
      {run.error && <ErrorNote error={run.error} />}
      {Object.keys(run.summary).length > 0 && (
        <div className="space-y-2">
          {Object.entries(run.summary).map(([tag, s]) => (
            <SummaryLine key={tag} tag={tag} s={(s ?? {}) as Record<string, Json>} />
          ))}
        </div>
      )}
      {run.results.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Agent</TableHead>
              <TableHead>Item</TableHead>
              <TableHead>Outcome</TableHead>
              <TableHead>When</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {[...run.results].reverse().map((r, i) => (
              <TableRow key={i}>
                <TableCell>{LABEL[r.role]}</TableCell>
                <TableCell className="max-w-72 whitespace-normal"><Mono>{r.key}</Mono></TableCell>
                <TableCell className="max-w-md whitespace-normal">
                  {r.role === "longtail" ? <Badge variant="secondary">batch</Badge> : r.saved ? <Badge>saved</Badge> : <Badge variant="outline">flagged</Badge>}
                  {r.reason && <span className="ml-2 text-xs text-muted-foreground">{r.reason}</span>}
                </TableCell>
                <TableCell className="text-muted-foreground">{ago(r.at)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
