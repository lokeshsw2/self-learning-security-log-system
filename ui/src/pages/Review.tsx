import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Empty, ErrorNote, Kpi, Loading, Mono, RawLine, useLoad } from "@/components/common"
import { ago, fmt, reviewApi, type Drift, type DriftRow, type ReviewItem } from "@/lib/api"
import { go } from "@/lib/router"

const AGENT_LABEL: Record<string, string> = {
  "ls-direct": "Logstash filter writer",
  "parser-gen": "Parser writer",
  "ocsf-mapping": "OCSF mapper",
  "source-naming": "Source naming",
  "grouping-repair": "Grouping repair",
  detection: "Detection",
  longtail: "Long tail",
}

export function ReviewPage() {
  const inbox = useLoad(() => reviewApi.inbox(), [])
  const drift = useLoad(() => reviewApi.drift(), [])
  const n = inbox.data?.length ?? 0
  const driftN = drift.data
    ? drift.data.rule_failing.length + drift.data.new_format_known_source.length + (drift.data.last_lsaudit?.groups_failing ?? 0)
    : 0
  return (
    <Tabs defaultValue="inbox" className="space-y-4">
      <TabsList>
        <TabsTrigger value="inbox">Needs a person {n > 0 && <Badge variant="secondary" className="ml-1.5">{n}</Badge>}</TabsTrigger>
        <TabsTrigger value="health">Audit & drift {driftN > 0 && <Badge variant="secondary" className="ml-1.5">{driftN}</Badge>}</TabsTrigger>
      </TabsList>
      <TabsContent value="inbox" className="space-y-3">
        {inbox.error && <ErrorNote error={inbox.error} />}
        {!inbox.data && !inbox.error && <Loading rows={5} />}
        {inbox.data && inbox.data.length === 0 && (
          <Card><CardContent><Empty>Nothing is waiting for a person.</Empty></CardContent></Card>
        )}
        {inbox.data?.map((it) => (
          <InboxCard key={`${it.name}/${it.key}`} item={it} onDone={() => { inbox.reload(); drift.reload() }} />
        ))}
      </TabsContent>
      <TabsContent value="health" className="space-y-4">
        {drift.error && <ErrorNote error={drift.error} />}
        {!drift.data && !drift.error && <Loading rows={5} />}
        {drift.data && <Health d={drift.data} reload={drift.reload} />}
      </TabsContent>
    </Tabs>
  )
}

function InboxCard({ item, onDone }: { item: ReviewItem; onDone: () => void }) {
  const [answer, setAnswer] = useState("")
  const [busy, setBusy] = useState(false)
  const g = item.group
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    try {
      await fn()
      toast.success(ok)
      onDone()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={item.name === "human-review" ? "destructive" : "outline"}>
            {item.name === "human-review" ? "Audit failed repeatedly" : "Agent gave up"}
          </Badge>
          {item.agent && <Badge variant="secondary">{AGENT_LABEL[item.agent] ?? item.agent}</Badge>}
          <span className="text-xs text-muted-foreground">{ago(item.at)}</span>
        </div>
        <CardTitle className="text-base">
          {g ? (
            <button className="text-left hover:underline" onClick={() => go("group", g.signature)}>
              {g.labels.product || g.source} <span className="font-normal text-muted-foreground">· {g.format} · {fmt(g.count)} lines</span>
            </button>
          ) : (
            <Mono>{item.key}</Mono>
          )}
        </CardTitle>
        {g && <CardDescription><Mono>{g.template}</Mono></CardDescription>}
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="rounded-md border bg-muted/40 p-3 text-sm whitespace-pre-wrap">{item.why}</div>
        {item.examples.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-xs font-medium text-muted-foreground">Where it went wrong</div>
            {item.examples.map((x, i) => (
              <div key={i} className="rounded-md border p-2">
                <div className="text-xs text-destructive">{x.problem}</div>
                {x.line && <RawLine text={x.line} className="mt-1 text-muted-foreground" />}
              </div>
            ))}
          </div>
        )}
        {g && g.samples.length > 0 && (
          <details>
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground">Sample lines ({g.samples.length})</summary>
            <div className="mt-1.5 space-y-1">{g.samples.map((s, i) => <RawLine key={i} text={s} className="rounded bg-muted/40 p-1.5" />)}</div>
          </details>
        )}
        <Textarea
          value={answer}
          onChange={(e) => setAnswer(e.target.value)}
          placeholder={g
            ? "Tell the agent what to do, e.g. “Use detection_finding; assignedTo is often empty.” It retries this group with your answer and keeps it for later groups."
            : "Your answer. It is stored as a decision the agents read."}
          rows={3}
        />
        <div className="flex flex-wrap gap-2">
          <Button disabled={busy || !answer.trim()} onClick={() => act(() => reviewApi.answer(item.name, item.key, answer),
            g ? "Sent back to the agent with your answer" : "Answer saved")}>
            {g ? "Answer and retry" : "Save answer"}
          </Button>
          {g && (
            <Button variant="outline" disabled={busy} onClick={() => act(() => reviewApi.resolve(item.name, item.key, "ignore_group"),
              "Group ignored: its lines stay unparsed")}>
              Ignore this group
            </Button>
          )}
          <Button variant="ghost" disabled={busy} onClick={() => act(() => reviewApi.resolve(item.name, item.key, "dismiss"), "Dismissed")}>
            Dismiss
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function Health({ d, reload }: { d: Drift; reload: () => void }) {
  const run = d.lsaudit_run
  const running = !!run?.running
  useEffect(() => {
    if (!running) return
    const t = setInterval(reload, 3000)
    return () => clearInterval(t)
  }, [running, reload])
  const last = run?.result ?? d.last_lsaudit
  const start = async () => {
    try {
      await reviewApi.lsaudit()
      toast.success("Audit started")
      reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Logstash filter audit (Variant B)</CardTitle>
          <CardDescription>
            Runs every saved filter again on the newest stored lines of its group, and checks events already written to
            ClickHouse. New lines failing is how a changed format shows up. Failing groups go back to the filter writer
            with examples; after two failed rounds they come here.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-3">
            <Button onClick={start} disabled={running}>{running ? "Auditing…" : "Run audit"}</Button>
            {run?.error && <span className="text-sm text-destructive">{run.error}</span>}
            {running && <span className="text-sm text-muted-foreground">started {ago(run?.started)}</span>}
          </div>
          {last ? (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Kpi label="Filters checked" value={fmt(last.groups_checked)} />
              <Kpi label="Lines checked" value={fmt(last.lines_checked)} />
              <Kpi label="Failing" value={fmt(last.groups_failing)} />
              <Kpi label="Sent back" value={fmt(Object.values(last.routed ?? {}).reduce((a, b) => a + b, 0))} />
            </div>
          ) : (
            <Empty>No audit has run yet.</Empty>
          )}
          {last && Object.keys(last.by_check ?? {}).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(last.by_check).map(([c, n]) => <Badge key={c} variant="outline">{c}: {fmt(n)} lines</Badge>)}
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Lines the live Logstash failed on (24 h) <Badge variant="secondary" className="ml-1">{d.logstash_failures.length}</Badge></CardTitle>
          <CardDescription>Lines that reached a deployed format's pipeline and failed there: a format changed under a deployed filter. Lines of formats not deployed yet are not counted.</CardDescription>
        </CardHeader>
        {d.logstash_failures.length > 0 && (
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Pipeline</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead className="text-right">Lines</TableHead>
                  <TableHead>Example</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.logstash_failures.map((f) => (
                  <TableRow key={f.pipeline + f.reason}>
                    <TableCell><Mono>{f.pipeline}</Mono></TableCell>
                    <TableCell>{f.reason}</TableCell>
                    <TableCell className="text-right tabular-nums">{fmt(f.n)}</TableCell>
                    <TableCell className="max-w-xl whitespace-normal"><RawLine text={f.example.slice(0, 300)} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        )}
      </Card>
      <DriftTable title="Rules that started failing" hint="Variant A groups whose parser fails on new lines; the parser writer has them again."
        rows={d.rule_failing} extra={(r) => `${fmt(r.failures)} failures`} />
      <DriftTable title="New formats from a known source" hint="Groups first seen recently from a source whose other formats are already parsed: often a product update."
        rows={d.new_format_known_source} extra={(r) => `${r.known_groups} known formats`} />
      <DriftTable title="New key sets on known formats" hint="Structured groups that absorbed lines with new fields. The audit shows whether their rules still hold."
        rows={d.new_key_sets} extra={(r) => `${r.new_signatures} new key sets`} />
      <DriftTable title="Deployed groups that went quiet" hint="No lines for a long time: the source may have stopped, or changed format."
        rows={d.went_quiet} extra={(r) => `last batch ${r.last_batch}`} />
    </>
  )
}

function DriftTable({ title, hint, rows, extra }: { title: string; hint: string; rows: DriftRow[]; extra: (r: DriftRow) => string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title} <Badge variant="secondary" className="ml-1">{rows.length}</Badge></CardTitle>
        <CardDescription>{hint}</CardDescription>
      </CardHeader>
      {rows.length > 0 && (
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Group</TableHead>
                <TableHead>Format</TableHead>
                <TableHead className="text-right">Lines</TableHead>
                <TableHead>Signal</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.slice(0, 50).map((r) => (
                <TableRow key={r.signature} className="cursor-pointer" onClick={() => go("group", r.signature)}>
                  <TableCell className="max-w-xl whitespace-normal"><Mono>{r.template}</Mono></TableCell>
                  <TableCell>{r.format}</TableCell>
                  <TableCell className="text-right tabular-nums">{fmt(r.count)}</TableCell>
                  <TableCell className="text-muted-foreground">{extra(r)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      )}
    </Card>
  )
}
