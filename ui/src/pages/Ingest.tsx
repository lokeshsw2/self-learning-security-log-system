import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { FileUp, Play, Radio, Square } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { Empty, ErrorNote, Kpi, Mono, useLoad } from "@/components/common"
import { api, fmt, type IngestResult } from "@/lib/api"
import { go } from "@/lib/router"

const CHUNK = 5000

export function IngestPage() {
  const { data: o, error, reload } = useLoad(() => api.overview(), [])
  const [text, setText] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [last, setLast] = useState<IngestResult | null>(null)
  const [kind, setKind] = useState("file")
  const [target, setTarget] = useState("")
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const t = setInterval(reload, 5000)
    return () => clearInterval(t)
  }, [reload])

  async function parse() {
    let lines = text.split("\n")
    if (file) lines = lines.concat((await file.text()).split("\n"))
    lines = lines.filter((l) => l.trim())
    if (!lines.length) {
      toast.error("Paste lines or choose a file first.")
      return
    }
    const id = "ui-" + new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14) + "-" + Math.random().toString(16).slice(2, 8)
    const tot: IngestResult = { ingest_id: id, records: 0, parsed: 0, pending: 0, dlq: 0, new_groups: 0 }
    try {
      for (let i = 0; i < lines.length; i += CHUNK) {
        setBusy(`Processing ${fmt(i)} of ${fmt(lines.length)} lines…`)
        const r = await api.ingest(lines.slice(i, i + CHUNK), id, i + CHUNK >= lines.length)
        tot.records += r.records
        tot.parsed += r.parsed
        tot.pending += r.pending
        tot.dlq += r.dlq
        tot.new_groups += r.new_groups
      }
      setLast(tot)
      toast.success(`${fmt(tot.parsed)} of ${fmt(tot.records)} lines parsed`)
      reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  async function attach() {
    if (!target.trim()) return
    try {
      await api.startStream(kind, target.trim())
      toast.success("Stream attached")
      setTarget("")
      reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const queued = o ? Object.values(o.meta.queue).reduce((a, b) => a + b, 0) : 0

  return (
    <div className="space-y-4">
      {error && <ErrorNote error={error} />}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <Kpi label="Events in ClickHouse" value={o ? fmt(o.events) : "–"} />
        <Kpi label="Unparsed lines" value={o ? fmt(o.unparsed) : "–"} />
        <Kpi label="Sources" value={o ? fmt(o.meta.sources) : "–"} />
        <Kpi label="Groups" value={o ? fmt(o.meta.groups) : "–"} />
        <Kpi label="Parsers" value={o ? fmt(o.meta.rules.parser) : "–"} />
        <Kpi label="Mappings" value={o ? fmt(o.meta.rules.mapping) : "–"} />
        <Kpi label="Waiting for AI" value={o ? fmt(queued) : "–"} />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Paste lines or upload a file</CardTitle>
            <CardDescription>Raw lines from any source. No vendor name is needed: the source is found from the content.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste raw log lines, one per line"
              className="min-h-44 font-mono text-xs"
            />
            <div className="flex flex-wrap items-center gap-2">
              <input ref={fileRef} type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              <Button variant="outline" onClick={() => fileRef.current?.click()}>
                <FileUp /> {file ? file.name : "Choose file"}
              </Button>
              {file && (
                <Button variant="ghost" size="sm" onClick={() => { setFile(null); if (fileRef.current) fileRef.current.value = "" }}>
                  Clear file
                </Button>
              )}
              <Button onClick={parse} disabled={!!busy}>
                <Play /> Parse
              </Button>
              {busy && <span className="text-sm text-muted-foreground">{busy}</span>}
            </div>
            {last && (
              <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/40 p-3 text-sm">
                <span>{fmt(last.records)} lines:</span>
                <Badge>{fmt(last.parsed)} parsed</Badge>
                <Badge variant="outline">{fmt(last.pending)} waiting for a rule</Badge>
                {last.dlq > 0 && <Badge variant="destructive">{fmt(last.dlq)} failed</Badge>}
                {last.new_groups > 0 && <Badge variant="secondary">{fmt(last.new_groups)} new groups</Badge>}
                <Button variant="link" size="sm" onClick={() => go("events", undefined, { ingest: last.ingest_id })}>
                  View events →
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Attach a stream</CardTitle>
            <CardDescription>Follow a growing file, or read a Kafka topic as broker/topic.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-1.5">
              <Label>Type</Label>
              <Select value={kind} onValueChange={(v) => setKind(String(v))}>
                <SelectTrigger className="w-full">
                  <SelectValue>{(v: string) => (v === "kafka" ? "Kafka topic" : "File (follow new lines)")}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="file">File (follow new lines)</SelectItem>
                  <SelectItem value="kafka">Kafka topic</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>Target</Label>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={kind === "file" ? "/var/log/app.log" : "localhost:9092/raw-logs"}
                className="font-mono text-xs"
              />
            </div>
            <Button variant="outline" onClick={attach}>
              <Radio /> Attach
            </Button>
            {o && o.streams.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Stream</TableHead>
                    <TableHead className="text-right">Lines</TableHead>
                    <TableHead className="text-right">Parsed</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {o.streams.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="max-w-56 whitespace-normal">
                        <Mono>{s.kind}: {s.target}</Mono>
                        {s.error && <div className="text-xs text-destructive">{s.error}</div>}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{fmt(s.lines)}</TableCell>
                      <TableCell className="text-right tabular-nums">{fmt(s.parsed)}</TableCell>
                      <TableCell className="text-right">
                        {s.running ? (
                          <Button size="sm" variant="ghost" onClick={() => api.stopStream(s.id).then(reload)}>
                            <Square /> Stop
                          </Button>
                        ) : (
                          <Badge variant="secondary">stopped</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Recent ingests</CardTitle>
          </CardHeader>
          <CardContent>
            {o && o.ingests.length === 0 && <Empty>Nothing ingested yet.</Empty>}
            {o && o.ingests.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Ingest</TableHead>
                    <TableHead>Started (UTC)</TableHead>
                    <TableHead className="text-right">Events</TableHead>
                    <TableHead className="text-right">Unparsed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {o.ingests.map((x) => (
                    <TableRow key={x.ingest_id} className="cursor-pointer" onClick={() => go("events", undefined, { ingest: x.ingest_id })}>
                      <TableCell><Mono>{x.ingest_id}</Mono></TableCell>
                      <TableCell className="text-muted-foreground">{x.first_at}</TableCell>
                      <TableCell className="text-right tabular-nums">{fmt(x.parsed)}</TableCell>
                      <TableCell className="text-right tabular-nums">{fmt(x.unparsed)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Events by OCSF class</CardTitle>
          </CardHeader>
          <CardContent>
            {o && o.by_class.length === 0 && <Empty>No events yet.</Empty>}
            <div className="space-y-2">
              {o?.by_class.map((c) => {
                const pct = o.events ? (100 * c.n) / o.events : 0
                return (
                  <button
                    key={c.class_uid}
                    className="block w-full text-left"
                    onClick={() => go("events", undefined, { class: String(c.class_uid) })}
                  >
                    <div className="flex justify-between text-sm">
                      <span>{c.class_name} <span className="text-xs text-muted-foreground">{c.class_uid}</span></span>
                      <span className="tabular-nums text-muted-foreground">{fmt(c.n)}</span>
                    </div>
                    <div className="mt-1 h-1.5 rounded-full bg-muted">
                      <div className="h-1.5 rounded-full bg-primary" style={{ width: `${Math.max(pct, 1)}%` }} />
                    </div>
                  </button>
                )
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
