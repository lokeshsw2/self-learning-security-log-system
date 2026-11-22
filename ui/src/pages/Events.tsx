import { useEffect, useState } from "react"
import { ChevronRight, Search } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { Empty, ErrorNote, JsonView, Loading, Mono, RawLine } from "@/components/common"
import { api, fmt, sourceKey, type EventRow } from "@/lib/api"
import { go, href, type Route } from "@/lib/router"

const PAGE = 50

export function EventsPage({ route }: { route: Route }) {
  const p = route.params
  const [form, setForm] = useState({ ingest: p.ingest ?? "", source: p.source ?? "", cls: p.class ?? "", q: p.q ?? "" })
  const [rows, setRows] = useState<EventRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const query = { ingest_id: p.ingest, source: p.source, group: p.group, class_uid: p.class, q: p.q }

  useEffect(() => {
    setForm({ ingest: p.ingest ?? "", source: p.source ?? "", cls: p.class ?? "", q: p.q ?? "" })
    setRows(null)
    setError(null)
    api.events({ ...query, limit: PAGE, offset: 0 }).then(
      (r) => { setRows(r.rows); setTotal(r.total) },
      (e: Error) => setError(e.message),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.ingest, p.source, p.group, p.class, p.q])

  function search() {
    go("events", undefined, { ingest: form.ingest.trim(), source: form.source.trim(), class: form.cls.trim(), q: form.q.trim(), group: p.group ?? "" })
  }

  async function more() {
    const r = await api.events({ ...query, limit: PAGE, offset: rows?.length ?? 0 })
    setRows((x) => [...(x ?? []), ...r.rows])
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardContent>
          <form
            className="grid items-end gap-3 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_0.6fr_1fr_auto]"
            onSubmit={(e) => { e.preventDefault(); search() }}
          >
            <Field label="Ingest" value={form.ingest} onChange={(v) => setForm({ ...form, ingest: v })} />
            <Field label="Source" value={form.source} onChange={(v) => setForm({ ...form, source: v })} />
            <Field label="OCSF class uid" value={form.cls} onChange={(v) => setForm({ ...form, cls: v })} />
            <Field label="Raw text contains" value={form.q} onChange={(v) => setForm({ ...form, q: v })} />
            <Button type="submit"><Search /> Search</Button>
          </form>
          {p.group && (
            <div className="mt-3 flex items-center gap-2 text-sm">
              Group <Mono>{p.group}</Mono>
              <Button variant="ghost" size="sm" onClick={() => go("events", undefined, { ...p, group: "" })}>clear</Button>
            </div>
          )}
        </CardContent>
      </Card>

      {error && <ErrorNote error={error} />}
      {!rows && !error && <Loading rows={6} />}
      {rows && (
        <>
          <div className="px-1 text-sm text-muted-foreground">{fmt(total)} events</div>
          {rows.length === 0 && <Empty>No events match.</Empty>}
          <div className="space-y-2">
            {rows.map((r) => <EventCard key={`${r.ingest_id}-${r.raw_id}`} r={r} />)}
          </div>
          {rows.length < total && (
            <div className="flex justify-center">
              <Button variant="outline" onClick={more}>Load more</Button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="grid gap-1.5">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder="any" />
    </div>
  )
}

function EventCard({ r }: { r: EventRow }) {
  const fields = Object.entries(r.fields ?? {})
  const errs = r.errors && r.errors !== "[]" ? r.errors : null
  return (
    <Collapsible>
      <Card size="sm" className="gap-0 py-0">
        <CollapsibleTrigger className="group w-full cursor-pointer px-4 py-3 text-left hover:bg-muted/40">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <ChevronRight className="size-4 text-muted-foreground transition-transform group-data-[panel-open]:rotate-90" />
            <Badge variant={r.class_uid === 0 ? "secondary" : "default"}>{r.class_name}</Badge>
            {r.valid !== 1 && <Badge variant="destructive">invalid</Badge>}
            <span className="text-muted-foreground">{r.time} UTC</span>
            {(r.vendor_name || r.product_name) && <span className="text-muted-foreground">{r.vendor_name} · {r.product_name}</span>}
            {r.user_name && <span>user <b>{r.user_name}</b></span>}
            {r.src_ip && <span className="font-mono text-xs">{r.src_ip}{r.dst_ip && ` → ${r.dst_ip}`}</span>}
          </div>
          <RawLine text={r.message} className="mt-1.5 pl-6 text-muted-foreground" />
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="grid gap-4 border-t p-4 lg:grid-cols-2">
            <div className="space-y-4">
              <div>
                <h3 className="mb-2 text-sm font-medium">Parsed fields <span className="text-muted-foreground">({fields.length})</span></h3>
                <Table>
                  <TableBody>
                    {fields.map(([k, v]) => (
                      <TableRow key={k}>
                        <TableCell className="w-1 align-top text-muted-foreground"><Mono>{k}</Mono></TableCell>
                        <TableCell className="whitespace-normal"><Mono>{typeof v === "object" ? JSON.stringify(v) : String(v)}</Mono></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div>
                <h3 className="mb-2 text-sm font-medium">Made by</h3>
                <Table>
                  <TableBody>
                    <Prov label="Source" text={r.lp_source} to={href("sources", sourceKey(r.lp_source))} />
                    <Prov label="Group" text={r.lp_group_id} to={href("group", r.lp_group_id)} />
                    <Prov label="Parser" text={`${r.parser_rule} v${r.lp_parser_version}`} to={href("rule", r.parser_rule)} />
                    <Prov label="Mapping" text={`${r.mapping_rule} v${r.lp_mapping_version}`} to={href("rule", r.mapping_rule)} />
                    {errs && (
                      <TableRow>
                        <TableCell className="w-1 text-muted-foreground">Problems</TableCell>
                        <TableCell className="whitespace-normal text-destructive"><Mono>{errs}</Mono></TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
            <div>
              <h3 className="mb-2 text-sm font-medium">OCSF event</h3>
              <JsonView value={r.event} />
            </div>
          </div>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}

function Prov({ label, text, to }: { label: string; text: string; to: string }) {
  return (
    <TableRow>
      <TableCell className="w-1 text-muted-foreground">{label}</TableCell>
      <TableCell className="whitespace-normal">
        <a href={to} className="text-primary hover:underline"><Mono>{text}</Mono></a>
      </TableCell>
    </TableRow>
  )
}
