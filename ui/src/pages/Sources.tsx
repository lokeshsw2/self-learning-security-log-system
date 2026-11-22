import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Crumbs, Empty, ErrorNote, JsonView, Loading, Mono, RawLine, StatusBadge, useLoad } from "@/components/common"
import { ago, api, fmt, sourceKey, type RuleVersion } from "@/lib/api"
import { go, href } from "@/lib/router"

export function SourcesPage() {
  const { data, error } = useLoad(() => api.sources(), [])
  const [q, setQ] = useState("")
  if (error) return <ErrorNote error={error} />
  if (!data) return <Loading rows={8} />
  const rows = data.filter((s) => !q || `${s.source} ${s.vendor ?? ""} ${s.product ?? ""} ${s.keys.join(" ")}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <Card>
      <CardHeader>
        <CardTitle>Sources</CardTitle>
        <CardDescription>
          Found from the content of each line (format and program). Vendor and product come from source rules the agents wrote.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by format, program, vendor…" className="max-w-sm" />
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Format / program</TableHead>
              <TableHead>Vendor · product</TableHead>
              <TableHead className="text-right">Lines</TableHead>
              <TableHead className="text-right">Groups</TableHead>
              <TableHead className="text-right">With parser</TableHead>
              <TableHead className="text-right">Mapped</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((s) => {
              const labels = [...new Set(s.keys.map((k) => k.split("|")[0]).filter((l) => l !== "-"))]
              return (
                <TableRow key={s.source} className="cursor-pointer" onClick={() => go("sources", s.source)}>
                  <TableCell className="max-w-72 whitespace-normal"><Mono>{s.source}</Mono></TableCell>
                  <TableCell className="whitespace-normal">
                    {s.vendor ? (
                      <span>{s.vendor} · {s.product}</span>
                    ) : (
                      <span className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="outline">unnamed</Badge>
                        {labels.length > 0 && <span className="text-xs text-muted-foreground">training labels: {labels.slice(0, 5).join(", ")}{labels.length > 5 ? " …" : ""}</span>}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{fmt(s.lines)}</TableCell>
                  <TableCell className="text-right tabular-nums">{fmt(s.groups)}</TableCell>
                  <TableCell className="text-right tabular-nums">{fmt(s.parsed_groups)}</TableCell>
                  <TableCell className="text-right tabular-nums">{fmt(s.mapped_groups)}</TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

export function SourcePage({ source }: { source: string }) {
  const { data, error } = useLoad(() => api.groups(source), [source])
  return (
    <div>
      <Crumbs items={[{ label: "Sources", href: href("sources") }, { label: source }]} />
      {error && <ErrorNote error={error} />}
      {!data && !error && <Loading rows={6} />}
      {data && (
        <Card>
          <CardHeader>
            <CardTitle>Groups (event types)</CardTitle>
            <CardDescription>{fmt(data.length)} groups. Each has its own parser and OCSF mapping.</CardDescription>
          </CardHeader>
          <CardContent>
            {data.length === 0 ? (
              <Empty>No groups.</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Template</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Lines</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.map((g) => (
                    <TableRow key={g.signature} className="cursor-pointer" onClick={() => go("group", g.signature)}>
                      <TableCell className="whitespace-normal"><RawLine text={g.template} /></TableCell>
                      <TableCell className="w-1"><StatusBadge status={g.status} /></TableCell>
                      <TableCell className="w-1 text-right tabular-nums">{fmt(g.count)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export function GroupPage({ signature }: { signature: string }) {
  const { data: g, error } = useLoad(() => api.group(signature), [signature])
  if (error) return <ErrorNote error={error} />
  if (!g) return <Loading rows={8} />
  const key = sourceKey(g.source)
  const chains = Object.values(g.rules)
  const stats = Object.entries(g.stats ?? {}).slice(0, 40)
  return (
    <div className="space-y-4">
      <Crumbs items={[{ label: "Sources", href: href("sources") }, { label: key, href: href("sources", key) }, { label: g.signature }]} />
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            Group <StatusBadge status={g.status} />
            <span className="text-sm font-normal text-muted-foreground">
              {fmt(g.count)} lines · {g.format} · {g.signatures.length} signature{g.signatures.length === 1 ? "" : "s"}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <RawLine text={g.template} className="rounded-lg border bg-muted/40 p-3" />
          <Button variant="outline" size="sm" onClick={() => go("events", undefined, { group: g.signature })}>
            Events of this group
          </Button>
        </CardContent>
      </Card>

      {chains.length === 0 && (
        <Card>
          <CardHeader>
            <CardTitle>No parser yet</CardTitle>
            <CardDescription>This group is waiting for the parser agent. Its lines are in Unparsed.</CardDescription>
          </CardHeader>
        </Card>
      )}
      {chains.flat().map((c) => (
        <RuleCard key={c.rule_id} version={c.versions.find((v) => v.status === "active") ?? c.versions[c.versions.length - 1]} count={c.versions.length} />
      ))}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Samples kept</CardTitle>
            <CardDescription>Diverse, recent and failure examples. These are what the agents and the save gates see.</CardDescription>
          </CardHeader>
          <CardContent className="divide-y">
            {g.samples.length === 0 && <Empty>None.</Empty>}
            {g.samples.map((s, i) => (
              <div key={i} className="flex gap-2 py-2">
                {s.tag && <Badge variant="secondary" className="shrink-0">{s.tag}</Badge>}
                <RawLine text={s.raw} />
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Field statistics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {stats.length === 0 ? (
              <Empty>None.</Empty>
            ) : (
              <Table>
                <TableBody>
                  {stats.map(([k, v]) => (
                    <TableRow key={k}>
                      <TableCell className="w-1 align-top text-muted-foreground"><Mono>{k}</Mono></TableCell>
                      <TableCell className="whitespace-normal"><Mono className="text-muted-foreground">{JSON.stringify(v).slice(0, 240)}</Mono></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {g.decisions.length > 0 && (
              <div>
                <h3 className="mb-2 text-sm font-medium">Decisions</h3>
                <div className="space-y-1.5 text-sm">
                  {g.decisions.map((d, i) => (
                    <div key={i}>
                      {d.question} → <b>{d.answer}</b> <Badge variant="outline">{d.tier}</Badge>{" "}
                      <span className="text-muted-foreground">by {d.answered_by}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export function RuleCard({ version: v, count }: { version: RuleVersion; count?: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <a href={href("rule", v.rule_id)} className="font-mono text-sm hover:underline">{v.rule_id}</a>
          <Badge>v{v.version}</Badge>
          <Badge variant={v.status === "active" ? "secondary" : "outline"}>{v.status}</Badge>
          <span className="text-xs font-normal text-muted-foreground">
            by {v.meta.created_by ?? "?"} · {ago(v.created_at)}
            {count && count > 1 ? ` · ${count} versions` : ""}
          </span>
        </CardTitle>
        {v.meta.note && <CardDescription>{String(v.meta.note)}</CardDescription>}
      </CardHeader>
      <CardContent>
        <JsonView value={v.body} />
      </CardContent>
    </Card>
  )
}
