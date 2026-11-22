import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Empty, ErrorNote, Loading, Mono, RawLine, useLoad } from "@/components/common"
import { api, fmt } from "@/lib/api"
import { go } from "@/lib/router"

export function UnparsedPage() {
  const { data, error } = useLoad(() => api.unparsed(), [])
  if (error) return <ErrorNote error={error} />
  if (!data) return <Loading rows={6} />
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Unparsed by group</CardTitle>
          <CardDescription>
            Lines with no event yet. When a rule is written for the group, these lines are parsed and move to Events.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {data.by_group.length === 0 ? (
            <Empty>No unparsed lines.</Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Group</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Why</TableHead>
                  <TableHead className="text-right">Lines</TableHead>
                  <TableHead>Example</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.by_group.map((g) => (
                  <TableRow key={g.lp_group_id || g.example} className="cursor-pointer" onClick={() => g.lp_group_id && go("group", g.lp_group_id)}>
                    <TableCell><Mono>{g.lp_group_id || "—"}</Mono></TableCell>
                    <TableCell className="max-w-48 whitespace-normal"><Mono>{g.source}</Mono></TableCell>
                    <TableCell className="text-muted-foreground">{g.reason}</TableCell>
                    <TableCell className="text-right tabular-nums">{fmt(g.n)}</TableCell>
                    <TableCell className="max-w-xl whitespace-normal"><RawLine text={g.example} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {data.rows.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent unparsed lines</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableBody>
                {data.rows.map((r) => (
                  <TableRow key={r.raw_id}>
                    <TableCell className="w-1 text-muted-foreground">{r.received_at}</TableCell>
                    <TableCell className="w-1"><Badge variant="outline">{r.status}</Badge></TableCell>
                    <TableCell className="whitespace-normal"><RawLine text={r.message} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
