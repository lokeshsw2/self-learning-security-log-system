// Minimal hash router: #/view/arg?key=value. Links survive a reload and can be shared.
import { useEffect, useState } from "react"

export interface Route {
  view: string
  arg: string
  params: Record<string, string>
}

function parse(): Route {
  const h = window.location.hash.replace(/^#\/?/, "")
  const [path, query = ""] = h.split("?")
  const [view = "ingest", ...rest] = path.split("/")
  return {
    view: view || "ingest",
    arg: decodeURIComponent(rest.join("/")),
    params: Object.fromEntries(new URLSearchParams(query)),
  }
}

export function useRoute(): Route {
  const [r, setR] = useState(parse)
  useEffect(() => {
    const on = () => setR(parse())
    window.addEventListener("hashchange", on)
    return () => window.removeEventListener("hashchange", on)
  }, [])
  return r
}

export function href(view: string, arg?: string, params?: Record<string, string>) {
  const q = params ? new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString() : ""
  return `#/${view}${arg ? "/" + encodeURIComponent(arg) : ""}${q ? "?" + q : ""}`
}

export function go(view: string, arg?: string, params?: Record<string, string>) {
  window.location.hash = href(view, arg, params)
}
