
unless defined?(::LP_LOADED)
LP_LOADED = 1
require "json"
require "digest"
require "csv"
require "date"
module LP
  class Err < StandardError; end
  RX = {}
  MAXF = 3000
  MONTHS = {"jan"=>1,"feb"=>2,"mar"=>3,"apr"=>4,"may"=>5,"jun"=>6,"jul"=>7,"aug"=>8,"sep"=>9,"oct"=>10,"nov"=>11,"dec"=>12}
  ISO = /\A(\d{4})-(\d\d)-(\d\d)[Tt ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s*(Z|z|UTC|GMT|[+-]\d\d:?\d\d)?\z/
  SLASH = /\A(\d{4})\/(\d\d?)\/(\d\d?)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\z/
  SYSL = /\A(?:[A-Z][a-z]{2},? )?([A-Z][a-z]{2})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d\d):(\d\d):(\d\d)(?:[.,](\d+))?(?:\s+(\d{4}))?(?:\s+(Z|UTC|GMT|[+-]\d\d:?\d\d))?\z/
  CLF = /\A(\d\d?)\/([A-Za-z]{3})\/(\d{4})[: ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?(?:\s+([+-]\d{4}))?\z/
  OFFS = /\A([+-])(\d\d):?(\d\d)\z/
  NUM = /\A-?\d+(?:\.\d+)?\z/
  INTR = /\A\s*([+-]?\d+)\s*\z/
  FLTR = /\A\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\s*\z/
  S = "[@metadata][s]"

  def self.tz=(v) @tz = v end
  def self.tz() @tz || "UTC" end
  def self.rx(src) RX[src] ||= Regexp.new(src) end
  def self.dig(s) Digest::SHA1.hexdigest(s)[0, 16] end
  def self.now
    @now ||= ENV["LP_NOW"] ? ENV["LP_NOW"].to_f : false
    @now || Time.now.to_f
  end
  def self.pystr(v)
    case v
    when true then "True"
    when false then "False"
    when nil then "None"
    else v.to_s
    end
  end
  def self.pystrip(s, chars)
    return s.strip if chars.nil?
    c = Regexp.escape(chars)
    s.gsub(Regexp.new("\\A[" + c + "]+"), "").gsub(Regexp.new("[" + c + "]+\\z"), "")
  end
  def self.empty?(v) v.nil? || v == "" end

  # ------------------------------------------------------------ decoders
  def self.flatten(obj, depth = 8, prefix = "", out = {})
    return out if out.size >= MAXF
    if obj.is_a?(Hash) && depth > 0
      out[prefix[0..-2]] = "{}" if obj.empty? && !prefix.empty?
      obj.each { |k, v| flatten(v, depth - 1, "#{prefix}#{k}.", out) }
    elsif obj.is_a?(Array) && depth > 0
      out[prefix[0..-2]] = "[]" if obj.empty? && !prefix.empty?
      obj.first(200).each_with_index { |v, i| flatten(v, depth - 1, "#{prefix}#{i}.", out) }
    elsif obj.is_a?(Hash) || obj.is_a?(Array)
      out[prefix[0..-2]] = JSON.generate(obj)
    elsif !obj.nil?
      out[prefix[0..-2]] = obj
    end
    out
  end

  def self.shape(obj, depth)
    out = []
    walk = lambda do |o, d, pre|
      o.each do |k, v|
        if v.is_a?(Hash) && d > 1 && !v.empty?
          walk.call(v, d - 1, "#{pre}#{k}.")
        else
          out << "#{pre}#{k}"
        end
      end
    end
    walk.call(obj, depth, "")
    out.sort
  end

  def self.kv_pairs(text, d)
    fields = {}
    covered = 0
    if d["mode"] == "pair"
      pat = rx(d["pair_pattern"])
      names = pat.names
      left = []
      pos = 0
      first = nil
      text.scan(pat) do
        m = Regexp.last_match
        first ||= m.begin(0)
        k = m[:k]
        v = nil
        ["q", "s"].each do |qg|
          if names.include?(qg) && !m[qg].nil?
            v = m[qg]
            if d.fetch("unescape", true) && v.include?("\\")
              v = v.gsub("\\\"") { "\"" }.gsub("\\\\") { "\\" }
            end
            break
          end
        end
        v = m["v"] if v.nil? && names.include?("v")
        v = "" if v.nil?
        if !fields.key?(k)
          fields[k] = v
        else
          n = 2
          n += 1 while fields.key?("#{k}##{n}")
          fields["#{k}##{n}"] = v
        end
        left << text[pos...m.begin(0)]
        pos = m.end(0)
        covered += m.end(0) - m.begin(0)
        break if fields.size >= MAXF
      end
      left << text[pos..-1].to_s
      leftover = left.join(" ").split.join(" ")
      return [fields, leftover, covered, text[0, first || 0].strip]
    end
    pat = rx(d["key_pattern"])
    ms = []
    text.scan(pat) { ms << Regexp.last_match }
    return [{}, text.strip, 0, text.strip] if ms.empty?
    strip = d["strip"] || " \t"
    ms.each_with_index do |m, i|
      e = i + 1 < ms.size ? ms[i + 1].begin(0) : text.size
      v = pystrip(text[m.end(0)...e].to_s, strip)
      if d.fetch("unescape", true) && v.include?("\\")
        v = v.gsub("\\=") { "=" }.gsub("\\|") { "|" }.gsub("\\\\") { "\\" }
      end
      k = m[:k]
      fields[k] = v unless fields.key?(k)
      break if fields.size >= MAXF
    end
    leftover = text[0, ms[0].begin(0)].strip
    [fields, leftover, text.size - ms[0].begin(0), leftover]
  end

  CEF_EXT = {"mode" => "span", "key_pattern" => "(?:\\A|\\s)(?<k>[A-Za-z_][\\w.\\-]*)=", "strip" => " \t"}
  LEEF_EXT = {"mode" => "span", "key_pattern" => "(?:\\A|[\\t ])(?<k>[A-Za-z_][\\w.\\-]*)=", "strip" => " \t"}

  def self.split_header(text, n)
    parts = []
    cur = +""
    i = 0
    while i < text.size && parts.size < n
      ch = text[i]
      if ch == "\\" && i + 1 < text.size && "|\\".include?(text[i + 1])
        cur << text[i + 1]
        i += 2
        next
      end
      if ch == "|"
        parts << cur
        cur = +""
      else
        cur << ch
      end
      i += 1
    end
    raise Err, "header" if parts.size < n
    parts << text[i..-1].to_s
    parts
  end

  def self.labels(fields)
    fields.keys.select { |k| k.end_with?("Label") }.each do |k|
      base = k[0..-6]
      name = fields[k].to_s.strip
      fields["label.#{name}"] = fields[base] if fields.key?(base) && !name.empty? && !fields.key?("label.#{name}")
    end
  end

  def self.parse_cef(text)
    i = text.index("CEF:")
    raise Err, "cef" if i.nil?
    h = split_header(text[(i + 4)..-1], 7)
    fields = {"cef.version" => h[0].strip, "cef.vendor" => h[1], "cef.product" => h[2], "cef.device_version" => h[3],
              "cef.signature_id" => h[4], "cef.name" => h[5], "cef.severity" => h[6]}
    ext = kv_pairs(h[7], CEF_EXT)[0]
    labels(ext)
    ext.each { |k, v| fields[k] = v unless fields.key?(k) }
    fields
  end

  def self.parse_leef(text)
    i = text.index("LEEF:")
    raise Err, "leef" if i.nil?
    h = split_header(text[(i + 5)..-1], 5)
    fields = {"leef.version" => h[0].strip, "leef.vendor" => h[1], "leef.product" => h[2],
              "leef.product_version" => h[3], "leef.event_id" => h[4]}
    rest = h[5]
    delim = nil
    if h[0].strip.start_with?("2") && rest.include?("|")
      head, tail = rest.split("|", 2)
      if head.size == 1 || (head.downcase.start_with?("x", "0x") && head.size <= 6)
        if head.size == 1
          delim = head
        else
          hx = head.downcase.sub(/\A[0x]+/, "")
          delim = [(hx.empty? ? "9" : hx).to_i(16)].pack("U")
        end
        rest = tail.to_s
      end
    end
    if delim && !"\t ".include?(delim)
      ext = {}
      rest.split(delim).each do |part|
        if part.include?("=")
          k, v = part.split("=", 2)
          ext[k.strip] = v.strip unless ext.key?(k.strip)
        end
      end
    else
      ext = kv_pairs(rest, LEEF_EXT)[0]
    end
    labels(ext)
    ext.each { |k, v| fields[k] = v unless fields.key?(k) }
    fields
  end

  # port of Python csv.reader (excel dialect, non-strict) for one line
  def self.csv_split(text, d)
    fields = []
    cur = +""
    state = :start
    text.each_char do |ch|
      case state
      when :start
        if ch == "\""
          state = :quoted
        elsif ch == d
          fields << cur
          cur = +""
        else
          cur << ch
          state = :field
        end
      when :field
        if ch == d
          fields << cur
          cur = +""
          state = :start
        else
          cur << ch
        end
      when :quoted
        if ch == "\""
          state = :qq
        else
          cur << ch
        end
      when :qq
        if ch == "\""
          cur << "\""
          state = :quoted
        elsif ch == d
          fields << cur
          cur = +""
          state = :start
        else
          cur << ch
          state = :field
        end
      end
    end
    fields << cur
    fields
  end

  def self.split_delimited(text, d, quote = "\"")
    return csv_split(text, d) if quote && text.include?(quote)
    text.split(d, -1)
  end

  def self.parse_delimited(text, d, columns, strip = true)
    vals = split_delimited(text, d)
    raise Err, "columns" if columns && vals.size != columns.size
    names = columns || (0...vals.size).map { |i| "c#{i}" }
    out = {}
    names.each_with_index do |n, i|
      v = vals[i]
      v = v.strip if strip
      out[n] = v unless v == ""
    end
    out
  end

  # ------------------------------------------------------------ detection
  def self.kv_test(ev, name, t)
    c = t["DET"][name]["test"]
    text = ev.get(S + "[payload]")
    d = t["DIAL"][c["dialect"]]
    return if d.nil?
    fields, _l, covered, _p = kv_pairs(text, d)
    if fields.size >= (c["min_pairs"] || 3) && covered.to_f / [1, text.size].max >= (c["min_coverage"] || 0.5)
      ev.set(S + "[hit]", name)
      ev.set(S + "[extra]", c["dialect"])
    end
  end

  def self.delim_test(ev, name, t)
    c = t["DET"][name]["test"]
    text = ev.get(S + "[payload]")
    d = c["delimiter"]
    return if text.count(d) + 1 < (c["min_fields"] || 5)
    parts = split_delimited(text, d)
    return if c.key?("max_first_share") && parts[0].size > c["max_first_share"] * text.size
    if parts.size >= (c["min_fields"] || 5)
      ev.set(S + "[hit]", name)
      ev.set(S + "[extra]", d)
    end
  end

  def self.jwrap_test(ev, name, t)
    c = t["DET"][name]["test"]
    s = ev.get(S + "[payload]").strip
    return unless s.start_with?("{") && s.end_with?("}")
    begin
      obj = JSON.parse(s)
    rescue StandardError
      return
    end
    return unless obj.is_a?(Hash)
    return if obj.size > (c["max_keys"] || 6)
    c["fields"].each do |f|
      v = obj[f]
      if v.is_a?(String) && v.size > 20
        caps = {}
        obj.each do |k, x|
          next if k == f
          caps[k] = pystr(x) if x.is_a?(String) || x.is_a?(Integer) || x.is_a?(Float) || x == true || x == false
        end
        caps["payload"] = v
        ev.set(S + "[c]", caps)
        ev.set(S + "[hit]", name)
        return
      end
    end
  end

  def self.post(ev, lvl, t)
    hit = ev.get(S + "[hit]")
    if hit.nil?
      ev.set(S + "[done]", true)
      return
    end
    chk = t["DET"][hit]
    caps = ev.get(S + "[c]")
    caps = caps ? caps.to_h : {}
    ev.remove(S + "[c]")
    ev.remove(S + "[hit]")
    caps.delete_if { |k, v| v.nil? || (v == "-" && k != "payload") }
    payload = caps.delete("payload")
    fb = chk["payload_fallback"]
    payload = caps[fb] if payload.nil? && fb
    payload = caps[fb] if payload == "" && fb && !empty?(caps[fb])
    (chk["header_patterns"] || {}).each do |fld, pats|
      src = caps[fld]
      next if empty?(src)
      pats.each do |p|
        m = rx(p).match(src)
        if m
          m.names.each { |n| caps[n] = m[n] unless m[n].nil? }
          break
        end
      end
    end
    h = ev.get(S + "[h]")
    h = h ? h.to_h : {}
    caps.each { |k, v| h["@" + k] = v unless h.key?("@" + k) }
    ev.set(S + "[h]", h)
    app = (chk["app"] || []).map { |k| caps[k] }.select { |x| !empty?(x) }.join("-")
    ev.set(S + "[app]", app.strip[0, 80]) unless app.empty?
    chain = ev.get(S + "[chain]") + chk["name"] + ">"
    ev.set(S + "[chain]", chain)
    if chk["type"] == "envelope"
      ev.set(S + "[payload]", payload.nil? ? "" : payload)
      ev.set(S + "[done]", true) unless chain.count(">") - 1 <= 4
    else
      ev.set(S + "[payload]", payload) unless payload.nil?
      ev.set(S + "[fmt]", chk["format"])
      ev.set(S + "[dialect]", ev.get(S + "[extra]")) if chk["test"]["kind"] == "kv"
      ev.set(S + "[delim]", ev.get(S + "[extra]")) if chk["test"]["kind"] == "delimited"
      ev.set(S + "[done]", true)
    end
    ev.remove(S + "[extra]")
  end

  def self.bucket(ev, t)
    chain = ev.get(S + "[chain]").split(">").reject { |x| x.empty? }
    if ev.get(S + "[fmt]").nil?
      chain << "unstructured"
      ev.set(S + "[fmt]", "unstructured")
    end
    app = ev.get(S + "[app]")
    b = chain.join(">") + "|" + (empty?(app) ? "-" : app)
    ev.set(S + "[bucket]", b)
    ev.set(S + "[rkey]", dig(b)) if ev.get(S + "[fmt]") == "unstructured"
  end

  # ------------------------------------------------------------ signature
  def self.mask(text, pats, prot)
    segs = [[text, nil]]
    pats.each do |src, ph, grp|
      pat = rx(src)
      nxt = []
      segs.each do |seg, p|
        if !p.nil? || seg.empty?
          nxt << [seg, p]
          next
        end
        pos = 0
        seg.scan(pat) do
          m = Regexp.last_match
          s = m.begin(grp)
          e = m.end(grp)
          next if s.nil? || e <= s || s < pos
          next if !prot.empty? && prot.include?(pystrip(seg[s...e], "\"\x27[](){}<>.,;:!").downcase)
          nxt << [seg[pos...s], nil] if s > pos
          nxt << [seg[s...e], ph]
          pos = e
        end
        nxt << [seg[pos..-1], nil] if pos < seg.size
      end
      segs = nxt
    end
    segs.map { |seg, p| p.nil? ? seg : p }.join
  end

  def self.sign(ev, t)
    fmt = ev.get(S + "[fmt]")
    bucket = ev.get(S + "[bucket]")
    payload = ev.get(S + "[payload]")
    hdr = (ev.get(S + "[h]") || {}).to_h
    rule = t["SIGN"][bucket] || t["SIGN"]["*"]
    text = ""
    begin
      case fmt
      when "json"
        obj = ev.get(S + "[j]")
        return unless obj.is_a?(Hash)
        obj = obj.to_h
        keys = shape(obj, rule["depth"] || 1)
        flat = flatten(obj)
      when "kv"
        d = t["DIAL"][ev.get(S + "[dialect]")]
        flat, leftover, _c, prefix = kv_pairs(payload, d)
        keys = flat.keys.map { |k| k.split("#", 2)[0] }.uniq.sort
        if !prefix.empty? && rule.fetch("text", true)
          text = mask(prefix, t["MASKS"][bucket] || [], t["PROT"]).split.join(" ")
        end
        flat["_text"] = leftover unless leftover.empty?
      when "cef"
        flat = parse_cef(payload)
        keys = ["cef|#{flat["cef.vendor"]}|#{flat["cef.product"]}|#{flat["cef.signature_id"][0, 80]}"]
      when "leef"
        flat = parse_leef(payload)
        keys = ["leef|#{flat["leef.vendor"]}|#{flat["leef.product"]}|#{flat["leef.event_id"][0, 80]}"]
      when "delimited"
        vals = split_delimited(payload, ev.get(S + "[delim]") || ",")
        flat = {}
        vals.each_with_index { |v, i| flat["c#{i}"] = v }
        keys = ["n=#{vals.size}"]
      else
        return
      end
    rescue StandardError
      return
    end
    disc = []
    (rule["discriminators"] || []).each do |d|
      v = flat.key?(d) ? flat[d] : hdr[d]
      disc << "#{d}=#{pystr(v)[0, 120]}" if !v.nil? && !v.is_a?(Hash) && !v.is_a?(Array)
    end
    if %w[cef leef delimited].include?(fmt)
      sk = keys
    else
      mode = rule["keys"] || "auto"
      if mode == "auto"
        sk = disc.empty? ? keys : []
      elsif mode == "core"
        core = rule["core_keys"] || []
        sk = keys.select { |k| core.include?(k) }
      elsif mode == "none"
        sk = []
      else
        sk = keys
      end
    end
    prot = []
    unless t["PROT"].empty? || fmt == "delimited"
      flat.each do |k, v|
        prot << "#{k}=#{v.downcase}" if v.is_a?(String) && v.size > 2 && v.size <= 24 && k.count(".") <= 1 && t["PROT"].include?(v.downcase)
      end
      prot = prot.sort.first(4)
    end
    disc += prot
    sig = dig([fmt, sk.join("\x1e"), disc.join("\x1e"), text].join("\x1f"))
    ev.set(S + "[flat]", flat)
    ev.set(S + "[sig]", sig)
    ev.set(S + "[rkey]", dig(bucket + "\x1f" + sig))
  end

  # ------------------------------------------------------------ fields
  def self.header(ev) (ev.get(S + "[h]") || {}).to_h end

  def self.from_flat(ev)
    flat = (ev.get(S + "[flat]") || {}).to_h
    ev.set(S + "[f]", flat)
  end

  def self.decode(ev, kind, a, t)
    p = ev.get(S + "[payload]")
    f = nil
    case kind
    when "json"
      obj = JSON.parse(p)
      raise Err, "json" unless obj.is_a?(Hash)
      f = flatten(obj)
    when "kv"
      d = t["DIAL"][a["dialect"]]
      raise Err, "dialect" if d.nil?
      f, left, _c, _p = kv_pairs(p, d)
      raise Err, "no pairs" if f.empty?
      f["_text"] = left unless left.empty?
    when "cef" then f = parse_cef(p)
    when "leef" then f = parse_leef(p)
    when "delimited"
      f = parse_delimited(p, a["delimiter"], a["columns"], a.fetch("strip", true))
    else raise Err, "kind"
    end
    ev.set(S + "[f]", f)
  end

  def self.nested(ev, specs, t)
    f = ev.get(S + "[f]").to_h
    specs.each do |n|
      v = f[n["field"]]
      next if !v.is_a?(String) || v.strip.empty?
      prefix = n["prefix"] || (n["field"] + ".")
      begin
        if n["kind"] == "json"
          obj = JSON.parse(v.strip)
          next unless obj.is_a?(Hash)
          sub = flatten(obj)
        else
          d = t["DIAL"][n["dialect"] || "kv_eq"]
          sub = d ? kv_pairs(v, d)[0] : {}
        end
      rescue StandardError
        next
      end
      sub.each { |k, sv| f[prefix + k] = sv unless f.key?(prefix + k) }
    end
    ev.set(S + "[f]", f)
  end

  def self.extract(ev, specs)
    f = ev.get(S + "[f]").to_h
    specs.each do |e|
      v = f[e["field"]]
      next unless v.is_a?(String)
      m = rx(e["pattern"]).match(v)
      next unless m
      m.names.each { |n| f[n] = m[n] if !m[n].nil? && m[n] != "" && !f.key?(n) }
    end
    ev.set(S + "[f]", f)
  end

  # finish: merge the envelope header, drop empty values (the mapper treats them as absent)
  def self.finish(ev)
    f = (ev.get(S + "[f]") || {}).to_h
    header(ev).each { |k, v| f[k] = v unless f.key?(k) }
    f.delete_if { |_k, v| v.nil? || v == "" }
    ev.set(S + "[f]", f)
  end

  def self.split_key(ev, fl, pr)
    f = ev.get(S + "[f]").to_h
    parts = fl.map { |x| "#{x}=#{pystr(f.key?(x) ? f[x] : "")[0, 80]}" }
    parts += pr.map { |k| "has:#{k}=#{empty?(f[k]) ? 0 : 1}" }
    ev.set(S + "[child]", dig(parts.join(" ")))
  end

  def self.cond(f, c)
    v = f[c["field"]]
    return !empty?(v) == c["exists"] if c.key?("exists")
    return false if v.nil?
    s = pystr(v)
    return s == c["equals"] if c.key?("equals")
    return c["in"].include?(s) if c.key?("in")
    return !rx(c["matches"]).match(s).nil? if c.key?("matches")
    true
  end

  def self.variant(ev, conds)
    f = ev.get(S + "[f]").to_h
    conds.each_with_index do |c, i|
      if cond(f, c)
        ev.set(S + "[variant]", (i + 1).to_s)
        return
      end
    end
    ev.set(S + "[variant]", "0")
  end

  # ------------------------------------------------------------ transforms
  def self.year_for(mon, day)
    n = Time.at(now).utc
    [n.year, n.year - 1].each do |y|
      next unless Date.valid_civil?(y, mon, day)
      return y if Time.utc(y, mon, day) <= n + 2 * 86400
    end
    n.year - 1
  end

  def self.tz_off(name, y, mo, d, h, mi, s)
    name ||= tz
    return 0 if ["Z", "z", "UTC", "GMT"].include?(name)
    m = OFFS.match(name)
    return (m[1] == "-" ? -1 : 1) * (m[2].to_i * 3600 + m[3].to_i * 60) if m
    require "tzinfo"
    zone = TZInfo::Timezone.get(name)
    local = Time.utc(y, mo, d, h, mi, s)
    local.to_i - zone.local_to_utc(local).to_i
  rescue LoadError, StandardError
    raise Err, "tz"
  end

  def self.mk_ms(y, mo, d, h, mi, s, us, off)
    raise Err, "date" unless Date.valid_civil?(y, mo, d) && h < 24 && mi < 60 && s < 61
    (Time.utc(y, mo, d, h, mi, [s, 59].min).to_i - off) * 1000 + us / 1000
  end

  def self.frac_us(f) (f || "0")[0, 6].ljust(6, "0").to_i end

  def self.parse_ts(value, a)
    s = pystrip(pystr(value).strip, "[]")
    return nil if s.empty?
    unit = a["unit"]
    if NUM.match?(s) && !a["formats"]
      f = s.to_f
      unit ||= (f.abs < 1e11 ? "s" : f.abs < 1e14 ? "ms" : f.abs < 1e17 ? "us" : "ns")
      sc = {"s" => 1000.0, "ms" => 1.0, "us" => 1e-3, "ns" => 1e-6}[unit]
      return (f * sc).to_i
    end
    tzn = a["tz"]
    (a["formats"] || []).each do |fmt|
      h = (Date._strptime(s, fmt) rescue nil)
      next if h.nil? || h.key?(:leftover)
      mo = h[:mon] || 1
      da = h[:mday] || 1
      y = h[:year]
      if !fmt.include?("%Y") && !fmt.include?("%y") && !fmt.include?("%G")
        y = year_for(mo, da)
      end
      y ||= 1900
      us = ((h[:sec_fraction] || 0) * 1_000_000).to_i
      hh = h[:hour] || 0
      mi = h[:min] || 0
      se = h[:sec] || 0
      off = h.key?(:offset) && !h[:offset].nil? ? h[:offset] : tz_off(tzn, y, mo, da, hh, mi, se)
      return mk_ms(y, mo, da, hh, mi, se, us, off)
    end
    off = nil
    if (m = ISO.match(s))
      y, mo, da, h, mi, se, frac, off = m.captures
    elsif (m = SLASH.match(s))
      y, mo, da, h, mi, se, frac = m.captures
    elsif (m = SYSL.match(s))
      mon, da, y1, h, mi, se, frac, y2, off = m.captures
      mo = MONTHS[mon.downcase]
      raise Err, "ts" if mo.nil?
      y = y1 || y2 || a["year"] || year_for(mo, da.to_i)
    elsif (m = CLF.match(s))
      da, mon, y, h, mi, se, frac, off = m.captures
      mo = MONTHS[mon.downcase]
      raise Err, "ts" if mo.nil?
    else
      raise Err, "ts"
    end
    y = y.to_i; mo = mo.to_i; da = da.to_i; h = h.to_i; mi = mi.to_i; se = se.to_i
    o = tz_off(off || tzn, y, mo, da, h, mi, se)
    mk_ms(y, mo, da, h, mi, se, frac_us(frac), o)
  end

  def self.to_int(v, a)
    return (v ? 1 : 0) if v == true || v == false
    return v.to_i if v.is_a?(Numeric)
    s = v.to_s.strip
    s = s.delete(",") if a["allow_commas"]
    base = a.fetch("base", 10)
    if base == 16
      raise Err, "int" unless s =~ /\A[+-]?(0[xX])?[0-9a-fA-F]+\z/
      return s.to_i(16)
    elsif base == "auto"
      return Integer(s)
    end
    if s.include?(".") || s.downcase.include?("e")
      raise Err, "int" unless FLTR.match?(s)
      return s.to_f.to_i
    end
    raise Err, "int" unless s =~ /\A[+-]?\d+\z/
    s.to_i
  rescue ArgumentError
    raise Err, "int"
  end

  def self.to_float(v, a = {})
    raise Err, "float" unless v.is_a?(Numeric) || FLTR.match?(v.to_s)
    f = v.to_f
    raise Err, "float" if f.nan? || f.infinite?
    f
  end

  def self.to_bool(v)
    s = v.to_s.strip.downcase
    s = pystr(v).strip.downcase if v == true || v == false
    return true if %w[true 1 yes y t on].include?(s)
    return false if %w[false 0 no n f off].include?(s)
    raise Err, "bool"
  end

  def self.enum_lookup(v, a)
    table = a["map"] || {}
    s = pystr(v)
    if a.fetch("case_insensitive", true)
      s = s.downcase.strip
      table = table.map { |k, x| [k.to_s.downcase, x] }.to_h
    end
    return table[s] if table.key?(s)
    (a["patterns"] || {}).each { |pat, x| return x if rx(pat).match(pystr(v)) }
    a["default"]
  end

  def self.regex_extract(v, a)
    m = rx(a["pattern"]).match(pystr(v))
    return nil if m.nil?
    g = a.fetch("group", m.captures.empty? ? 0 : 1)
    m[g]
  rescue IndexError
    raise Err, "group"
  end

  def self.dns_name(v)
    s = pystr(v).strip
    unless s.include?("(")
      r = s.sub(/\.+\z/, "")
      return r.empty? ? nil : r
    end
    parts = s.split(/\((\d{1,2})\)/, -1)
    labels = []
    i = 2
    while i < parts.size
      labels << parts[i] unless parts[i].empty?
      i += 2
    end
    labels.empty? ? nil : labels.join(".")
  end

  def self.syslog_sev(v, a)
    n = to_int(v, {})
    fp = a.key?("from_pri") ? a["from_pri"] : n > 7
    sev = fp ? n % 8 : n
    {0 => 6, 1 => 5, 2 => 5, 3 => 4, 4 => 3, 5 => 2, 6 => 1, 7 => 1}[sev] || 0
  end

  def self.tr(v, fn, a)
    return nil if v.nil?
    if v.is_a?(Array) && fn != "split"
      r = v.map { |x| tr1(x, fn, a) }.compact
      return r.empty? ? nil : r
    end
    tr1(v, fn, a)
  end

  def self.tr1(v, fn, a)
    case fn
    when "parse_timestamp" then parse_ts(v, a)
    when "to_int" then to_int(v, a)
    when "to_float" then to_float(v)
    when "to_bool" then to_bool(v)
    when "to_str" then pystr(v)
    when "enum_lookup" then enum_lookup(v, a)
    when "lower" then pystr(v).downcase
    when "upper" then pystr(v).upcase
    when "trim" then r = pystrip(pystr(v), a["chars"]); r.empty? ? nil : r
    when "regex_extract" then regex_extract(v, a)
    when "split_index"
      parts = pystr(v).split(a["sep"], -1)
      r = parts[a.fetch("index", 0)]
      r.nil? || r.strip.empty? ? nil : r.strip
    when "split"
      r = pystr(v).split(a.fetch("sep", ","), -1).map { |x| x.strip }.reject { |x| x.empty? }
      r.empty? ? nil : r
    when "null_if" then a["values"].include?(pystr(v).strip) ? nil : v
    when "scale"
      f = to_float(v) * a["factor"]
      a.fetch("int", true) ? f.to_i : f
    when "prefix" then "#{a["prefix"]}#{pystr(v)}#{a["suffix"]}"
    when "windows_filetime" then (to_int(v, {}) - 116444736000000000) / 10000
    when "dns_name" then dns_name(v)
    when "syslog_severity" then syslog_sev(v, a)
    else raise Err, "fn"
    end
  end

  def self.coerce(v, kind, arr)
    return v if v.nil? || kind == "obj"
    one = lambda do |x|
      case kind
      when "int"
        return x if x.is_a?(Integer)
        return x.to_i if x.is_a?(Float) && x == x.to_i
        m = INTR.match(pystr(x))
        raise Err, "int" if m.nil? || x == true || x == false
        m[1].to_i
      when "float"
        (x.is_a?(Numeric) ? x : to_float(x))
      when "bool"
        (x == true || x == false) ? x : to_bool(x)
      when "str"
        x == true ? "true" : x == false ? "false" : (x.is_a?(String) ? x : pystr(x))
      else x
      end
    end
    if arr
      (v.is_a?(Array) ? v : [v]).map { |x| one.call(x) }
    else
      raise Err, "list" if v.is_a?(Array)
      one.call(v)
    end
  end

  def self.put(o, path, v)
    cur = o
    parts = path.split(".")
    parts.each_with_index do |part, i|
      last = i == parts.size - 1
      m = /\A(.*)\[(\d+)\]\z/.match(part)
      if m
        name = m[1]
        idx = m[2].to_i
        lst = (cur[name] ||= [])
        raise Err, "array" unless lst.is_a?(Array)
        lst << (last ? nil : {}) while lst.size <= idx
        if last
          lst[idx] = v
        else
          lst[idx] = {} unless lst[idx].is_a?(Hash)
          cur = lst[idx]
        end
      elsif last
        cur[part] = v
      else
        nxt = (cur[part] ||= {})
        raise Err, "object" unless nxt.is_a?(Hash)
        cur = nxt
      end
    end
  end

  def self.pick(f, used, srcs)
    srcs.each do |s|
      v = f[s]
      unless empty?(v)
        used[s] = true
        return v
      end
    end
    nil
  end

  def self.joined(f, used, srcs, sep)
    parts = srcs.map { |s| f[s] }
    return nil if parts.any? { |p| empty?(p) }
    srcs.each { |s| used[s] = true }
    parts.map { |p| pystr(p) }.join(sep)
  end

  # ------------------------------------------------------------ finishing
  def self.fin(ev, o, f, used, cfg, t)
    cls = cfg["cls"]
    o["class_uid"] = cls
    o["category_uid"] = cfg["cat"]
    o["activity_id"] = 0 unless o["activity_id"].is_a?(Integer)
    o["type_uid"] = cls * 100 + o["activity_id"]
    o["severity_id"] = 0 unless o["severity_id"].is_a?(Integer)
    unless o.key?("time")
      ts = f["@timestamp"]
      if ts
        begin
          x = parse_ts(ts, {})
          if x
            o["time"] = x
            used["@timestamp"] = true
          end
        rescue StandardError
        end
      end
      o["time"] = (now * 1000).to_i unless o.key?("time")
    end
    md = (o["metadata"] ||= {})
    md["version"] = cfg["ver"]
    prod = (md["product"] ||= {})
    prod["name"] = cfg["pname"] if !prod.key?("name") && !prod.key?("uid")
    prod["vendor_name"] = cfg["vendor"] if !prod.key?("vendor_name") && cfg["vendor"]
    md["profiles"] = cfg["profiles"] if !cfg["profiles"].empty?
    caps = t["CAPS"][cfg["cname"]] || {}
    o.keys.each do |k|
      a = caps[k]
      next if a.nil? || o.key?(a["sibling"])
      next if o[k].is_a?(Hash) || o[k].is_a?(Array)
      cap = a["enum"][pystr(o[k])]
      o[a["sibling"]] = cap if cap && !cap.empty?
    end
    if cfg["unmapped"] == "rest"
      drop = cfg["drop"]
      rest = {}
      f.each do |k, v|
        next if used[k] || drop.include?(k) || v.nil? || v == ""
        rest[k] = (v.is_a?(String) || v.is_a?(Numeric) || v == true || v == false) ? v : pystr(v)
      end
      o["unmapped"] = rest unless rest.empty?
    end
    ev.set("[ocsf]", o)
  end
end
end
