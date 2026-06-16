import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'

type RGB = [number, number, number]

const C = {
  accent:  [14,  165, 233] as RGB,
  white:   [255, 255, 255] as RGB,
  text:    [15,   23,  42] as RGB,
  muted:   [100, 116, 139] as RGB,
  border:  [226, 232, 240] as RGB,
  bg:      [248, 250, 252] as RGB,
  tableHd: [30,   41,  59] as RGB,
  crit:    [220,  38,  38] as RGB,
  high:    [234,  88,  12] as RGB,
  med:     [202, 138,   4] as RGB,
  low:     [ 22, 163,  74] as RGB,
}

function riskInfo(s: number): { label: string; color: RGB } {
  if (s >= 8) return { label: 'CRITICAL', color: C.crit }
  if (s >= 5) return { label: 'HIGH',     color: C.high }
  if (s >= 3) return { label: 'MEDIUM',   color: C.med  }
  return           { label: 'LOW',      color: C.low  }
}

function safeN(v: unknown): number {
  const n = Number(v)
  return isFinite(n) && n >= 0 ? Math.min(n, 10) : 0
}

function extractFromRaw(raw: string) {
  try {
    const m = raw.match(/\{[\s\S]*\}/)
    if (!m) return {}
    const p = JSON.parse(m[0])
    const recs = p.recommendations
    return {
      score:   p.risk_score != null ? safeN(p.risk_score) : undefined,
      summary: p.exposure_level || p.summary || undefined,
      recs:    Array.isArray(recs) ? recs.filter((v: unknown): v is string => typeof v === 'string')
             : typeof recs === 'string' ? [recs]
             : typeof recs === 'object' && recs ? Object.values(recs).filter((v): v is string => typeof v === 'string')
             : [],
    }
  } catch { return {} }
}

export interface ReportAgent {
  agent: string
  label:  string
  status: string
  result?: {
    risk_score?:      number
    raw_ai_response?: string
    alerts?:          Array<{ title?: string; description?: string; severity?: string }>
    recommendations?: unknown[]
  }
  error?: string
}

export interface PdfLabels {
  reportTitle:    string
  analyzedTarget: string
  maxRiskDetected:string
  totalAgents:    string
  completed:      string
  withError:      string
  riskMax:        string
  footer:         string
  execSummary:    string
  agentCol:       string
  scoreCol:       string
  levelCol:       string
  alertsCol:      string
  recsCol:        string
  agentsWithError:string
  unknownError:   string
  agentResults:   string
  alertsLabel:    string
  recsLabel:      string
  exposureLevel:  string
  pageLabel:      string
  pageFooter:     string
}

// ── page helpers ──────────────────────────────────────────────────────────────

function header(doc: jsPDF, target: string, title: string) {
  doc.setFillColor(...C.white)
  doc.rect(0, 0, 210, 18, 'F')
  doc.setFillColor(...C.accent)
  doc.rect(0, 0, 3, 18, 'F')
  doc.setDrawColor(...C.border)
  doc.setLineWidth(0.3)
  doc.line(0, 18, 210, 18)

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(10)
  doc.setTextColor(...C.accent)
  doc.text('AI-SOC', 8, 12)

  doc.setTextColor(...C.text)
  doc.setFont('helvetica', 'normal')
  doc.text(title, 26, 12)

  doc.setTextColor(...C.muted)
  doc.setFontSize(8)
  doc.text(target, 198, 12, { align: 'right' })
}

function footer(doc: jsPDF, page: number, labels: PdfLabels) {
  doc.setFontSize(8)
  doc.setTextColor(...C.muted)
  doc.text(`${labels.pageLabel} ${page}  ·  ${labels.pageFooter}`, 105, 291, { align: 'center' })
}

function badge(doc: jsPDF, x: number, y: number, w: number, h: number, text: string, color: RGB) {
  doc.setFillColor(...color)
  doc.roundedRect(x, y, w, h, 1.5, 1.5, 'F')
  doc.setTextColor(...C.white)
  doc.text(text, x + w / 2, y + h / 2 + 1.5, { align: 'center' })
}

function sectionLabel(doc: jsPDF, x: number, y: number, text: string) {
  // small accent bar before label
  doc.setFillColor(...C.accent)
  doc.rect(x, y - 4, 2, 5, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(7.5)
  doc.setTextColor(...C.muted)
  doc.text(text, x + 4, y)
}

function recBullet(doc: jsPDF, x: number, y: number) {
  // small filled accent circle instead of arrow character
  doc.setFillColor(...C.accent)
  doc.circle(x, y - 1.2, 0.9, 'F')
}

function checkBreak(doc: jsPDF, y: number, need: number, target: string, page: { n: number }, labels: PdfLabels): number {
  if (y + need > 278) {
    footer(doc, page.n, labels)
    doc.addPage()
    page.n++
    header(doc, target, labels.agentResults)
    return 26
  }
  return y
}

// ── main export ───────────────────────────────────────────────────────────────

export function generateReport(params: {
  target:     string
  targetType: string
  results:    ReportAgent[]
  maxRisk:    number
  labels:     PdfLabels
}) {
  const { target, targetType, results, maxRisk, labels } = params
  const doc  = new jsPDF({ unit: 'mm', format: 'a4' })
  const done = results.filter(r => r.status === 'done')
  const errs = results.filter(r => r.status === 'error')
  const risk = riskInfo(maxRisk)
  const now  = new Date()
  const page = { n: 1 }

  // ── COVER ─────────────────────────────────────────────────────────────────
  doc.setFillColor(...C.accent)
  doc.rect(0, 0, 210, 8, 'F')
  doc.rect(0, 289, 210, 8, 'F')

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(52)
  doc.setTextColor(...C.accent)
  doc.text('AI-SOC', 105, 72, { align: 'center' })

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(16)
  doc.setTextColor(...C.text)
  doc.text(labels.reportTitle, 105, 83, { align: 'center' })

  doc.setDrawColor(...C.border)
  doc.setLineWidth(0.5)
  doc.line(45, 90, 165, 90)

  doc.setFontSize(8)
  doc.setTextColor(...C.muted)
  doc.text(labels.analyzedTarget, 105, 102, { align: 'center' })

  doc.setFontSize(22)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(...C.text)
  doc.text(target, 105, 113, { align: 'center' })

  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(...C.accent)
  doc.text(targetType.toUpperCase(), 105, 121, { align: 'center' })
  doc.setTextColor(...C.muted)
  doc.text(now.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }), 105, 130, { align: 'center' })

  doc.setFillColor(...C.bg)
  doc.roundedRect(68, 140, 74, 40, 4, 4, 'F')
  doc.setFillColor(...risk.color)
  doc.roundedRect(79, 144, 52, 28, 3, 3, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(26)
  doc.setTextColor(...C.white)
  doc.text(maxRisk.toFixed(1), 105, 157, { align: 'center' })
  doc.setFontSize(11)
  doc.text(risk.label, 105, 166, { align: 'center' })

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.setTextColor(...C.muted)
  doc.text(labels.maxRiskDetected, 105, 187, { align: 'center' })

  doc.setDrawColor(...C.border)
  doc.setLineWidth(0.3)
  doc.line(40, 196, 170, 196)

  const cols = [
    { v: results.length, l: labels.totalAgents, x: 70 },
    { v: done.length,    l: labels.completed,   x: 105 },
    { v: errs.length,    l: labels.withError,   x: 140 },
  ]
  cols.forEach(({ v, l, x }, i) => {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(28)
    doc.setTextColor(...C.text)
    doc.text(v.toString(), x, 214, { align: 'center' })
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(...C.muted)
    doc.text(l.toUpperCase(), x, 222, { align: 'center' })
    if (i < 2) {
      doc.setDrawColor(...C.border)
      doc.setLineWidth(0.3)
      doc.line(x + 20, 198, x + 20, 224)
    }
  })
  doc.line(40, 226, 170, 226)

  doc.setFontSize(8)
  doc.setTextColor(...C.muted)
  doc.text(labels.footer, 105, 280, { align: 'center' })

  // ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
  doc.addPage()
  page.n++
  header(doc, target, labels.execSummary)

  const boxes = [
    { v: results.length.toString(), l: labels.totalAgents, c: C.accent },
    { v: done.length.toString(),    l: labels.completed,   c: C.low    },
    { v: errs.length.toString(),    l: labels.withError,   c: errs.length > 0 ? C.high : C.muted },
    { v: risk.label,                l: labels.riskMax,     c: risk.color },
  ]
  const bw = 43, bh = 18, gap = 2, bStart = 12
  boxes.forEach(({ v, l, c }, i) => {
    const bx = bStart + i * (bw + gap)
    doc.setFillColor(...C.bg)
    doc.roundedRect(bx, 22, bw, bh, 2, 2, 'F')
    doc.setFillColor(...c)
    doc.roundedRect(bx, 22, 3, bh, 1, 1, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(...c)
    doc.text(v, bx + bw / 2, 29, { align: 'center' })
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(...C.muted)
    doc.text(l.toUpperCase(), bx + bw / 2, 36, { align: 'center' })
  })

  const tRows = done.map(r => {
    const raw   = extractFromRaw(r.result?.raw_ai_response || '')
    const score = raw.score ?? safeN(r.result?.risk_score)
    const { label: lv } = riskInfo(score)
    return [
      r.label,
      score.toFixed(1),
      lv,
      (r.result?.alerts?.length ?? 0).toString(),
      (raw.recs?.length ?? r.result?.recommendations?.length ?? 0).toString(),
    ]
  })

  autoTable(doc, {
    startY: 44,
    head: [[labels.agentCol, labels.scoreCol, labels.levelCol, labels.alertsCol, labels.recsCol]],
    body: tRows,
    theme: 'striped',
    styles:     { fontSize: 9, cellPadding: 3, textColor: C.text },
    headStyles: { fillColor: C.tableHd, textColor: C.white, fontStyle: 'bold', fontSize: 9 },
    alternateRowStyles: { fillColor: [245, 248, 252] },
    columnStyles: {
      0: { cellWidth: 50 },                      // Agente — reduced
      1: { cellWidth: 16, halign: 'center' },    // Score
      2: { cellWidth: 28, halign: 'center' },    // Nivel
      3: { cellWidth: 24, halign: 'center' },    // Alertas — wider
      4: { cellWidth: 40, halign: 'center' },    // Recomendaciones — wider
    },
    didParseCell(d) {
      if (d.section !== 'body') return
      if (d.column.index === 2) {
        const lv = d.cell.text[0]
        d.cell.styles.textColor = lv === 'CRITICAL' ? C.crit : lv === 'HIGH' ? C.high : lv === 'MEDIUM' ? C.med : C.low
        d.cell.styles.fontStyle = 'bold'
      }
      if (d.column.index === 1) {
        d.cell.styles.textColor = riskInfo(parseFloat(d.cell.text[0])).color
        d.cell.styles.fontStyle = 'bold'
      }
    },
  })

  if (errs.length > 0) {
    const lastY = (doc as any).lastAutoTable?.finalY ?? 200
    if (lastY < 240) {
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(10)
      doc.setTextColor(...C.text)
      doc.text(labels.agentsWithError, 12, lastY + 10)
      autoTable(doc, {
        startY: lastY + 14,
        head: [[labels.agentCol, 'Error']],
        body: errs.map(r => [r.label, r.error || labels.unknownError]),
        theme: 'plain',
        styles: { fontSize: 8, textColor: C.text },
        headStyles: { fillColor: [254, 242, 242], textColor: C.crit },
        columnStyles: { 0: { cellWidth: 55 }, 1: { cellWidth: 120 } },
      })
    }
  }

  footer(doc, page.n, labels)

  // ── PER-AGENT DETAIL ──────────────────────────────────────────────────────
  if (done.length === 0) {
    const fn = `aisoc-report-${target.replace(/[^a-z0-9]/gi, '-')}-${now.toISOString().slice(0, 10)}.pdf`
    doc.save(fn)
    return
  }

  doc.addPage()
  page.n++
  header(doc, target, labels.agentResults)
  let y = 26

  for (const r of done) {
    const raw   = extractFromRaw(r.result?.raw_ai_response || '')
    const score = raw.score ?? safeN(r.result?.risk_score)
    const { label: lv, color: rc } = riskInfo(score)
    const recs   = raw.recs && raw.recs.length > 0 ? raw.recs : (r.result?.recommendations ?? []).filter((v): v is string => typeof v === 'string')
    const alerts = r.result?.alerts ?? []

    const need = 18
      + (alerts.length > 0 ? 12 : 0)
      + alerts.slice(0, 3).reduce((s, a) => {
          doc.setFont('helvetica', 'normal')
          doc.setFontSize(7.5)
          return s + 6 + (a.description ? doc.splitTextToSize(a.description.slice(0, 180), 162).length * 4 : 0)
        }, 0)
      + (recs.length > 0 ? 12 : 0)
      + recs.slice(0, 4).reduce((s, rec) => {
          doc.setFont('helvetica', 'normal')
          doc.setFontSize(8)
          return s + doc.splitTextToSize(String(rec), 162).length * 5
        }, 0)
      + (raw.summary ? 8 : 0) + 10

    y = checkBreak(doc, y, need, target, page, labels)

    // card header
    doc.setFillColor(...C.bg)
    doc.rect(12, y, 186, 13, 'F')
    doc.setFillColor(...rc)
    doc.rect(12, y, 3, 13, 'F')

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(10)
    doc.setTextColor(...C.text)
    doc.text(r.label, 19, y + 8.5)

    doc.setFontSize(8)
    badge(doc, 162, y + 2.5, 18, 8, score.toFixed(1), rc)

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(...rc)
    doc.text(lv, 183, y + 8.5)

    y += 17

    // alerts section
    if (alerts.length > 0) {
      y += 4
      y = checkBreak(doc, y, 14, target, page, labels)
      sectionLabel(doc, 14, y, labels.alertsLabel)
      y += 10  // enough gap so badge top (y-4) clears the label bar bottom (y+1)

      for (const a of alerts.slice(0, 3)) {
        y = checkBreak(doc, y, 14, target, page, labels)
        const sev = (a.severity || 'info').toUpperCase()
        const sc  = sev === 'CRITICAL' ? C.crit : sev === 'HIGH' ? C.high : sev === 'MEDIUM' ? C.med : C.low
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(7.5)
        badge(doc, 14, y - 4, 20, 6, sev, sc)
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(8)
        doc.setTextColor(...C.text)
        const titleLines = doc.splitTextToSize(a.title || '', 148)
        doc.text(titleLines, 37, y)
        y += titleLines.length * 5
        if (a.description) {
          doc.setFont('helvetica', 'normal')
          doc.setFontSize(7)
          doc.setTextColor(...C.muted)
          const dl = doc.splitTextToSize(a.description.slice(0, 200), 162)
          doc.text(dl, 14, y)
          y += dl.length * 4
        }
        y += 4  // inter-alert gap
      }
    }

    // recommendations section
    if (recs.length > 0) {
      y += 4
      y = checkBreak(doc, y, 12, target, page, labels)
      sectionLabel(doc, 14, y, labels.recsLabel)
      y += 8

      for (const rec of recs.slice(0, 4)) {
        y = checkBreak(doc, y, 10, target, page, labels)
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(8)
        doc.setTextColor(...C.text)
        recBullet(doc, 16, y)
        const lines = doc.splitTextToSize(String(rec), 162)
        doc.text(lines, 20, y)
        y += lines.length * 5.5
      }
    }

    // summary / exposure
    if (raw.summary) {
      y += 2
      doc.setFont('helvetica', 'italic')
      doc.setFontSize(7.5)
      doc.setTextColor(...C.muted)
      doc.text(`${labels.exposureLevel}: ${raw.summary}`, 14, y)
      y += 6
    }

    // separator
    doc.setDrawColor(...C.border)
    doc.setLineWidth(0.2)
    doc.line(12, y + 3, 198, y + 3)
    y += 10
  }

  footer(doc, page.n, labels)

  const filename = `aisoc-report-${target.replace(/[^a-z0-9]/gi, '-')}-${now.toISOString().slice(0, 10)}.pdf`
  doc.save(filename)
}
