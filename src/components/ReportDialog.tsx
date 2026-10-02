import { useEffect, useRef, useState } from 'react';
import { FileDown, X } from 'lucide-react';
import { openReport, type ParsedScan } from '../parser';

/** Small modal to collect client/author details, then open the printable report. */
export function ReportDialog({ scan, onClose }: { scan: ParsedScan; onClose: () => void }) {
  const [client, setClient] = useState('');
  const [author, setAuthor] = useState('');
  const [assessment, setAssessment] = useState('');
  const [reportId, setReportId] = useState('');
  const [appendix, setAppendix] = useState(true);
  const [confirmed, setConfirmed] = useState(true);
  const [potential, setPotential] = useState(true);
  const [err, setErr] = useState('');
  const firstField = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    firstField.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'Tab') {
        const elements = dialogRef.current?.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), [tabindex]:not([tabindex="-1"])'
        );
        if (!elements?.length) return;
        const first = elements[0];
        const last = elements[elements.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      previousFocus?.focus();
    };
  }, [onClose]);

  const generate = () => {
    const ok = openReport(scan, {
      assessmentName: assessment.trim() || undefined,
      reportId: reportId.trim() || undefined,
      clientName: client.trim() || undefined,
      preparedBy: author.trim() || undefined,
      includeAppendix: appendix,
      includeConfirmed: confirmed,
      includePotential: potential,
    });
    if (!ok) {
      setErr('Your browser blocked the report window. Allow pop-ups for this site and try again.');
      return;
    }
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="report-dialog-title" aria-describedby="report-dialog-description" className="max-h-[90vh] w-full max-w-md overflow-y-auto card p-5" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h3 id="report-dialog-title" className="flex items-center gap-2 text-lg font-semibold text-white">
            <FileDown size={18} className="text-accent" /> Export security report
          </h3>
          <button className="rounded p-1 text-slate-500 hover:text-white" onClick={onClose} aria-label="Close report options">
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        <p id="report-dialog-description" className="mb-4 text-xs text-slate-400">
          Generates a professional, client-ready report (executive summary, prioritized remediation,
          detailed findings). It opens in a new tab with the print dialog — choose{' '}
          <strong>“Save as PDF”</strong> as the destination.
        </p>

        <label className="mb-3 block">
          <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Assessment name (optional)
          </span>
          <input className="input" placeholder="e.g. External network review" value={assessment} onChange={(e) => setAssessment(e.target.value)} />
        </label>
        <label className="mb-3 block">
          <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Report reference (optional)
          </span>
          <input className="input" placeholder="e.g. NW-2026-014" value={reportId} onChange={(e) => setReportId(e.target.value)} />
        </label>
        <label className="mb-3 block">
          <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Client / organization (optional)
          </span>
          <input
            ref={firstField}
            className="input"
            placeholder="e.g. Acme Corp"
            value={client}
            onChange={(e) => setClient(e.target.value)}
          />
        </label>
        <label className="mb-3 block">
          <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Prepared by (optional)
          </span>
          <input
            className="input"
            placeholder="Your name"
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
          />
        </label>
        <label className="mb-4 flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={appendix}
            onChange={(e) => setAppendix(e.target.checked)}
            className="accent-accent"
          />
          Include open-ports appendix
        </label>
        <fieldset className="mb-4 space-y-2 rounded-lg border border-edge p-3">
          <legend className="px-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Finding sections</legend>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="accent-accent" />
            Confirmed findings
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={potential} onChange={(e) => setPotential(e.target.checked)} className="accent-accent" />
            Potential findings
          </label>
        </fieldset>

        {err && (
          <p className="mb-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
            {err}
          </p>
        )}

        <div className="flex justify-end gap-2">
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" onClick={generate}>
            <FileDown size={15} /> Generate report
          </button>
        </div>
      </div>
    </div>
  );
}
