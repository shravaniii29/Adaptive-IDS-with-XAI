import { useCallback, useEffect, useState } from "react";
import { Activity, Loader2, Zap, SlidersHorizontal } from "lucide-react";
import Card from "../common/Card";
import {
  getCalibration,
  getRetrainStatus,
  listCandidates,
  triggerDemoDrift,
  promoteCandidate,
  discardCandidate,
  recalibrateNetwork,
  applyCalibration,
  discardCalibration,
  type CalibrationProposal,
  type CalibrationResponse,
  type Candidate,
  type RetrainStatus,
} from "../../services/modelOpsService";

const pct = (n: number | undefined) => (n === undefined ? "—" : `${(n * 100).toFixed(1)}%`);

function CalibrationRow({ label, alpha, threshold }: { label: string; alpha?: number; threshold?: number }) {
  return (
    <div className="flex items-center justify-between rounded-lg bg-white/[0.03] px-3 py-2 text-xs">
      <span className="text-slate-300">{label}</span>
      <span className="font-mono text-slate-400">
        {alpha === undefined ? "—" : `${(1 - alpha).toFixed(1)}·xgb + ${alpha.toFixed(1)}·iso ≥ ${threshold?.toFixed(3) ?? "—"}`}
      </span>
    </div>
  );
}

// Model health for the demo: trigger concept drift, watch a candidate retrain,
// and promote it (which replaces the deployed model — an explicit, approved
// step) or discard it. Also shows the live confidence-fusion calibration.
export default function ModelHealthPanel() {
  const [calibration, setCalibration] = useState<CalibrationResponse | null>(null);
  const [retrain, setRetrain] = useState<RetrainStatus | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [proposal, setProposal] = useState<CalibrationProposal | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const refresh = useCallback(() => {
    getRetrainStatus().then(setRetrain).catch(() => undefined);
    listCandidates().then((d) => setCandidates(d.candidates)).catch(() => undefined);
    getCalibration().then((c) => {
      setCalibration(c);
      // keep a server-held pending proposal in sync (survives refresh / reload)
      if (c.proposal) setProposal(c.proposal);
    }).catch(() => undefined);
  }, []);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 3000);
    return () => window.clearInterval(id);
  }, [refresh]);

  const recalibrate = () => {
    setBusy("recalibrate");
    setNote(null);
    recalibrateNetwork()
      .then((p) => { setProposal(p); setNote("New threshold computed for this network — review and Apply below."); })
      .catch((e: Error) => setNote(e.message))
      .finally(() => setBusy(null));
  };

  const applyCalib = () => {
    setBusy("apply-calib");
    applyCalibration()
      .then((r) => setNote(`Applied live — now flagging when the fused score ≥ ${r.threshold.toFixed(3)} (α ${r.alpha}).`))
      .catch((e: Error) => setNote(e.message))
      .finally(() => { setBusy(null); setProposal(null); refresh(); });
  };

  const discardCalib = () => {
    setBusy("discard-calib");
    discardCalibration().catch(() => undefined).finally(() => { setBusy(null); setProposal(null); refresh(); });
  };

  const trigger = () => {
    setBusy("trigger");
    setNote(null);
    triggerDemoDrift()
      .then(() => setNote("Drift triggered — retraining a candidate model…"))
      .catch((e: Error) => setNote(e.message))
      .finally(() => { setBusy(null); refresh(); });
  };

  const promote = (id: string) => {
    setBusy(id);
    promoteCandidate(id)
      .then(() => setNote("Candidate promoted — the deployed model was replaced (backup saved)."))
      .catch((e: Error) => setNote(e.message))
      .finally(() => { setBusy(null); refresh(); });
  };

  const discard = (id: string) => {
    setBusy(id);
    discardCandidate(id).catch(() => undefined).finally(() => { setBusy(null); refresh(); });
  };

  const pending = candidates.filter((c) => c.status === "pending");
  const retraining = retrain?.running ?? false;

  return (
    <Card>
      <div className="flex items-center gap-2">
        <Activity className="text-indigo-300" size={20} />
        <h2 className="text-xl font-semibold text-white">Model health &amp; adaptive retraining</h2>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          onClick={trigger}
          disabled={busy === "trigger" || retraining}
          className="flex items-center gap-2 rounded-xl bg-amber-500/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-amber-400 disabled:opacity-50"
        >
          {busy === "trigger" || retraining ? <Loader2 size={16} className="animate-spin" /> : <Zap size={16} />}
          {retraining ? "Retraining candidate…" : "Trigger drift (demo)"}
        </button>
        <span className="text-xs text-slate-500">
          Simulates concept drift, then retrains a candidate on recent data. The deployed model is never replaced automatically.
        </span>
      </div>

      {note && <p className="mt-3 text-xs text-indigo-200">{note}</p>}
      {retrain?.error && <p className="mt-2 text-xs text-rose-300">Retrain failed: {retrain.error}</p>}

      {pending.length > 0 && (
        <div className="mt-5 space-y-3">
          <p className="text-sm font-semibold text-slate-200">Candidate ready for review</p>
          {pending.map((c) => (
            <div key={c.id} className="rounded-xl border border-emerald-400/30 bg-emerald-500/[0.04] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-xs text-slate-400">#{c.id}</span>
                <span className="text-xs text-slate-500">{c.training_rows.toLocaleString()} train / {c.validation_rows.toLocaleString()} val rows</span>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
                <div className="text-slate-500">Recall</div><div className="text-slate-500">F1</div>
                <div className="text-slate-500">Precision</div><div className="text-slate-500">Accuracy</div>
                <div className="text-slate-400">deployed {pct(c.deployed_metrics.recall)}</div>
                <div className="text-slate-400">deployed {pct(c.deployed_metrics.f1)}</div>
                <div className="text-slate-400">deployed {pct(c.deployed_metrics.precision)}</div>
                <div className="text-slate-400">deployed {pct(c.deployed_metrics.accuracy)}</div>
                <div className="font-semibold text-emerald-300">candidate {pct(c.candidate_metrics.recall)}</div>
                <div className="font-semibold text-emerald-300">candidate {pct(c.candidate_metrics.f1)}</div>
                <div className="font-semibold text-emerald-300">candidate {pct(c.candidate_metrics.precision)}</div>
                <div className="font-semibold text-emerald-300">candidate {pct(c.candidate_metrics.accuracy)}</div>
              </div>
              <div className="mt-4 flex gap-2">
                <button
                  onClick={() => promote(c.id)}
                  disabled={busy === c.id}
                  className="flex items-center gap-1 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-400 disabled:opacity-50"
                >
                  {busy === c.id && <Loader2 size={13} className="animate-spin" />} Promote (replace deployed)
                </button>
                <button
                  onClick={() => discard(c.id)}
                  disabled={busy === c.id}
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
                >
                  Discard
                </button>
              </div>
              <p className="mt-2 text-[11px] text-slate-500">Promoting backs up the current model first, so it can be reverted.</p>
            </div>
          ))}
        </div>
      )}

      <div className="mt-6">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm font-semibold text-slate-200">Confidence-fusion calibration</p>
          <button
            onClick={recalibrate}
            disabled={busy === "recalibrate"}
            className="flex items-center gap-2 rounded-lg border border-sky-400/40 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-200 transition hover:bg-sky-500/20 disabled:opacity-50"
          >
            {busy === "recalibrate" ? <Loader2 size={14} className="animate-spin" /> : <SlidersHorizontal size={14} />}
            Recalibrate for this network
          </button>
        </div>
        <div className="space-y-2">
          <CalibrationRow label="V8 (deployed)" alpha={calibration?.v8?.alpha} threshold={calibration?.v8?.threshold} />
        </div>

        {proposal && (
          <div className="mt-3 rounded-xl border border-sky-400/30 bg-sky-500/[0.05] p-4">
            <p className="text-sm font-semibold text-sky-100">Proposed threshold for this network</p>
            <div className="mt-2 flex items-center justify-between rounded-lg bg-white/[0.03] px-3 py-2 text-xs">
              <span className="text-slate-400">
                from {proposal.benign_flows} live benign flows · {proposal.attack_flows} stored attacks
              </span>
              <span className="font-mono text-sky-200">
                {(1 - proposal.alpha).toFixed(1)}·xgb + {proposal.alpha.toFixed(1)}·iso ≥ {proposal.threshold.toFixed(3)}
              </span>
            </div>
            <div className="mt-2 grid grid-cols-3 gap-x-4 text-xs">
              <div className="text-slate-500">attack recall</div>
              <div className="text-slate-500">benign specificity</div>
              <div className="text-slate-500">balanced acc.</div>
              <div className="font-semibold text-emerald-300">{pct(proposal.recall)}</div>
              <div className="font-semibold text-emerald-300">{pct(proposal.specificity)}</div>
              <div className="font-semibold text-emerald-300">{pct(proposal.balanced)}</div>
            </div>
            {proposal.current_threshold !== undefined && proposal.current_threshold !== null && (
              <p className="mt-2 text-[11px] text-slate-500">
                Current deployed: α {proposal.current_alpha} · threshold {Number(proposal.current_threshold).toFixed(3)}
              </p>
            )}
            <div className="mt-3 flex gap-2">
              <button
                onClick={applyCalib}
                disabled={busy === "apply-calib"}
                className="flex items-center gap-1 rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-400 disabled:opacity-50"
              >
                {busy === "apply-calib" && <Loader2 size={13} className="animate-spin" />} Apply (updates live)
              </button>
              <button
                onClick={discardCalib}
                disabled={busy === "discard-calib"}
                className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
              >
                Discard
              </button>
            </div>
            <p className="mt-2 text-[11px] text-slate-500">Applies instantly to new flows — no restart. Re-run anytime your network changes.</p>
          </div>
        )}

        <p className="mt-2 text-[11px] text-slate-500">
          V8 flags a flow when its weighted confidence score crosses the threshold. "Recalibrate" fits that threshold to this network's own traffic (V8-scored benign flows vs stored V8 attacks), then applies it live on Apply.
        </p>
      </div>
    </Card>
  );
}
