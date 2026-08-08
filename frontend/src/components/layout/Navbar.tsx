import { Bell, CheckCheck, Circle, Search, X } from "lucide-react";
import { useState } from "react";
import { useLocation } from "react-router-dom";
import { useDrift } from "../../hooks/useDrift";
import { usePrediction } from "../../hooks/usePrediction";
import { useSystemStatus } from "../../hooks/useSystemStatus";
import ThemeToggle from "../common/ThemeToggle";

const titles: Record<string, string> = { "/": "Security Overview", "/live-logs": "Live Threat Feed", "/explainability": "Explainability", "/reports": "Reports", "/settings": "Settings" };
type Notice = { title: string; detail: string; tone: "alert" | "warning" | "info" };

export default function Navbar() {
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [read, setRead] = useState(false);
  const { prediction } = usePrediction();
  const { drift } = useDrift();
  const { system, error } = useSystemStatus();
  const notices: Notice[] = [
    ...(error ? [{ title: "Backend unavailable", detail: "Unable to reach the FastAPI service.", tone: "alert" as const }] : []),
    ...(system?.status === "degraded" ? [{ title: "System degraded", detail: system.last_error ?? "The backend reported a health issue.", tone: "alert" as const }] : []),
    ...(drift?.drift_detected ? [{ title: "Concept drift detected", detail: `Flow ${drift.flow_id} triggered a drift alert.`, tone: "warning" as const }] : []),
    ...(prediction ? [{ title: "New flow analysed", detail: `Flow ${prediction.flow_id} is the latest backend detection.`, tone: "info" as const }] : []),
  ];
  const unread = notices.length > 0 && !read;
  const toneClass = (tone: Notice["tone"]) => tone === "alert" ? "bg-rose-500/10 text-rose-200" : tone === "warning" ? "bg-amber-500/10 text-amber-200" : "bg-indigo-500/10 text-indigo-200";

  return <div className="flex w-full items-center justify-between gap-3"><div><h1 className="text-base font-semibold text-white sm:text-lg">{titles[pathname] ?? "Adaptive IDS"}</h1><p className="hidden text-xs text-slate-500 sm:block">Explainable AI network defense</p></div><div className="flex items-center gap-2 sm:gap-4"><label className="relative hidden md:block"><Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} /><input aria-label="Search flows" placeholder="Search flows..." className="w-52 rounded-lg border border-white/10 bg-white/5 py-2 pl-9 pr-3 text-sm outline-none transition focus:border-indigo-400" /></label><div className="hidden items-center gap-1.5 text-xs text-emerald-300 sm:flex"><Circle size={9} fill="currentColor" />Healthy</div><ThemeToggle /><div className="relative"><button aria-label="Notifications" aria-expanded={open} onClick={() => setOpen((value) => !value)} className="relative rounded-lg p-2 text-slate-400 transition hover:bg-white/10 hover:text-white"><Bell size={19} />{unread && <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-rose-400 ring-2 ring-slate-950" />}</button>{open && <section className="absolute right-0 top-12 z-50 w-80 rounded-xl border border-white/10 bg-slate-900 p-3 shadow-2xl"><div className="mb-2 flex items-center justify-between"><h2 className="text-sm font-semibold">Notifications</h2><div className="flex gap-1"><button aria-label="Mark all read" onClick={() => setRead(true)} className="rounded p-1 text-slate-400 hover:bg-white/10"><CheckCheck size={16} /></button><button aria-label="Close notifications" onClick={() => setOpen(false)} className="rounded p-1 text-slate-400 hover:bg-white/10"><X size={16} /></button></div></div>{notices.length ? <ul className="space-y-2">{notices.map((notice) => <li key={notice.title} className={`rounded-lg p-3 text-sm ${toneClass(notice.tone)}`}><p className="font-medium">{notice.title}</p><p className="mt-0.5 text-xs opacity-80">{notice.detail}</p></li>)}</ul> : <p className="p-4 text-center text-sm text-slate-400">No new notifications.</p>}</section>}</div></div></div>;
}
