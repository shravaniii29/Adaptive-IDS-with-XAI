import clsx from "clsx";
import type { ScenarioResult } from "../../types/simulation";

interface Props {
  scenarios: ScenarioResult[];
  selected: string;
  onSelect: (name: string) => void;
}

export default function ScenarioTabs({ scenarios, selected, onSelect }: Props) {
  return (
    <div className="flex flex-wrap gap-2">
      {scenarios.map((s) => (
        <button
          key={s.name}
          onClick={() => onSelect(s.name)}
          className={clsx(
            "rounded-xl px-4 py-2.5 text-sm font-medium transition",
            selected === s.name
              ? s.is_attack
                ? "bg-rose-500/15 text-rose-200 ring-1 ring-inset ring-rose-400/30"
                : "bg-emerald-500/15 text-emerald-200 ring-1 ring-inset ring-emerald-400/30"
              : "bg-white/5 text-slate-400 hover:bg-white/10 hover:text-slate-200"
          )}
        >
          {s.name}
          <span className="ml-2 text-xs opacity-60">n={s.flow_count}</span>
        </button>
      ))}
    </div>
  );
}
