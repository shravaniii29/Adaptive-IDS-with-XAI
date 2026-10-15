import type { SimulationListEntry } from "../../types/simulation";

interface Props {
  simulations: SimulationListEntry[];
  selected: string | null;
  onSelect: (name: string) => void;
}

const formatDate = (unixSeconds: number | null) =>
  unixSeconds ? new Date(unixSeconds * 1000).toLocaleString() : "unknown date";

export default function SimulationSelector({ simulations, selected, onSelect }: Props) {
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
      <label className="text-sm font-medium text-slate-400" htmlFor="simulation-select">
        Live-test run
      </label>

      <select
        id="simulation-select"
        value={selected ?? ""}
        onChange={(event) => onSelect(event.target.value)}
        className="w-full rounded-xl border border-white/10 bg-[#111827] px-4 py-2.5 text-sm text-slate-100 outline-none transition focus:border-indigo-400/50 sm:w-auto sm:min-w-[420px]"
      >
        {simulations.map((sim) => (
          <option key={sim.name} value={sim.name}>
            {sim.name} — {formatDate(sim.generated_at)} ({sim.trials ?? "?"} trial{sim.trials === 1 ? "" : "s"})
          </option>
        ))}
      </select>
    </div>
  );
}
