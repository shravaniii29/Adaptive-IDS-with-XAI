import { useEffect, useState } from "react";
import PageContainer from "../../components/layout/PageContainer";
import PageHeader from "../../components/common/PageHeader";
import Loader from "../../components/common/Loader";
import ErrorState from "../../components/common/ErrorState";
import EmptyState from "../../components/common/EmptyState";
import StatCard from "../../components/dashboard/StatCard";
import SimulationSelector from "../../components/simulation/SimulationSelector";
import ScenarioTabs from "../../components/simulation/ScenarioTabs";
import ScenarioModelChart from "../../components/simulation/ScenarioModelChart";
import ModelF1Chart from "../../components/simulation/ModelF1Chart";
import RunSimulationPanel from "../../components/simulation/RunSimulationPanel";
import { useSimulationDetail, useSimulationList, useSimulationRun } from "../../hooks/useSimulations";
import { modelLabel } from "../../types/simulation";

export default function LiveSimulation() {
  const { data: simulations, error: listError, loading: listLoading, refresh: refreshList } = useSimulationList();
  const [selectedRun, setSelectedRun] = useState<string | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
  const [showOverall, setShowOverall] = useState(false);

  const { status: runStatus, error: runError, start: startRun, cancel: cancelRun } = useSimulationRun((finalStatus) => {
    refreshList();
    if (finalStatus.exit_code === 0 && finalStatus.out_dir) setSelectedRun(finalStatus.out_dir);
  });

  useEffect(() => {
    if (simulations && simulations.length > 0 && !selectedRun) {
      setSelectedRun(simulations[0].name);
    }
  }, [simulations, selectedRun]);

  const { data: detail, error: detailError, loading: detailLoading } = useSimulationDetail(selectedRun);

  useEffect(() => {
    if (detail && detail.scenarios.length > 0) {
      const stillValid = detail.scenarios.some((s) => s.name === selectedScenario);
      if (!stillValid) setSelectedScenario(detail.scenarios[0].name);
    }
  }, [detail, selectedScenario]);

  if (listLoading) {
    return (
      <PageContainer>
        <PageHeader title="Live Simulation" subtitle="Attack-by-attack results from simulate_attacks.py live-test runs." />
        <Loader label="Loading available runs..." />
      </PageContainer>
    );
  }

  if (listError) {
    return (
      <PageContainer>
        <PageHeader title="Live Simulation" subtitle="Attack-by-attack results from simulate_attacks.py live-test runs." />
        <ErrorState message={listError} />
      </PageContainer>
    );
  }

  const activeScenario = detail?.scenarios.find((s) => s.name === selectedScenario) ?? null;

  const bestModel = detail
    ? Object.entries(detail.aggregate_metrics).sort((a, b) => (b[1].f1 ?? 0) - (a[1].f1 ?? 0))[0]
    : null;

  const totalFlows = detail ? Object.values(detail.aggregate_metrics)[0]?.total_flows ?? 0 : 0;

  return (
    <PageContainer>
      <PageHeader
        title="Live Simulation"
        subtitle="Run a fresh attack simulation, or pick an attack type below to see how every model handled a past one."
      />

      <RunSimulationPanel status={runStatus} error={runError} onStart={startRun} onCancel={cancelRun} />

      {(!simulations || simulations.length === 0) && (
        <div className="mt-6">
          <EmptyState
            title="No live-test runs yet"
            description="Click Run simulation above, or run python simulate_attacks.py <out_dir> [trials] from the project root."
          />
        </div>
      )}

      {simulations && simulations.length > 0 && (
        <>
          <div className="mt-6 flex justify-end">
            <SimulationSelector simulations={simulations} selected={selectedRun} onSelect={setSelectedRun} />
          </div>

          {detailLoading && <Loader label="Loading run..." />}
          {detailError && <ErrorState message={detailError} />}

          {detail && !detailLoading && (
            <>
              <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard title="Trials" value={detail.trials} color="#38bdf8" />
                <StatCard title="Scenarios" value={detail.scenarios.length} color="#a78bfa" />
                <StatCard title="Flows scored" value={totalFlows} color="#facc15" />
                <StatCard
                  title="Best model (F1)"
                  value={bestModel ? `${Math.round((bestModel[1].f1 ?? 0) * 1000) / 10}%` : "—"}
                  color="#22c55e"
                />
              </div>

              {bestModel && (
                <p className="mt-3 text-xs text-slate-500">
                  Best overall performer (pooled across all attack types):{" "}
                  <span className="text-slate-300">{modelLabel(bestModel[0])}</span>
                </p>
              )}

              <div className="mt-8">
                <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-500">Attack type</p>
                <ScenarioTabs scenarios={detail.scenarios} selected={selectedScenario ?? ""} onSelect={setSelectedScenario} />
              </div>

              {activeScenario && (
                <div className="mt-6">
                  <ScenarioModelChart scenario={activeScenario} />
                </div>
              )}

              <div className="mt-8">
                <button
                  onClick={() => setShowOverall((v) => !v)}
                  className="text-sm font-medium text-indigo-300 underline decoration-dotted underline-offset-4 hover:text-indigo-200"
                >
                  {showOverall ? "Hide" : "Show"} overall (pooled across every attack type)
                </button>
              </div>

              {showOverall && (
                <div className="mt-4">
                  <ModelF1Chart aggregateMetrics={detail.aggregate_metrics} />
                </div>
              )}
            </>
          )}
        </>
      )}
    </PageContainer>
  );
}
