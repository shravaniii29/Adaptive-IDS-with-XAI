import PageHeader from "../../components/common/PageHeader";
import LiveLogTable from "../../components/dashboard/LiveLogTable";
import PageContainer from "../../components/layout/PageContainer";
import { useDrift } from "../../hooks/useDrift";
import { usePrediction } from "../../hooks/usePrediction";
import { useAgentAnalysis } from "../../hooks/useAgentAnalysis";

export default function LiveLogs() {
  const { history, prediction } = usePrediction();
  const { drift } = useDrift();
  const { analysis } = useAgentAnalysis(prediction?.flow_id);

  return <PageContainer>
    <PageHeader title="Live threat feed" subtitle="Live flow detections from the connected IDS." />
    <LiveLogTable entries={history} driftDetected={drift?.drift_detected} latestAnalysis={analysis} />
  </PageContainer>;
}
