import PageHeader from "../../components/common/PageHeader";
import EmptyState from "../../components/common/EmptyState";
import PageContainer from "../../components/layout/PageContainer";
export default function Explainability() { return <PageContainer><PageHeader title="Explainability" subtitle="Understand why the model marked a network flow as suspicious." /><EmptyState title="Select a detection" description="Feature importance and SHAP explanations will appear after a prediction is selected." /></PageContainer>; }
