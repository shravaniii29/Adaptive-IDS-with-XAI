import PageHeader from "../../components/common/PageHeader";
import EmptyState from "../../components/common/EmptyState";
import PageContainer from "../../components/layout/PageContainer";
export default function Reports() { return <PageContainer><PageHeader title="Reports" subtitle="Export and review detection activity." /><EmptyState title="No reports yet" description="Reports will become available as network flows are analysed." /></PageContainer>; }
