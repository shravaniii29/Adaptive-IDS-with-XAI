import PageHeader from "../../components/common/PageHeader";
import EmptyState from "../../components/common/EmptyState";
import PageContainer from "../../components/layout/PageContainer";
export default function LiveLogs() { return <PageContainer><PageHeader title="Live threat feed" subtitle="Incoming network events will appear here." /><EmptyState title="Waiting for flow data" description="Connect the backend WebSocket to stream detections in real time." /></PageContainer>; }
