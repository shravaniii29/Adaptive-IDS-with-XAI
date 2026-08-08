import PageHeader from "../../components/common/PageHeader";
import Card from "../../components/common/Card";
import PageContainer from "../../components/layout/PageContainer";
export default function Settings() { return <PageContainer><PageHeader title="Settings" subtitle="Frontend connection preferences." /><Card><p className="font-medium text-slate-100">API connection</p><p className="mt-1 text-sm text-slate-400">Configure VITE_API_BASE_URL and VITE_WS_URL in your frontend .env file.</p></Card></PageContainer>; }
