import { BrowserRouter, Route, Routes } from "react-router-dom";
import DashboardLayout from "../layouts/DashboardLayout";
import Dashboard from "../pages/Dashboard/Dashboard";
import Explainability from "../pages/Explainability/Explainability";
import LiveLogs from "../pages/LiveLogs/LiveLogs";
import NotFound from "../pages/NotFound/NotFound";
import Reports from "../pages/Reports/Reports";
import Settings from "../pages/Settings/Settings";

export default function AppRoutes() { return <BrowserRouter><Routes><Route element={<DashboardLayout />}><Route index element={<Dashboard />} /><Route path="live-logs" element={<LiveLogs />} /><Route path="explainability" element={<Explainability />} /><Route path="reports" element={<Reports />} /><Route path="settings" element={<Settings />} /></Route><Route path="*" element={<NotFound />} /></Routes></BrowserRouter>; }
