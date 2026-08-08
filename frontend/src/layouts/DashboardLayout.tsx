import { useState } from "react";
import { Menu, X } from "lucide-react";
import { Outlet } from "react-router-dom";
import Footer from "../components/layout/Footer";
import Navbar from "../components/layout/Navbar";
import Sidebar from "../components/layout/Sidebar";

/** Shared shell for every authenticated monitoring page. */
export default function DashboardLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const closeSidebar = () => setIsSidebarOpen(false);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {isSidebarOpen && (
        <button
          aria-label="Close navigation menu"
          className="fixed inset-0 z-30 bg-slate-950/70 backdrop-blur-sm lg:hidden"
          onClick={closeSidebar}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 w-72 border-r border-white/10 bg-slate-950 transition-transform duration-200 lg:translate-x-0 ${
          isSidebarOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center justify-end px-4 lg:hidden">
          <button
            aria-label="Close navigation menu"
            className="rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white"
            onClick={closeSidebar}
          >
            <X size={20} />
          </button>
        </div>
        <Sidebar onNavigate={closeSidebar} />
      </aside>

      <div className="flex min-h-screen flex-col lg:pl-72">
        <div className="sticky top-0 z-20 flex min-h-16 items-center border-b border-white/10 bg-slate-950/85 px-4 backdrop-blur-xl sm:px-6">
          <button
            aria-label="Open navigation menu"
            className="mr-3 rounded-lg p-2 text-slate-300 hover:bg-white/10 lg:hidden"
            onClick={() => setIsSidebarOpen(true)}
          >
            <Menu size={20} />
          </button>
          <Navbar />
        </div>

        <main className="flex-1 bg-[radial-gradient(circle_at_top_right,_rgba(79,70,229,.16),_transparent_30%),radial-gradient(circle_at_bottom_left,_rgba(14,165,233,.10),_transparent_28%)] p-4 sm:p-6 lg:p-8">
          <Outlet />
        </main>

        <Footer />
      </div>
    </div>
  );
}
