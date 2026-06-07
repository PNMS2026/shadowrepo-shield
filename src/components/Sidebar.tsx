import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ScanSearch,
  History,
  ShieldCheck,
  Settings,
  FileSearch,
} from "lucide-react";

const NAV_ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan", icon: ScanSearch, label: "New Scan" },
  { to: "/history", icon: History, label: "Scan History" },
  { to: "/verify", icon: FileSearch, label: "Verify Proof" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export default function Sidebar() {

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">
          <ShieldCheck size={20} color="white" />
        </div>
        <div>
          <div className="logo-text">ShadowRepo</div>
          <div className="logo-sub">Shield</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Navigation</div>
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `nav-item${isActive ? " active" : ""}`
            }
            end={item.to === "/"}
          >
            <item.icon size={18} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="version" style={{ marginTop: "10px" }}>
          v1.0.0 • Local-First
        </div>
      </div>
    </aside>
  );
}
