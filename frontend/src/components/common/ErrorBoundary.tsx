import { Component, type ReactNode } from "react";

interface Props { children: ReactNode; fallback?: ReactNode; label?: string }
interface State { failed: boolean }

// Keeps one component's bad data from taking the whole page down: React
// unmounts the entire tree when a render throws, which is what turned a
// single malformed explanation into a blank dashboard.
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: unknown) {
    console.error(`${this.props.label ?? "Component"} failed to render`, error);
  }

  render() {
    if (this.state.failed) {
      return this.props.fallback ?? <p className="text-xs text-slate-500">{this.props.label ?? "This section"} could not be shown for this flow.</p>;
    }
    return this.props.children;
  }
}
