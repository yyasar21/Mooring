import { App } from "./App";
import { DetachedApp } from "./components/detached/DetachedApp";
import { bootRoute } from "./lib/route";

/**
 * The router: `#/detached/<sessionId>` mounts the detached window's entry instead of `App`, so
 * the main boot (`app_info`, `vault_status`, `listen("vault:locked")`, the tree) never runs in a
 * window whose capability forbids it. The route is fixed at boot (`bootRoute`).
 */
export function Root() {
  const route = bootRoute();
  return route.kind === "detached" ? <DetachedApp sessionId={route.sessionId} /> : <App />;
}
