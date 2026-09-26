// hark stub: no views are ever mounted in the daemon; state is read as JSON.
export function createSandboxHost() {
  const registry = new Map();
  return { registry, mount() { throw new Error('hark mounts no views'); }, destroy() {}, pushState() {}, has: thread => registry.has(thread) };
}
