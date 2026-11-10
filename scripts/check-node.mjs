// Plain JS so it runs on any Node: the real scripts run .ts files directly, which needs Node >= 22.18.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 18)) {
  console.error(`Node ${process.versions.node} can't run this project: it needs Node >= 22.18 (runs .ts files directly).`);
  console.error('Run `nvm use` (see .nvmrc) and try again.');
  process.exit(1);
}
