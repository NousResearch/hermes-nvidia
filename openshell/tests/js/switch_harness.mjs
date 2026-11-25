// Runs desktop/plugin.js's switch and header logic against stand-ins for the desktop SDK (no desktop, no
// React): the page's import lines are pointed at the stubs below, the module is loaded from a temp copy,
// and each scenario prints one JSON line. Driven by tests/test_desktop_switch_js.py.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const pluginPath = process.argv[2]
const source = readFileSync(pluginPath, 'utf8')
const names = /import\s*\{([^}]*)\}\s*from\s*'@hermes\/plugin-sdk'/.exec(source)[1].split(',').map(s => s.trim()).filter(Boolean)

const dir = mkdtempSync(join(process.argv[3], 'openshell-js-'))  // the test's own temp dir
const sdk = names
  .map(name =>
    name === 'atom'
      ? `export const atom = initial => { let v = initial; return { get: () => v, set: n => { v = n } } }`
      : name === 'host'
        ? `export const host = globalThis.__host`
        : name === 'useValue'
          ? `export const useValue = a => (a && typeof a.get === 'function' ? a.get() : (a ?? null))`
          : name === 'useQueryClient'
            ? `export const useQueryClient = () => globalThis.__queryClient`
            : name === 'useQuery' || name === 'useMutation'
              ? // a scenario that renders the whole page gives these an answer; elsewhere they are inert
                `export const ${name} = q => (globalThis.__${name} ? globalThis.__${name}(q) : null)`
              : `export const ${name} = globalThis.__stub(${JSON.stringify(name)})`
  )
  .join('\n')
writeFileSync(join(dir, 'sdk.mjs'), sdk)
// A tiny element tree (type name, props, children) so components can be rendered by calling them; hooks are
// inert (useState holds its initial value, useEffect never runs) unless a scenario sets globalThis.__useState
// (the value a state starts with) or globalThis.__useEffect (it is handed each effect and its dependencies).
writeFileSync(
  join(dir, 'react.mjs'),
  'export const createElement = (type, props, ...children) => ({ type: typeof type === "function" ? type.name : type, props: props || {}, children })\n' +
    'export const useState = v => [globalThis.__useState ? globalThis.__useState(v) : v, () => {}]\n' +
    'export const useEffect = (fn, deps) => { if (globalThis.__useEffect) globalThis.__useEffect(fn, deps) }\n'
)
writeFileSync(
  join(dir, 'plugin.mjs'),
  source.replace(/from '@hermes\/plugin-sdk'/, "from './sdk.mjs'").replace(/from 'react'/, "from './react.mjs'")
)

globalThis.__stub = name =>
  name.endsWith('_AREA') || name.endsWith('_AREAS') ? { right: name } : Object.defineProperty(() => null, 'name', { value: name })

const log = []
const host = {}
globalThis.__host = host
let fetchAnswer = null  // a scenario's own answer for the launcher's switch/off; reset() clears it
globalThis.fetch = async (url, init) => {
  log.push({ fetch: url, body: JSON.parse(init.body) })
  return fetchAnswer ? fetchAnswer() : { ok: true, json: async () => ({ ok: true }) }
}

const { __test__: P } = await import(pathToFileURL(join(dir, 'plugin.mjs')).href)

function reset(features) {
  log.length = 0
  for (const key of Object.keys(host)) delete host[key]
  if (features !== undefined) host.profileBackendFeatures = features
  host.notify = n => log.push(n.kind === 'error' ? { notify: n.message } : { notify: n.message, kind: n.kind })
  host.state = {}
  fetchAnswer = null
}

const onBodies = []  // what each /switch/on call sent (the last session's answer rides in the body)
function fakeRest({ onSwitchOn, statuses, handback, answerFails }) {
  let n = 0
  return async (path, opts) => {
    log.push({ rest: path, switching: P.switchState() })
    if (path === '/switch/on') onBodies.push(opts.body)
    if (path === '/handback') {
      if (handback === 'fails') throw new Error('500: {"detail": "boom"}')
      return handback || { open: false, rows: [], unanswered: 0 }
    }
    if (path === '/handback/answer') {
      log.push({ answer: opts.body, method: opts.method })
      if (answerFails) throw new Error('500: {"detail": "RuntimeError: boom"}')
      return { kept: opts.body.rows, skipped: [], unanswered: 0 }
    }
    if (path === '/switch/on') {
      if (onSwitchOn) return onSwitchOn()
      return { profile: 'work', url: 'http://127.0.0.1:47972', token: 'tok', undo_ticket: 'undo-1' }
    }
    if (path === '/status') return statuses[Math.min(n++, statuses.length - 1)]
    if (path === '/switch/ticket') return opts?.method === 'DELETE' ? { ok: true } : { ticket: 't-1', url: 'http://127.0.0.1:47972' }
    throw new Error(`unexpected ${path}`)
  }
}

const queryClient = {
  setQueryData: (key, value) => log.push({ seed: key, value, switching: P.switchState() }),
  invalidateQueries: q => log.push({ invalidate: q.queryKey, switching: P.switchState() })
}

globalThis.__queryClient = queryClient
const on = { profile: 'work', sandboxed: true, state: 'running' }
const off = { profile: 'work', sandboxed: false, state: 'off' }
const out = {}

// 1. Ask first: the dialog comes before anything starts; prepare starts it; the final status is seeded
//    while the switch state is still up.
reset({ beforeApply: true, prepare: true, purpose: true })
P.useRest(fakeRest({ statuses: [on] }))
host.setProfileBackend = async input => {
  log.push({ set: Object.keys(input).sort(), purpose: input.purpose, switching: P.switchState() })
  const backend = await input.prepare()
  log.push({ prepared: backend })
  return { applied: true }
}
await P.turnOn('work', queryClient)
out.askFirst = [...log]

// 2. Cancel in the dialog: prepare never runs, nothing starts, nothing to undo.
reset({ prepare: true, purpose: true })
P.useRest(fakeRest({ statuses: [off] }))
host.setProfileBackend = async input => {
  log.push({ set: Object.keys(input).sort() })
  return { applied: false }
}
await P.turnOn('work', queryClient)
out.cancel = [...log]

// 3. Yes, prepare ran, then the desktop refuses the address: the undo ticket stops the launcher.
reset({ prepare: true, purpose: true })
P.useRest(fakeRest({ statuses: [off] }))
host.setProfileBackend = async input => {
  await input.prepare()
  throw new Error('Only loopback URLs')
}
await P.turnOn('work', queryClient)
out.refused = [...log]

// 4. An older desktop (no profileBackendFeatures): start, then ask, with url/token and the purpose line.
reset(undefined)
P.useRest(fakeRest({ statuses: [off] }))
host.setProfileBackend = async input => {
  log.push({ set: Object.keys(input).sort(), switching: P.switchState() })
  return { applied: false }
}
await P.turnOn('work', queryClient)
out.legacy = [...log]

// 5. Off: seeded with the host's final status before the switch state clears.
reset({ prepare: true, beforeApply: true })
P.useRest(fakeRest({ statuses: [off] }))
host.clearProfileBackend = async input => {
  log.push({ clear: Object.keys(input).sort(), switching: P.switchState() })
  await input.beforeApply()
  return { applied: true }
}
await P.turnOff('work', queryClient)
out.off = [...log]

// 5b. Off, Cancel in the dialog: nothing stops, the header never said "Stopping", the ticket is dropped.
reset({ prepare: true, beforeApply: true })
P.useRest(fakeRest({ statuses: [on] }))
host.clearProfileBackend = async input => {
  log.push({ clear: Object.keys(input).sort(), switching: P.switchState() })
  return { applied: false }
}
await P.turnOff('work', queryClient)
out.offCancel = [...log]

// 6. Header copy: one name per state.
out.copy = {
  turningOn: P.T.turningOn,
  turningOff: P.T.turningOff,
  starting: P.stateView({ sandboxed: true, state: 'starting' }).label,
  restarting: P.stateView({ sandboxed: true, state: 'restarting' }).label,
  stopping: P.stateView({ sandboxed: true, state: 'stopping' }).label,
  switchingOff: P.stateView({ sandboxed: true, state: 'running', switching_off: true }).label,
  folder: P.stateView({ sandboxed: true, state: 'restarting', restarting: { label: 'Restarting the sandbox to add outside' } }).label,
  running: P.stateView(on).label,
  off: P.stateView(off).label
}

// 7. Host compatibility: the bar (reason, action, buttons) and the switch, rendered by calling the components.
const texts = node =>
  node == null || node === false ? [] : typeof node === 'string' ? [node] : (node.children || []).flatMap(texts)
const find = (node, type) =>
  node == null || typeof node !== 'object' ? [] : [...(node.type === type ? [node] : []), ...(node.children || []).flatMap(c => find(c, type))]
const buttons = tree => find(tree, 'Button').map(b => ({ text: texts(b).join(''), disabled: Boolean(b.props.disabled), variant: b.props.variant || null }))
const offWith = host_ => ({ ...off, switch: { available: host_.ok, reason: host_.ok ? null : host_.reason, action: host_.action, host: host_ } })
const needsUpdate = {
  ok: false,
  platform: 'windows',
  code: 'windows-update',
  reason: 'Needs the September 2026 Windows update. This PC has Windows 11 25H2, build 26200.9278.',
  action: { text: 'Install it in Settings > Windows Update, then check again.' }
}
const noDocker = {
  ok: false,
  platform: 'linux',
  code: 'docker-missing',
  reason: 'Needs Docker.',
  action: { text: 'Install Docker Engine, then check again.', label: 'Install Docker', url: 'https://docs.docker.com/engine/install/' }
}
const fine = { ok: true, platform: 'windows', code: 'ok', reason: null, action: null }

reset({ prepare: true, beforeApply: true })
host.setProfileBackend = async () => ({ applied: false })
host.clearProfileBackend = async () => ({ applied: false })
const opened = []
P.useOs({ openExternal: async url => (opened.push(url), true) })
const updateBar = P.CompatBar({ status: offWith(needsUpdate) })
const dockerBar = P.CompatBar({ status: offWith(noDocker) })
find(dockerBar, 'Button')[0].props.onClick()
P.useOs(null)
const dockerBarNoOs = P.CompatBar({ status: offWith(noDocker) })
const switchOf = status => {
  const tree = P.SandboxSwitch({ status })
  const [sw] = find(tree, 'Switch')
  const [tip] = find(tree, 'Tip')
  return { disabled: sw.props.disabled, tip: tip ? tip.props.label : null, label: texts(tree).join('') }
}
out.compat = {
  update: { role: updateBar.props.role, texts: texts(updateBar), buttons: buttons(updateBar) },
  docker: { texts: texts(dockerBar), buttons: buttons(dockerBar), opened },
  dockerNoOs: { buttons: buttons(dockerBarNoOs) },
  okBar: P.CompatBar({ status: offWith(fine) }),
  sandboxedBar: P.CompatBar({ status: { ...on, switch: { available: true, reason: null } } }),
  problemWhileOn: P.hostProblem({ ...on, switch: { host: needsUpdate } }),
  switchBlocked: switchOf(offWith(needsUpdate)),
  switchFine: switchOf(offWith(fine))
}

// 8. "Check again": the host route's fresh status is shown at once; a failure is a toast.
reset({ prepare: true, beforeApply: true })
P.useRest(async (path, opts) => {
  log.push({ rest: path, method: opts?.method })
  if (path === '/switch/check') return offWith(fine)
  throw new Error(`unexpected ${path}`)
})
await P.recheckHost('work', queryClient)
out.recheck = [...log]
reset({ prepare: true, beforeApply: true })
P.useRest(async () => {
  throw new Error('500: {"detail": "boom"}')
})
await P.recheckHost('work', queryClient)
out.recheckFailed = [...log]

// 9. The Sandbox page's allowed destinations: what the launcher keeps open by itself (config.builtin) is listed
//    first with its reason and nothing to remove; the user's own keep their Remove button, and an edit sends
//    only those.
const flat = node => (Array.isArray(node) ? node.flatMap(flat) : node == null || node === false ? [] : [node])
const deep = (node, type) =>
  flat(node).flatMap(n => (typeof n !== 'object' ? [] : [...(n.type === type ? [n] : []), ...deep(n.children || [], type)]))
const deepTexts = node => flat(node).flatMap(n => (typeof n === 'string' ? [n] : typeof n === 'object' ? deepTexts(n.children || []) : []))
const pageConfig = (allow, builtin) => ({
  network: { egress: 'deny', allow },
  endpoints: [],
  capabilities: {},
  ...(builtin === undefined ? {} : { builtin })
})
const usageData = { host: 'telemetry.nousresearch.com', port: 443, reason: 'Usage data this profile shares with Nous', rule: 'hermes_builtin_usage_data' }
const destinations = (config, sent = []) => {
  const send = (...args) => sent.push(args)
  const tree = P.NetworkSection({ config, status: {}, send, sendQuietly: send, pending: false, ask: () => {} })
  const lists = deep(tree, 'List')
  const list = lists[lists.length - 1]
  return {
    rows: deep(list, 'Row').map(row => ({
      title: row.props.title,
      note: row.props.note || null,
      mono: Boolean(row.props.mono),
      port: deepTexts(row.props.access).join(''),
      removable: Boolean(row.props.action)
    })),
    texts: deepTexts(list),
    remove: title => deep(list, 'Row').find(row => row.props.title === title).props.action.props.onClick()
  }
}
const pypi = { host: 'pypi.org', port: 443 }
const sentEdits = []
const both = destinations(pageConfig([pypi], [usageData]), sentEdits)
both.remove('pypi.org')
const noteRow = P.Row({ title: 'telemetry.nousresearch.com', note: usageData.reason, mono: true })
const noteNode = deep(noteRow, 'div').find(n => deepTexts(n).join('') === usageData.reason && n.children.length === 1 && typeof n.children[0] === 'string')
out.builtin = {
  both: both.rows,
  edit: sentEdits,
  olderLauncher: destinations(pageConfig([pypi])).rows,
  onlyBuiltin: (({ rows, texts }) => ({ rows, texts }))(destinations(pageConfig([], [usageData]))),
  nothing: (({ rows, texts }) => ({ rows, texts }))(destinations(pageConfig([], []))),
  note: { text: deepTexts(noteNode), className: noteNode.props.className || null }
}

// 10. The header counts every destination the page lists: the user's own (the running sandbox's) and the ones the
//     launcher keeps open by itself (status.builtin, the same rows as config.builtin).
const headerOf = (allow, builtin, egress = 'deny') => {
  const status = { ...on, applied: { folders: [], network: { egress, allow } }, ...(builtin === undefined ? {} : { builtin }) }
  const parts = deepTexts(P.Header({ status })).filter(text => /destination|Internet/.test(text))
  return { parts, rows: destinations(pageConfig(allow, builtin)).rows.length }
}
out.headerCount = {
  both: headerOf([pypi], [usageData]),
  onlyBuiltin: headerOf([], [usageData]),
  twoAndBuiltin: headerOf([pypi, { cidr: '10.0.0.0/8', port: 22 }], [usageData]),
  onlyOwn: headerOf([pypi], []),
  olderLauncher: headerOf([pypi]),
  nothing: headerOf([], []),
  internetAllowed: headerOf([], [usageData], 'allow').parts
}

// 11. The withheld-key bar: one bar while the launcher reports keys it withheld because the sandbox's model entry
//     names another endpoint than the pinned one (status.endpoint_changed). Allow posts each pair to the launcher's
//     host route; Dismiss hides the bar until the list changes.
reset({ prepare: true, beforeApply: true })
const changedRow = { label: 'Model', host: '127.0.0.1', port: 18923, env: 'OTHER_API_KEY' }
const secondRow = { label: 'Fallback model', host: 'models.example.com', port: 443, env: 'SPARE_API_KEY' }
const withChanged = rows => ({ ...on, pinned: true, endpoint_changed: rows })
const barOf = (status, sent = []) => {
  const tree = P.EndpointBar({ status, send: async (...args) => void sent.push(args) })
  return tree && { role: tree.props.role, texts: texts(tree), buttons: buttons(tree), tree }
}
const allowSent = []
const oneBar = barOf(withChanged([changedRow]), allowSent)
await find(oneBar.tree, 'Button')[0].props.onClick()
const twoSent = []
const twoBar = barOf(withChanged([changedRow, secondRow]), twoSent)
await find(twoBar.tree, 'Button')[0].props.onClick()
const failing = P.EndpointBar({ status: withChanged([changedRow]), send: async () => { throw new Error('No withheld key for this endpoint.') } })
await find(failing, 'Button')[0].props.onClick()
const allowFailed = [...log]
const unpinnedBar = barOf({ ...withChanged([changedRow]), pinned: false })
const before = P.endpointsDismissed()
find(oneBar.tree, 'Button')[1].props.onClick()
const dismissedKey = P.endpointsDismissed()
out.endpointBar = {
  one: { role: oneBar.role, texts: oneBar.texts, buttons: oneBar.buttons },
  allowSent,
  two: { texts: twoBar.texts, sent: twoSent },
  allowFailed,
  unpinned: { texts: unpinnedBar.texts, buttons: unpinnedBar.buttons },
  none: barOf(withChanged([])),
  olderLauncher: barOf(on),
  notSandboxed: barOf({ ...off, endpoint_changed: [changedRow] }),
  dismiss: {
    before,
    shownAfter: P.withheldEndpoints(withChanged([changedRow]), dismissedKey).length,
    otherList: P.withheldEndpoints(withChanged([changedRow, secondRow]), dismissedKey).length,
    otherProfile: P.withheldEndpoints({ ...withChanged([changedRow]), profile: 'other' }, dismissedKey).length
  }
}

// 12. The hand-back card (launcher/handback.py): what the sandbox changed among the files that run on this computer.
//     The card and the switch take the list as a prop; its two buttons turn the sandbox off with an answer.
const hbRow = (id, label, name, detail, extra = {}) => ({ id, kind: 'x', tier: 1, label, name, detail, answer: null, can_restore: true, fixed: false, state: `state-of-${id}`, ...extra })
const hbRows = [
  hbRow('cfg:hooks_auto_accept', 'Shell hooks', 'hooks_auto_accept', 'turned on'),
  hbRow('cfg:mcp_servers.injected', 'MCP server', 'injected', 'new, runs /bin/sh -c id'),
  hbRow('file:plugins/p1/__init__.py', 'Plugin file', 'plugins/p1/__init__.py', 'changed', { can_restore: false }),
  hbRow('env:.op.env', 'Env file', '.op.env', 'created', { fixed: true })
]
const hbItems = [
  { id: 't2:SOUL.md', label: 'Context file', name: 'SOUL.md', detail: 'changed' },
  { id: 't2:memories/MEMORY.md', label: 'Memory', name: 'memories/MEMORY.md', detail: 'changed' },
  { id: 't2:skills/new-one/SKILL.md', label: 'Skill', name: 'skills/new-one/SKILL.md', detail: 'new' },
  { id: 't2:skills/writing/SKILL.md', label: 'Skill', name: 'skills/writing/SKILL.md', detail: 'changed' }
]
const hbAlso = {
  tier2: { counts: { skills: 2, memories: 1, context: 1 }, files: 4, items: hbItems, more: 0 },
  other_settings: { count: 2, paths: ['display.skin', 'mcp_servers_note'] }
}
const hbNothingElse = { tier2: { counts: { skills: 0, memories: 0, context: 0 }, files: 0, items: [], more: 0 }, other_settings: { count: 0, paths: [] } }
const hbView = { open: true, rows: hbRows, unanswered: 3, incomplete: [], ...hbAlso }
const badgeOf = node => {
  const [badge] = deep(node, 'Badge')
  const [tip] = deep(node, 'Tip')
  return badge ? { text: deepTexts(badge).join(''), tip: tip ? tip.props.label : null } : null
}
const cardOf = (view, status = on) => {
  const tree = P.HandbackCard({ status, view })
  if (!tree) return null
  return {
    tree,
    texts: texts(tree),
    rows: deep(tree, 'Row').map(row => ({
      label: deepTexts(row.props.meta).join(''),
      name: row.props.title,
      detail: row.props.note,
      mono: Boolean(row.props.mono),
      badge: badgeOf(row.props.badge)
    })),
    buttons: deep(tree, 'Button').map(b => ({ text: deepTexts(b).join(''), disabled: Boolean(b.props.disabled), variant: b.props.variant || null })),
    tips: deep(tree, 'Tip').map(t => t.props.label),
    also: deep(tree, 'AlsoChanged').length
  }
}
const alsoOf = (view, open = false) => {
  const tree = P.AlsoChanged({ view, open, onToggle: () => {} })
  return tree && {
    texts: deepTexts(tree),
    buttons: deep(tree, 'Button').map(b => deepTexts(b).join('')),
    rows: deep(tree, 'Row').map(row => [row.props.title, row.props.note || null, deepTexts(row.props.meta).join('')])
  }
}
const withSwitch = status => ({ ...status, switch: { available: true, reason: null } })
const hbSwitchOf = (status, handback) => {
  const tree = P.SandboxSwitch({ status, handback })
  const [sw] = find(tree, 'Switch')
  const [tip] = find(tree, 'Tip')
  return { disabled: sw.props.disabled, tip: tip ? tip.props.label : null }
}
const clickCard = async (view, text, { answer, statuses = [off], confirm = true, answerFails = false } = {}) => {
  reset({ prepare: true, beforeApply: true })
  P.useRest(fakeRest({ statuses, handback: view, answerFails }))
  fetchAnswer = answer || null
  host.setProfileBackend = async () => ({ applied: false })
  host.clearProfileBackend = async input => {
    log.push({ clear: Object.keys(input).sort(), switching: P.switchState() })
    if (!confirm) return { applied: false }
    await input.beforeApply()
    return { applied: true }
  }
  const card = P.HandbackCard({ status: withSwitch(on), view })
  await deep(card, 'Button').find(b => deepTexts(b).join('') === text).props.onClick()
  return [...log]
}
const answered = body => () => ({ ok: true, json: async () => body })
const refused = (status, body) => () => ({ ok: false, status, json: async () => body })
const offBody = handback => ({ ok: true, state: 'off', marker_cleared: true, handback })

reset({ prepare: true, beforeApply: true })
host.setProfileBackend = async () => ({ applied: false })
host.clearProfileBackend = async () => ({ applied: false })
const hbCard = cardOf(hbView)
const onlyOther = { open: true, rows: [], unanswered: 0, incomplete: [], ...hbAlso }
out.handback = {
  card: { texts: hbCard.texts, rows: hbCard.rows, buttons: hbCard.buttons, also: hbCard.also },
  noRows: { card: cardOf({ open: true, rows: [], unanswered: 0, incomplete: [], ...hbNothingElse }), switch: hbSwitchOf(withSwitch(on), { open: true, rows: [], unanswered: 0 }) },
  onlyOther: { card: cardOf(onlyOther), switch: hbSwitchOf(withSwitch(on), onlyOther) },
  noView: { card: cardOf(undefined), closed: cardOf({ open: false, rows: [], unanswered: 0 }), switch: hbSwitchOf(withSwitch(on), undefined) },
  // A profile that is off shows a list only while the host says its last session is still to be reviewed (13):
  // one left in the page's cache from before a switch-off is not shown.
  notSandboxed: P.reviewView(off, hbView) === undefined ? null : cardOf(hbView, off),
  also: {
    closed: alsoOf(hbView),
    open: alsoOf(hbView, true),
    cut: alsoOf({ ...hbView, tier2: { ...hbAlso.tier2, more: 50 } }, true).texts.filter(t => /more/.test(t)),
    one: alsoOf({ ...hbView, tier2: { counts: { skills: 1, memories: 0, context: 0 }, files: 1, items: [], more: 0 }, other_settings: { count: 1, paths: ['display.skin'] } }).texts,
    none: alsoOf({ ...hbView, ...hbNothingElse })
  },
  incomplete: cardOf({ ...hbView, incomplete: ['skills'] }).texts.filter(t => /checked/.test(t)),
  incompleteNone: hbCard.texts.filter(t => /checked/.test(t)),
  switchDisabled: hbSwitchOf(withSwitch(on), hbView),
  switchFixedOnly: hbSwitchOf(withSwitch(on), { open: true, rows: [hbRows[3]], unanswered: 0 }),
  switchOff: hbSwitchOf(withSwitch(off), P.reviewView(withSwitch(off), hbView))
}
host.state.busyBySession = { s1: true }
out.handback.busy = { buttons: cardOf(hbView).buttons, tips: cardOf(hbView).tips.filter(t => /turn/.test(t)), switch: hbSwitchOf(withSwitch(on), { open: true, rows: [], unanswered: 0 }) }

out.handback.revert = await clickCard(hbView, 'Revert and turn off', { answer: answered(offBody({ reverted: ['a', 'b', 'c'], kept: [], held: '20261117-101500' })) })
out.handback.revertOne = await clickCard(hbView, 'Revert and turn off', { answer: answered(offBody({ reverted: ['a'], kept: [], held: 'h' })) })
out.handback.keep = await clickCard(hbView, 'Keep and turn off', { answer: answered(offBody({ reverted: ['env:.op.env'], kept: ['cfg:hooks_auto_accept'], held: 'h' })) })
out.handback.keepLate = await clickCard(hbView, 'Keep and turn off', { answer: answered(offBody({ reverted: ['file:scripts/late.sh'], kept: [], held: 'h' })) })
out.handback.keepLateTwo = await clickCard(hbView, 'Keep and turn off', { answer: answered(offBody({ reverted: ['x', 'y', 'env:.op.env'], kept: [], held: 'h' })) })
out.handback.keepNotRecorded = await clickCard(hbView, 'Keep and turn off', { answerFails: true })
out.handback.cancel = await clickCard(hbView, 'Revert and turn off', { confirm: false, statuses: [on] })
out.handback.cancelCard = Boolean(cardOf(hbView))
out.handback.late409 = await clickCard(hbView, 'Keep and turn off', { statuses: [on], answer: refused(409, { detail: '2 changes need an answer.', code: 'handback_needs_answer', unanswered: 2 }) })
const stuck = "Couldn't revert 1 change: hooks_auto_accept. The sandbox is stopped. Close any app using this profile's files, then turn off again."
out.handback.incomplete409 = await clickCard(hbView, 'Revert and turn off', { statuses: [on], answer: refused(409, { detail: stuck, code: 'handback_incomplete', left: ['cfg:hooks_auto_accept'] }) })
out.handback.other500 = await clickCard(hbView, 'Revert and turn off', { statuses: [on], answer: refused(500, { detail: "The sandbox didn't turn off: boom" }) })
out.handback.reviewFailed = await clickCard(hbView, 'Revert and turn off', { answer: answered(offBody({ reverted: [], kept: [], held: null, error: 'RuntimeError: boom' })) })
out.handback.keptWithProblem = await clickCard(hbView, 'Keep and turn off', { answer: answered(offBody({ reverted: [], kept: [], held: null, left: ['file:scripts/late.sh'], problem: "Couldn't revert 1 change: scripts/late.sh." })) })

// A plain turn-off (the switch) reads the list first: with changes that need an answer the card asks instead.
const plainOff = async (handback, answer) => {
  reset({ prepare: true, beforeApply: true })
  P.useRest(fakeRest({ statuses: [off], handback }))
  fetchAnswer = answer || null
  host.clearProfileBackend = async input => {
    log.push({ clear: Object.keys(input).sort(), switching: P.switchState() })
    await input.beforeApply()
    return { applied: true }
  }
  await P.turnOff('work', queryClient)
  return [...log]
}
out.handback.foundAtTheClick = await plainOff({ ...hbView, unanswered: 2 })
out.handback.plainOnlyOther = await plainOff(onlyOther, answered(offBody({ reverted: [], kept: [], held: null })))
out.handback.plainFixedReverted = await plainOff({ open: true, rows: [hbRows[3]], unanswered: 0 }, answered(offBody({ reverted: ['env:.op.env'], kept: [], held: 'h' })))
out.handback.plainListFails = await plainOff('fails', answered(offBody(null)))
out.handback.copy = {
  first: P.T.handbackFirst,
  late: P.T.handbackLate,
  noCopyTip: P.T.handbackNoCopyTip
}

// 13. The last session's changes, for a profile that is off (the host route's GET /handback while its record is
//     still open, status.handback.open): the same card, whose two buttons answer and then turn the sandbox ON;
//     the switch waits for one of them. Nothing is read first at the click: the host route refuses a switch-on
//     without the answer (409 handback_needs_answer) and the page then says so.
const offOpen = { ...withSwitch(off), handback: { open: true, held: 0 } }
const started = handback => () => ({ profile: 'work', url: 'http://127.0.0.1:47972', token: 'tok', undo_ticket: 'undo-1', handback })
const clickOnCard = async (view, text, { switchOn, confirm = true } = {}) => {
  reset({ prepare: true, beforeApply: true })
  onBodies.length = 0
  P.useRest(fakeRest({ statuses: [on], handback: view, onSwitchOn: switchOn }))
  host.clearProfileBackend = async () => ({ applied: false })
  host.setProfileBackend = async input => {
    log.push({ set: Object.keys(input).sort(), switching: P.switchState() })
    if (!confirm) return { applied: false }
    const backend = await input.prepare()
    log.push({ prepared: backend })
    return { applied: true }
  }
  const card = P.HandbackCard({ status: offOpen, view })
  await deep(card, 'Button').find(b => deepTexts(b).join('') === text).props.onClick()
  return { log: [...log], bodies: [...onBodies] }
}
const needsAnswer = () => {
  throw new Error('409: {"detail": "2 changes need an answer.", "code": "handback_needs_answer", "unanswered": 2}')
}
reset({ prepare: true, beforeApply: true })
host.setProfileBackend = async () => ({ applied: false })
host.clearProfileBackend = async () => ({ applied: false })
const reviewCard = cardOf(hbView, offOpen)
const blockedCard = cardOf(hbView, { ...offOpen, switch: { available: false, reason: 'Needs Docker.' } })
out.review = {
  card: { texts: reviewCard.texts.slice(0, 2), rows: reviewCard.rows.map(r => r.name), buttons: reviewCard.buttons, also: reviewCard.also },
  switch: hbSwitchOf(offOpen, P.reviewView(offOpen, hbView)),
  switchNoRows: hbSwitchOf(offOpen, P.reviewView(offOpen, { open: true, rows: [], unanswered: 0 })),
  noRowsCard: cardOf({ open: true, rows: [], unanswered: 0, incomplete: [], ...hbNothingElse }, offOpen),
  blocked: { buttons: blockedCard.buttons, tips: blockedCard.tips.filter(t => /Docker/.test(t)) },
  view: { open: Boolean(P.reviewView(offOpen, hbView)), stale: P.reviewView(withSwitch(off), hbView) === undefined, whileOn: Boolean(P.reviewView(on, hbView)), noStatus: P.reviewView(undefined, hbView) === undefined }
}
out.review.revert = await clickOnCard(hbView, 'Revert and turn on', { switchOn: started({ reverted: ['a', 'b', 'c'], kept: [], held: 'h' }) })
out.review.keep = await clickOnCard(hbView, 'Keep and turn on', { switchOn: started({ reverted: ['file:scripts/late.sh'], kept: ['cfg:hooks_auto_accept'], held: 'h' }) })
out.review.keepNothingLate = await clickOnCard(hbView, 'Keep and turn on', { switchOn: started({ reverted: ['env:.op.env'], kept: ['cfg:hooks_auto_accept'], held: 'h' }) })
out.review.cancel = await clickOnCard(hbView, 'Revert and turn on', { confirm: false })
out.review.refused = await clickOnCard(hbView, 'Keep and turn on', { switchOn: needsAnswer })
// The switch itself, clicked before the page had the list: the host route refuses, nothing started.
reset({ prepare: true, beforeApply: true })
onBodies.length = 0
P.useRest(fakeRest({ statuses: [off], onSwitchOn: needsAnswer }))
host.setProfileBackend = async input => {
  await input.prepare()
  return { applied: true }
}
await P.turnOn('work', queryClient)
out.review.plainRefused = { log: [...log], bodies: [...onBodies] }
out.review.copy = { captionOff: P.T.handbackCaptionOff, first: P.T.handbackFirst }

// 14. A model endpoint whose key is withheld (status.endpoint_changed, the bar's rows): its row in the Network list
//     says "Key withheld" instead of "Allowed"; the other rows keep their state, and so does a blocked one.
const endpointRows = (endpoints, endpoint_changed) => {
  const config = { network: { egress: 'deny', allow: [] }, endpoints, capabilities: {} }
  const tree = P.NetworkSection({ config, status: { ...on, endpoint_changed }, send: () => {}, sendQuietly: () => {}, pending: false, ask: () => {} })
  return deep(deep(tree, 'List')[0], 'Row').filter(row => row.props.sub).map(row => ({ title: row.props.title, sub: row.props.sub, ...badgeOf(row.props.access) }))
}
const modelRow = { label: 'Model', provider: 'custom', url: 'http://127.0.0.1:47970/v1', reach: 'allowed', via: 'loopback' }
const fallbackRow = { label: 'Fallback model', provider: 'custom', url: 'http://127.0.0.1:47986/v1', reach: 'allowed', via: 'loopback' }
const httpsRow = { label: 'Model', provider: 'custom', url: 'https://models.example.com/v1', reach: 'allowed', via: 'rule' }
const withheldFallback = { label: 'Fallback model', host: '127.0.0.1', port: 47986, env: 'LAB_OTHER_KEY' }
out.withheldRow = {
  one: endpointRows([modelRow, fallbackRow], [withheldFallback]),
  none: endpointRows([modelRow, fallbackRow], []),
  olderLauncher: endpointRows([modelRow, fallbackRow], undefined),
  https: endpointRows([httpsRow], [{ label: 'Model', host: 'Models.Example.com', port: 443, env: 'SPARE_API_KEY' }]),
  otherPort: endpointRows([fallbackRow], [{ ...withheldFallback, port: 47985 }]),
  otherLabel: endpointRows([fallbackRow], [{ ...withheldFallback, label: 'Model' }]),
  otherHost: endpointRows([fallbackRow], [{ ...withheldFallback, host: '10.0.0.5' }]),
  blocked: endpointRows([{ ...fallbackRow, reach: 'blocked', via: null }], [withheldFallback]),
  copy: { state: P.T.keyWithheld, tip: P.T.keyWithheldTip }
}

// 15. The card and the preview follow the status the page already polls: the launcher's status carries a stamp
//     that changes when the watched files do (status.handback.stamp), and the page reads the list again when it
//     differs and each time it opens. No timer for the list itself. What the user kept is named by one line.
const listKey = ['openshell', 'work', 'handback']
const followed = (stamp, wanted) => {
  log.length = 0
  const did = P.followReview(queryClient, 'work', stamp, wanted)
  return { did, read: log.filter(e => e.invalidate).map(e => e.invalidate) }
}
const pageOf = (status, list) => {
  reset({ prepare: true, beforeApply: true })
  host.state = { profile: 'work' }
  const effects = []
  const queries = []
  const data = { status, config: { network: { egress: 'deny', allow: [] }, endpoints: [], capabilities: {}, folders: [] }, handback: list }
  globalThis.__useEffect = (fn, deps) => effects.push({ fn, deps })
  globalThis.__useQuery = q => {
    queries.push({ part: q.queryKey[2], enabled: q.enabled, refetchInterval: q.refetchInterval })
    return { data: data[q.queryKey[2]], error: null }
  }
  globalThis.__useMutation = () => ({ isPending: false, mutateAsync: async () => ({}) })
  let tree
  try {
    tree = P.SandboxPage()
  } finally {
    delete globalThis.__useEffect
    delete globalThis.__useQuery
    delete globalThis.__useMutation
  }
  const listQuery = queries.find(q => q.part === 'handback')
  const follow = effects.find(e => Array.isArray(e.deps) && e.deps.length === 3)  // [profile, stamp, wanted]
  log.length = 0
  if (follow) follow.fn()
  const kept = deep(tree, 'KeptLine')[0]
  return {
    listQuery: listQuery && { enabled: listQuery.enabled, refetchInterval: listQuery.refetchInterval },
    deps: follow ? follow.deps : null,
    read: log.filter(e => e.invalidate).map(e => e.invalidate),
    timers: queries.filter(q => q.part === 'handback' && q.refetchInterval !== false).length,
    card: deep(tree, 'HandbackCard').length,
    keptLine: kept ? { count: kept.props.status?.handback?.kept, items: kept.props.items } : null
  }
}
const keptItems = [
  { id: 'cfg:secrets.command', kind: 'config_added', label: 'Secret source', name: 'command', detail: 'new, runs print-keys', kept_at: '2030-01-01T00:00:00Z' },
  { id: 'cron:bbbbbbbbbbbb', kind: 'cron_new', label: 'Cron job', name: 'injected-job', detail: 'new, runs scripts/cron-injected.sh', kept_at: '2030-01-01T00:00:00Z' }
]
const keptLineOf = (count, items, open) => {
  if (open) globalThis.__useState = v => (v === false ? true : v)
  let line
  try {
    line = P.KeptLine({ status: { ...on, handback: { open: true, kept: count } }, items })
  } finally {
    delete globalThis.__useState
  }
  if (!line) return null
  return {
    texts: deepTexts(line),
    buttons: deep(line, 'Button').map(b => deepTexts(b).join('')),
    rows: deep(line, 'Row').map(r => ({ title: r.props.title, note: r.props.note, label: deepTexts(r.props.meta).join('') }))
  }
}
const stamped = (status, stamp, more = {}) => ({ ...withSwitch(status), handback: { open: true, stamp, kept: 0, ...more } })
out.follow = {
  changed: followed('s2', true),
  first: followed('s1', true),
  olderLauncher: followed(undefined, true),
  notWanted: followed('s1', false),
  pageOn: pageOf(stamped(on, 's1'), hbView),
  pageOnLater: pageOf(stamped(on, 's2'), hbView),
  pageOff: pageOf({ ...withSwitch(off), handback: { open: false, stamp: 's1', kept: 0, held: 0 } }, undefined),
  pageOffOpen: pageOf({ ...withSwitch(off), handback: { open: true, stamp: 's1', kept: 0, held: 0 } }, hbView),
  pageOffKept: pageOf({ ...withSwitch(off), handback: { open: false, stamp: 's3', kept: 2, held: 0 } }, { open: false, rows: [], unanswered: 0, kept: keptItems }),
  pageOlderLauncher: pageOf({ ...withSwitch(on), handback: { open: true } }, hbView),
  wanted: {
    on: P.reviewWanted(on),
    off: P.reviewWanted(off),
    offOpen: P.reviewWanted({ ...off, handback: { open: true } }),
    offKept: P.reviewWanted({ ...off, handback: { open: false, kept: 1 } }),
    none: P.reviewWanted(undefined)
  }
}
out.kept = {
  none: keptLineOf(0, []),
  one: keptLineOf(1, keptItems.slice(0, 1)),
  two: keptLineOf(2, keptItems),
  twoOpen: keptLineOf(2, keptItems, true),
  beforeTheList: keptLineOf(2, undefined, true),
  copy: { one: P.T.keptCount(1), three: P.T.keptCount(3) }
}

// -- a launcher that stopped answering: a switch-off made elsewhere, a crash, the words of a failed call --------
const refusedConn = new Error("Error invoking remote method 'hermes:api': Error: connect ECONNREFUSED 127.0.0.1:47972")
const onGoing = { ...withSwitch(on), switching_off: true, state: 'stopped' }  // the launcher's last words
const hostOff = withSwitch(off)
const hostStillMarked = { ...off, switch: { available: true, reason: null, marked: true, on: false } }
const tick = () => new Promise(resolve => setTimeout(resolve, 25))
const lostSetup = ({ confirm = true, statuses = [hostOff], features = { prepare: true, beforeApply: true } } = {}) => {
  reset(features)
  host.state = { profile: 'work' }
  P.useRest(fakeRest({ statuses }))
  host.setProfileBackend = async () => ({ applied: false })
  host.clearProfileBackend = async input => {
    log.push({ clear: Object.keys(input).sort(), plugin: input.plugin, profile: input.profile, switching: P.switchState() })
    return { applied: confirm }
  }
}
const forget = () => P.followLost(queryClient, 'work', null)
const followOf = async (query, setup = {}) => {
  forget()
  lostSetup(setup)
  const lost = P.lostView(query)
  const asked = P.followLost(queryClient, 'work', lost)
  const again = P.followLost(queryClient, 'work', lost)  // the next poll, and the chip beside the page
  await tick()
  const later = P.followLost(queryClient, 'work', lost)  // a poll after the user answered the dialog
  await tick()
  return { lost, asked, again, later, log: [...log], offered: P.offered() }
}
const barOfLost = (lost, profile = 'work') => {
  const tree = P.LostBar({ lost, profile })
  return tree && { role: tree.props.role, texts: deepTexts(tree), buttons: deep(tree, 'Button').map(b => ({ text: deepTexts(b).join(''), disabled: Boolean(b.props.disabled) })), tree }
}
const lostSwitchOf = (status, lost, more = {}) => {
  const tree = P.SandboxSwitch({ ...more, status, lost })
  const [sw] = find(tree, 'Switch')
  const [tip] = find(tree, 'Tip')
  return { checked: sw.props.checked, disabled: sw.props.disabled, tip: tip ? tip.props.label : null, label: texts(tree).join('') }
}
const headerLabel = (status, lost) => deepTexts(P.Header({ status, lost })).filter(x => typeof x === 'string')
const elsewhere = await followOf({ data: onGoing, error: refusedConn })
const declined = await followOf({ data: onGoing, error: refusedConn }, { confirm: false })
const crash = await followOf({ data: withSwitch(on), error: refusedConn })
// The notice's button after a crash: the route is given back, and this computer's backend says what is left.
forget()
lostSetup({ statuses: [hostStillMarked] })
const crashBar = barOfLost({ off: false })
deep(crashBar.tree, 'Button')[0].props.onClick()
await tick()
const crashClick = [...log]
// The same button after the user said no to the automatic question.
forget()
lostSetup({ confirm: false })
await P.switchBack('work', queryClient)
const declinedClick = [...log]
// This window's own switch is in flight: the poll failing is its doing, nothing is asked.
forget()
lostSetup()
P.setSwitching({ profile: 'work', to: 'off' })
const mine = P.followLost(queryClient, 'work', { off: true })
P.setSwitching(null)
const mineLog = [...log]
// A desktop that cannot switch at all is never asked.
forget()
lostSetup()
delete host.clearProfileBackend
const noSdk = { asked: P.followLost(queryClient, 'work', { off: true }), bar: barOfLost({ off: true }) && barOfLost({ off: true }).buttons }
// A click on the switch itself while the launcher is gone: the toast is the page's sentence, never the transport's.
reset({ prepare: true, beforeApply: true })
host.setProfileBackend = async () => ({ applied: false })
host.clearProfileBackend = async () => ({ applied: false })
P.useRest(async path => {
  log.push({ rest: path })
  throw refusedConn
})
await P.turnOff('work', queryClient)
const deadClick = [...log]
// The whole page and the status-bar chip with the launcher gone.
const rendered = (component, query) => {
  forget()
  lostSetup()
  const effects = []
  const data = { status: query, config: { data: { network: { egress: 'deny', allow: [] }, endpoints: [], capabilities: {}, folders: [] }, error: null }, handback: { data: hbView, error: null } }
  globalThis.__useEffect = (fn, deps) => effects.push({ fn, deps })
  globalThis.__useQuery = q => data[q.queryKey[2]] || { data: undefined, error: null }
  globalThis.__useMutation = () => ({ isPending: false, mutateAsync: async () => ({}) })
  let tree
  try {
    tree = component()
  } finally {
    delete globalThis.__useEffect
    delete globalThis.__useQuery
    delete globalThis.__useMutation
  }
  log.length = 0
  for (const effect of effects) effect.fn()
  return { tree, effects: effects.length }
}
const pageLost = rendered(P.SandboxPage, { data: { ...onGoing, handback: { open: true, stamp: 's1', kept: 0 } }, error: refusedConn })
await tick()
const pageLostLog = [...log]
const pageCrash = rendered(P.SandboxPage, { data: { ...withSwitch(on), handback: { open: true, stamp: 's1', kept: 0 } }, error: refusedConn })
await tick()
const pageCrashLog = [...log]
const chipLost = rendered(P.SandboxChip, { data: onGoing, error: refusedConn })
await tick()
const chipLostLog = [...log]
const chipCrash = rendered(P.SandboxChip, { data: withSwitch(on), error: refusedConn })
await tick()
const chipCrashLog = [...log]
const chipOn = rendered(P.SandboxChip, { data: withSwitch(on), error: null })
forget()
const tipOf = node => (deep(node, 'Tip')[0] || { props: {} }).props.label || null
const pageView = (r, logged) => ({
  lostBar: deep(r.tree, 'LostBar').map(b => b.props.lost),
  cardView: deep(r.tree, 'HandbackCard').map(c => c.props.view === undefined),
  headerLost: deep(r.tree, 'Header').map(x => x.props.lost),
  clears: logged.filter(e => e.clear).length
})
out.lost = {
  elsewhere,
  declined,
  crash,
  crashBar: crashBar && { role: crashBar.role, texts: crashBar.texts, buttons: crashBar.buttons },
  crashClick,
  declinedClick,
  mine: { asked: mine, log: mineLog },
  noSdk,
  deadClick,
  views: {
    back: P.lostView({ data: withSwitch(on), error: null }),
    restarting: P.lostView({ data: withSwitch(on), error: new Error('503: {"detail": "The sandbox is restarting."}') }),
    neverOn: P.lostView({ data: hostOff, error: refusedConn }),
    noData: P.lostView({ data: undefined, error: refusedConn }),
    fetchFailed: P.lostView({ data: onGoing, error: new TypeError('Failed to fetch') })
  },
  bars: {
    elsewhere: (b => ({ texts: b.texts, buttons: b.buttons }))(barOfLost({ off: true })),
    crashDefault: barOfLost({ off: false }, 'default').texts,
    none: barOfLost(null)
  },
  switches: {
    elsewhere: lostSwitchOf(onGoing, { off: true }),
    crash: lostSwitchOf(withSwitch(on), { off: false }),
    stillMarked: lostSwitchOf(hostStillMarked, null),
    plainOff: lostSwitchOf(hostOff, null)
  },
  header: { elsewhere: headerLabel(onGoing, { off: true }), crash: headerLabel(withSwitch(on), { off: false }) },
  stillOn: {
    marked: P.stillMarked(hostStillMarked, null),
    whileSwitching: P.stillMarked(hostStillMarked, { profile: 'work', to: 'on' }),
    sandboxed: P.stillMarked({ ...withSwitch(on), switch: { available: true, marked: true } }, null),
    unmarked: P.stillMarked(hostOff, null),
    bar: deepTexts(P.StillOnBar({ status: hostStillMarked })),
    noBar: P.StillOnBar({ status: hostOff })
  },
  page: { elsewhere: pageView(pageLost, pageLostLog), crash: pageView(pageCrash, pageCrashLog) },
  chip: {
    elsewhere: { shown: Boolean(chipLost.tree), clears: chipLostLog.filter(e => e.clear).length },
    crash: { shown: Boolean(chipCrash.tree), tip: tipOf(chipCrash.tree), clears: chipCrashLog.filter(e => e.clear).length },
    on: { shown: Boolean(chipOn.tree), tip: tipOf(chipOn.tree) }
  },
  words: Object.fromEntries(
    [
      "Error invoking remote method 'hermes:api': Error: connect ECONNREFUSED 127.0.0.1:47972",
      'connect ECONNREFUSED 127.0.0.1:47972',
      'read ECONNRESET',
      'socket hang up',
      'Failed to fetch',
      'fetch failed',
      'net::ERR_CONNECTION_REFUSED',
      '',
      '409: {"detail": "1 change needs an answer."}',
      '500: boom',
      'Only loopback URLs'
    ].map(raw => [raw, P.errorText(new Error(raw))])
  ),
  copy: {
    notAnswering: P.T.notAnswering,
    lostState: P.T.lostState,
    lostHelp: P.T.lostHelp('work'),
    offElsewhere: P.T.offElsewhere,
    offElsewhereHelp: P.T.offElsewhereHelp,
    switchBack: P.T.switchBack,
    stillOn: P.T.stillOn('work'),
    stillOnDefault: P.T.stillOn('default'),
    stuckOff: P.T.stuckOff('work', 'x.')
  }
}

// The desktop itself cannot make the change: the page says so in its own words and stays as it was.
forget()
lostSetup()
host.clearProfileBackend = async () => {
  throw new Error("Error invoking remote method 'hermes:profile-backend:clear': Error: connect ECONNREFUSED 127.0.0.1:9")
}
out.lost.failedBack = { result: await P.switchBack('work', queryClient), log: [...log] }
forget()

// -- the card offers only what can happen; what Revert does with a "no copy kept" row is the launcher's word -----
const fixedRows = [hbRow('env:auth.json', 'Credential file', 'auth.json', 'replaced', { fixed: true, can_restore: false })]
const fixedView = { open: true, rows: fixedRows, unanswered: 0, incomplete: [], ...hbNothingElse }
const noCopyRows = [hbRow('file:scripts/big.py', 'Script', 'scripts/big.py', 'changed', { can_restore: false })]
const slim = card => card && { texts: card.texts, buttons: card.buttons, rows: card.rows, tips: card.tips }
const rowStyle = props => {
  const tree = P.Row(props)
  return { columns: tree.props.style.gridTemplateColumns, cells: tree.children.flat().filter(Boolean).length, noteTitle: (deep(tree, 'div').find(d => d.props.title === props.note) || { props: {} }).props.title || null }
}
reset({ prepare: true, beforeApply: true })
host.setProfileBackend = async () => ({ applied: false })
host.clearProfileBackend = async () => ({ applied: false })
out.buttons = {
  fixedOnlyOn: slim(cardOf(fixedView, withSwitch(on))),
  fixedOnlyOff: slim(cardOf(fixedView, { ...withSwitch(off), handback: { open: true } })),
  fixedOnlySwitch: hbSwitchOf(withSwitch(on), fixedView),
  mixed: slim(cardOf(hbView, withSwitch(on))),
  noCopyLeave: slim(cardOf({ open: true, rows: noCopyRows, unanswered: 1, incomplete: [], no_copy: 'leave', ...hbNothingElse }, withSwitch(on))),
  noCopyHold: slim(cardOf({ open: true, rows: noCopyRows, unanswered: 1, incomplete: [], no_copy: 'hold', ...hbNothingElse }, withSwitch(on))),
  noCopyOlderLauncher: slim(cardOf({ open: true, rows: noCopyRows, unanswered: 1, incomplete: [], ...hbNothingElse }, withSwitch(on))),
  copy: { fixedOnly: P.T.handbackFixedOnly, fixedOnlyOff: P.T.handbackFixedOnlyOff, tips: P.T.handbackNoCopyTip }
}
out.layout = {
  cardRowsPlain: deep(P.HandbackCard({ status: withSwitch(on), view: hbView }), 'Row').map(r => r.props.plain === true),
  keptRowsPlain: (() => {
    globalThis.__useState = v => (v === false ? true : v)
    try {
      return deep(P.KeptLine({ status: { ...on, handback: { open: true, kept: 2 } }, items: keptItems }), 'Row').map(r => r.props.plain === true)
    } finally {
      delete globalThis.__useState
    }
  })(),
  alsoRowsPlain: deep(P.AlsoChanged({ view: hbView, open: true, onToggle: () => {} }), 'Row').map(r => r.props.plain === true),
  plain: rowStyle({ title: 'scripts/__pycache__/a-long-module-name.cpython-314.pyc', note: 'new, runs when the script is imported', plain: true, mono: true }),
  full: rowStyle({ title: 'api.example.com', note: 'https' })
}

// -- after "Switch back" from a launcher that never said it was turning off -------------------------------------
// The desktop does not run a profile that is still switched on for a plugin's backend: once the route is given
// back, every call for the profile fails in the desktop itself, before any backend is asked. The page then has
// the launcher's last answer ("running") and nobody who reports it.
const ticketErr = new Error("Error invoking remote method 'hermes:api': Error: Gateway ticket bootstrap failed")
const noRouteErr = new Error(
  "Error invoking remote method 'hermes:api': Error: Profile \"work\" runs through the openshell plugin, but this app has no connection to it. Hermes won't start it on this computer."
)
const slowErr = new Error("Error invoking remote method 'hermes:api': Error: hermes gateway ensure produced no result (exit 7): hermes gateway ensure timed out.")
// (the launcher's last answer, with what a running sandbox reports: the header drew "Running" and these details)
const lastSeen = {
  ...withSwitch(on),
  applied: { folders: [], network: { egress: 'deny', allow: [] } },
  capabilities: { label: 'OpenShell sandbox' },
  handback: { open: true, stamp: 's1', kept: 0 }
}
const pause = ms => new Promise(resolve => setTimeout(resolve, ms))
// What the page draws for a status query, read through the props it hands its own parts.
const drawn = query => {
  const page = rendered(P.SandboxPage, query)
  const [header] = deep(page.tree, 'Header')
  const sw = lostSwitchOf(header.props.status, header.props.lost, header.props)
  const bars = deep(page.tree, 'LeftBar').map(b => (P.LeftBar ? P.LeftBar(b.props) : null)).filter(Boolean)
  const chip = rendered(P.SandboxChip, query)
  return {
    header: deepTexts(P.Header(header.props)).filter(x => typeof x === 'string'),
    switch: sw,
    bar: bars.map(b => ({ role: b.props.role, texts: deepTexts(b), buttons: deep(b, 'Button').length })),
    lostBar: deep(page.tree, 'LostBar').map(b => b.props.lost),
    stillOnBar: deep(page.tree, 'StillOnBar').map(b => Boolean(P.StillOnBar(b.props))),
    card: deep(page.tree, 'HandbackCard').map(c => c.props.view === undefined),
    chip: { shown: Boolean(chip.tree), tip: tipOf(chip.tree) }
  }
}
out.left = {}
try {
  // The notice's button, with the profile still switched on: the first look at this computer's backend is refused
  // (were it to answer later, as after "sandbox off" in a terminal, the status poll brings that).
  forget()
  lostSetup()
  let looks = 0
  P.useRest(async path => {
    log.push({ rest: path })
    if (looks++ === 0) throw ticketErr
    return hostOff
  })
  const silentBar = barOfLost({ off: false })
  deep(silentBar.tree, 'Button')[0].props.onClick()
  await tick()
  out.left.click = [...log]
  out.left.refused = drawn({ data: lastSeen, error: ticketErr, dataUpdatedAt: 1 })
  out.left.noRoute = drawn({ data: lastSeen, error: noRouteErr, dataUpdatedAt: 1 })
  // This computer's backend is only slow to come back (the sandbox was already turned off in a terminal).
  out.left.slow = drawn({ data: lastSeen, error: slowErr, dataUpdatedAt: 1 })
  out.left.pending = drawn({ data: lastSeen, error: null, dataUpdatedAt: 1 })
  // An answer that came after the switch-back is shown as it is: off, still switched on, or on again.
  const later = Date.now() + 60_000
  out.left.answeredOff = drawn({ data: hostOff, error: null, dataUpdatedAt: later })
  out.left.answeredMarked = drawn({ data: hostStillMarked, error: null, dataUpdatedAt: later })
  out.left.answeredOn = drawn({ data: lastSeen, error: null, dataUpdatedAt: later })
  await pause(1800)  // (a page without this rule keeps asking; let it get its answer before the next case)
  // The one look can be answered (a backend on this computer that serves such a profile): that answer is shown.
  forget()
  lostSetup({ statuses: [hostStillMarked] })
  await P.switchBack('work', queryClient, { off: false })
  out.left.lookAnswered = { log: [...log], view: drawn({ data: hostStillMarked, error: null, dataUpdatedAt: 1 }) }
  // A switch-off made elsewhere is not this case: the launcher said it was turning off and the profile is
  // unmarked. This computer refuses the profile for a moment while it reads that; the page waits for its status.
  forget()
  lostSetup()
  let offLooks = 0
  P.useRest(async path => {
    log.push({ rest: path })
    if (offLooks++ === 0) throw ticketErr
    return hostOff
  })
  await P.switchBack('work', queryClient, { off: true })
  out.left.afterOffElsewhere = { log: [...log], view: drawn({ data: onGoing, error: ticketErr, dataUpdatedAt: 1 }) }
  // Another profile's page is not touched by it.
  out.left.otherProfile = deepTexts(P.Header({ status: { ...withSwitch(on), profile: 'other' }, lost: null })).filter(x => typeof x === 'string')
  out.left.words = Object.fromEntries([ticketErr, noRouteErr].map(e => [e.message, P.errorText(e)]))
  out.left.copy = { leftState: P.T.leftState, leftOn: P.T.leftOn && P.T.leftOn('work'), leftOnDefault: P.T.leftOn && P.T.leftOn('default') }
} catch (error) {
  out.left.error = String(error && error.stack ? error.stack : error)
}
forget()

// -- providers: the rows before and after the switch, what keeps the switch off, the move to .env ---------------
// The backend words every row (launcher/settings_view.py); the page shows it, a state badge, and for a key written
// in config.yaml the button that moves it. Off: config.providers and config.providers_block. On: status.providers.
out.providers = {}
try {
  const PV = {
    key: { id: 'key:OPENROUTER_API_KEY', label: 'OpenRouter', kind: 'key', state: 'ready', detail: 'Works in the sandbox. The key stays on this computer and is used only at openrouter.ai.', main: true, env: 'OPENROUTER_API_KEY' },
    signIn: { id: 'sign_in:nous', label: 'Nous Portal', kind: 'sign_in', state: 'ready', detail: 'Works in the sandbox. Stays signed in on this computer.', main: false },
    needs: { id: 'sign_in:openai-codex', label: 'OpenAI Codex', kind: 'sign_in', state: 'needs_sign_in', detail: 'Not signed in. Sign in to OpenAI Codex first.', main: true },
    gone: { id: 'sign_in:copilot-acp', label: 'GitHub Copilot ACP', kind: 'sign_in', state: 'unavailable', detail: 'Not available in the sandbox: GitHub Copilot ACP signs in through its own program.', main: true },
    inline: { id: 'config:model.api_key', label: 'Key in config.yaml', kind: 'key', state: 'key_in_config', detail: 'Written in config.yaml, where the sandbox could read it. Move it to .env first.', main: false, env: 'CUSTOM_API_KEY', path: 'model.api_key' },
    inline2: { id: 'config:providers.spare.api_key', label: 'Key in config.yaml', kind: 'key', state: 'key_in_config', detail: 'Written in config.yaml, where the sandbox could read it. Move it to .env first.', main: false, env: 'SPARE_API_KEY', path: 'providers.spare.api_key' },
    noKey: { id: 'key:deepseek', label: 'DeepSeek', kind: 'key', state: 'no_key', detail: "No key found: DEEPSEEK_API_KEY is not set in this profile's .env.", main: false, env: 'DEEPSEEK_API_KEY' },
    expired: { id: 'nous:agent_key', label: 'Nous Portal', kind: 'sign_in', state: 'expired', detail: 'Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on.', main: true },
    withheld: { id: 'withheld:OPENAI_API_KEY:evil.example:443', label: 'OPENAI_API_KEY', kind: 'key', state: 'withheld', detail: 'Model endpoint changed in the sandbox. Key withheld.', main: false, env: 'OPENAI_API_KEY' },
    // (a state this page does not know, on a row that carries what only a key written in config.yaml should)
    odd: { id: 'x:1', label: 'Some provider', kind: 'sign_in', state: 'renewing', detail: 'A state this page does not know.', main: false, path: 'some.place', env: 'SOME_NAME' }
  }
  const blockInline = { code: 'key_in_config', reason: 'A key is written in config.yaml, where the sandbox could read it. Move it to .env first.', rows: [PV.inline.id] }
  const blockInline2 = { code: 'key_in_config', reason: 'Keys are written in config.yaml, where the sandbox could read them. Move them to .env first.', rows: [PV.inline.id, PV.inline2.id] }
  const blockGone = { code: 'model_unavailable', reason: "This profile's model uses GitHub Copilot ACP, which isn't available in the sandbox.", rows: [PV.gone.id] }
  const blockNeeds = { code: 'model_needs_sign_in', reason: "This profile's model uses OpenAI Codex, which needs a sign-in first.", rows: [PV.needs.id] }
  const cfg = (rows, block = null) => ({ network: { egress: 'deny', allow: [] }, endpoints: [], capabilities: {}, folders: [], providers: rows, providers_block: block })
  const offS = withSwitch(off)
  const onS = rows => ({ ...withSwitch(on), ...(rows === undefined ? {} : { providers: rows }) })
  const slimView = v => ({ known: v.known, on: v.on, rows: v.rows.map(r => r.id), block: v.block ? v.block.code : null })

  // 1. Where the rows come from.
  out.providers.views = {
    off: slimView(P.providersView(offS, cfg([PV.key, PV.signIn]))),
    offBlocked: slimView(P.providersView(offS, cfg([PV.inline, PV.key], blockInline))),
    offNoRows: slimView(P.providersView(offS, cfg([]))),
    offOlderBackend: slimView(P.providersView(offS, { network: { egress: 'deny', allow: [] } })),
    offNoConfigYet: slimView(P.providersView(offS, undefined)),
    on: slimView(P.providersView(onS([PV.key, PV.expired]), cfg([PV.inline], blockInline))),  // the config's rows are not the launcher's
    onOlderLauncher: slimView(P.providersView(onS(undefined), cfg([PV.key]))),
    junkRows: slimView(P.providersView(offS, cfg([null, 'x', { label: 'no id' }, PV.key])))
  }

  // 2. The rows as drawn: name, code, badges, sentence, button.
  const asked = []
  const sent = []
  let sendAnswer = async () => ({ moved: [{ path: 'model.api_key', env: 'CUSTOM_API_KEY' }], left: [] })
  const send = async (...args) => (sent.push(args), sendAnswer(...args))
  const ask = dialog => asked.push(dialog)
  const sectionOf = (view, pending = false) => {
    const tree = P.ProvidersSection({ view, ask, send, pending })
    if (!tree) return null
    return {
      tree,
      title: tree.props.title,
      texts: deepTexts(tree),
      rows: deep(tree, 'Row').map(row => ({
        title: row.props.title,
        plain: row.props.plain === true,
        code: flat(row.props.badge).filter(b => b && b.type === 'span').map(b => ({ text: deepTexts(b).join(''), mono: b.props.className === 'font-mono' })),
        badges: deep(flat(row.props.badge), 'Badge').map(b => ({ text: deepTexts(b).join(''), variant: b.props.variant })),
        tips: deep(flat(row.props.badge), 'Tip').map(t => t.props.label),
        note: deepTexts(row.props.note).join(''),
        buttons: deep(flat(row.props.meta), 'Button').map(b => ({ text: deepTexts(b).join(''), disabled: Boolean(b.props.disabled), variant: b.props.variant || null }))
      }))
    }
  }
  const slimSection = sec => sec && { title: sec.title, rows: sec.rows }
  const every = [PV.inline, PV.key, PV.signIn, PV.needs, PV.gone, PV.noKey, PV.expired, PV.withheld, PV.odd]
  out.providers.section = {
    off: slimSection(sectionOf(P.providersView(offS, cfg(every, blockInline)))),
    on: slimSection(sectionOf(P.providersView(onS(every), cfg([])))),
    pending: sectionOf(P.providersView(offS, cfg([PV.inline], blockInline)), true).rows[0].buttons,
    empty: (sec => ({ title: sec.title, texts: sec.texts, rows: sec.rows.length }))(sectionOf(P.providersView(offS, cfg([])))),
    unknownOff: sectionOf(P.providersView(offS, { network: {} })),
    unknownOn: sectionOf(P.providersView(onS(undefined), cfg([PV.key]))),
    noView: P.ProvidersSection({ view: undefined, ask, send, pending: false })
  }

  // 3. The bar above the tabs.
  const pbarOf = view => {
    const tree = P.ProvidersBar({ view, ask, send })
    return tree && { tree, role: tree.props.role, texts: deepTexts(tree), buttons: deep(tree, 'Button').map(b => ({ text: deepTexts(b).join(''), disabled: Boolean(b.props.disabled) })) }
  }
  const slimBar = bar => bar && { role: bar.role, texts: bar.texts, buttons: bar.buttons }
  out.providers.bar = {
    inline: slimBar(pbarOf(P.providersView(offS, cfg([PV.inline, PV.key], blockInline)))),
    inlineTwo: slimBar(pbarOf(P.providersView(offS, cfg([PV.inline, PV.inline2, PV.key], blockInline2)))),
    modelGone: slimBar(pbarOf(P.providersView(offS, cfg([PV.gone], blockGone)))),
    modelNeeds: slimBar(pbarOf(P.providersView(offS, cfg([PV.needs, PV.signIn], blockNeeds)))),
    offFine: pbarOf(P.providersView(offS, cfg([PV.key, PV.signIn, PV.noKey]))),
    onExpired: slimBar(pbarOf(P.providersView(onS([PV.expired, PV.key]), cfg([])))),
    onLapsed: slimBar(pbarOf(P.providersView(onS([{ ...PV.expired, detail: "The Nous Portal sign-in wasn't renewed in time. The model answers again once it is." }, { ...PV.expired, id: 'codex:token', label: 'OpenAI Codex', detail: 'Sign-in expired. Turn the sandbox off, sign in to OpenAI Codex, then turn it on.' }]), cfg([])))),
    onFine: pbarOf(P.providersView(onS([PV.key, PV.signIn, PV.withheld]), cfg([]))),
    onIgnoresTheHostBlock: pbarOf(P.providersView(onS([PV.key]), cfg([PV.inline], blockInline))),
    launcherGone: pbarOf(undefined)
  }

  // 4. The switch and the card's "turn on" buttons: disabled with the reason; nothing else outranks a host problem.
  reset({ prepare: true, beforeApply: true })
  host.setProfileBackend = async () => ({ applied: false })
  host.clearProfileBackend = async () => ({ applied: false })
  const pSwitchOf = (status, providers, handback) => {
    const tree = P.SandboxSwitch({ status, providers, handback })
    const [sw] = find(tree, 'Switch')
    const [tip] = find(tree, 'Tip')
    return { checked: sw.props.checked, disabled: sw.props.disabled, tip: tip ? tip.props.label : null, label: texts(tree).join('') }
  }
  const offOpenS = { ...offS, handback: { open: true, held: 0 } }
  const pCardOf = providers => {
    const tree = P.HandbackCard({ status: offOpenS, view: hbView, providers })
    return { buttons: deep(tree, 'Button').map(b => ({ text: deepTexts(b).join(''), disabled: Boolean(b.props.disabled) })), tips: [...new Set(deep(tree, 'Tip').map(t => t.props.label).filter(t => /config\.yaml|model uses/.test(t)))] }
  }
  out.providers.switch = {
    inline: pSwitchOf(offS, P.providersView(offS, cfg([PV.inline], blockInline))),
    modelGone: pSwitchOf(offS, P.providersView(offS, cfg([PV.gone], blockGone))),
    modelNeeds: pSwitchOf(offS, P.providersView(offS, cfg([PV.needs], blockNeeds))),
    fine: pSwitchOf(offS, P.providersView(offS, cfg([PV.key, PV.signIn]))),
    noProviders: pSwitchOf(offS, P.providersView(offS, cfg([]))),
    olderBackend: pSwitchOf(offS, P.providersView(offS, { network: {} })),
    hostProblemFirst: pSwitchOf(offWith(needsUpdate), P.providersView(offWith(needsUpdate), cfg([PV.inline], blockInline))),
    beforeTheLastSessionsAnswer: pSwitchOf(offS, P.providersView(offS, cfg([PV.inline], blockInline)), { unanswered: 2 }),
    onIsNeverHeld: pSwitchOf(withSwitch(on), P.providersView(onS([PV.expired]), cfg([PV.inline], blockInline))),
    headerHandsItOn: deep(P.Header({ status: offS, providers: P.providersView(offS, cfg([PV.inline], blockInline)) }), 'SandboxSwitch').map(x => Boolean(x.props.providers && x.props.providers.block)),
    cardBlocked: pCardOf(P.providersView(offS, cfg([PV.inline], blockInline))),
    cardFine: pCardOf(P.providersView(offS, cfg([PV.key])))
  }

  // 5. A turn-on that is held starts nothing: no call, no question from the desktop, the reason as the toast.
  reset({ prepare: true, beforeApply: true, purpose: true })
  P.useRest(fakeRest({ statuses: [off] }))
  host.setProfileBackend = async input => {
    log.push({ set: Object.keys(input).sort() })
    await input.prepare()
    return { applied: true }
  }
  await P.turnOn('work', queryClient, { block: blockInline })
  out.providers.heldTurnOn = [...log]
  // A card's "Keep and turn on" with the block: the same.
  reset({ prepare: true, beforeApply: true, purpose: true })
  P.useRest(fakeRest({ statuses: [off] }))
  host.setProfileBackend = async input => {
    log.push({ set: Object.keys(input).sort() })
    return { applied: false }
  }
  const heldCard = P.HandbackCard({ status: offOpenS, view: hbView, providers: P.providersView(offS, cfg([PV.gone], blockGone)) })
  deep(heldCard, 'Button').find(b => deepTexts(b).join('') === P.T.handbackKeepOn).props.onClick()
  await tick()
  out.providers.heldCardClick = [...log]
  // The switch itself, were a click to reach it while it is held: the same.
  reset({ prepare: true, beforeApply: true, purpose: true })
  P.useRest(fakeRest({ statuses: [off] }))
  host.setProfileBackend = async input => {
    log.push({ set: Object.keys(input).sort() })
    return { applied: false }
  }
  find(P.SandboxSwitch({ status: offS, providers: P.providersView(offS, cfg([PV.needs], blockNeeds)) }), 'Switch')[0].props.onCheckedChange(true)
  await tick()
  out.providers.heldSwitchClick = [...log]
  // Without a block the switch turns on as before (a null block is no block).
  reset({ prepare: true, beforeApply: true, purpose: true })
  P.useRest(fakeRest({ statuses: [on] }))
  host.setProfileBackend = async input => {
    log.push({ set: Object.keys(input).sort() })
    await input.prepare()
    return { applied: true }
  }
  await P.turnOn('work', queryClient, { block: null })
  out.providers.freeTurnOn = log.filter(e => e.set || e.rest === '/switch/on' || e.notify).map(e => (e.set ? 'asked' : e.rest ? 'started' : e.notify))

  // 6. The host route refuses the switch-on for the same reasons (the page's rows may be seconds old): its sentence
  //    is the toast, never the transport's text, and nothing is left started.
  const refusal = async (detail, extra = {}, features = { prepare: true, beforeApply: true, purpose: true }) => {
    reset(features)
    P.useRest(fakeRest({ statuses: [off], onSwitchOn: () => { throw new Error(`409: ${JSON.stringify({ detail, ...extra })}`) } }))
    host.setProfileBackend = async input => {
      if (input.prepare) await input.prepare()
      return { applied: true }
    }
    await P.turnOn('work', queryClient)
    return { notes: log.filter(e => e.notify).map(e => e.notify), fetches: log.filter(e => e.fetch).length, switching: P.switchState(), reread: log.some(e => e.invalidate) }
  }
  out.providers.refused = {
    inline: await refusal(blockInline.reason),
    withCode: await refusal(blockGone.reason, { code: 'providers_block' }),
    olderDesktop: await refusal(blockNeeds.reason, {}, undefined),
    remote: await (async () => {
      reset({ prepare: true, beforeApply: true, purpose: true })
      P.useRest(fakeRest({ statuses: [off], onSwitchOn: () => { throw new Error(`Error invoking remote method 'hermes:api': Error: 409: ${JSON.stringify({ detail: blockInline.reason })}`) } }))
      host.setProfileBackend = async input => (await input.prepare(), { applied: true })
      await P.turnOn('work', queryClient)
      return log.filter(e => e.notify).map(e => e.notify)
    })()
  }

  // 7. The move: the button asks first; the confirm sends the paths; the answer is the toast.
  reset({ prepare: true, beforeApply: true })
  asked.length = 0
  sent.length = 0
  const barInline = pbarOf(P.providersView(offS, cfg([PV.inline, PV.inline2, PV.key], blockInline2)))
  deep(barInline.tree, 'Button')[0].props.onClick()
  const afterClick = { asked: asked.length, sent: sent.length, notes: log.filter(e => e.notify).length }
  const dialogOf = d => ({ kind: d.kind, title: d.title, body: d.body, target: d.target, confirmLabel: d.confirmLabel, destructive: Boolean(d.destructive) })
  const barDialog = asked[0]
  sendAnswer = async () => ({ moved: [{ path: 'model.api_key', env: 'CUSTOM_API_KEY' }, { path: 'providers.spare.api_key', env: 'SPARE_API_KEY' }], left: [] })
  await barDialog.run()
  const twoMoved = { sent: [...sent], notes: log.filter(e => e.notify) }
  // One row's own button: that key only.
  reset({ prepare: true, beforeApply: true })
  asked.length = 0
  sent.length = 0
  const rowSection = sectionOf(P.providersView(offS, cfg([PV.inline, PV.inline2], blockInline2)))
  deep(flat(deep(rowSection.tree, 'Row')[1].props.meta), 'Button')[0].props.onClick()
  const rowDialog = asked[0]
  sendAnswer = async () => ({ moved: [{ path: 'providers.spare.api_key', env: 'SPARE_API_KEY' }], left: [] })
  await rowDialog.run()
  const oneMoved = { sent: [...sent], notes: log.filter(e => e.notify) }
  const moveWith = async answer => {
    reset({ prepare: true, beforeApply: true })
    sent.length = 0
    sendAnswer = answer
    await P.moveKeys(send, [PV.inline, PV.inline2])
    return log.filter(e => 'notify' in e)
  }
  out.providers.move = {
    afterClick,
    barDialog: dialogOf(barDialog),
    twoMoved,
    rowDialog: dialogOf(rowDialog),
    oneMoved,
    partly: await moveWith(async () => ({ moved: [{ path: 'model.api_key', env: 'CUSTOM_API_KEY' }], left: ['providers.spare.api_key'] })),
    refused: await moveWith(async () => { throw new Error("Couldn't move model.api_key to .env: Permission denied") }),
    whileOn: await moveWith(async () => { throw new Error('Turn the sandbox off for this profile first.') }),
    noRoute: await moveWith(async () => { throw new Error('Not Found') }),
    noMethod: await moveWith(async () => { throw new Error('Method Not Allowed') }),
    oddAnswer: await moveWith(async () => ({}))
  }

  // 8. Live: each poll's answer is what is drawn. The key is moved; a sign-in expires and is renewed.
  reset({ prepare: true, beforeApply: true })
  host.setProfileBackend = async () => ({ applied: false })
  host.clearProfileBackend = async () => ({ applied: false })
  const offLook = config => {
    const view = P.providersView(offS, config)
    return { switch: pSwitchOf(offS, view), bar: slimBar(pbarOf(view)), states: sectionOf(view).rows.map(r => [r.title, r.badges.map(b => b.text).join('+'), r.buttons.length]) }
  }
  const onLook = rows => {
    const view = P.providersView(onS(rows), cfg([]))
    return { bar: slimBar(pbarOf(view)), states: sectionOf(view).rows.map(r => [r.title, r.badges.map(b => b.text).join('+'), r.note]) }
  }
  const movedKey = { id: 'key:CUSTOM_API_KEY', label: 'Model', kind: 'key', state: 'ready', detail: 'Works in the sandbox. The key stays on this computer and is used only at llm.example.com.', main: true, env: 'CUSTOM_API_KEY' }
  out.providers.live = {
    beforeMove: offLook(cfg([PV.inline, PV.signIn], blockInline)),
    afterMove: offLook(cfg([movedKey, PV.signIn])),
    signedIn: offLook(cfg([{ ...PV.needs, state: 'ready', detail: 'Works in the sandbox. Stays signed in on this computer.' }])),
    needsSignIn: offLook(cfg([PV.needs], blockNeeds)),
    ready: onLook([{ ...PV.expired, state: 'ready', detail: 'Works in the sandbox. Stays signed in on this computer.' }]),
    expired: onLook([PV.expired]),
    renewed: onLook([{ ...PV.expired, state: 'ready', detail: 'Works in the sandbox. Stays signed in on this computer.' }])
  }

  // 9. The whole page: the bar above the tabs, the rows above the keys, the switch told why; nothing of it while
  //    the launcher is gone. The withheld-key bar is drawn from the same status as before.
  const pageWith = (statusQuery, config, keys) => {
    reset({ prepare: true, beforeApply: true })
    host.state = { profile: 'work' }
    host.setProfileBackend = async () => ({ applied: false })
    host.clearProfileBackend = async () => ({ applied: false })
    const data = { status: statusQuery, config: { data: config, error: null }, keys: { data: keys, error: null }, grants: { data: { grants: [] }, error: null } }
    globalThis.__useEffect = () => {}
    globalThis.__useQuery = q => data[q.queryKey[2]] || { data: undefined, error: null }
    globalThis.__useMutation = () => ({ isPending: false, mutateAsync: async () => ({}) })
    let tree
    try {
      tree = P.SandboxPage()
    } finally {
      delete globalThis.__useEffect
      delete globalThis.__useQuery
      delete globalThis.__useMutation
    }
    const column = flat(tree.children)[0]
    const order = flat(column.children).filter(n => n && typeof n === 'object').flatMap(n => (n.type === 'div' ? flat(n.children).filter(Boolean).map(c => c.type) : [n.type]))
    const view = x => (x === undefined ? 'none' : slimView(x))
    return {
      order,
      bar: deep(tree, 'ProvidersBar').map(b => view(b.props.view)),
      section: deep(tree, 'ProvidersSection').map(b => view(b.props.view)),
      header: deep(tree, 'Header').map(b => view(b.props.providers)),
      card: deep(tree, 'HandbackCard').map(b => view(b.props.providers)),
      endpointBar: deep(tree, 'EndpointBar').length
    }
  }
  const keysData = { keys: [{ name: 'OPENROUTER_API_KEY', is_set: true }], credentials: 'host' }
  out.providers.page = {
    off: pageWith({ data: { ...offS, handback: { open: false, stamp: 's', kept: 0, held: 0 } }, error: null }, cfg([PV.inline, PV.key], blockInline), keysData),
    on: pageWith({ data: { ...onS([PV.key, PV.expired]), handback: { open: true, stamp: 's', kept: 0 } }, error: null }, cfg([]), keysData),
    launcherGone: pageWith({ data: { ...onS([PV.key]), handback: { open: true, stamp: 's', kept: 0 } }, error: refusedConn }, cfg([]), keysData)
  }

  // 10. The words.
  out.providers.copy = {
    providers: P.T.providers,
    noProviders: P.T.noProviders,
    mainModel: P.T.mainModel,
    mainModelTip: P.T.mainModelTip,
    providerState: P.T.providerState,
    moveToEnv: P.T.moveToEnv,
    move: P.T.move,
    moveTitle: [P.T.moveTitle(1), P.T.moveTitle(3)],
    moveBody: [P.T.moveBody(1), P.T.moveBody(2)],
    moveUnavailable: P.T.moveUnavailable,
    credentials: P.T.credentials
  }
} catch (error) {
  out.providers.error = String(error && error.stack ? error.stack : error)
}

// What the page says by itself: a sign-in that ended while the sandbox is on (once, from the status-bar chip), what
// a saved key means for a sandbox that is on (one line), and one notice for whatever refuses the switch.
out.says = {}
try {
  const spy = () => {
    const seen = []
    const prev = host.notify
    host.notify = n => {
      seen.push({ id: n.id ?? null, kind: n.kind, title: n.title ?? null, message: n.message, timed: typeof n.durationMs === 'number' && n.durationMs > 0 })
      return prev(n)
    }
    return seen
  }
  const EXPIRED = 'Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on.'
  const LAPSED = "The Nous Portal sign-in wasn't renewed in time. The model answers again once it is."
  const nous = (state, detail) => ({ id: 'sign_in:nous', label: 'Nous Portal', kind: 'sign_in', state, detail, main: true })
  const key = { id: 'key:OPENROUTER_API_KEY', label: 'OpenRouter', kind: 'key', state: 'ready', detail: 'Works in the sandbox.', env: 'OPENROUTER_API_KEY' }
  const onWith = rows => ({ ...on, ...(rows === undefined ? {} : { providers: rows }) })
  const fine = nous('ready', 'Works in the sandbox. Stays signed in on this computer.')

  // 1. Once per sign-in that ended, with the row's own sentence.
  reset({ prepare: true })
  let seen = spy()
  P.forgetTold()
  const steps = {}
  const step = (name, profile, status) => {
    const before = seen.length
    P.tellExpired(profile, status)
    steps[name] = seen.slice(before)
  }
  step('fine', 'work', onWith([fine, key]))
  step('expired', 'work', onWith([nous('expired', EXPIRED), key]))
  step('nextPoll', 'work', onWith([nous('expired', EXPIRED), key]))
  step('noAnswer', 'work', undefined)
  step('afterNoAnswer', 'work', onWith([nous('expired', EXPIRED), key]))
  step('olderLauncher', 'work', onWith(undefined))
  step('afterOlderLauncher', 'work', onWith([nous('expired', EXPIRED), key]))
  step('otherProfile', 'play', { ...on, profile: 'play', providers: [nous('expired', EXPIRED)] })
  step('renewed', 'work', onWith([fine, key]))
  step('renewedNextPoll', 'work', onWith([fine, key]))
  step('lapsed', 'work', onWith([nous('expired', LAPSED), key]))
  step('thenExpired', 'work', onWith([nous('expired', EXPIRED), key]))
  step('switchedOff', 'work', { ...off, providers: [] })
  step('onAgainFine', 'work', onWith([fine, key]))
  step('expiredAgain', 'work', onWith([nous('expired', EXPIRED), key]))
  step('junk', 'work', onWith([null, 'x', { state: 'expired' }, { id: 'a', state: 'expired', label: 'A' }]))
  out.says.expired = steps

  // 2. The chip is in the status bar whatever page is open: it is what tells.
  P.forgetTold()
  const chipSays = status => {
    const drawn = rendered(P.SandboxChip, { data: status, error: null })  // (resets the host and runs the effects)
    return { effects: drawn.effects, notes: log.filter(e => e.notify).map(e => e.notify) }
  }
  out.says.chip = {
    fine: chipSays({ ...withSwitch(on), providers: [fine, key] }),
    expired: chipSays({ ...withSwitch(on), providers: [nous('expired', EXPIRED), key] }),
    again: chipSays({ ...withSwitch(on), providers: [nous('expired', EXPIRED), key] })
  }
  P.forgetTold()

  // 3. A key saved while the sandbox is on: one line for what the launcher says happened; none for a profile that is off.
  const saved = async answer => {
    reset({ prepare: true })
    const notes = spy()
    const calls = []
    const result = await P.saveKey(async (...args) => (calls.push(args), answer()), 'OPENROUTER_API_KEY', 'made-up-value')
      .then(() => 'saved', error => `failed: ${error.message}`)
    return { calls, notes, result }
  }
  out.says.key = {
    inUse: await saved(async () => ({ ok: true, sandbox_restart_required: false, sandbox: 'in_use' })),
    afterRestart: await saved(async () => ({ ok: true, sandbox_restart_required: true, sandbox: 'after_restart' })),
    notUsed: await saved(async () => ({ ok: true, sandbox_restart_required: false, sandbox: 'not_used' })),
    off: await saved(async () => ({ ok: true })),
    olderLauncher: await saved(async () => ({ ok: true, sandbox_restart_required: true })),
    unknownWord: await saved(async () => ({ ok: true, sandbox: 'something_else' })),
    refused: await saved(async () => { throw new Error('Invalid key name.') }),
    copy: P.T.keySaved
  }
  // The dialog's Save is that save: the line comes, then the dialog closes.
  reset({ prepare: true })
  const dialogNotes = spy()
  const dialogSteps = []
  const keyDialog = P.KeyDialog({
    dialog: { kind: 'key', name: 'OPENROUTER_API_KEY' },
    onClose: () => dialogSteps.push('closed'),
    send: async (...args) => (dialogSteps.push(args), { ok: true, sandbox_restart_required: false, sandbox: 'in_use' })
  })
  await keyDialog.props.onSubmit()
  out.says.key.dialog = { steps: dialogSteps, notes: dialogNotes.map(n => n.message) }

  // 4. Two refusals of the switch in a row: the second replaces the first (one id), it does not sit behind it.
  const refusedTwice = async () => {
    const ids = []
    for (const detail of ['A key is written in config.yaml.', "This profile's model uses GitHub Copilot ACP, which isn't available in the sandbox."]) {
      reset({ prepare: true, beforeApply: true, purpose: true })
      const notes = spy()
      P.useRest(fakeRest({ statuses: [off], onSwitchOn: () => { throw new Error(`409: ${JSON.stringify({ detail })}`) } }))
      host.setProfileBackend = async input => (await input.prepare(), { applied: true })
      await P.turnOn('work', queryClient)
      ids.push(...notes.map(n => ({ id: n.id, message: n.message })))
    }
    reset({ prepare: true, beforeApply: true, purpose: true })
    const notes = spy()
    await P.turnOn('work', queryClient, { block: { reason: 'A reason from the rows.' } })
    ids.push(...notes.map(n => ({ id: n.id, message: n.message })))
    return ids
  }
  out.says.refusals = await refusedTwice()
} catch (error) {
  out.says.error = String(error && error.stack ? error.stack : error)
}
forget()

// What a look at the page found: a file that cannot be read, a held switch that looked like a plain Off switch, an
// expired sign-in drawn like a neutral notice, a fallback model's row, a main model without a key, the wording.
out.held = {}
try {
  const R = {
    key: { id: 'key:OPENROUTER_API_KEY', label: 'OpenRouter', kind: 'key', state: 'ready', detail: 'Works in the sandbox. The key stays on this computer and is used only at openrouter.ai.', main: true, env: 'OPENROUTER_API_KEY' },
    inline: { id: 'config:model.api_key', label: 'Key in config.yaml', kind: 'key', state: 'key_in_config', detail: 'Written in config.yaml, where the sandbox could read it.', main: false, env: 'MODEL_API_KEY', path: 'model.api_key' },
    inline2: { id: 'config:providers.spare.api_key', label: 'Key in config.yaml', kind: 'key', state: 'key_in_config', detail: 'Written in config.yaml, where the sandbox could read it.', main: false, env: 'SPARE_API_KEY', path: 'providers.spare.api_key' },
    gone: { id: 'sign_in:qwen-oauth', label: 'Qwen OAuth', kind: 'sign_in', state: 'unavailable', detail: 'Not available in the sandbox: Qwen OAuth keeps its sign-in outside this profile.', main: true },
    fallback: { id: 'sign_in:qwen-oauth', label: 'Qwen OAuth', kind: 'sign_in', state: 'unavailable', detail: 'Not available in the sandbox: Qwen OAuth keeps its sign-in outside this profile.', main: false, fallback: true },
    both: { id: 'key:ANTHROPIC_API_KEY', label: 'Anthropic', kind: 'key', state: 'ready', detail: 'Works in the sandbox.', main: true, fallback: true, env: 'ANTHROPIC_API_KEY' },
    noKey: { id: 'key:openrouter', label: 'OpenRouter', kind: 'key', state: 'no_key', detail: "No key found: OPENROUTER_API_KEY is not set in this profile's .env. The model won't answer in the sandbox without it.", main: true, env: 'OPENROUTER_API_KEY' },
    expired: { id: 'sign_in:nous', label: 'Nous Portal', kind: 'sign_in', state: 'expired', detail: 'Sign-in expired. Turn the sandbox off, sign in to Nous Portal, then turn it on.', main: true },
    lapsed: { id: 'sign_in:xai-oauth', label: 'xAI', kind: 'sign_in', state: 'expired', detail: "The xAI sign-in wasn't renewed in time. The model answers again once it is.", main: false }
  }
  const CANT_READ = "Can't read this profile's config.yaml. Another program may have it open."
  const NO_KEY = "This profile's model has no key in .env (OPENROUTER_API_KEY). It won't answer in the sandbox until one is set."
  const unread = { code: 'unreadable', file: 'config.yaml', reason: CANT_READ, rows: [] }
  const oneKey = { code: 'key_in_config', reason: 'A key is written in config.yaml, where the sandbox could read it. Move it to .env first.', rows: [R.inline.id] }
  const twoKeys = { code: 'key_in_config', reason: 'Keys are written in config.yaml, where the sandbox could read them. Move them to .env first.', rows: [R.inline.id, R.inline2.id] }
  const modelGone = { code: 'model_unavailable', reason: "This profile's model uses Qwen OAuth, which isn't available in the sandbox.", rows: [R.gone.id], detail: 'Qwen OAuth keeps its sign-in outside this profile.' }
  const note = { code: 'model_no_key', reason: NO_KEY, rows: [R.noKey.id] }
  const conf = (rows, block = null, extra = {}) => ({ network: { egress: 'deny', allow: [] }, endpoints: [], capabilities: {}, folders: [], providers: rows, providers_block: block, ...extra })
  const offS = withSwitch(off)
  const onS = rows => ({ ...withSwitch(on), providers: rows })
  const viewOf = (rows, block, extra) => P.providersView(offS, conf(rows, block, extra))
  const asked = []
  const sent = []
  const send = async (...args) => (sent.push(args), { moved: [], left: [] })
  const ask = dialog => asked.push(dialog)

  // 1. The switch: held for a reason no click here can change, it is disabled (the desktop's own dimmed look and
  //    cursor), keeps its tip, and the word beside it says that it will not turn on.
  reset({ prepare: true, beforeApply: true })
  host.setProfileBackend = async () => ({ applied: false })
  host.clearProfileBackend = async () => ({ applied: false })
  const switchOf = (status, providers, handback, busy) => {
    host.state = busy ? { busyBySession: { get: () => ({ s1: true }) } } : {}
    const tree = P.SandboxSwitch({ status, providers, handback })
    const [sw] = find(tree, 'Switch')
    const [tip] = find(tree, 'Tip')
    return { checked: sw.props.checked, disabled: sw.props.disabled, tip: tip ? tip.props.label : null, label: texts(tree).join('') }
  }
  out.held.switch = {
    key: switchOf(offS, viewOf([R.inline], oneKey)),
    model: switchOf(offS, viewOf([R.gone], modelGone)),
    unread: switchOf(offS, viewOf([R.key], unread)),
    unreadNoRows: switchOf(offS, viewOf([], unread)),
    host: switchOf({ ...off, switch: { available: false, reason: 'Needs Docker.' } }, viewOf([R.key])),
    olderDesktop: (() => { reset(undefined); return switchOf(offS, viewOf([R.key])) })(),
    fine: (() => { reset({ prepare: true, beforeApply: true }); host.setProfileBackend = async () => ({ applied: false }); host.clearProfileBackend = async () => ({ applied: false }); return switchOf(offS, viewOf([R.key])) })(),
    noKey: switchOf(offS, viewOf([R.noKey], null, { providers_note: note })),
    // The card's two buttons turn it on with the answer: the switch waits, and its word stays the state's.
    review: switchOf({ ...offS, handback: { open: true, held: 0 } }, viewOf([R.key]), { open: true, rows: [], unanswered: 2 }),
    whileOn: switchOf(withSwitch(on), P.providersView(onS([R.expired]), conf([R.inline], oneKey))),
    copy: P.T.cantTurnOn
  }

  // 2. The rows: what was last read stays; where nothing was ever read, the reason stands in the list's place.
  const sectionOf = (view, pending = false) => {
    const tree = P.ProvidersSection({ view, ask, send, pending })
    return tree && {
      texts: deepTexts(tree),
      rows: deep(tree, 'Row').map(row => ({
        title: row.props.title,
        badges: deep(flat(row.props.badge), 'Badge').map(b => ({ text: deepTexts(b).join(''), variant: b.props.variant })),
        tips: deep(flat(row.props.badge), 'Tip').map(t => t.props.label),
        note: deepTexts(row.props.note).join(''),
        buttons: deep(flat(row.props.meta), 'Button').map(b => deepTexts(b).join(''))
      }))
    }
  }
  out.held.section = {
    unreadKept: sectionOf(viewOf([R.key], unread)),
    unreadNothing: sectionOf(viewOf([], unread)),
    empty: sectionOf(viewOf([])).texts,
    // One key: the bar's button is the one. Several: each row also has its own, for that key alone. Rows that
    // were last read from a config that cannot be read now offer nothing.
    inline: sectionOf(viewOf([R.inline, R.key], oneKey)),
    inlineTwo: sectionOf(viewOf([R.inline, R.inline2, R.key], twoKeys)),
    inlineUnread: sectionOf(viewOf([R.inline, R.inline2, R.key], unread)),
    fallback: sectionOf(viewOf([R.key, R.fallback, R.both])),
    fallbackOn: sectionOf(P.providersView(onS([R.key, R.fallback]), conf([]))),
    noKey: sectionOf(viewOf([R.noKey], null, { providers_note: note })),
    copy: { fallback: P.T.fallbackModel, tip: P.T.fallbackModelTip }
  }

  // 3. The bar above the tabs.
  const barOf = (view, pending = false) => {
    const tree = P.ProvidersBar({ view, ask, send, pending })
    return tree && {
      role: tree.props.role,
      texts: deepTexts(tree),
      badges: deep(tree, 'Badge').map(b => ({ text: deepTexts(b).join(''), variant: b.props.variant })),
      buttons: deep(tree, 'Button').map(b => ({ text: deepTexts(b).join(''), disabled: Boolean(b.props.disabled) }))
    }
  }
  out.held.bar = {
    unread: barOf(viewOf([R.key], unread)),
    oneKey: barOf(viewOf([R.inline, R.key], oneKey)),
    twoKeys: barOf(viewOf([R.inline, R.inline2], twoKeys)),
    pending: barOf(viewOf([R.inline], oneKey), true),
    modelGone: barOf(viewOf([R.gone], modelGone)),
    // A backend that sends no line of its own for the bar: the row's sentence, as before.
    modelGoneOlder: barOf(viewOf([R.gone], { ...modelGone, detail: undefined })),
    noKey: barOf(viewOf([R.noKey], null, { providers_note: note })),
    expired: barOf(P.providersView(onS([R.expired, R.key]), conf([]))),
    expiredTwo: barOf(P.providersView(onS([R.expired, R.lapsed]), conf([])))
  }
  asked.length = 0
  find(P.ProvidersBar({ view: viewOf([R.inline, R.inline2], twoKeys), ask, send, pending: false }), 'Button')[0].props.onClick()
  out.held.dialog = asked.map(d => ({ kind: d.kind, title: d.title, body: d.body, target: d.target, confirmLabel: d.confirmLabel }))
  out.held.copy = { moveBody: [P.T.moveBody(1), P.T.moveBody(2)], moveLine: P.T.moveLine(R.inline), willMove: typeof P.T.willMove === 'function' ? P.T.willMove(R.inline) : null }

  // 4. A click that got through to a held switch says the reason and starts nothing, also for a file that cannot
  //    be read; the host route's refusal of the same thing is shown in its own words.
  const clicks = {}
  for (const [name, block] of Object.entries({ unread, modelGone })) {
    reset({ prepare: true, beforeApply: true, purpose: true })
    P.useRest(fakeRest({ statuses: [off] }))
    host.setProfileBackend = async input => (log.push({ dialog: input.purpose }), await input.prepare(), { applied: true })
    await P.turnOn('work', queryClient, { block })
    clicks[name] = [...log]
  }
  reset({ prepare: true, beforeApply: true, purpose: true })
  P.useRest(fakeRest({ statuses: [off], onSwitchOn: () => { throw new Error(`422: ${JSON.stringify({ detail: CANT_READ, code: 'unreadable', keys: [] })}`) } }))
  host.setProfileBackend = async input => (await input.prepare(), { applied: true })
  await P.turnOn('work', queryClient)
  clicks.routeRefused = log.filter(entry => entry.notify)
  out.held.clicks = clicks

  // 5. A main model without a key does not hold the switch: the desktop's confirm carries the one line about it.
  const purposeOf = async (options, features) => {
    reset(features)
    const seen = []
    P.useRest(fakeRest({ statuses: [on] }))
    host.setProfileBackend = async input => {
      seen.push(input.purpose)
      if (input.prepare) await input.prepare()
      return { applied: true }
    }
    await P.turnOn('work', queryClient, options)
    return seen
  }
  const noKeyView = viewOf([R.noKey], null, { providers_note: note })
  out.held.confirm = {
    view: { block: noKeyView.block, note: noKeyView.note },
    noNote: viewOf([R.key]).note,
    onIgnoresTheNote: P.providersView(onS([R.key]), conf([R.noKey], null, { providers_note: note })).note,
    noKey: await purposeOf({ block: null, note: noKeyView.note }, { prepare: true, beforeApply: true, purpose: true }),
    plain: await purposeOf({ block: null, note: null }, { prepare: true, beforeApply: true, purpose: true }),
    olderDesktop: await purposeOf({ block: null, note: noKeyView.note }, undefined),
    // A line too long for the confirm is not cut into an untrue one: the plugin's own line stands.
    tooLong: await purposeOf({ block: null, note: { ...note, reason: 'x'.repeat(200) } }, { prepare: true, beforeApply: true, purpose: true }),
    purpose: P.T.purpose
  }
  // The switch hands the note on, as it hands on what holds it.
  reset({ prepare: true, beforeApply: true, purpose: true })
  const handed = []
  P.useRest(fakeRest({ statuses: [on] }))
  host.setProfileBackend = async input => (handed.push(input.purpose), { applied: false })
  host.clearProfileBackend = async () => ({ applied: false })
  host.state = {}
  find(P.SandboxSwitch({ status: offS, providers: noKeyView }), 'Switch')[0].props.onCheckedChange(true)
  await new Promise(resolve => setTimeout(resolve, 20))
  out.held.confirm.fromTheSwitch = handed
  // The card's "turn on" buttons start the same switch-on: the same line.
  reset({ prepare: true, beforeApply: true, purpose: true })
  const fromCard = []
  P.useRest(fakeRest({ statuses: [on] }))
  host.setProfileBackend = async input => (fromCard.push(input.purpose), { applied: false })
  host.clearProfileBackend = async () => ({ applied: false })
  host.state = {}
  const reviewCard = P.HandbackCard({ status: { ...offS, handback: { open: true, held: 0 } }, view: hbView, providers: noKeyView })
  deep(reviewCard, 'Button').find(b => deepTexts(b).join('') === 'Keep and turn on').props.onClick()
  await new Promise(resolve => setTimeout(resolve, 20))
  out.held.confirm.fromTheCard = fromCard
} catch (error) {
  out.held.error = String(error && error.stack ? error.stack : error)
}
forget()


// -- tool categories: what a sign-in or a key keeps open is listed and counted; a grant says what it reaches ---
out.categories = {}
try {
  const opened = [
    { host: 'inference-api.nousresearch.com', port: 443, reason: 'Model \u00b7 Nous Portal', rule: '_provider_a' },
    { host: 'firecrawl-gateway.nousresearch.com', port: 443, reason: 'Web extract \u00b7 Nous Portal', rule: '_provider_a' }
  ]
  const blocked = { folders: [], network: { egress: 'deny', allow: [{ host: 'pypi.org', port: 443 }] } }
  out.categories.summary = {
    own: P.policySummary(blocked, []),
    opened: P.policySummary(blocked, P.keptOpen({ opened })),
    withBuiltin: P.policySummary(blocked, P.keptOpen({ builtin: [usageData], opened })),
    onlyOpened: P.policySummary({ folders: [], network: { egress: 'deny', allow: [] } }, P.keptOpen({ opened: opened.slice(0, 1) })),
    neither: P.keptOpen({}).length + P.keptOpen(undefined).length
  }
  const net = P.NetworkSection({ config: { ...pageConfig([], [usageData]), opened }, status: {}, applied: null, pending: false, ask: () => {}, send: () => {}, sendQuietly: () => {} })
  out.categories.listed = deep(net, 'Row').filter(row => typeof row.props.title === 'string' && /nousresearch\.com/.test(row.props.title)).map(row => row.props.title)
  out.categories.destinations = deep(net, 'Row')
    .filter(row => typeof row.props.title === 'string' && row.props.title.includes('nousresearch.com'))
    .map(row => ({ title: row.props.title, note: row.props.note, removable: Boolean(row.props.action) }))
  const grants = {
    grants: [
      { id: 'network:always:tool:web_extract', kind: 'network', label: 'Web extract', target: 'firecrawl-gateway.nousresearch.com, mcp.exa.ai', ports: [443], scope: 'always', status: 'active', bound: true, note: 'Reads any public page through these services.' },
      { id: 'network:allow:tool:image_gen', kind: 'network', label: 'Image generation', target: 'fal-queue-gateway.nousresearch.com', ports: [443], scope: 'allow', status: 'pending', restart: true },
      { id: 'network:allow:example.com', kind: 'network', target: 'example.com', ports: [80, 443], scope: 'allow', status: 'pending' }
    ]
  }
  const asked = []
  const section = P.GrantsSection({ grants, pending: false, ask: dialog => asked.push(dialog), send: () => {} })
  const rows = deep(section, 'Row')
  out.categories.grants = rows.map(row => ({
    title: row.props.title,
    sub: row.props.sub,
    note: row.props.note,
    tip: row.props.meta ? row.props.meta.props.label : null,
    removable: Boolean(row.props.action)
  }))
  rows[0].props.action.props.onClick()
  out.categories.removeDialog = asked.map(dialog => ({ title: dialog.title, body: dialog.body, target: dialog.target }))
  const through = { kind: 'network', program: 'python3.14', rule: '_provider_a', outcome: 'allowed' }
  out.categories.activity = {
    gateway: P.activitySub({ ...through, use: 'Web extract' }),
    model: P.activitySub(through),
    site: P.activitySub({ kind: 'network', program: 'curl', rule: 'allowed_host_example_com', use: 'Web extract', outcome: 'allowed' })
  }
  out.categories.tips = { restart: P.T.grantRestartTip, applying: P.T.grantApplyingTip }
} catch (error) {
  out.categories.error = String(error && error.stack ? error.stack : error)
}


// -- the page follows the launcher whatever the window does; an edit sends only what it changes ----------------
out.follows = {}
try {
  const onS = { ...on, applied: { folders: [], network: { egress: 'deny', allow: [] } }, capabilities: { label: 'OpenShell sandbox' } }
  const inference = { host: 'inference-api.nousresearch.com', port: 443, reason: 'Model \u00b7 Nous Portal', rule: '_provider_a' }
  const gateway = { host: 'firecrawl-gateway.nousresearch.com', port: 443, reason: 'Web extract \u00b7 Nous Portal', rule: '_provider_a' }

  // 1. Every poll of the page goes on while the window is hidden or has no focus, reads again at once when the
  //    window is shown again, and no read can hang the poll. (TanStack Query runs a tick of refetchInterval only
  //    when refetchIntervalInBackground is set or the document is not hidden.)
  const collect = render => {
    const asked = []
    globalThis.__useEffect = () => {}
    globalThis.__useQuery = q => {
      asked.push(q)
      return { data: undefined, error: null }
    }
    globalThis.__useMutation = () => ({ isPending: false, mutateAsync: async () => ({}) })
    try {
      render()
    } finally {
      delete globalThis.__useEffect
      delete globalThis.__useQuery
      delete globalThis.__useMutation
    }
    return asked.filter(q => q.refetchInterval)
  }
  reset({ prepare: true, beforeApply: true })
  const polled = [
    ...collect(() => P.SandboxPage()),
    ...collect(() => P.ActivityView({ send: () => {}, status: { ...onS } })),
    ...collect(() => P.PolicyHistory({ send: () => {}, status: { ...onS } }))
  ]
  out.follows.polls = polled.map(q => ({
    part: Array.isArray(q.queryKey[2]) ? q.queryKey[2][0] : q.queryKey[2],
    every: q.refetchInterval,
    whileHidden: Boolean(q.refetchIntervalInBackground),
    whenShownAgain: q.refetchOnWindowFocus ?? null
  }))
  const reads = []
  P.useRest(async (path, opts) => {
    reads.push({ path: path.split('?')[0], timeoutMs: opts ? opts.timeoutMs ?? null : null })
    return {}
  })
  for (const q of polled) await q.queryFn()
  out.follows.reads = reads
  // The chip in the status bar is on every page: it keeps the desktop's rule (no polling in a hidden window) and
  // reads again when the window is shown.
  out.follows.chip = collect(() => P.SandboxChip()).map(q => ({
    part: q.queryKey[2],
    whileHidden: Boolean(q.refetchIntervalInBackground),
    whenShownAgain: q.refetchOnWindowFocus ?? null
  }))

  // 2. What the launcher changed by itself is read again with the status that showed it: the other parts of the
  //    page do not wait for their own poll.
  const base = {
    ...onS,
    restart_required: false,
    opened: [inference, gateway],
    builtin: [],
    temporary: { folders: [], approved: { allowed_tool_web_extract: {} } },
    saved: { folders: [], network: { egress: 'deny', allow: [] } },
    providers: [{ id: 'sign_in:nous', state: 'ready', detail: 'Works in the sandbox.' }]
  }
  const follow = (status, profile = 'followed') => {
    log.length = 0
    P.followLauncher(queryClient, profile, P.launcherStamp(status))
    return log.filter(entry => entry.invalidate).map(entry => entry.invalidate[2])
  }
  out.follows.reread = {
    firstSight: follow(base),
    nothingNew: follow({ ...base, started_at: 5, handback: { stamp: 'x' } }),
    restartBegan: follow({ ...base, state: 'restarting', restarting: { label: 'Restarting the sandbox to remove Web extract' } }),
    restartEnded: follow({ ...base, opened: [inference], temporary: { folders: [], approved: {} } }),
    cardAnswered: follow({ ...base, opened: [inference], temporary: { folders: [], approved: { allowed_host_example_com: {} } } }),
    savedByACard: follow({ ...base, opened: [inference], temporary: { folders: [], approved: {} }, saved: { folders: [], network: { egress: 'deny', allow: [], approved: { allowed_host_example_com: {} } } } }),
    folderGranted: follow({ ...base, opened: [inference], temporary: { folders: [{ path: 'C:/work', access: 'ro' }], approved: {} }, saved: { folders: [], network: { egress: 'deny', allow: [], approved: { allowed_host_example_com: {} } } } }),
    renewal: follow({ ...base, opened: [inference], temporary: { folders: [{ path: 'C:/work', access: 'ro' }], approved: {} }, saved: { folders: [], network: { egress: 'deny', allow: [], approved: { allowed_host_example_com: {} } } }, providers: [{ id: 'sign_in:nous', state: 'needs_sign_in', detail: 'Sign in again.' }] }),
    otherProfileFirstSight: follow(base, 'other')
  }
  // Each of these alone is a change: an address opened for a sign-in, a restart the launcher has queued, a
  // restart the saved settings need, a provider's row.
  const alone = changed => {
    follow(base, 'alone')
    return follow({ ...base, ...changed }, 'alone')
  }
  out.follows.alone = {
    opened: alone({ opened: [inference] }),
    restartQueued: alone({ restart_queued: true }),
    restartRequired: alone({ restart_required: true }),
    provider: alone({ providers: [{ id: 'sign_in:nous', state: 'ready', detail: 'Works in the sandbox. Used at two addresses.' }] }),
    state: alone({ state: 'restarting' }),
    allowedFromChat: alone({ temporary: { folders: [], approved: {} } }),
    folderFromChat: alone({ temporary: { folders: [{ path: 'C:/work', access: 'ro' }], approved: { allowed_tool_web_extract: {} } } }),
    savedFromChat: alone({ saved: { folders: [], network: { egress: 'deny', allow: [], approved: { allowed_host_example_com: {} } } } }),
    savedFolder: alone({ saved: { folders: [{ path: 'C:/work', access: 'rw' }], network: { egress: 'deny', allow: [] } } })
  }
  // ... and the page asks for it with every status it draws.
  const effects = []
  const data = { status: { data: base, error: null }, config: { data: { network: { egress: 'deny', allow: [] }, endpoints: [], capabilities: {}, folders: [] }, error: null } }
  globalThis.__useEffect = (fn, deps) => effects.push({ fn, deps })
  globalThis.__useQuery = q => data[q.queryKey[2]] || { data: undefined, error: null }
  globalThis.__useMutation = () => ({ isPending: false, mutateAsync: async () => ({}) })
  try {
    P.SandboxPage()
  } finally {
    delete globalThis.__useEffect
    delete globalThis.__useQuery
    delete globalThis.__useMutation
  }
  out.follows.wired = effects.filter(effect => (effect.deps || []).includes(P.launcherStamp(base))).length
  // Drawn again with a status that shows a change, the page's own effect reads the other parts again.
  const drawn = status => {
    const made = []
    globalThis.__useEffect = (fn, deps) => made.push({ fn, deps })
    globalThis.__useQuery = q => ({ ...data, status: { data: status, error: null } })[q.queryKey[2]] || { data: undefined, error: null }
    globalThis.__useMutation = () => ({ isPending: false, mutateAsync: async () => ({}) })
    try {
      P.SandboxPage()
    } finally {
      delete globalThis.__useEffect
      delete globalThis.__useQuery
      delete globalThis.__useMutation
    }
    log.length = 0
    for (const effect of made.filter(effect => (effect.deps || []).includes(P.launcherStamp(status)))) effect.fn()
    return log.filter(entry => entry.invalidate).map(entry => entry.invalidate[2])
  }
  drawn(base)
  out.follows.wiredReads = drawn({ ...base, opened: [inference], temporary: { folders: [], approved: {} } })

  // 3. A network edit sends the internet setting and the destinations, never the approvals saved from chat cards.
  const withApproval = {
    network: {
      egress: 'deny',
      allow: [{ host: 'postman-echo.com', port: 443 }],
      approved: { allowed_host_www_wikipedia_org: { name: 'allowed_host_www_wikipedia_org', endpoints: [{ host: 'www.wikipedia.org', port: 443 }] } }
    },
    endpoints: [],
    capabilities: {}
  }
  const sent = []
  const asks = []
  const push = (...args) => sent.push(args)
  const net = P.NetworkSection({ config: withApproval, status: {}, send: push, sendQuietly: push, pending: false, ask: dialog => asks.push(dialog) })
  deep(net, 'Row').find(row => row.props.title === 'postman-echo.com').props.action.props.onClick()
  deep(net, 'AddButton')[0].props.onClick()
  asks[0].next({ host: 'example.org', port: 443 }).run()
  deep(deep(net, 'Row').find(row => row.props.title === 'Internet access').props.access, 'Select')[0].props.onValueChange('allow')
  asks[1].run()
  out.follows.networkEdits = sent.map(([path, method, body]) => ({ path, method, body }))

  // 4. The restart bar asks for a restart only when the user has one to make.
  const bar = status => {
    host.state = {}
    const tree = P.RestartBar({ status, send: () => {} })
    return tree ? deepTexts(tree).join(' | ') : null
  }
  out.follows.bar = {
    usersOwn: bar({ ...onS, restart_required: true }),
    launcherWillRestart: bar({ ...onS, restart_required: true, restart_queued: true }),
    launcherRestarts: bar({ ...onS, state: 'restarting', restart_required: true, restarting: { label: 'Restarting the sandbox to remove Web extract' } }),
    usersRestartRuns: bar({ ...onS, state: 'restarting', restart_required: true }),
    nothing: bar({ ...onS, restart_required: false })
  }

  // 5. A tool's services wrap at the commas, on the row and in the Remove dialog; a site's row is one line.
  const toolGrant = { id: 'network:allow:tool:web_extract', kind: 'network', label: 'Web extract', target: 'firecrawl-gateway.nousresearch.com, mcp.exa.ai, search.parallel.ai', ports: [443], scope: 'allow', status: 'active', bound: true }
  const siteGrant = { id: 'network:always:example.com', kind: 'network', target: 'example.com', ports: [80, 443], scope: 'always', status: 'active' }
  const asked5 = []
  const section = P.GrantsSection({ grants: { grants: [toolGrant, siteGrant] }, pending: false, ask: dialog => asked5.push(dialog), send: () => {} })
  out.follows.rows = deep(section, 'Row').map(row => {
    const line = deep(P.Row(row.props), 'div').find(div => div.props.title === row.props.sub)
    return {
      sub: row.props.sub,
      oneLine: line.props.style.whiteSpace === 'nowrap',
      pieces: deep(line, 'span').map(span => deepTexts(span).join('')),
      // no piece breaks inside a name
      whole: deep(line, 'span').every(span => span.props.style.whiteSpace === 'nowrap')
    }
  })
  deep(section, 'Row')[0].props.action.props.onClick()
  const confirm = P.Dialogs({ dialog: asked5[0], setDialog: () => {}, send: () => {} })
  const target = deep(confirm, 'div')[0]
  out.follows.dialog = {
    text: asked5[0].target,
    breaksInsideNames: target.props.style.wordBreak === 'break-all' || deep(target, 'span').some(span => span.props.style.whiteSpace !== 'nowrap'),
    pieces: deep(target, 'span').map(span => deepTexts(span).join(''))
  }
  // A plain target (a folder's path) is drawn as it was.
  const pathDialog = P.Dialogs({ dialog: { kind: 'confirm', title: 't', body: 'b', target: 'D:\\work\\a folder, with a comma', run: () => {} }, setDialog: () => {}, send: () => {} })
  out.follows.pathDialog = { pieces: deep(deep(pathDialog, 'div')[0], 'span').length, text: deepTexts(deep(pathDialog, 'div')[0]).join('') }

  // 6. The Activity row a removal leaves says what happened.
  const badge = row => deepTexts(P.ActivityBadges({ row })).join(' | ')
  out.follows.activity = {
    removedByTheUser: badge({ kind: 'decisions', choice: 'ended', who: 'you', label: 'Access removed' }),
    endedByItself: badge({ kind: 'decisions', choice: 'ended', who: 'sandbox', label: 'Access ended' })
  }

  // 7. The model's address is on the page once: among the allowed destinations when a key or sign-in is used
  //    there, else in the fixed row.
  const titles = config =>
    deep(P.NetworkSection({ config, status: {}, send: () => {}, sendQuietly: () => {}, pending: false, ask: () => {} }), 'Row').map(row => row.props.title)
  const local = {
    network: { egress: 'deny', allow: [{ host: 'postman-echo.com', port: 443 }] },
    endpoints: [{ label: 'Model', url: 'http://127.0.0.1:47970/v1', reach: 'allowed', via: 'loopback' }],
    capabilities: { host_loopback: 'open' },
    opened: [{ host: 'localhost', port: 47970, reason: 'Model', rule: '_provider_k' }]
  }
  const portal = {
    ...local,
    endpoints: [
      { label: 'Model', url: 'https://inference-api.nousresearch.com/v1', reach: 'allowed', via: 'rule' },
      { label: 'Fallback', url: 'https://api.example.com/v1', reach: 'blocked', via: null }
    ],
    opened: [inference, gateway]
  }
  out.follows.model = {
    on: titles(local),
    off: titles({ ...local, opened: [] }),
    internetAllowed: titles({ ...local, network: { egress: 'allow', allow: [] } }),
    portal: titles(portal),
    count: P.policySummary({ folders: [], network: local.network }, P.keptOpen(local))
  }
} catch (error) {
  out.follows.error = String(error && error.stack ? error.stack : error)
}

// The switch in the three states a sandbox without its gateway was seen in (tests/test_switch_when_the_sandbox_is_down_js.py):
// the launcher answers "failed" with its sentence; the launcher answers while the desktop's own bar says the
// backend is offline; nothing answers at all.
out.down = {}
try {
  const sentence = "The sandbox's gateway stopped. Turn the sandbox off, then on again."
  const failed = { ...withSwitch(on), state: 'failed', error: sentence }
  const exited = { ...withSwitch(on), state: 'exited', error: 'sandbox exited with 1' }
  const switchIn = status => {
    const tree = P.SandboxSwitch({ status })
    const [sw] = find(tree, 'Switch')
    const [tip] = find(tree, 'Tip')
    return { checked: sw.props.checked, disabled: Boolean(sw.props.disabled), tip: tip ? tip.props.label : null, toggle: sw.props.onCheckedChange }
  }
  // One click on the switch with the desktop's confirm answered yes, through to the launcher's own route.
  const clickOff = async (status, { busy = false, handback } = {}) => {
    forget()
    reset({ prepare: true, beforeApply: true })
    host.state = busy ? { busyBySession: { s1: true } } : {}
    P.useRest(fakeRest({ statuses: [off], handback }))
    fetchAnswer = answered(offBody(null))
    host.setProfileBackend = async () => ({ applied: false })
    host.clearProfileBackend = async input => {
      log.push({ clear: Object.keys(input).sort(), switching: P.switchState() })
      await input.beforeApply()
      return { applied: true }
    }
    const sw = switchIn(status)
    if (!sw.disabled) sw.toggle(false)
    for (let i = 0; i < 8; i++) await tick()
    return { switch: { checked: sw.checked, disabled: sw.disabled, tip: sw.tip }, log: [...log] }
  }
  out.down.header = { label: P.stateView(failed).label, tone: P.stateView(failed).tone }
  out.down.failed = await clickOff(failed)
  out.down.failedBusy = await clickOff(failed, { busy: true })  // a chat left waiting on a sandbox that is gone
  out.down.exitedBusy = await clickOff(exited, { busy: true })
  out.down.runningBusy = await clickOff(withSwitch(on), { busy: true })  // a reply does run: the switch waits
  out.down.offline = await clickOff(withSwitch(on), { handback: 'fails' })  // the desktop's bar says offline; the launcher answers
  // The review card's two buttons, with a chat left waiting on a sandbox that is gone.
  reset({ prepare: true, beforeApply: true })
  host.state = { busyBySession: { s1: true } }
  host.setProfileBackend = async () => ({ applied: false })
  host.clearProfileBackend = async () => ({ applied: false })
  out.down.cardBusy = { failed: cardOf(hbView, failed).buttons, running: cardOf(hbView, withSwitch(on)).buttons }
  // Nothing answers at all: the switch is held with the reason, the notice has the button, the button asks.
  forget()
  lostSetup()
  const lost = P.lostView({ data: failed, error: refusedConn })
  const bar = barOfLost(lost)
  out.down.lost = { view: lost, switch: lostSwitchOf(failed, lost), bar: { texts: bar.texts, buttons: bar.buttons } }
  deep(bar.tree, 'Button')[0].props.onClick()
  await tick()
  await tick()
  out.down.lostClick = [...log]
  forget()
} catch (error) {
  out.down.error = String(error && error.stack ? error.stack : error)
}

// A switch-on asked for in short requests (tests/test_desktop_switch_js.py): while the sandbox is still starting the
// host route answers `pending`, and the page sends the same request again until the final answer, or an error, comes.
out.waited = {}
try {
  const address = { profile: 'work', url: 'http://127.0.0.1:47972', token: 'tok', undo_ticket: 'undo-1' }
  const stillStarting = { pending: true, profile: 'work' }
  const inTurn = answers => {
    let asked = 0
    return () => {
      const next = answers[Math.min(asked++, answers.length - 1)]
      if (next instanceof Error) throw next
      return next
    }
  }
  const asksFirst = async input => {
    log.push({ set: Object.keys(input).sort(), switching: P.switchState() })
    log.push({ prepared: await input.prepare() })
    return { applied: true }
  }
  const switchOn = async (answers, { features = { prepare: true, beforeApply: true, purpose: true }, statuses = [on], desktop = asksFirst } = {}) => {
    reset(features)
    onBodies.length = 0
    P.useRest(fakeRest({ statuses, onSwitchOn: inTurn(answers) }))
    host.setProfileBackend = desktop
    await P.turnOn('work', queryClient)
    return { log: [...log], bodies: [...onBodies], switching: P.switchState() }
  }
  out.waited.slow = await switchOn([stillStarting, stillStarting, address])
  out.waited.answersAtOnce = await switchOn([address])
  out.waited.failsLater = await switchOn([stillStarting, new Error('504: {"detail": "The sandbox didn\'t start within 240 seconds."}')], { statuses: [off] })
  out.waited.olderDesktop = await switchOn([stillStarting, address], {
    features: null,  // no host.profileBackendFeatures: the desktop is asked after the sandbox started
    desktop: async input => {
      log.push({ set: Object.keys(input).sort(), switching: P.switchState() })
      return { applied: true }
    }
  })
  out.waited.refusedAfterTheWait = await switchOn([stillStarting, address], {
    statuses: [off],
    desktop: async input => {
      await input.prepare()
      throw new Error('Only loopback URLs')
    }
  })
} catch (error) {
  out.waited.error = String(error && error.stack ? error.stack : error)
}

process.stdout.write(JSON.stringify(out))
