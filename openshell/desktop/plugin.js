/**
 * Sandbox settings for the openshell plugin: the /sandbox page, its sidebar row and palette command,
 * and a status-bar chip while the active profile runs sandboxed.
 *
 * Everything shown is read back from the host-side owner of the profile's sandbox state: the sandbox
 * launcher for a sandboxed profile (it answers /api/plugins/openshell/* itself, never forwarding into
 * the sandbox), or the host backend's dashboard router for a profile that runs unsandboxed. Edits go
 * to those routes, which validate and save them; the page then shows what they read back.
 *
 * The switch (order and reasons: launcher/switch.py). On: host.setProfileBackend asks the user FIRST
 * (with the plugin's `purpose` line); only after a yes does its `prepare` call the host route, which
 * starts the launcher as a login service, waits for the sandbox and marks the profile last; the desktop
 * applies the override as soon as prepare resolves. A Cancel starts nothing. Desktops without `prepare`
 * (host.profileBackendFeatures) get the old order: start, then ask, and a cancel spends the route's undo
 * ticket on the launcher. Off: take a ticket from the launcher, host.clearProfileBackend asks the user,
 * then (beforeApply) the ticket goes straight to the launcher's switch/off over loopback, which stops
 * the sandbox and unmarks last; only after that does the desktop stop routing the profile to the
 * launcher. Either way the page's status is seeded with the final answer before the switch state clears.
 *
 * The hand-back (launcher/handback.py): once the sandbox is off, Hermes on this computer runs what the profile
 * folder holds, and the sandbox wrote most of it. The launcher lists what changed among the settings and files
 * that run here (GET /handback). While that list has rows, the page shows them in a card with two buttons,
 * "Revert and turn off" and "Keep and turn off", which turn the sandbox off with that answer; the switch itself
 * reads the list first and shows the card instead of turning off when a row needs an answer.
 * A session that ended without that answer (its launcher was killed, the review could not run) is reviewed before
 * the next switch-on: the host route lists its changes for the profile that is off, the same card shows them with
 * "Revert and turn on" and "Keep and turn on", and the switch waits for one of them.
 * The list follows the status the page polls: the launcher's status carries a stamp that changes when the watched
 * files do, and the page reads the list again when it differs (and each time it opens). What the user kept is
 * named afterwards by one line, "Kept from the sandbox: N items", while those changes are still in the profile.
 *
 * Providers (launcher/settings_view.py words every row). Before the switch the host route's config lists the
 * profile's providers, one row each, with what each will do in the sandbox, and `providers_block` says what keeps
 * the switch from turning on: a key written in config.yaml (the bar offers "Move to .env", which asks first), or
 * the profile's model on a provider that is not available in the sandbox or needs a sign-in first. The switch and
 * the "turn on" buttons are disabled with that reason, and the word beside the switch says that it will not turn on.
 * A file the rows are read from that cannot be read holds the switch the same way: the rows stay as they were last
 * read. A model without a key does not hold it; the desktop's confirm then carries the one line about it
 * (`providers_note`). While the sandbox is on the same rows come with the launcher's status, and a sign-in that
 * expired is named in a bar with its row's badge and sentence, which says what to do. A row never shows a value.
 */
import {
  atom,
  Badge,
  Button,
  Checkbox,
  Codicon,
  ConfirmDialog,
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  EmptyState,
  host,
  Input,
  PALETTE_AREA,
  ROUTES_AREA,
  SegmentedControl,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  SIDEBAR_NAV_AREA,
  Skeleton,
  STATUSBAR_AREAS,
  StatusDot,
  Switch,
  Tabs,
  TabsList,
  TabsTrigger,
  Tip,
  useMutation,
  useQuery,
  useQueryClient,
  useValue
} from '@hermes/plugin-sdk'
import { createElement as h, useEffect, useState } from 'react'

const ROUTE = '/sandbox'
const PLUGIN_ID = 'openshell'
const STATUS_POLL_MS = 3000
const CONFIG_POLL_MS = 5000
// A polled read that gets no answer ends, so the next one goes out.
const POLL_TIMEOUT_MS = 15_000
const RESTART_TIMEOUT_MS = 240_000
const SWITCH_TIMEOUT_MS = 300_000
const HANDOFF_POLL_MS = 1500
const HANDOFF_WAIT_MS = 90_000

let rest = null
// The desktop's OS door (ctx.os): opens an action's web link (Docker's install guide). It admits web
// schemes only, so Windows Update (ms-settings:) stays a line of text.
let osApi = null

// The switch in flight ({ profile, to: 'on' | 'off' }); module state so it survives leaving the page.
const $switching = atom(null)
// The withheld-key bar the user dismissed: the list it showed, so a changed list shows the bar again.
const $endpointsDismissed = atom('')
// Sign-ins that ended while the sandbox is on and were said: profile -> { row id: the sentence said }.
const $told = atom({})
// Whatever refuses the switch uses one notice, so a second refusal replaces the first instead of sitting behind it.
const SWITCH_NOTICE = 'openshell:switch'

/** The terminal command that turns a profile's sandbox off (the default profile takes no -p). */
const cliOff = profile => (profile && profile !== 'default' ? `hermes -p ${profile} sandbox off` : 'hermes sandbox off')

const T = {
  title: 'Sandbox',
  on: 'On',
  off: 'Off',
  // Beside a switch that is off and that no click here turns on; the bar below says why.
  cantTurnOn: "Can't turn on",
  // One name per state, the desktop's own words (status bar, composer).
  turningOn: 'Starting sandbox…',
  turningOff: 'Stopping sandbox…',
  needsDesktop: 'Needs a newer version of the desktop app.',
  stuckOff: (profile, detail) => `Couldn't finish turning off: ${detail} Run "${cliOff(profile)}".`,
  // The launcher of a profile this window still shows as on stopped answering (see `lostView`).
  notAnswering: "The sandbox isn't answering.",
  lostState: 'Not answering',
  lostHelp: profile => `If it doesn't come back, run "${cliOff(profile)}" in a terminal, then switch back.`,
  offElsewhere: 'The sandbox was turned off outside this window.',
  offElsewhereHelp: 'Switch back to run this profile on this computer again.',
  switchBack: 'Switch back',
  stillOn: profile => `The sandbox is still switched on for this profile, but it isn't running. Run "${cliOff(profile)}" in a terminal.`,
  // After "Switch back" from a launcher that never said it was turning off (see `leftView`).
  leftState: 'Not connected',
  leftOn: profile => `The sandbox is still switched on for this profile, but this window isn't connected to it. Run "${cliOff(profile)}" in a terminal.`,
  // The plugin's own line in the desktop's confirm (setProfileBackend `purpose`; one line, at most 160 chars).
  purpose: 'Runs this profile in a sandbox that limits the files and websites it can reach.',
  states: {
    running: 'Running',
    starting: 'Starting sandbox…',
    restarting: 'Restarting sandbox…',
    stopping: 'Stopping sandbox…',
    stopped: 'Stopped'
  },
  notSandboxed: 'Not sandboxed',
  offNote: 'These settings apply when the sandbox is on.',
  restartBar: 'Changes apply after restart.',
  // A key saved while the sandbox is on, by the launcher's word for what that means there.
  keySaved: {
    in_use: 'Saved. In use in the sandbox now.',
    after_restart: 'Saved. Used in the sandbox after a restart.',
    not_used: 'Saved. Not used in the sandbox: no model in this profile names it.'
  },
  signInRenewed: 'Sign-in renewed.',
  endpointChanged: 'Model endpoint changed in the sandbox. Key withheld.',
  endpointsChanged: 'Model endpoints changed in the sandbox. Keys withheld.',
  endpointsUnpinned: 'Turn the sandbox off and on to finish updating. Keys for these endpoints are withheld until then.',
  dismiss: 'Dismiss',
  // Providers: one row each, with what it does in the sandbox. The sentence of a row is the backend's.
  providers: 'Providers',
  noProviders: 'No providers set up.',
  mainModel: 'Model',
  mainModelTip: "This profile's model uses this provider.",
  fallbackModel: 'Fallback',
  fallbackModelTip: "This profile's fallback model uses this provider.",
  providerState: {
    needs_sign_in: 'Sign in first',
    expired: 'Sign-in expired',
    unavailable: 'Not available',
    withheld: 'Key withheld',
    key_in_config: 'In config.yaml',
    no_key: 'No key'
  },
  moveToEnv: 'Move to .env',
  moveTitle: n => (n === 1 ? 'Move this key to .env?' : `Move ${n} keys to .env?`),
  moveBody: n =>
    n === 1
      ? "Takes the key out of config.yaml and saves it in this profile's .env. config.yaml then refers to it by name."
      : "Takes each key out of config.yaml and saves it in this profile's .env. config.yaml then refers to each by name.",
  moveLine: row => `${row.path} -> ${row.env}`,
  willMove: row => `${row.path} moves to .env as ${row.env}`,
  move: 'Move',
  moved: items =>
    items.length === 1
      ? `Moved ${items[0].path} to .env as ${items[0].env}.`
      : `Moved ${items.length} keys to .env: ${items.map(item => item.env).join(', ')}.`,
  movedLeft: paths => `Still in config.yaml: ${paths.join(', ')}.`,
  moveUnavailable: "This version can't move keys. Take the key out of config.yaml and save it in .env yourself.",
  // The hand-back card: what the sandbox changed among the settings and files that run on this computer.
  handbackTitle: 'Changed in the sandbox',
  handbackCaption: 'These run on this computer once the sandbox is off.',
  handbackCaptionOff: 'From the last sandbox session. These run on this computer now.',
  handbackFixed: 'Always reverted',
  handbackNoCopy: 'No copy kept',
  // What Revert does with such a row is the launcher's decision (the list's `no_copy`): leave it, or take it out.
  handbackNoCopyTip: {
    leave: "No earlier copy was kept. Revert leaves it as the sandbox changed it.",
    hold: "Reverting removes the sandbox's version. The earlier one can't be restored."
  },
  handbackFixedOnly: 'Put back when the sandbox restarts or turns off.',
  handbackFixedOnlyOff: 'Put back when the sandbox turns on.',
  handbackAlso: parts => `Also changed: ${parts.join(', ')}.`,
  skillCount: n => (n === 1 ? '1 skill' : `${n} skills`),
  memoryCount: n => (n === 1 ? '1 memory' : `${n} memories`),
  contextFile: 'SOUL.md',
  otherSettingCount: n => (n === 1 ? '1 other setting' : `${n} other settings`),
  show: 'Show',
  hide: 'Hide',
  handbackMore: n => `${n} more`,
  handbackIncomplete: names => `Not fully checked: ${names.join(', ')}.`,
  handbackRevert: 'Revert and turn off',
  handbackKeep: 'Keep and turn off',
  handbackRevertOn: 'Revert and turn on',
  handbackKeepOn: 'Keep and turn on',
  handbackFirst: 'Changes need an answer first.',
  handbackReverted: n => (n === 1 ? 'Reverted 1 change.' : `Reverted ${n} changes.`),
  handbackRevertedLate: n =>
    n === 1 ? '1 change made after the list was shown was reverted.' : `${n} changes made after the list was shown were reverted.`,
  handbackLate: 'The sandbox changed more settings. Review them and turn off again.',
  handbackSkipped: "Couldn't review the sandbox's changes. The sandbox is off.",
  // Changes the user kept at an earlier hand-back that are still in the profile: they run on this computer.
  keptCount: n => (n === 1 ? 'Kept from the sandbox: 1 item' : `Kept from the sandbox: ${n} items`),
  restart: 'Restart',
  restartBusyTip: 'Available when the current turn finishes.',
  pending: 'Pending',
  pendingTip: 'Applies after restart.',
  unavailable: 'Sandbox settings unavailable',
  notEnabled: 'The openshell plugin is not enabled for this profile.',
  folders: 'Folders',
  addFolder: 'Add folder…',
  profileFolder: 'Profile folder',
  keysHidden: 'Keys hidden',
  keysHiddenTip: "The sandbox can't read this profile's .env, auth files or tokens.",
  missing: 'Missing',
  missingTip: 'This folder no longer exists.',
  readOnly: 'Read only',
  readWrite: 'Read & write',
  remove: 'Remove',
  path: 'Path',
  access: 'Access',
  cancel: 'Cancel',
  next: 'Continue',
  save: 'Save',
  grantTitle: 'Give the sandbox access?',
  grantRo: 'The sandbox will be able to open files in this folder.',
  grantRw: 'The sandbox will be able to change and delete files in this folder.',
  grantConfirm: 'Give access',
  writeTitle: name => `Allow changes in ${name}?`,
  writeConfirm: 'Allow changes',
  network: 'Network',
  internet: 'Internet access',
  blocked: 'Blocked',
  allowed: 'Allowed',
  keyWithheld: 'Key withheld',
  keyWithheldTip: "The sandbox can reach this endpoint. It doesn't get the key until you allow it.",
  internetTitle: 'Allow internet access?',
  internetBody: 'The sandbox will be able to connect to any address on the internet.',
  allow: 'Allow',
  destinations: 'Allowed destinations',
  addDestination: 'Add destination…',
  noDestinations: 'None',
  address: 'Address',
  port: 'Port',
  portLabel: port => `Port ${port}`,
  destinationTitle: 'Allow this destination?',
  reachTip: {
    loopback: 'Services on this computer are always reachable from the sandbox.',
    rule: 'Matches an allowed destination.',
    internet: 'Internet access is allowed.',
    blocked: 'Not reachable from the sandbox.'
  },
  loopbackCaption: 'Services on this computer are always reachable from the sandbox.',
  keys: 'Keys',
  addKey: 'Add key…',
  noKeys: 'No keys stored.',
  replace: 'Replace…',
  replaceTitle: name => `Replace ${name}`,
  addKeyTitle: 'Add key',
  name: 'Name',
  value: 'Value',
  removeKeyTitle: name => `Remove ${name}?`,
  removeKeyBody: "Deletes it from this profile's .env.",
  credentials: {
    environment: 'Passed to the sandbox when it starts.',
    placeholders: 'Values stay on this computer. A key the sandbox can use works only at its own address.',
    host: "Read by this profile's backend."
  },
  chip: 'Sandboxed',
  openCommand: 'Open sandbox settings',
  folderCount: n => (n === 1 ? '1 folder' : `${n} folders`),
  internetBlocked: 'Internet blocked',
  internetAllowed: 'Internet allowed',
  destinationCount: n => (n === 1 ? '1 allowed destination' : `${n} allowed destinations`),
  grants: 'Allowed from chat',
  noGrants: 'Nothing allowed from chat cards.',
  grantsCaption: "Allow lasts until the sandbox is switched off. Always allow is saved to the sandbox's policy.",
  grantScope: { allow: 'Until switched off', always: 'Saved' },
  grantScopeTip: {
    allow: 'Ends when the sandbox is switched off. Not saved.',
    always: "Saved to the sandbox's policy: it stays after the sandbox is switched off."
  },
  grantNetwork: ports =>
    ports && ports.length && ports.every(p => p === 443)
      ? 'https · any program'
      : `http and https · any program${ports && ports.some(p => p !== 80 && p !== 443) ? ` · ports ${ports.join(', ')}` : ''}`,
  // A tool category with a sign-in or key bound for it: those hosts are for Hermes's tools, not any program.
  grantBound: 'https',
  grantApplying: 'Applying',
  grantApplyingTip: 'Takes effect in a moment (when the current reply ends on this build).',
  grantRestartTip: 'The sandbox restarts to add it when the current turn ends.',
  removeGrant: 'Remove',
  removeGrantTitle: target => `Remove access to ${target}?`,
  removeGrantNetwork: 'The sandbox can no longer reach it; the agent is asked again next time.',
  removeGrantFolder: 'The sandbox restarts without this folder when the current turn ends.',
  checkAgain: 'Check again'
}

// -- data -------------------------------------------------------------------------------------------

const keyFor = (profile, part) => ['openshell', profile, part]

function useActiveProfile() {
  return useValue(host.state.profile) || 'default'
}

// The launcher changes what the page shows by itself (a card answered in a chat, a restart, a sign-in renewed),
// so the open page keeps reading while its window is covered, minimized or without focus: by default a poll
// skips every tick in a hidden window. A window shown again reads at once.
const LIVE = { refetchIntervalInBackground: true, refetchOnWindowFocus: 'always', retry: false }
// The chip is in the status bar on every page: it stops with a hidden window, as the desktop's own polls do,
// and reads when the window is shown again.
const WHEN_SHOWN = { refetchOnWindowFocus: 'always', retry: false }

const polled = path => rest(path, { timeoutMs: POLL_TIMEOUT_MS })

function useStatus(profile, options = WHEN_SHOWN) {
  return useQuery({
    queryKey: keyFor(profile, 'status'),
    queryFn: () => polled('/status'),
    refetchInterval: STATUS_POLL_MS,
    ...options
  })
}

function usePolled(profile, part, every = CONFIG_POLL_MS) {
  return useQuery({
    queryKey: keyFor(profile, part),
    queryFn: () => polled(`/${part}`),
    refetchInterval: every,
    ...LIVE
  })
}

/** The backend's own words for a failed call: the JSON `detail` after the transport's "<status>: " prefix. */
function errorText(error) {
  const message = error instanceof Error ? error.message : String(error ?? '')
  const start = message.indexOf('{')

  if (start >= 0) {
    try {
      const detail = JSON.parse(message.slice(start)).detail

      if (typeof detail === 'string' && detail) {
        return detail
      }
    } catch {
      // not JSON: fall through to the bare message
    }
  }

  const plain = message.replace(/^Error invoking remote method '[^']+': (Error: )?/, '').replace(/^\d{3}: /, '')

  // A call that never reached a backend: say so in the page's words, never the transport's.
  return !plain.trim() || TRANSPORT_ERROR.test(plain) || RUNS_ELSEWHERE.test(plain) ? T.notAnswering : plain
}

// What the desktop's transport and fetch say when nothing listens (or stops listening) at the address.
const TRANSPORT_ERROR =
  /\bE(?:CONNREFUSED|CONNRESET|CONNABORTED|PIPE|TIMEDOUT|HOSTUNREACH|NETUNREACH|NOTFOUND|AI_AGAIN)\b|socket hang up|fetch failed|Failed to fetch|NetworkError|net::ERR_|network error|timed out|Backend offline/i

// What the desktop itself answers, before any backend is asked, for a profile that is still switched on for a
// plugin's backend and has no route to it: this computer does not run such a profile.
const RUNS_ELSEWHERE = /Gateway ticket bootstrap failed|but this app has no connection to it/

/** True for a failed call that got no HTTP answer at all: the backend is not there. */
function unreachable(error) {
  const message = error instanceof Error ? error.message : String(error ?? '')

  return Boolean(error) && statusCode(error) === null && TRANSPORT_ERROR.test(message)
}

function statusCode(error) {
  const match = /(?:^|: )(\d{3}): /.exec(error instanceof Error ? error.message : '')

  return match ? Number(match[1]) : null
}

/** The `code` of a refusal's JSON body (the switch routes name their hand-back refusals with one), or null. */
function errorCode(error) {
  const message = error instanceof Error ? error.message : String(error ?? '')
  const start = message.indexOf('{')

  if (start >= 0) {
    try {
      const code = JSON.parse(message.slice(start)).code

      return typeof code === 'string' ? code : null
    } catch {
      // not JSON: no code
    }
  }

  return null
}

function useSend(profile) {
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: ({ path, method, body, timeoutMs }) => rest(path, { method, body, timeoutMs }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['openshell', profile] })
  })

  // Throws the backend's message, which dialogs show inline.
  const send = async (path, method, body, timeoutMs) => {
    try {
      return await mutation.mutateAsync({ path, method, body, timeoutMs })
    } catch (error) {
      throw new Error(errorText(error))
    }
  }

  // For one-click edits (narrowing access): a failure is a toast.
  const sendQuietly = (path, method, body) =>
    send(path, method, body).catch(error => host.notify({ kind: 'error', message: error.message }))

  return { send, sendQuietly, pending: mutation.isPending }
}

// -- small pieces -----------------------------------------------------------------------------------

const S = {
  scroll: { height: '100%', overflowY: 'auto' },
  column: { maxWidth: '60rem', margin: '0 auto', padding: '2.25rem 2.5rem 4rem' },
  header: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' },
  titleRow: { display: 'flex', alignItems: 'baseline', gap: '0.625rem', minWidth: 0 },
  h1: { margin: 0, fontSize: '1.25rem', lineHeight: 1.3, fontWeight: 600, color: 'var(--ui-text-primary)' },
  profile: { fontSize: '0.875rem', color: 'var(--ui-text-tertiary)' },
  switchBox: { display: 'flex', alignItems: 'center', gap: '0.5rem', paddingTop: '0.25rem' },
  switchLabel: { fontSize: '0.8125rem', color: 'var(--ui-text-secondary)', minWidth: '1.5rem' },
  statusLine: {
    display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.375rem',
    fontSize: '0.8125rem', color: 'var(--ui-text-secondary)'
  },
  sep: { color: 'var(--ui-text-quaternary)' },
  bar: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginTop: '1.25rem',
    padding: '0.625rem 0.75rem 0.625rem 1rem', borderRadius: '6px', fontSize: '0.8125rem',
    background: 'var(--ui-bg-tertiary)', color: 'var(--ui-text-primary)'
  },
  barText: { display: 'grid', gap: '0.125rem', minWidth: 0 },
  barHead: { display: 'flex', alignItems: 'center', gap: '0.5rem' },
  barSub: { color: 'var(--ui-text-secondary)' },
  barButtons: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 },
  cardCaption: { margin: '0 0 0.625rem', fontSize: '0.75rem', color: 'var(--ui-text-tertiary)' },
  cardLine: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginTop: '0.625rem',
    fontSize: '0.8125rem', color: 'var(--ui-text-secondary)'
  },
  cardButtons: { display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.875rem' },
  section: { marginTop: '2.25rem' },
  sectionHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: '0.625rem' },
  h2: { margin: 0, fontSize: '0.875rem', fontWeight: 600, color: 'var(--ui-text-primary)' },
  h3: { margin: '1.25rem 0 0.5rem', fontSize: '0.8125rem', fontWeight: 500, color: 'var(--ui-text-secondary)' },
  list: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px' },
  row: {
    display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto 9.5rem 1.75rem', alignItems: 'center',
    columnGap: '0.75rem', padding: '0.625rem 0.5rem 0.625rem 0.875rem', minHeight: '3.25rem'
  },
  rowPlain: {
    display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', alignItems: 'center',
    columnGap: '0.75rem', padding: '0.625rem 0.875rem', minHeight: '3.25rem'
  },
  rowDivider: { borderTop: '1px solid var(--ui-stroke-secondary)' },
  rowText: { minWidth: 0 },
  rowHead: { display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 },
  rowTitle: {
    minWidth: 0, fontSize: 'var(--conversation-text-font-size, 0.8125rem)', color: 'var(--ui-text-primary)',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
  },
  rowSub: {
    marginTop: '0.125rem', fontSize: 'var(--conversation-caption-font-size, 0.75rem)', color: 'var(--ui-text-tertiary)',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
  },
  meta: { display: 'flex', alignItems: 'center', gap: '0.375rem', justifySelf: 'end' },
  staticAccess: { fontSize: '0.8125rem', color: 'var(--ui-text-secondary)', paddingLeft: '0.625rem' },
  action: { display: 'flex', justifyContent: 'center' },
  empty: { padding: '0.75rem 0.875rem', fontSize: '0.8125rem', color: 'var(--ui-text-tertiary)' },
  caption: { margin: '0.625rem 0 0', fontSize: '0.75rem', color: 'var(--ui-text-tertiary)' },
  field: { display: 'grid', gap: '0.375rem', marginTop: '0.875rem' },
  label: { fontSize: '0.75rem', fontWeight: 500, color: 'var(--ui-text-secondary)' },
  fieldError: { marginTop: '0.75rem', fontSize: 'var(--conversation-caption-font-size, 0.75rem)' },
  rowCode: { flexShrink: 0, fontSize: '0.75rem', color: 'var(--ui-text-tertiary)', whiteSpace: 'nowrap' },
  rowWrap: { whiteSpace: 'normal' },
  piece: { whiteSpace: 'nowrap' },
  confirmTarget: { marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--ui-text-secondary)', wordBreak: 'break-all' },
  confirmList: { marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--ui-text-secondary)' },
  keyActions: { display: 'flex', alignItems: 'center', gap: '0.25rem', justifySelf: 'end', gridColumn: '3 / span 2' }
}

const CHIP_CLASS =
  'inline-flex h-full items-center gap-1 rounded-none px-1.5 text-[0.6875rem] transition-colors ' +
  'text-(--ui-text-tertiary) hover:bg-(--chrome-action-hover) hover:text-foreground'

const baseName = path => String(path).split(/[\\/]/).filter(Boolean).pop() || String(path)

function Section({ title, aside, caption, children }) {
  return h(
    'section',
    { style: S.section },
    h('div', { style: S.sectionHead }, h('h2', { style: S.h2 }, title), aside || null),
    children,
    caption ? h('p', { style: S.caption }, caption) : null
  )
}

function List({ children }) {
  const rows = (Array.isArray(children) ? children : [children]).flat().filter(Boolean)

  return h(
    'div',
    { style: S.list },
    rows.map((row, i) => h('div', { key: row.key ?? i, style: i ? S.rowDivider : undefined }, row))
  )
}

/** One row of a list. `plain`: a row with no access control and no action (the review list, the kept list): the
 *  two columns those take are left out, so the name and the detail get the whole width up to the label. */
/** A list of names ("a, b, c") as pieces that wrap between the names, never inside one. */
function byComma(text) {
  const names = String(text).split(', ')

  return names.flatMap((name, index) => [
    h('span', { key: index, style: S.piece }, index < names.length - 1 ? `${name},` : name),
    index < names.length - 1 ? ' ' : null
  ])
}

function Row({ title, badge, sub, note, mono = false, meta, access, action, wide, plain = false, wrap = false }) {
  if (plain) {
    return h(
      'div',
      { style: S.rowPlain },
      h(
        'div',
        { style: S.rowText },
        h(
          'div',
          { style: S.rowHead },
          h('span', { className: mono ? 'font-mono' : undefined, style: S.rowTitle, title: typeof title === 'string' ? title : undefined }, title),
          badge || null
        ),
        note ? h('div', { style: S.rowSub, title: typeof note === 'string' ? note : undefined }, note) : null
      ),
      h('div', { style: S.meta }, meta || null)
    )
  }

  return h(
    'div',
    { style: S.row },
    h(
      'div',
      { style: S.rowText },
      h(
        'div',
        { style: S.rowHead },
        h('span', { className: mono ? 'font-mono' : undefined, style: S.rowTitle, title: typeof title === 'string' ? title : undefined }, title),
        badge || null
      ),
      sub
        ? wrap
          ? h('div', { className: 'font-mono', style: { ...S.rowSub, ...S.rowWrap }, title: sub }, byComma(sub))
          : h('div', { className: 'font-mono', style: S.rowSub, title: sub }, sub)
        : null,
      note ? h('div', { style: S.rowSub }, note) : null
    ),
    h('div', { style: S.meta }, meta || null),
    wide ? h('div', { style: S.keyActions }, wide) : [h('div', { key: 'a' }, access || null), h('div', { key: 'b', style: S.action }, action || null)]
  )
}

function AddButton({ label, onClick, disabled }) {
  return h(Button, { disabled, onClick, size: 'sm', type: 'button', variant: 'outline' }, h(Codicon, { name: 'add', size: '0.875rem' }), label)
}

function RemoveButton({ label = T.remove, onClick, disabled }) {
  return h(
    Tip,
    { label },
    h(Button, { 'aria-label': label, disabled, onClick, size: 'icon-xs', type: 'button', variant: 'ghost' }, h(Codicon, { name: 'close', size: '0.875rem' }))
  )
}

function PendingBadge() {
  return h(Tip, { label: T.pendingTip }, h(Badge, { variant: 'warn' }, T.pending))
}

function AccessSelect({ value, onChange, disabled }) {
  return h(
    Select,
    { disabled, onValueChange: onChange, value },
    h(SelectTrigger, { 'aria-label': T.access, className: 'w-full', size: 'sm' }, h(SelectValue, null)),
    h(SelectContent, null, h(SelectItem, { value: 'ro' }, T.readOnly), h(SelectItem, { value: 'rw' }, T.readWrite))
  )
}

function Field({ label, children }) {
  return h('label', { style: S.field }, h('span', { style: S.label }, label), children)
}

/** An input dialog: `onSubmit` throws the backend's refusal, shown inline; the dialog stays open. */
function FormDialog({ open, title, submitLabel, onClose, onSubmit, children }) {
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async event => {
    event.preventDefault()
    setBusy(true)
    setError(null)

    try {
      await onSubmit()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return h(
    Dialog,
    { onOpenChange: next => !next && onClose(), open },
    h(
      DialogContent,
      null,
      h(
        'form',
        { onSubmit: submit },
        h(DialogHeader, null, h(DialogTitle, null, title)),
        children,
        error ? h('div', { className: 'text-destructive', role: 'alert', style: S.fieldError }, error) : null,
        h(
          DialogFooter,
          { style: { marginTop: '1.25rem' } },
          h(Button, { onClick: onClose, type: 'button', variant: 'outline' }, T.cancel),
          h(Button, { disabled: busy, loading: busy, type: 'submit' }, submitLabel)
        )
      )
    )
  )
}

// -- header -----------------------------------------------------------------------------------------

function stateView(status) {
  if (!status.sandboxed) {
    return { tone: 'muted', label: T.notSandboxed }
  }

  if (status.state === 'failed' || status.state === 'exited') {
    return { tone: 'bad', label: String(status.error || status.state).split('\n')[0], error: true }
  }

  const tone = status.state === 'running' ? 'good' : status.state === 'stopped' ? 'muted' : 'warn'

  if (status.switching_off) {
    return { tone: 'warn', label: T.states.stopping }
  }

  // A chat card's folder grant (or a removal) restarts the sandbox: say why ("Restarting the sandbox to add
  // outside…", the desktop's words) instead of a bare "Restarting sandbox…".
  if (status.restarting?.label && (status.state === 'restarting' || status.state === 'starting')) {
    return { tone, label: `${status.restarting.label}…` }
  }

  return { tone, label: T.states[status.state] || status.state }
}

// The destinations counted are the rows the page lists: the user's own and the ones the launcher keeps open by
// itself or for a sign-in or key (keptOpen; a launcher that sends neither key lists none).
// Every destination that is open without being on the user's own list: what the launcher keeps open by itself
// (builtin) and every address a sign-in or key is used at (opened), each with its reason.
function keptOpen(source) {
  return [...(Array.isArray(source?.builtin) ? source.builtin : []), ...(Array.isArray(source?.opened) ? source.opened : [])]
}

function policySummary(policy, builtin) {
  const parts = [T.folderCount(policy.folders.length + 1)]

  if (policy.network.egress === 'allow') {
    parts.push(T.internetAllowed)
  } else {
    parts.push(T.internetBlocked)

    const count = policy.network.allow.length + (Array.isArray(builtin) ? builtin.length : 0)

    if (count) {
      parts.push(T.destinationCount(count))
    }
  }

  return parts
}

// -- the switch -------------------------------------------------------------------------------------

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

const hostCanSwitch = () =>
  typeof host.setProfileBackend === 'function' && typeof host.clearProfileBackend === 'function'

/** Spend a one-time ticket on the launcher's switch/off. A direct loopback call: by then ctx.rest
 *  addresses the host for this profile (off), or never reached the launcher (an undone on). */
async function launcherOff(url, ticket, handback) {
  const response = await fetch(`${url}/api/plugins/${PLUGIN_ID}/switch/off`, {
    body: JSON.stringify(handback ? { ticket, handback } : { ticket }),
    headers: { 'Content-Type': 'text/plain' },
    method: 'POST'
  })

  if (!response.ok) {
    let detail = `${response.status}`
    let code = null

    try {
      const answer = await response.json()

      detail = answer.detail || detail
      code = answer.code || null
    } catch {
      // no JSON body: keep the status
    }

    // `code` names the launcher's two hand-back refusals (handback_needs_answer, handback_incomplete).
    throw Object.assign(new Error(detail), { code })
  }

  return response.json()
}

/** What the page says when the launcher refused to turn off. A change the sandbox made between the list and the
 *  click asks again; a revert that could not finish is the launcher's own sentence (what to close, then again).
 *  For neither does the "run hermes ... sandbox off" advice apply. */
function offFailure(profile, error) {
  if (error?.code === 'handback_needs_answer') {
    return T.handbackLate
  }

  if (error?.code === 'handback_incomplete') {
    return errorText(error)
  }

  return T.stuckOff(profile, errorText(error))
}

/** After a switch-off: say what the hand-back did that the user has not seen on the card. */
function notifyHandedBack(done, answer, shown) {
  if (!done || typeof done !== 'object') {
    return
  }

  if (done.error) {
    // The launcher could not make or apply the list; it turned off all the same (it never holds the switch).
    host.notify({ kind: 'warning', message: T.handbackSkipped })

    return
  }

  if (done.problem) {
    host.notify({ kind: 'warning', message: String(done.problem) })
  }

  const reverted = Array.isArray(done.reverted) ? done.reverted : []
  // Keep: only what was reverted although it was not on the list (a change made after it was shown).
  const count = answer === 'keep' ? reverted.filter(id => !shown.includes(id)).length : reverted.length

  if (count) {
    host.notify({ kind: 'info', message: answer === 'keep' ? T.handbackRevertedLate(count) : T.handbackReverted(count) })
  }
}

/** After a switch-on that reviewed the last session first: say what was reverted, as a switch-off does. A review
 *  that could not run says nothing here (the route refuses the switch-on unless the answer was keep). */
function notifyReviewed(done, answer, rows) {
  if (done && typeof done === 'object' && !done.error) {
    notifyHandedBack(done, answer, rows.map(row => row.id))
  }
}

/** Wait until whichever backend ctx.rest reaches for this profile reports `sandboxed`; resolves that
 *  final status (null when none came in time, or within `looks` tries), which the page shows at once
 *  (`seedStatus`). */
async function settle(sandboxed, looks = Infinity) {
  const deadline = Date.now() + HANDOFF_WAIT_MS

  for (let look = 1; look <= looks && Date.now() < deadline; look += 1) {
    try {
      const status = await rest('/status')

      if (Boolean(status?.sandboxed) === sandboxed) {
        return status
      }
    } catch {
      // the host refuses the profile for a moment while it re-reads the marker
    }

    if (look < looks) {
      await sleep(HANDOFF_POLL_MS)
    }
  }

  return null
}

/** Put settle's final status in the page's status query BEFORE the switch state clears, so the header goes
 *  straight from "Starting sandbox…" to the new state (no "Off · Not sandboxed" frame from the old query). */
function seedStatus(queryClient, profile, status) {
  if (status && typeof status === 'object') {
    queryClient.setQueryData(keyFor(profile, 'status'), status)
  }
}

// A switch in flight for this window, set before the desktop's confirm opens (the page shows nothing
// until the user said yes, but a second click must not start a second switch).
let switchBusy = false

// -- a launcher that stopped answering ----------------------------------------------------------------
//
// While a profile is sandboxed the desktop routes it to the launcher, and so does ctx.rest: every call of this
// page goes there. When the launcher is gone (the sandbox was turned off in a terminal, or it crashed), the
// status poll fails and the page is left with its last answer. The SDK gives the page no call that reaches this
// computer's backend for that profile while the route stands, and none that reads core's marker, so the page
// goes by what it has: the failed poll, and the launcher's own last words. A launcher that turns off says so
// (`switching_off`) for a few seconds before it ends, and it ends only after the profile is unmarked; one that
// just stops answering said nothing.
//   * It said it was turning off, and this window did not ask it to: the switch-off happened elsewhere. The page
//     gives the route back the way its own switch-off does (host.clearProfileBackend, which asks the user once)
//     and shows the profile's status from this computer's backend.
//   * It said nothing: the page says the sandbox isn't answering and what to do, with the same button. It does
//     not give the route back by itself: a launcher that comes back (its login service restarts it) finds its
//     window still there.
// Giving the route back does not turn the sandbox off. The profile stays switched on for it until "sandbox off"
// runs on this computer, which stops what the launcher may have left behind before it lets the profile go; the
// page reaches nothing that could. And the desktop does not run a profile that is switched on for a plugin's
// backend, so after the button of the second case every call of this page fails in the desktop itself. The
// launcher's last answer ("running") is then nobody's report: the page stops showing it (`leftView`) and says
// what it knows until some backend answers for the profile again.

/** `{ off }` when the status poll fails without an HTTP answer for a profile the page last saw sandboxed (`off`:
 *  the launcher's last answer said it was switching off), else null. `query` is the page's status query. */
function lostView(query) {
  const data = query?.data

  if (!data?.sandboxed || !unreachable(query.error)) {
    return null
  }

  return { off: Boolean(data.switching_off) }
}

// Profiles this window has already asked about: one dialog per launcher that went away, not one per poll.
const $offered = atom({})

// Profiles whose route this window gave back from a launcher that had not said it was turning off, and when.
const $left = atom({})

/** `{ refused }` from such a switch-back until a backend answers for the profile again, else null. `refused`:
 *  the desktop says the profile runs through a plugin, so it is still switched on for the sandbox; false while
 *  nothing has been said yet (this computer's backend can take a while to serve a profile again). `query` is the
 *  page's status query: its data is still the launcher's last answer. */
function leftView(query, profile) {
  const since = $left.get()[profile]

  if (!since || (query?.dataUpdatedAt || 0) > since) {
    return null
  }

  const error = query?.error

  return { refused: RUNS_ELSEWHERE.test(error instanceof Error ? error.message : String(error ?? '')) }
}

/** Stop routing `profile` to a launcher that is gone, after the desktop's own confirm, and show what this
 *  computer's backend says about it. `lost` is what `lostView` said. Resolves whether the route was given back. */
async function switchBack(profile, queryClient, lost) {
  if (switchBusy) {
    return false
  }

  switchBusy = true
  let final = null
  // The launcher never said it was turning off: the profile is most likely still switched on for the sandbox.
  const silent = lost?.off === false

  try {
    const { applied } = await host.clearProfileBackend({ plugin: PLUGIN_ID, profile })

    if (!applied) {
      return false
    }

    if (silent) {
      $left.set({ ...$left.get(), [profile]: Date.now() })
    }

    // One look is enough then: the desktop refuses such a profile for as long as it is switched on, and the
    // page's own poll brings the answer when there is one.
    final = await settle(false, silent ? 1 : Infinity)

    return true
  } catch (error) {
    host.notify({ id: SWITCH_NOTICE, kind: 'error', message: errorText(error) })

    return false
  } finally {
    if (final) {
      $left.set(Object.fromEntries(Object.entries($left.get()).filter(([name]) => name !== profile)))
    }

    seedStatus(queryClient, profile, final)
    switchBusy = false
    queryClient.invalidateQueries({ queryKey: ['openshell'] })
  }
}

/** Called on every change of what `lostView` says. A switch-off made elsewhere gives the route back at once
 *  (asked once per launcher that went away); anything else is left to the page's notice. True when it asked. */
function followLost(queryClient, profile, lost) {
  const offered = $offered.get()

  if (!lost) {
    if (offered[profile]) {
      $offered.set(Object.fromEntries(Object.entries(offered).filter(([name]) => name !== profile)))
    }

    return false
  }

  if (!lost.off || offered[profile] || switchBusy || $switching.get() || !hostCanSwitch()) {
    return false
  }

  $offered.set({ ...offered, [profile]: true })
  void switchBack(profile, queryClient, lost)

  return true
}

/** The profile is marked as sandboxed but nothing runs it and this window is on this computer's backend (the
 *  host route's `switch.marked`): the session ended without a switch-off. */
function stillMarked(status, switching) {
  return Boolean(status && !status.sandboxed && status.switch?.marked && !switching)
}

/** What the page says while the launcher is gone, with the button that gives the route back. */
function LostBar({ lost, profile }) {
  const queryClient = useQueryClient()
  const switching = useValue($switching)

  if (!lost) {
    return null
  }

  return h(
    'div',
    { role: 'status', style: S.bar },
    h(
      'div',
      { style: S.barText },
      h('span', null, lost.off ? T.offElsewhere : T.notAnswering),
      h('span', { style: S.barSub }, lost.off ? T.offElsewhereHelp : T.lostHelp(profile))
    ),
    hostCanSwitch()
      ? h(
          'div',
          { style: S.barButtons },
          h(Button, { disabled: Boolean(switching), onClick: () => void switchBack(profile, queryClient, lost), size: 'sm', type: 'button' }, T.switchBack)
        )
      : null
  )
}

/** A session that ended without a switch-off, seen from this computer's backend: what to run. */
function StillOnBar({ status }) {
  const switching = useValue($switching)

  return stillMarked(status, switching)
    ? h('div', { role: 'status', style: S.bar }, h('div', { style: S.barText }, h('span', null, T.stillOn(status.profile))))
    : null
}

/** After "Switch back" from a launcher that never said it was turning off (`leftView`): what is known, and what
 *  to run. No button: nothing this page can call turns the sandbox off without its launcher. */
function LeftBar({ left, profile }) {
  return left
    ? h('div', { role: 'status', style: S.bar }, h('div', { style: S.barText }, h('span', null, left.refused ? T.leftOn(profile) : T.notAnswering)))
    : null
}

/** The desktop asks first and calls `prepare` only after the user said yes (`host.profileBackendFeatures`). */
const hostAsksFirst = () => Boolean(host.profileBackendFeatures?.prepare)

/** The plugin's line in the desktop's confirm: its own, or the one line about a model that has no key
 *  (`providersView`'s note). The confirm takes one line of 160 characters; a longer one is not cut short. */
const confirmLine = note => (typeof note?.reason === 'string' && note.reason && note.reason.length <= 160 ? note.reason : T.purpose)

/** Turn the sandbox on. `options.handback` is the card's answer ('revert' or 'keep') to `options.view`, the list
 *  of what the last sandbox session left without a review; the host route reviews that session before it pins
 *  anything, and refuses (handback_needs_answer) while its changes have no answer. `options.block` is what keeps
 *  the switch from turning on now; the host route refuses for the same reasons, and its sentence is the toast.
 *  `options.note` is what the user should know before turning it on (a model without a key): the confirm says it. */
async function turnOn(profile, queryClient, options = {}) {
  if (switchBusy) {
    return
  }

  // What keeps the switch from turning on (`providersView`): said before the desktop asks, and nothing starts.
  if (options.block?.reason) {
    host.notify({ id: SWITCH_NOTICE, kind: 'error', message: options.block.reason })

    return
  }

  switchBusy = true
  let started = null
  let final = null
  let handedBack = null
  const answer = options.handback || null
  const rows = Array.isArray(options.view?.rows) ? options.view.rows : []
  // A keep holds for the rows as they were shown; the host route puts back what changed since.
  const body = !answer ? {} : answer === 'keep' ? { handback: answer, seen: Object.fromEntries(rows.map(row => [row.id, row.state])) } : { handback: answer }

  try {
    if (hostAsksFirst()) {
      // Ask first, then start. Cancel: prepare never ran, nothing to undo. The
      // launcher marks the profile at the very end of /switch/on, and the desktop applies its override
      // the moment prepare resolves.
      const { applied } = await host.setProfileBackend({
        plugin: PLUGIN_ID,
        profile,
        purpose: confirmLine(options.note),
        prepare: async () => {
          $switching.set({ profile, to: 'on' })
          started = await rest('/switch/on', { body, method: 'POST', timeoutMs: SWITCH_TIMEOUT_MS })
          handedBack = started.handback

          return { url: started.url, token: started.token }
        }
      })

      if (!applied) {
        if (started) {
          // the desktop refused the address or the set did not apply: stop what prepare started
          const undo = started
          started = null
          await launcherOff(undo.url, undo.undo_ticket)
          final = await settle(false)
        }

        return
      }

      started = null
      final = await settle(true)
      notifyReviewed(handedBack, answer, rows)

      return
    }

    // Older desktops: start, then ask (the confirm then shows the launcher's address as a detail line).
    $switching.set({ profile, to: 'on' })
    started = await rest('/switch/on', { body, method: 'POST', timeoutMs: SWITCH_TIMEOUT_MS })
    handedBack = started.handback
    const { url, token, undo_ticket: undo } = started
    const { applied } = await host.setProfileBackend({ plugin: PLUGIN_ID, profile: started.profile, purpose: confirmLine(options.note), token, url })
    started = null

    if (!applied) {
      await launcherOff(url, undo)
    }

    final = await settle(applied)
    notifyReviewed(handedBack, answer, rows)
  } catch (error) {
    if (started) {
      await launcherOff(started.url, started.undo_ticket).catch(() => undefined)
      final = await settle(false)
    }

    // The last session's changes have no answer yet: the card (re-read below) asks, and nothing started.
    host.notify({ id: SWITCH_NOTICE, kind: 'error', message: errorCode(error) === 'handback_needs_answer' ? T.handbackFirst : errorText(error) })
  } finally {
    seedStatus(queryClient, profile, final)
    $switching.set(null)
    switchBusy = false
    queryClient.invalidateQueries({ queryKey: ['openshell'] })
  }
}

/** Turn the sandbox off. `options.handback` is the card's answer ('revert' or 'keep') to `options.view`, the list
 *  it showed; without one (the switch) the list is read first, and rows that need an answer show the card
 *  instead: no ticket, no dialog, nothing stops. */
async function turnOff(profile, queryClient, options = {}) {
  if (switchBusy) {
    return
  }

  switchBusy = true
  let final = null
  let handedBack = null
  let view = options.view || null
  const answer = options.handback || null

  try {
    if (!answer) {
      // A list that cannot be read never keeps the switch from turning off: the launcher decides again.
      view = await rest('/handback').catch(() => null)

      if (view && view.unanswered > 0) {
        queryClient.setQueryData(keyFor(profile, 'handback'), view)

        return
      }
    }

    const rows = Array.isArray(view?.rows) ? view.rows : []

    if (answer === 'keep') {
      // Recorded before anything stops, for the rows as they were shown. A keep that was not recorded turns
      // nothing off: the launcher would revert what the user asked to keep.
      await rest('/handback/answer', {
        body: {
          answer: 'keep',
          rows: rows.filter(row => !row.fixed).map(row => row.id),
          seen: Object.fromEntries(rows.map(row => [row.id, row.state]))
        },
        method: 'POST'
      })
    }

    // Order (launcher/switch.py): the user confirms first; then the launcher stops the sandbox and
    // clears core's marker (beforeApply); only then does the desktop stop routing the profile to it.
    // The desktop therefore never sees the profile marked without its backend. The header says
    // "Stopping sandbox…" only once the user has confirmed: while the dialog is open nothing stops,
    // and Cancel leaves the page as it was.
    const ticket = await rest('/switch/ticket', { body: {}, method: 'POST' })
    let tornDown = false

    const beforeApply = async () => {
      $switching.set({ profile, to: 'off' })

      try {
        handedBack = (await launcherOff(ticket.url, ticket.ticket, answer))?.handback
      } catch (error) {
        throw new Error(offFailure(profile, error))
      }

      tornDown = true
    }

    const { applied } = await host.clearProfileBackend({ beforeApply, plugin: PLUGIN_ID, profile })

    if (!applied) {
      if (!tornDown) {
        await rest('/switch/ticket', { method: 'DELETE' }).catch(() => undefined)
      }

      return
    }

    if (!tornDown) {
      // A desktop without beforeApply cleared the override first: tear down now (the old order).
      $switching.set({ profile, to: 'off' })

      try {
        handedBack = (await launcherOff(ticket.url, ticket.ticket, answer))?.handback
      } catch (error) {
        host.notify({ id: SWITCH_NOTICE, kind: 'error', message: offFailure(profile, error) })

        return
      }
    }

    final = await settle(false)
    notifyHandedBack(handedBack, answer, rows.map(row => row.id))
  } catch (error) {
    host.notify({ id: SWITCH_NOTICE, kind: 'error', message: errorText(error) })
  } finally {
    seedStatus(queryClient, profile, final)
    $switching.set(null)
    switchBusy = false
    queryClient.invalidateQueries({ queryKey: ['openshell'] })
  }
}

/** The launcher says its sandbox is gone (it failed, or ended on its own): no reply runs in it. A chat that was
 *  left waiting on it never ends its turn, so "a reply is running" must not hold the way out. */
function sandboxDown(status) {
  return Boolean(status?.sandboxed) && (status.state === 'failed' || status.state === 'exited')
}

function SandboxSwitch({ status, handback, lost, left, providers }) {
  const queryClient = useQueryClient()
  const switching = useValue($switching)
  const busyBySession = useValue(host.state.busyBySession)
  const turnRunning = !sandboxDown(status) && Object.values(busyBySession || {}).some(Boolean)
  const on = Boolean(status.sandboxed)
  const mine = switching && switching.profile === status.profile
  // A sandbox that was turned off elsewhere is off, whatever the last answer said.
  const checked = mine ? switching.to === 'on' : lost?.off ? false : on

  // Why the switch cannot be used right now (its tip), or null. First what no click can change here.
  const reason = !hostCanSwitch()
    ? T.needsDesktop
    : left
      ? left.refused
        ? T.leftOn(status.profile) // still switched on: only "sandbox off" in a terminal turns it off
        : T.notAnswering
      : lost
        ? lost.off
          ? T.offElsewhere // nothing answers a click: the notice has the button
          : T.notAnswering
        : stillMarked(status, switching)
          ? T.stillOn(status.profile)
          : status.switch && !status.switch.available
            ? status.switch.reason
            : !status.switch
              ? T.needsDesktop
              : providers?.block
                ? providers.block.reason // a key in config.yaml, or the model's provider cannot work in the sandbox
                : handback?.unanswered > 0
                  ? T.handbackFirst // the card's two buttons turn it off (or on, for the last session's list), with the answer
                  : turnRunning
                    ? T.restartBusyTip
                    : null

  // Off and held by what no click on this page changes (this desktop app, this computer, this profile's
  // providers): the word beside the switch says so. A review or a running reply only makes it wait.
  const held =
    !checked && !switching && !left && !lost && !stillMarked(status, switching) &&
    (!hostCanSwitch() || !status.switch?.available || Boolean(providers?.block))

  const toggle = next => {
    if (switching || next === on) {
      return
    }

    void (next
      ? turnOn(status.profile, queryClient, { block: providers?.block || null, note: providers?.note || null })
      : turnOff(status.profile, queryClient))
  }

  const control = h(Switch, { 'aria-label': T.title, checked, disabled: Boolean(reason || switching), onCheckedChange: toggle })

  return h(
    'div',
    { style: S.switchBox },
    reason ? h(Tip, { label: reason }, h('span', null, control)) : control,
    h('span', { style: S.switchLabel }, checked ? T.on : held ? T.cantTurnOn : T.off)
  )
}

// -- host compatibility (launcher/compat.py) --------------------------------------------------------

/** What keeps this computer from running the sandbox ({ reason, action }), or null. Only while the profile
 *  runs unsandboxed: a running sandbox can always be switched off. */
function hostProblem(status) {
  const check = status?.switch?.host

  if (status?.sandboxed || !check || check.ok) {
    return null
  }

  return { reason: check.reason, action: check.action || null }
}

/** Run the host check again now and show its answer (the host route's fresh status). */
async function recheckHost(profile, queryClient) {
  try {
    seedStatus(queryClient, profile, await rest('/switch/check', { body: {}, method: 'POST' }))
  } catch (error) {
    host.notify({ kind: 'error', message: errorText(error) })
  }
}

function CompatBar({ status }) {
  const queryClient = useQueryClient()
  const [checking, setChecking] = useState(false)
  const problem = hostProblem(status)

  if (!problem) {
    return null
  }

  const recheck = async () => {
    setChecking(true)

    try {
      await recheckHost(status.profile, queryClient)
    } finally {
      setChecking(false)
    }
  }

  const { action } = problem
  const link = action?.url && action.label && osApi?.openExternal

  return h(
    'div',
    { role: 'status', style: S.bar },
    h(
      'div',
      { style: S.barText },
      h('span', null, problem.reason),
      action?.text ? h('span', { style: S.barSub }, action.text) : null
    ),
    h(
      'div',
      { style: S.barButtons },
      link
        ? h(Button, { onClick: () => void osApi.openExternal(action.url), size: 'sm', type: 'button', variant: 'outline' }, action.label)
        : null,
      h(Button, { disabled: checking, loading: checking, onClick: recheck, size: 'sm', type: 'button' }, T.checkAgain)
    )
  )
}

function Header({ status, handback, lost, left, providers }) {
  const switching = useValue($switching)
  const mine = switching && switching.profile === status.profile
  const view = mine
    ? { tone: 'warn', label: switching.to === 'on' ? T.turningOn : T.turningOff }
    : left
      ? { tone: 'bad', label: left.refused ? T.leftState : T.lostState }
      : lost
        ? { tone: lost.off ? 'muted' : 'bad', label: lost.off ? T.notSandboxed : T.lostState }
        : stateView(status)
  const on = Boolean(status.sandboxed)

  const parts = mine || lost || left ? [] : on && status.applied ? [status.capabilities?.label || status.driver, ...policySummary(status.applied, keptOpen(status))] : on ? [] : [T.offNote]

  return h(
    'header',
    null,
    h(
      'div',
      { style: S.header },
      h('div', { style: S.titleRow }, h('h1', { style: S.h1 }, T.title), h('span', { style: S.profile }, status.profile)),
      h(SandboxSwitch, { handback, left, lost, providers, status })
    ),
    h(
      'div',
      { style: S.statusLine },
      h(StatusDot, { tone: view.tone }),
      h('span', { className: view.error ? 'text-destructive' : undefined }, view.label),
      ...parts.flatMap((part, i) => [h('span', { key: `s${i}`, style: S.sep }, '·'), h('span', { key: `p${i}` }, part)])
    )
  )
}

// -- the hand-back card (launcher/handback.py) ------------------------------------------------------

/** "Also changed: 2 skills, 1 memory, SOUL.md, 2 other settings." or null when nothing else changed. */
function alsoChangedLine(view) {
  const counts = view?.tier2?.counts || {}
  const other = view?.other_settings?.count || 0

  const parts = [
    counts.skills ? T.skillCount(counts.skills) : null,
    counts.memories ? T.memoryCount(counts.memories) : null,
    counts.context ? T.contextFile : null,
    other ? T.otherSettingCount(other) : null
  ].filter(Boolean)

  return parts.length ? T.handbackAlso(parts) : null
}

/** What else the sandbox changed: text the agent reads and ordinary settings. One line; Show lists them. Nothing
 *  here needs an answer and nothing here is reverted. */
function AlsoChanged({ view, open, onToggle }) {
  const line = alsoChangedLine(view)

  if (!line) {
    return null
  }

  const items = Array.isArray(view.tier2?.items) ? view.tier2.items : []
  const paths = Array.isArray(view.other_settings?.paths) ? view.other_settings.paths : []
  const more = view.tier2?.more || 0

  return h(
    'div',
    null,
    h(
      'div',
      { style: S.cardLine },
      h('span', null, line),
      h(Button, { onClick: onToggle, size: 'sm', type: 'button', variant: 'ghost' }, open ? T.hide : T.show)
    ),
    open
      ? h(
          List,
          null,
          [
            ...items.map(item => h(Row, { key: item.id, meta: h('span', { style: S.staticAccess }, item.label), mono: true, note: item.detail, plain: true, title: item.name })),
            ...paths.map(path => h(Row, { key: `setting:${path}`, mono: true, plain: true, title: path }))
          ]
        )
      : null,
    open && more ? h('p', { style: S.caption }, T.handbackMore(more)) : null
  )
}

/** What the user kept at an earlier hand-back and is still in the profile (status.handback.kept): one line, and
 *  Show lists the items as the launcher gives them (label, name, detail). They run on this computer like the
 *  profile's own settings, and a kept secret source is what the sandbox's keys are read with. Nothing to answer. */
function KeptLine({ status, items }) {
  const [open, setOpen] = useState(false)
  const count = status?.handback?.kept || 0

  if (!count) {
    return null
  }

  const rows = Array.isArray(items) ? items : []

  return h(
    'section',
    { role: 'region', style: S.section },
    h(
      'div',
      { style: S.cardLine },
      h('span', null, T.keptCount(count)),
      h(Button, { onClick: () => setOpen(!open), size: 'sm', type: 'button', variant: 'ghost' }, open ? T.hide : T.show)
    ),
    open
      ? h(
          List,
          null,
          rows.map(item => h(Row, { key: item.id, meta: h('span', { style: S.staticAccess }, item.label), mono: true, note: item.detail, plain: true, title: item.name }))
        )
      : null
  )
}

/** Whether the page reads the hand-back list for `status`: while the sandbox is on, while the host says the last
 *  session is still to be reviewed, and while kept items are to be listed. */
function reviewWanted(status) {
  return Boolean(status?.sandboxed || status?.handback?.open || status?.handback?.kept)
}

/** Read the hand-back list again. The page calls this when it opens and whenever `stamp` (status.handback.stamp,
 *  which the launcher changes when the watched files do) differs from the last one it saw, so the card and the
 *  preview follow the status the page already polls; there is no timer for the list itself. A launcher without
 *  the stamp is read once, as before. */
function followReview(queryClient, profile, stamp, wanted) {
  if (!wanted || stamp === undefined || stamp === null) {
    return false
  }

  void queryClient.invalidateQueries({ queryKey: keyFor(profile, 'handback') })

  return true
}

/** What the launcher changes by itself, as the status shows it: the sandbox's state and the reason of a restart,
 *  what is open for a sign-in or key, what chat cards allowed or saved, and each provider's state. */
function launcherStamp(status) {
  if (!status) {
    return ''
  }

  const names = rules => Object.keys(rules || {}).sort()
  const paths = folders => (Array.isArray(folders) ? folders.map(folder => `${folder.path}|${folder.access}`) : [])

  return JSON.stringify([
    status.state,
    status.restarting?.label || null,
    Boolean(status.restart_required),
    Boolean(status.restart_queued),
    keptOpen(status).map(dest => `${dest.host}|${dest.port}|${dest.reason}`),
    names(status.temporary?.approved),
    paths(status.temporary?.folders),
    names(status.saved?.network?.approved),
    paths(status.saved?.folders),
    (Array.isArray(status.providers) ? status.providers : []).map(row => `${row.id}|${row.state}|${row.detail}`)
  ])
}

// The stamp last seen for each profile.
const stamps = new Map()

/** Read the rest of the page again when `stamp` (launcherStamp) differs from the last one seen for the profile:
 *  the destinations, "Allowed from chat" and the keys then follow the status the page polls, instead of each
 *  waiting for a poll of its own. The first stamp of a profile reads nothing: the page has just read it all. */
function followLauncher(queryClient, profile, stamp) {
  const seen = stamps.get(profile)

  stamps.set(profile, stamp)

  if (!stamp || seen === undefined || seen === stamp) {
    return false
  }

  for (const part of ['config', 'grants', 'keys']) {
    void queryClient.invalidateQueries({ queryKey: keyFor(profile, part) })
  }

  return true
}

/** The list the page may show for `status`: the launcher's while the sandbox is on; for a profile that is off only
 *  while the host says its last session is still to be reviewed (status.handback.open). A list left in the page's
 *  cache from before a switch-off is not that. */
function reviewView(status, view) {
  return status?.sandboxed || status?.handback?.open ? view : undefined
}

/** The list of what the sandbox changed among the settings and files that run on this computer, shown only
 *  while it has rows. Each row is printed as the launcher gives it (label, name, detail). The two buttons turn
 *  the sandbox off with the answer: Revert puts every row back (the sandbox's versions are kept on the host),
 *  Keep leaves the rows shown as they are.
 *
 *  Beta decision: one answer for the whole list. A change the user made through the app while sandboxed (a
 *  model switched, an MCP server added) is a row like any other, and "Keep and turn off" is the answer for it.
 *  To answer row by row, give each row its own Keep and Revert here: the launcher's /handback/answer already
 *  takes single row ids, and a kept row no longer counts as unanswered. */
function HandbackCard({ status, view, providers }) {
  const queryClient = useQueryClient()
  const switching = useValue($switching)
  const busyBySession = useValue(host.state.busyBySession)
  const turnRunning = !sandboxDown(status) && Object.values(busyBySession || {}).some(Boolean)
  const [open, setOpen] = useState(false)
  const rows = Array.isArray(view?.rows) ? view.rows : []

  if (!rows.length) {
    return null
  }

  // While the sandbox is on the two buttons turn it off. For a profile that is off the list is the last
  // session's, which ended without an answer: the same two answers, and the sandbox turns on after them.
  const on = Boolean(status.sandboxed)
  const off = handback => (on ? turnOff : turnOn)(status.profile, queryClient, on ? { handback, view } : { block: providers?.block || null, handback, note: providers?.note || null, view })
  // Where the switch cannot turn on (this desktop, this computer, this profile's providers), neither can the
  // buttons: its reason is the tip.
  const blocked = on
    ? null
    : !hostCanSwitch() || !status.switch
      ? T.needsDesktop
      : !status.switch.available
        ? status.switch.reason
        : providers?.block
          ? providers.block.reason
          : null
  const disabled = Boolean(switching) || turnRunning || Boolean(blocked)
  const tip = blocked || (turnRunning ? T.restartBusyTip : null)
  const incomplete = Array.isArray(view.incomplete) ? view.incomplete : []

  const badge = row =>
    row.fixed
      ? h(Badge, { variant: 'muted' }, T.handbackFixed)
      : row.can_restore === false
        ? h(Tip, { label: T.handbackNoCopyTip[view.no_copy] || T.handbackNoCopyTip.hold }, h(Badge, { variant: 'warn' }, T.handbackNoCopy))
        : null

  // Only what can happen is offered: rows that are always reverted take no answer, so a list of nothing else
  // has no buttons (the switch itself turns off, and they are put back then).
  const answerable = rows.some(row => !row.fixed)

  const buttons = [
    h(Button, { disabled, key: 'revert', onClick: () => off('revert'), size: 'sm', type: 'button' }, on ? T.handbackRevert : T.handbackRevertOn),
    h(Button, { disabled, key: 'keep', onClick: () => off('keep'), size: 'sm', type: 'button', variant: 'outline' }, on ? T.handbackKeep : T.handbackKeepOn)
  ]

  return h(
    'section',
    { role: 'region', style: S.section },
    h('div', { style: S.sectionHead }, h('h2', { style: S.h2 }, T.handbackTitle)),
    h('p', { style: S.cardCaption }, on ? T.handbackCaption : T.handbackCaptionOff),
    h(
      List,
      null,
      rows.map(row =>
        h(Row, {
          badge: badge(row),
          key: row.id,
          meta: h('span', { style: S.staticAccess }, row.label),
          mono: true,
          note: row.detail,
          plain: true,
          title: row.name
        })
      )
    ),
    h(AlsoChanged, { onToggle: () => setOpen(!open), open, view }),
    incomplete.length ? h('p', { style: S.caption }, T.handbackIncomplete(incomplete)) : null,
    answerable
      ? h(
          'div',
          { style: S.cardButtons },
          tip ? buttons.map(button => h(Tip, { key: button.key, label: tip }, h('span', null, button))) : buttons
        )
      : h('p', { style: S.caption }, on ? T.handbackFixedOnly : T.handbackFixedOnlyOff)
  )
}

// Keys the launcher withheld from the sandbox: the profile's model entry names an endpoint that is not the one it
// had when the sandbox was switched on (status.endpoint_changed; the sandbox can edit its own config.yaml, the
// launcher's host-only copy it cannot). Allow lets the key be used there; it applies after a restart, which the
// restart bar then offers. A sandbox switched on by an older version has no such copy (status.pinned false):
// nothing to allow, turning it off and on makes one.
const endpointLine = row => `${row.env} -> ${row.host}:${row.port}`
const endpointsKey = (profile, rows) => [profile, ...rows.map(endpointLine)].join('|')

function withheldEndpoints(status, dismissed) {
  const rows = status.sandboxed && Array.isArray(status.endpoint_changed) ? status.endpoint_changed : []

  return rows.length && dismissed !== endpointsKey(status.profile, rows) ? rows : []
}

function EndpointBar({ status, send }) {
  const rows = withheldEndpoints(status, useValue($endpointsDismissed))
  const [sending, setSending] = useState(false)

  if (!rows.length) {
    return null
  }

  const pinned = status.pinned !== false

  const allow = async () => {
    setSending(true)

    try {
      for (const row of rows) {
        await send('/endpoints/allow', 'POST', { env: row.env, host: row.host, port: row.port })
      }
    } catch (error) {
      host.notify({ kind: 'error', message: error.message })
    } finally {
      setSending(false)
    }
  }

  return h(
    'div',
    { role: 'status', style: S.bar },
    h(
      'div',
      { style: S.barText },
      h('span', null, !pinned ? T.endpointsUnpinned : rows.length > 1 ? T.endpointsChanged : T.endpointChanged),
      ...rows.map(row => h('span', { key: endpointLine(row), style: S.barSub }, endpointLine(row)))
    ),
    h(
      'div',
      { style: S.barButtons },
      pinned ? h(Button, { disabled: sending, loading: sending, onClick: allow, size: 'sm', type: 'button' }, T.allow) : null,
      h(
        Button,
        {
          disabled: sending,
          onClick: () => $endpointsDismissed.set(endpointsKey(status.profile, rows)),
          size: 'sm',
          type: 'button',
          variant: 'outline'
        },
        T.dismiss
      )
    )
  )
}

// -- providers --------------------------------------------------------------------------------------
//
// One row per provider of the profile, with what it does in the sandbox. Off: the host route's config carries
// the rows (`providers`) and what keeps the switch from turning on (`providers_block`). On: the launcher's
// status carries the rows. Either is polled, so a row follows what the backend reports.

/** `{ known, on, rows, block, note }`: the rows to show (`known` false when the backend sent none: an older
 *  launcher, a config that has not come yet) and, for a profile that is off, what keeps the switch from turning on
 *  (`block`) or, when nothing does, what to know before turning it on (`note`: a model without a key). */
function providersView(status, config) {
  const on = Boolean(status?.sandboxed)
  const source = on ? status?.providers : config?.providers
  const rows = Array.isArray(source) ? source.filter(row => row && typeof row === 'object' && row.id) : []
  const block = !on && config?.providers_block?.reason ? config.providers_block : null
  const note = !on && !block && config?.providers_note?.reason ? config.providers_note : null

  return { block, known: Array.isArray(source), note, on, rows }
}

/** A sign-in that ended while the sandbox is on is said once, wherever the user is: a notice with the provider's
 *  name and the row's own sentence (what happened and what to do), the words the Sandbox page shows. It stays until
 *  it is dismissed. A sign-in that is renewed takes its notice back, and a later end is said again. A status that
 *  did not come, or that carries no rows, changes nothing. */
function tellExpired(profile, status) {
  if (!status || typeof status !== 'object') {
    return
  }

  const all = $told.get()
  const told = all[profile] || {}

  if (!status.sandboxed) {
    // Switched off: the next session starts over.
    if (Object.keys(told).length) {
      $told.set({ ...all, [profile]: {} })
    }

    return
  }

  if (!Array.isArray(status.providers)) {
    return
  }

  const next = {}

  for (const row of status.providers) {
    if (!row || typeof row !== 'object' || !row.id) {
      continue
    }

    const id = `openshell:sign-in:${profile}:${row.id}`

    if (row.state === 'expired' && row.label && row.detail) {
      next[row.id] = row.detail

      if (told[row.id] !== row.detail) {
        host.notify({ id, kind: 'error', message: row.detail, title: row.label })
      }
    } else if (row.state === 'ready' && told[row.id]) {
      host.notify({ durationMs: 5000, id, kind: 'info', message: T.signInRenewed, title: row.label })
    }
  }

  $told.set({ ...all, [profile]: next })
}

/** What `tellExpired` reads of a status, as one string: the effect that tells runs when it changes. */
const signInsKey = status =>
  status?.sandboxed && Array.isArray(status.providers)
    ? status.providers.map(row => (row && row.id ? `${row.id}|${row.state}|${row.detail || ''}` : '')).join('\n')
    : String(Boolean(status?.sandboxed))

/** Save a key and say in one line what that means for a sandbox that is on: the launcher's own word for it (in
 *  use now, after a restart, or not used there). A profile that is off gets no line: the key is saved. */
async function saveKey(send, name, value) {
  const done = await send('/keys', 'PUT', { key: name, value })
  const line = typeof done?.sandbox === 'string' && Object.hasOwn(T.keySaved, done.sandbox) ? T.keySaved[done.sandbox] : null

  if (line) {
    host.notify({ kind: 'info', message: line })
  }
}

/** Move keys written in config.yaml to .env (the rows' `path`). The backend's answer is a toast: what was moved
 *  and under which name, or why not, in its own words. */
async function moveKeys(send, rows) {
  try {
    const done = await send('/providers/move', 'POST', { keys: rows.map(row => row.path) })
    const moved = Array.isArray(done?.moved) ? done.moved : []
    const left = Array.isArray(done?.left) ? done.left : []

    const message = [moved.length ? T.moved(moved) : null, left.length ? T.movedLeft(left) : null].filter(Boolean).join(' ')

    if (message) {
      host.notify({ kind: left.length ? 'warning' : 'info', message })
    }
  } catch (error) {
    // A backend without the route answers with the web server's two words.
    host.notify({ kind: 'error', message: /^(Not Found|Method Not Allowed)$/i.test(error.message) ? T.moveUnavailable : error.message })
  }
}

/** Ask before anything is written: which keys, and where each goes. */
function askMove(ask, send, rows) {
  ask({
    kind: 'confirm',
    title: T.moveTitle(rows.length),
    body: T.moveBody(rows.length),
    target: rows.map(T.moveLine).join(', '),
    confirmLabel: T.move,
    run: () => moveKeys(send, rows)
  })
}

/** Above the tabs. Off: why the switch does not turn on and, under it, where each key written in config.yaml
 *  goes, with the one button that moves them, or the reason's own second line (a backend that sends none: the
 *  row's sentence). On: a sign-in that expired, with its provider's name, the row's badge and the row's own
 *  sentence (what happened and what to do about it). */
function ProvidersBar({ view, ask, send, pending }) {
  if (!view) {
    return null
  }

  if (view.block) {
    const ids = Array.isArray(view.block.rows) ? view.block.rows : []
    const rows = view.rows.filter(row => ids.includes(row.id))
    const movable = view.block.code === 'key_in_config' ? rows.filter(row => row.path && row.env) : []
    const own = typeof view.block.detail === 'string' ? view.block.detail : null

    return h(
      'div',
      { role: 'status', style: S.bar },
      h(
        'div',
        { style: S.barText },
        h('span', null, view.block.reason),
        ...(own === null
          ? rows.map(row => h('span', { key: row.id, style: S.barSub }, row.path && row.env ? T.willMove(row) : row.detail))
          : own
            ? [h('span', { key: 'own', style: S.barSub }, own)]
            : [])
      ),
      movable.length
        ? h(
            'div',
            { style: S.barButtons },
            h(Button, { disabled: Boolean(pending), onClick: () => askMove(ask, send, movable), size: 'sm', type: 'button' }, T.moveToEnv)
          )
        : null
    )
  }

  const expired = view.rows.filter(row => row.state === 'expired')

  if (!expired.length) {
    return null
  }

  return h(
    'div',
    { role: 'status', style: S.bar },
    h(
      'div',
      { style: S.barText },
      ...expired.flatMap(row => [
        h('span', { key: row.id, style: S.barHead }, row.label, h(Badge, { variant: PROVIDER_BADGE.expired }, T.providerState.expired)),
        h('span', { key: `${row.id}:d`, style: S.barSub }, row.detail)
      ])
    )
  )
}

const PROVIDER_BADGE = { expired: 'destructive', key_in_config: 'warn', needs_sign_in: 'warn', no_key: 'muted', unavailable: 'muted', withheld: 'warn' }

/** The rows, in the Keys part of the page. A row shows a name, a state and a sentence: never a value, and nothing
 *  to reveal. The bar above the tabs has the button that moves the keys written in config.yaml; where several are
 *  written there, each row also has its own, for that key alone. Where no row was ever read because a file cannot
 *  be read, that reason stands in the list's place. */
function ProvidersSection({ view, ask, send, pending }) {
  if (!view?.known) {
    return null
  }

  const movable = view.block?.code === 'key_in_config' ? view.rows.filter(row => row.state === 'key_in_config' && row.path && row.env) : []

  const rows = view.rows.length
    ? view.rows.map(row => {
        const state = T.providerState[row.state]
        const code = row.path || (row.env && row.env !== row.label ? row.env : null)

        return h(Row, {
          badge: [
            code ? h('span', { className: 'font-mono', key: 'c', style: S.rowCode }, code) : null,
            row.main ? h(Tip, { key: 'm', label: T.mainModelTip }, h(Badge, { variant: 'muted' }, T.mainModel)) : null,
            row.fallback ? h(Tip, { key: 'f', label: T.fallbackModelTip }, h(Badge, { variant: 'muted' }, T.fallbackModel)) : null,
            state ? h(Badge, { key: 's', variant: PROVIDER_BADGE[row.state] || 'muted' }, state) : null
          ],
          key: row.id,
          meta:
            !view.on && movable.length > 1 && movable.includes(row)
              ? h(Button, { disabled: pending, onClick: () => askMove(ask, send, [row]), size: 'sm', type: 'button', variant: 'outline' }, T.moveToEnv)
              : null,
          note: row.detail ? h('span', { style: S.rowWrap }, row.detail) : null,
          plain: true,
          title: row.label
        })
      })
    : [h('div', { key: 'none', style: S.empty }, view.block?.code === 'unreadable' ? view.block.reason : T.noProviders)]

  return h(Section, { title: T.providers }, h(List, null, rows))
}

function RestartBar({ status, send }) {
  const busyBySession = useValue(host.state.busyBySession)
  const turnRunning = Object.values(busyBySession || {}).some(Boolean)
  const restarting = status.state === 'restarting' || status.state === 'starting'
  const [sending, setSending] = useState(false)
  // A restart the launcher makes by itself (a grant removed on the page) needs no button: the header says it.
  const launchers = Boolean(status.restart_queued) || (restarting && Boolean(status.restarting?.label))

  if (!status.restart_required || launchers) {
    return null
  }

  const restart = async () => {
    setSending(true)

    try {
      await send('/restart', 'POST', {}, RESTART_TIMEOUT_MS)
    } catch (error) {
      host.notify({ kind: 'error', message: error.message })
    } finally {
      setSending(false)
    }
  }

  const button = h(
    Button,
    { disabled: turnRunning || restarting || sending, loading: sending || restarting, onClick: restart, size: 'sm', type: 'button' },
    T.restart
  )

  return h(
    'div',
    { role: 'status', style: S.bar },
    h('span', null, T.restartBar),
    turnRunning ? h(Tip, { label: T.restartBusyTip }, h('span', null, button)) : button
  )
}

// -- folders ----------------------------------------------------------------------------------------

const folderKey = folder => `${String(folder.path).toLowerCase()}|${folder.access}`

function FoldersSection({ config, status, send, sendQuietly, pending, ask }) {
  const applied = status.applied ? new Set(status.applied.folders.map(folderKey)) : null
  const folders = config.folders

  const put = next => ['/folders', 'PUT', { folders: next.map(({ path, access }) => ({ path, access })) }]

  const setAccess = (folder, access) => {
    const next = folders.map(f => (f.path === folder.path ? { ...f, access } : f))

    if (access === 'rw') {
      ask({
        kind: 'confirm',
        title: T.writeTitle(baseName(folder.path)),
        body: T.grantRw,
        target: folder.path,
        confirmLabel: T.writeConfirm,
        run: () => send(...put(next))
      })
    } else {
      sendQuietly(...put(next))
    }
  }

  const remove = folder => sendQuietly(...put(folders.filter(f => f.path !== folder.path)))

  const rows = [
    h(Row, {
      key: 'profile',
      title: T.profileFolder,
      badge: h(Tip, { label: T.keysHiddenTip }, h(Badge, { variant: 'muted' }, T.keysHidden)),
      sub: config.profile_folder,
      access: h('span', { style: S.staticAccess }, T.readWrite)
    }),
    ...folders.map(folder =>
      h(Row, {
        key: folder.path,
        title: baseName(folder.path),
        sub: folder.path,
        meta: folder.missing
          ? h(Tip, { label: T.missingTip }, h(Badge, { variant: 'warn' }, T.missing))
          : applied && !applied.has(folderKey(folder))
            ? h(PendingBadge)
            : null,
        access: h(AccessSelect, { disabled: pending, onChange: access => setAccess(folder, access), value: folder.access }),
        action: h(RemoveButton, { disabled: pending, onClick: () => remove(folder) })
      })
    )
  ]

  const add = () =>
    ask({
      kind: 'folder',
      next: entry => ({
        kind: 'confirm',
        title: T.grantTitle,
        body: entry.access === 'rw' ? T.grantRw : T.grantRo,
        target: entry.path,
        confirmLabel: T.grantConfirm,
        run: () => send(...put([...folders, entry]))
      })
    })

  return h(Section, { aside: h(AddButton, { disabled: pending, label: T.addFolder, onClick: add }), title: T.folders }, h(List, null, rows))
}

function AddFolderDialog({ dialog, onClose, ask, send }) {
  const [path, setPath] = useState('')
  const [access, setAccess] = useState('ro')

  const submit = async () => {
    const entry = await send('/folders/check', 'POST', { path, access })
    ask(dialog.next(entry))
  }

  return h(
    FormDialog,
    { onClose, onSubmit: submit, open: true, submitLabel: T.next, title: T.addFolder.replace('…', '') },
    h(Field, { label: T.path }, h(Input, { autoFocus: true, className: 'font-mono', onChange: e => setPath(e.target.value), placeholder: 'C:\\Users\\you\\Projects', value: path })),
    h(Field, { label: T.access }, h(AccessSelect, { onChange: setAccess, value: access }))
  )
}

// -- network ----------------------------------------------------------------------------------------

// The names a service on this computer goes by, in a model's address and in the launcher's list.
const THIS_COMPUTER = new Set(['localhost', '127.0.0.1', '::1', '[::1]', 'host.openshell.internal'])

// A destination is a website (`host`, where the driver filters by hostname) or an address/CIDR block.
const ruleTarget = rule => rule.host || rule.cidr
const ruleKey = rule => `${ruleTarget(rule)}|${rule.port}`

function NetworkSection({ config, status, send, sendQuietly, pending, ask }) {
  const network = config.network
  const applied = status.applied?.network
  const appliedRules = applied ? new Set(applied.allow.map(ruleKey)) : null
  // An edit sends the internet setting and the destinations. What chat cards saved (network.approved) stays as it
  // is on the host and is never sent back.
  const put = next => ['/network', 'PUT', { egress: next.egress, allow: next.allow }]

  const setEgress = egress => {
    if (egress === network.egress) {
      return
    }

    if (egress === 'allow') {
      ask({
        kind: 'confirm',
        title: T.internetTitle,
        body: T.internetBody,
        confirmLabel: T.allow,
        run: () => send(...put({ ...network, egress }))
      })
    } else {
      sendQuietly(...put({ ...network, egress }))
    }
  }

  // A model endpoint whose key the launcher withheld (status.endpoint_changed, the rows the bar above the tabs
  // names): reachable, but the row says what the sandbox lacks there instead of a bare "Allowed".
  const withheld = Array.isArray(status.endpoint_changed) ? status.endpoint_changed : []

  const keyWithheld = endpoint => {
    let at = null

    try {
      at = new URL(endpoint.url)
    } catch {
      return false
    }

    const port = Number(at.port) || (at.protocol === 'https:' ? 443 : 80)

    return withheld.some(row => row.label === endpoint.label && String(row.host).toLowerCase() === at.hostname.toLowerCase() && Number(row.port) === port)
  }

  const reach = endpoint => {
    const ok = endpoint.reach === 'allowed'

    if (ok && keyWithheld(endpoint)) {
      return h(Tip, { label: T.keyWithheldTip }, h(Badge, { variant: 'warn' }, T.keyWithheld))
    }

    return h(
      Tip,
      { label: T.reachTip[ok ? endpoint.via : 'blocked'] || T.reachTip.blocked },
      h(Badge, { variant: ok ? 'success' : 'destructive' }, ok ? T.allowed : T.blocked)
    )
  }

  // A model's address a key or sign-in is used at is listed among the allowed destinations with what it is for
  // (config.opened): its fixed row would say it a second time.
  const listed = endpoint => {
    let at = null

    try {
      at = new URL(endpoint.url)
    } catch {
      return false
    }

    const port = Number(at.port) || (at.protocol === 'https:' ? 443 : 80)
    const name = host => (THIS_COMPUTER.has(String(host).toLowerCase()) ? 'localhost' : String(host).toLowerCase())

    return network.egress === 'deny' && keptOpen(config).some(dest => name(dest.host) === name(at.hostname) && Number(dest.port) === port)
  }

  const top = [
    h(Row, {
      key: 'egress',
      title: T.internet,
      meta: applied && applied.egress !== network.egress ? h(PendingBadge) : null,
      access: h(
        Select,
        { disabled: pending, onValueChange: setEgress, value: network.egress },
        h(SelectTrigger, { 'aria-label': T.internet, className: 'w-full', size: 'sm' }, h(SelectValue, null)),
        h(SelectContent, null, h(SelectItem, { value: 'deny' }, T.blocked), h(SelectItem, { value: 'allow' }, T.allowed))
      )
    }),
    ...config.endpoints.filter(endpoint => !listed(endpoint)).map(endpoint =>
      h(Row, {
        key: `${endpoint.label}|${endpoint.url}`,
        access: h('span', { style: S.staticAccess }, reach(endpoint)),
        sub: endpoint.url,
        title: endpoint.label
      })
    )
  ]

  const remove = rule => sendQuietly(...put({ ...network, allow: network.allow.filter(r => ruleKey(r) !== ruleKey(rule)) }))

  const add = () =>
    ask({
      kind: 'destination',
      next: rule => ({
        kind: 'confirm',
        title: T.destinationTitle,
        target: `${ruleTarget(rule)} · ${T.portLabel(rule.port)}`,
        confirmLabel: T.allow,
        run: () => send(...put({ ...network, allow: [...network.allow, rule] }))
      })
    })

  // Destinations the launcher keeps open by itself (config.builtin), each with its reason: listed first, with
  // nothing to remove, and never sent back with an edit.
  const builtin = keptOpen(config).map(dest =>
    h(Row, {
      key: `builtin|${dest.host}|${dest.port}`,
      mono: true,
      title: dest.host,
      note: dest.reason,
      access: h('span', { style: S.staticAccess }, T.portLabel(dest.port))
    })
  )

  const rules = network.allow.length
    ? network.allow.map(rule =>
        h(Row, {
          key: ruleKey(rule),
          meta: appliedRules && !appliedRules.has(ruleKey(rule)) ? h(PendingBadge) : null,
          mono: true,
          title: ruleTarget(rule),
          access: h('span', { style: S.staticAccess }, T.portLabel(rule.port)),
          action: h(RemoveButton, { disabled: pending, onClick: () => remove(rule) })
        })
      )
    : builtin.length
      ? []
      : [h('div', { key: 'none', style: S.empty }, T.noDestinations)]

  const loopbackOpen = config.capabilities?.host_loopback === 'open'

  return h(
    Section,
    { caption: loopbackOpen ? T.loopbackCaption : null, title: T.network },
    h(List, null, top),
    network.egress === 'deny'
      ? h(
          'div',
          null,
          h(
            'div',
            { style: { ...S.sectionHead, marginTop: '1.25rem' } },
            h('h3', { style: { ...S.h3, margin: 0 } }, T.destinations),
            h(AddButton, { disabled: pending, label: T.addDestination, onClick: add })
          ),
          h(List, null, [...builtin, ...rules])
        )
      : null
  )
}

function AddDestinationDialog({ dialog, onClose, ask, send }) {
  const [cidr, setCidr] = useState('')
  const [port, setPort] = useState('')

  const submit = async () => {
    const address = cidr.trim()
    // A name with letters and no colon is a website; the backend refuses it where the driver can't filter by name.
    const target = /[a-z]/i.test(address) && !address.includes(':') ? { host: address } : { cidr: address }
    const rule = await send('/network/check', 'POST', { ...target, port: port.trim() })
    ask(dialog.next(rule))
  }

  return h(
    FormDialog,
    { onClose, onSubmit: submit, open: true, submitLabel: T.next, title: T.addDestination.replace('…', '') },
    h(Field, { label: T.address }, h(Input, { autoFocus: true, className: 'font-mono', onChange: e => setCidr(e.target.value), placeholder: 'example.com or 203.0.113.0/24', value: cidr })),
    h(Field, { label: T.port }, h(Input, { className: 'font-mono', inputMode: 'numeric', onChange: e => setPort(e.target.value), placeholder: '443', value: port }))
  )
}

// -- grants from chat cards -------------------------------------------------------------------------

/** What chat cards allowed (launcher/cards.py grants_view): Allow (until the sandbox is switched off) and
 *  Always allow (saved hosts), live, each with Remove. Folders saved with Always allow are in Folders. */
function GrantsSection({ grants, pending, ask, send }) {
  const items = grants?.grants || []

  const remove = grant =>
    ask({
      kind: 'confirm',
      title: T.removeGrantTitle(grant.label || grant.target),
      body: grant.kind === 'folder' ? T.removeGrantFolder : T.removeGrantNetwork,
      target: grant.target,
      list: grant.kind !== 'folder' && Boolean(grant.label),
      confirmLabel: T.removeGrant,
      run: () => send('/grants', 'DELETE', { id: grant.id })
    })

  const sub = grant => {
    if (grant.kind === 'folder') {
      return grant.target
    }

    const how = grant.bound ? T.grantBound : T.grantNetwork(grant.ports)

    return grant.label ? `${grant.target} · ${how}` : how
  }

  const rows = items.length
    ? items.map(grant =>
        h(Row, {
          key: grant.id,
          mono: !grant.label,
          title: grant.label || (grant.kind === 'folder' ? baseName(grant.target) : grant.target),
          sub: sub(grant),
          // A tool category lists its services: every name stays readable.
          wrap: grant.kind !== 'folder' && Boolean(grant.label),
          // What a tool category's services let the agent reach beyond the hosts listed (the launcher's words).
          note: grant.note || null,
          meta:
            grant.status === 'pending'
              ? h(
                  Tip,
                  { label: grant.kind === 'folder' || grant.restart ? T.grantRestartTip : T.grantApplyingTip },
                  h(Badge, { variant: 'warn' }, T.grantApplying)
                )
              : null,
          access: h(
            'span',
            { style: S.staticAccess },
            h(Tip, { label: T.grantScopeTip[grant.scope] || '' }, h('span', null, T.grantScope[grant.scope] || grant.scope))
          ),
          action: h(RemoveButton, { disabled: pending, label: T.removeGrant, onClick: () => remove(grant) })
        })
      )
    : [h('div', { key: 'none', style: S.empty }, T.noGrants)]

  return h(Section, { caption: T.grantsCaption, title: T.grants }, h(List, null, rows))
}

// -- keys -------------------------------------------------------------------------------------------

function KeysSection({ keys, pending, ask, send }) {
  const rows = keys.keys.length
    ? keys.keys.map(key =>
        h(Row, {
          key: key.name,
          mono: true,
          title: key.name,
          wide: [
            h(Button, { disabled: pending, key: 'r', onClick: () => ask({ kind: 'key', name: key.name }), size: 'sm', type: 'button', variant: 'outline' }, T.replace),
            h(RemoveButton, {
              disabled: pending,
              key: 'x',
              onClick: () =>
                ask({
                  kind: 'confirm',
                  title: T.removeKeyTitle(key.name),
                  body: T.removeKeyBody,
                  confirmLabel: T.remove,
                  destructive: true,
                  run: () => send('/keys', 'DELETE', { key: key.name })
                })
            })
          ]
        })
      )
    : [h('div', { key: 'none', style: S.empty }, T.noKeys)]

  return h(
    Section,
    {
      aside: h(AddButton, { disabled: pending, label: T.addKey, onClick: () => ask({ kind: 'key' }) }),
      caption: T.credentials[keys.credentials] || null,
      title: T.keys
    },
    h(List, null, rows)
  )
}

function KeyDialog({ dialog, onClose, send }) {
  const [name, setName] = useState(dialog.name || '')
  const [value, setValue] = useState('')

  const submit = async () => {
    await saveKey(send, name.trim(), value)
    onClose()
  }

  return h(
    FormDialog,
    { onClose, onSubmit: submit, open: true, submitLabel: T.save, title: dialog.name ? T.replaceTitle(dialog.name) : T.addKeyTitle },
    dialog.name
      ? null
      : h(Field, { label: T.name }, h(Input, { autoFocus: true, className: 'font-mono', onChange: e => setName(e.target.value), placeholder: 'EXAMPLE_API_KEY', value: name })),
    h(Field, { label: T.value }, h(Input, { autoFocus: Boolean(dialog.name), onChange: e => setValue(e.target.value), type: 'password', value }))
  )
}

// -- activity ---------------------------------------------------------------------------------------
//
// One live timeline of what the sandbox allowed and refused (launcher/activity.py): OpenShell's audit
// (network), refused file accesses and file writes from the agent's tool results (files), and the
// answers to access cards (decisions), newest first. Policy history with Restore where the driver keeps
// revisions. Export saves the rows shown as OCSF JSON Lines (mapping: docs/activity-log.md).

const ACTIVITY_POLL_MS = 3000
const REVISIONS_POLL_MS = 5000
const ROLLBACK_TIMEOUT_MS = 120_000
const ACTIVITY_LIMIT = 500
const WINDOW_SECONDS = { hour: 3600, day: 86_400, week: 604_800, all: null }

// Module state, so the tab and filters survive leaving the page.
const $pageTab = atom('settings')
const $activityFilter = atom({ kind: 'all', denied: false, window: 'day' })

const TA = {
  settings: 'Settings',
  activity: 'Activity',
  kinds: { all: 'All', network: 'Network', files: 'Files', decisions: 'Decisions' },
  deniedOnly: 'Denied only',
  period: 'Period',
  windows: { hour: 'Last hour', day: 'Last 24 hours', week: 'Last 7 days', all: 'All time' },
  export: 'Export OCSF JSON…',
  empty: 'No activity in this period.',
  emptyDenied: 'Nothing denied in this period.',
  truncated: n => `Showing the latest ${n}.`,
  allowed: 'Allowed',
  denied: 'Denied',
  ended: 'Ended',
  removed: 'Removed',
  notApplied: 'Not applied',
  pendingTip: 'Applies when the turn ends.',
  openChat: 'Open chat',
  openChatTitled: title => `Open chat: ${title}`,
  read: 'Read',
  write: 'Write',
  you: 'You',
  model: 'Model',
  sandbox: 'Sandbox',
  cards: { network: 'Network access', access: 'Folder access' },
  why: { 'turn ended': 'Turn ended', 'chat closed': 'Chat closed', 'launcher stopped': 'Sandbox stopped' },
  reason: text => `Reason: ${text}`,
  history: 'Policy history',
  historyOff: 'Available while the sandbox runs.',
  revision: v => `Revision ${v}`,
  revisionStatus: { loaded: 'Active', superseded: 'Replaced', failed: 'Failed', pending: 'Pending' },
  restore: 'Restore…',
  restoreTitle: v => `Restore revision ${v}?`,
  restoreBody: "Allowed destinations go back to this revision. Folders don't change.",
  restoreCuts: 'Open connections close, including a reply in progress.',
  restoreConfirm: 'Restore',
  noDestinations: 'No allowed destinations.',
  loading: 'Loading…'
}

const TIME_FORMAT = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' })
const DAY_FORMAT = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })

function when(seconds) {
  const date = new Date(seconds * 1000)

  return date.toDateString() === new Date().toDateString() ? TIME_FORMAT.format(date) : DAY_FORMAT.format(date)
}

const SA = {
  tabs: { marginTop: '1.5rem' },
  toolbar: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem',
    margin: '1.25rem 0 0.75rem'
  },
  group: { display: 'flex', alignItems: 'center', gap: '0.875rem' },
  check: { display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', color: 'var(--ui-text-secondary)', cursor: 'pointer' },
  // The theme's input border can match the page background; keep the box visible.
  checkbox: { borderColor: 'var(--ui-stroke-primary)' },
  tabsList: { alignSelf: 'flex-start' },
  row: {
    display: 'grid', gridTemplateColumns: '5.5rem 1rem minmax(0, 1fr) auto 1.75rem', alignItems: 'center',
    columnGap: '0.625rem', padding: '0.5rem 0.5rem 0.5rem 0.875rem', minHeight: '2.875rem'
  },
  time: { fontSize: '0.75rem', color: 'var(--ui-text-tertiary)', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' },
  icon: { display: 'flex', color: 'var(--ui-text-tertiary)' },
  quietTitle: { color: 'var(--ui-text-tertiary)' },
  badges: { display: 'flex', alignItems: 'center', gap: '0.375rem', justifySelf: 'end' },
  destinations: { marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--ui-text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }
}

const KIND_OPTIONS = Object.entries(TA.kinds).map(([id, label]) => ({ id, label }))
const ROW_ICONS = { network: 'globe', files: 'file', decisions: 'person' }

function activityParams(filter) {
  const params = new URLSearchParams()
  const span = WINDOW_SECONDS[filter.window]

  params.set('since', span ? String(Math.floor(Date.now() / 1000 - span)) : '0')
  params.set('limit', String(ACTIVITY_LIMIT))

  if (filter.kind !== 'all') {
    params.set('kinds', filter.kind)
  }

  if (filter.denied) {
    params.set('denied', '1')
  }

  return params.toString()
}

function useActivity(profile, filter) {
  return useQuery({
    queryKey: keyFor(profile, ['activity', filter.kind, filter.denied, filter.window]),
    // The window is measured from each fetch, so it slides with the clock.
    queryFn: () => polled(`/activity?${activityParams(filter)}`),
    refetchInterval: ACTIVITY_POLL_MS,
    ...LIVE
  })
}

function openChat(id) {
  const opened = typeof host.openSession === 'function' ? host.openSession(id) : host.navigate(`/${encodeURIComponent(id)}`)

  Promise.resolve(opened).catch(error => host.notify({ kind: 'error', message: errorText(error) }))
}

/** OpenShell's reason without the destination the row already names ("endpoint x:443 is not allowed…"). */
function shortReason(reason) {
  const text = String(reason || '').trim()
  const match = /^endpoint \S+ is (.+)$/i.exec(text)
  const short = match ? match[1] : text

  return short ? short[0].toUpperCase() + short.slice(1) : null
}

/** The refusal in a tool result, as the system worded it ("Permission denied"). */
function refusalPhrase(reason) {
  const match = /permission denied|access is denied|operation not permitted|read-only file system|no such file or directory/i.exec(
    String(reason || '')
  )

  return match ? match[0][0].toUpperCase() + match[0].slice(1).toLowerCase() : null
}

function activitySub(row) {
  const parts =
    row.kind === 'network'
      ? [
          row.program,
          // A request a sign-in or key was used for: the tool category that opened its host, else the model.
          String(row.rule || '').startsWith('_provider_') ? row.use || TA.model : null,
          row.outcome === 'denied' ? shortReason(row.reason) : null
        ]
      : row.kind === 'files'
        ? [
            row.tool,
            row.access === 'write' ? TA.write : TA.read,
            row.outcome === 'denied' ? refusalPhrase(row.reason) : null,
            parentPath(row.path)
          ]
        : row.kind === 'decisions'
          ? [
              row.who === 'you' ? TA.you : TA.sandbox,
              TA.cards[row.card] || null,
              row.program,
              row.why ? TA.why[row.why] || row.why : null,
              row.reason ? TA.reason(row.reason) : null,
              row.error || null,
              row.path && !row.host ? row.path : null
            ]
          : []

  return parts.filter(Boolean).join(' · ')
}

/** A row names a file or folder by its last part; the full path follows in the second line. */
const parentPath = path => (path ? String(path).replace(/[\\/][^\\/]*[\\/]?$/, '') || null : null)

const activityTitle = row => (row.path && !row.host ? baseName(row.path) : row.title)

function ActivityBadges({ row }) {
  const badges = []

  if (row.kind === 'decisions') {
    if (row.choice === 'ended') {
      badges.push(h(Badge, { key: 'b', variant: 'muted' }, row.who === 'you' ? TA.removed : TA.ended))
    } else {
      badges.push(h(Badge, { key: 'b', variant: row.choice === 'deny' ? 'destructive' : 'success' }, row.label))
    }

    if (row.status === 'pending') {
      badges.push(h(Tip, { key: 'p', label: TA.pendingTip }, h(Badge, { variant: 'warn' }, T.pending)))
    } else if (row.status === 'failed') {
      badges.push(h(Tip, { key: 'f', label: row.error || TA.notApplied }, h(Badge, { variant: 'destructive' }, TA.notApplied)))
    }
  } else if (row.outcome === 'allowed') {
    badges.push(h(Badge, { key: 'b', variant: 'success' }, TA.allowed))
  } else if (row.outcome === 'denied') {
    badges.push(h(Badge, { key: 'b', variant: 'destructive' }, TA.denied))
  }

  return h('div', { style: SA.badges }, badges)
}

function ChatButton({ row }) {
  const label = row.chat_title ? TA.openChatTitled(row.chat_title) : TA.openChat

  return h(
    Tip,
    { label },
    h(
      Button,
      { 'aria-label': label, onClick: () => openChat(row.chat), size: 'icon-xs', type: 'button', variant: 'ghost' },
      h(Codicon, { name: 'comment-discussion', size: '0.875rem' })
    )
  )
}

function ActivityRow({ row }) {
  const lifecycle = row.kind === 'lifecycle'
  const icon = lifecycle ? (row.event === 'started' ? 'debug-start' : 'debug-stop') : ROW_ICONS[row.kind] || 'circle-filled'
  const sub = activitySub(row)
  const title = activityTitle(row)

  return h(
    'div',
    { 'data-activity-kind': row.kind, 'data-outcome': row.outcome, style: SA.row },
    h('span', { style: SA.time, title: new Date(row.t * 1000).toLocaleString() }, when(row.t)),
    h('span', { style: SA.icon }, h(Codicon, { name: icon, size: '0.875rem' })),
    h(
      'div',
      { style: S.rowText },
      h(
        'div',
        { className: lifecycle || row.class === 'CONFIG' ? undefined : 'font-mono', style: { ...S.rowTitle, ...(lifecycle ? SA.quietTitle : null) }, title: row.title },
        title
      ),
      sub ? h('div', { style: S.rowSub, title: sub }, sub) : null
    ),
    h(ActivityBadges, { row }),
    h('div', { style: S.action }, row.chat ? h(ChatButton, { row }) : null)
  )
}

/** Save *records* as a JSON Lines file (the desktop asks where, starting in Downloads). */
function saveJsonl(filename, records) {
  const text = records.map(record => JSON.stringify(record)).join('\n') + (records.length ? '\n' : '')
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-ndjson' }))
  const link = document.createElement('a')

  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

function ActivityToolbar({ filter, exporting, onExport }) {
  const set = patch => $activityFilter.set({ ...$activityFilter.get(), ...patch })

  return h(
    'div',
    { style: SA.toolbar },
    h(
      'div',
      { style: SA.group },
      h(SegmentedControl, { onChange: kind => set({ kind }), options: KIND_OPTIONS, sizing: 'content', value: filter.kind }),
      h('label', { style: SA.check }, h(Checkbox, { checked: filter.denied, onCheckedChange: value => set({ denied: value === true }), style: SA.checkbox }), TA.deniedOnly)
    ),
    h(
      'div',
      { style: SA.group },
      h(
        Select,
        { onValueChange: window => set({ window }), value: filter.window },
        h(SelectTrigger, { 'aria-label': TA.period, className: 'w-36', size: 'sm' }, h(SelectValue, null)),
        h(
          SelectContent,
          null,
          Object.keys(WINDOW_SECONDS).map(key => h(SelectItem, { key, value: key }, TA.windows[key]))
        )
      ),
      h(
        Button,
        { disabled: exporting, loading: exporting, onClick: onExport, size: 'sm', type: 'button', variant: 'outline' },
        h(Codicon, { name: 'export', size: '0.875rem' }),
        TA.export
      )
    )
  )
}

function revisionDestinations(policy) {
  return Object.entries(policy?.network_policies || {})
    .filter(([name]) => !name.startsWith('_provider_'))
    .flatMap(([, rule]) =>
      (rule?.endpoints || []).map(ep => {
        const target = ep.host || ep.cidr || ep.ip || '?'
        const ports = ep.port ?? (Array.isArray(ep.ports) ? ep.ports.join(', ') : ep.ports)

        return ports ? `${target} · ${T.portLabel(ports)}` : target
      })
    )
}

function RestoreDialog({ version, status, send, onClose }) {
  const detail = useQuery({
    queryKey: keyFor(status.profile, ['revision', version]),
    queryFn: () => rest(`/policy/revisions/${version}`),
    retry: false
  })

  const destinations = detail.data ? revisionDestinations(detail.data.policy) : null
  const body = status.capabilities?.network_live_interrupts ? `${TA.restoreBody} ${TA.restoreCuts}` : TA.restoreBody

  return h(
    ConfirmDialog,
    {
      confirmLabel: TA.restoreConfirm,
      description: body,
      onClose,
      onConfirm: () => send('/policy/rollback', 'POST', { version }, ROLLBACK_TIMEOUT_MS),
      open: true,
      title: TA.restoreTitle(version)
    },
    h(
      'div',
      { className: 'font-mono', style: SA.destinations },
      destinations === null
        ? detail.error
          ? errorText(detail.error)
          : TA.loading
        : destinations.length
          ? destinations.join('\n')
          : TA.noDestinations
    )
  )
}

function PolicyHistory({ status, send }) {
  const running = Boolean(status.sandboxed) && status.state === 'running'
  const busyBySession = useValue(host.state.busyBySession)
  const turnRunning = Object.values(busyBySession || {}).some(Boolean)
  const [restoring, setRestoring] = useState(null)

  const revisions = useQuery({
    queryKey: keyFor(status.profile, 'revisions'),
    queryFn: () => polled('/policy/revisions'),
    refetchInterval: REVISIONS_POLL_MS,
    ...LIVE,
    enabled: running
  })

  if (!status.capabilities?.policy_revisions) {
    return null
  }

  let rows

  if (!running) {
    rows = [h('div', { key: 'off', style: S.empty }, TA.historyOff)]
  } else if (!revisions.data) {
    rows = [
      revisions.error
        ? h('div', { className: 'text-destructive', key: 'err', style: S.empty }, errorText(revisions.error))
        : h('div', { key: 'load', style: { padding: '0.75rem 0.875rem' } }, h(Skeleton, { style: { height: '1.25rem' } }))
    ]
  } else {
    const active = revisions.data.active_version

    rows = revisions.data.revisions.map(rev => {
      const current = rev.version === active
      const label = current ? TA.revisionStatus.loaded : TA.revisionStatus[rev.status] || rev.status
      const created = rev.created_at_ms ? when(rev.created_at_ms / 1000) : null

      const restore = h(
        Button,
        { disabled: turnRunning, onClick: () => setRestoring(rev.version), size: 'sm', type: 'button', variant: 'outline' },
        TA.restore
      )

      return h(Row, {
        key: rev.version,
        title: TA.revision(rev.version),
        sub: [created, rev.hash ? String(rev.hash).slice(0, 12) : null].filter(Boolean).join(' · '),
        meta: h(
          Tip,
          { label: rev.load_error || label },
          h(Badge, { variant: current ? 'success' : rev.status === 'failed' ? 'destructive' : 'muted' }, label)
        ),
        access:
          current || rev.status === 'failed'
            ? null
            : turnRunning
              ? h(Tip, { label: T.restartBusyTip }, h('span', null, restore))
              : restore
      })
    })
  }

  return h(
    Section,
    { title: TA.history },
    h(List, null, rows),
    restoring !== null ? h(RestoreDialog, { onClose: () => setRestoring(null), send, status, version: restoring }) : null
  )
}

function ActivityView({ status, send }) {
  const filter = useValue($activityFilter)
  const activity = useActivity(status.profile, filter)
  const [exporting, setExporting] = useState(false)

  const runExport = async () => {
    setExporting(true)

    try {
      const data = await rest(`/activity/export?${activityParams(filter)}`)
      saveJsonl(data.filename, data.records)
    } catch (error) {
      host.notify({ kind: 'error', message: errorText(error) })
    } finally {
      setExporting(false)
    }
  }

  const data = activity.data
  let body

  if (activity.error && !data) {
    body = h(List, null, [h('div', { className: 'text-destructive', key: 'err', style: S.empty }, errorText(activity.error))])
  } else if (!data) {
    body = h(Skeleton, { style: { height: '9rem' } })
  } else if (!data.rows.length) {
    body = h(List, null, [h('div', { key: 'none', style: S.empty }, filter.denied ? TA.emptyDenied : TA.empty)])
  } else {
    body = h(List, null, data.rows.map(row => h(ActivityRow, { key: row.id, row })))
  }

  return h(
    'div',
    null,
    h(ActivityToolbar, { exporting, filter, onExport: runExport }),
    body,
    data?.truncated ? h('p', { style: S.caption }, TA.truncated(data.rows.length)) : null,
    h(PolicyHistory, { send, status })
  )
}

function PageTabs() {
  const tab = useValue($pageTab)

  return h(
    Tabs,
    { onValueChange: value => $pageTab.set(value), style: SA.tabs, value: tab },
    h(TabsList, { style: SA.tabsList }, h(TabsTrigger, { value: 'settings' }, TA.settings), h(TabsTrigger, { value: 'activity' }, TA.activity))
  )
}

// -- page -------------------------------------------------------------------------------------------

function Dialogs({ dialog, setDialog, send }) {
  if (!dialog) {
    return null
  }

  const close = () => setDialog(null)

  if (dialog.kind === 'confirm') {
    return h(
      ConfirmDialog,
      {
        confirmLabel: dialog.confirmLabel,
        description: dialog.body,
        destructive: Boolean(dialog.destructive),
        onClose: close,
        onConfirm: dialog.run,
        open: true,
        title: dialog.title
      },
      dialog.target
        ? dialog.list
          ? h('div', { className: 'font-mono', style: S.confirmList }, byComma(dialog.target))
          : h('div', { className: 'font-mono', style: S.confirmTarget }, dialog.target)
        : null
    )
  }

  const Component = { destination: AddDestinationDialog, folder: AddFolderDialog, key: KeyDialog }[dialog.kind]

  return h(Component, { ask: setDialog, dialog, onClose: close, send })
}

function Loading() {
  return h(
    'div',
    { style: S.column },
    h(Skeleton, { style: { height: '1.75rem', width: '12rem' } }),
    h(Skeleton, { style: { height: '1rem', marginTop: '0.75rem', width: '24rem' } }),
    h(Skeleton, { style: { height: '9rem', marginTop: '2.5rem' } })
  )
}

function SandboxPage() {
  const profile = useActiveProfile()
  const status = useStatus(profile, LIVE)
  const config = usePolled(profile, 'config')
  const keys = usePolled(profile, 'keys')
  // Live: a card answered in a chat shows up here within a poll.
  const grants = usePolled(profile, 'grants', STATUS_POLL_MS)
  // What the sandbox changed among the files that run on this computer: read when the page opens, after every
  // switch and edit (they invalidate it), and again whenever the status says the watched files changed (its
  // stamp, below). It has no timer of its own: the launcher walks the profile folder for it. For a profile that
  // is off the host route answers it, with the last session's changes.
  const wanted = reviewWanted(status.data)
  const handback = useQuery({
    queryKey: keyFor(profile, 'handback'),
    queryFn: () => rest('/handback'),
    // A profile that is off has a list only when its last session ended without a review (status.handback.open)
    // or kept items are to be listed.
    enabled: wanted,
    refetchInterval: false,
    retry: false
  })
  const { send, sendQuietly, pending } = useSend(profile)
  const [dialog, setDialog] = useState(null)
  const tab = useValue($pageTab)
  const queryClient = useQueryClient()
  const stamp = status.data?.handback?.stamp

  useEffect(() => {
    followReview(queryClient, profile, stamp, wanted)
  }, [profile, stamp, wanted])

  // What the launcher changed by itself is read again with the status that shows it.
  const changed = launcherStamp(status.data)

  useEffect(() => {
    followLauncher(queryClient, profile, changed)
  }, [profile, changed])

  // After a switch-back from a launcher that said nothing, the launcher's last answer is not shown as a state.
  const left = leftView(status, profile)
  const lost = left ? null : lostView(status)

  useEffect(() => {
    followLost(queryClient, profile, lost)
  }, [profile, Boolean(lost), Boolean(lost?.off)])
  // The host check runs again each time the page opens for an unsandboxed profile (the status poll
  // reuses the backend's answer for a minute).
  const checkHost = Boolean(status.data) && !status.data.sandboxed

  useEffect(() => {
    if (checkHost) {
      void recheckHost(profile, queryClient)
    }
  }, [profile, checkHost])

  const failed = status.error || config.error

  if (failed && !status.data) {
    const code = statusCode(failed)

    return h(EmptyState, { description: code === 404 ? T.notEnabled : errorText(failed), title: T.unavailable })
  }

  if (!status.data || !config.data) {
    return h(Loading)
  }

  const shared = { ask: setDialog, config: config.data, pending, send, sendQuietly, status: status.data }
  // While the launcher is gone nothing here can be answered: the notice says what happened and what to do.
  const review = lost || left ? undefined : reviewView(status.data, handback.data)
  const providers = lost || left ? undefined : providersView(status.data, config.data)

  return h(
    'div',
    { style: S.scroll },
    h(
      'div',
      { style: S.column },
      h(Header, { handback: review, left, lost, providers, status: status.data }),
      h(LostBar, { lost, profile }),
      h(LeftBar, { left, profile }),
      h(StillOnBar, { status: status.data }),
      h(HandbackCard, { providers, status: status.data, view: review }),
      h(KeptLine, { items: handback.data?.kept, status: status.data }),
      h(CompatBar, { status: status.data }),
      h(ProvidersBar, { ask: setDialog, pending, send, view: providers }),
      h(EndpointBar, { send, status: status.data }),
      h(RestartBar, { send, status: status.data }),
      h(PageTabs, null),
      tab === 'activity'
        ? h(ActivityView, { send, status: status.data })
        : h(
            'div',
            null,
            h(FoldersSection, shared),
            h(NetworkSection, shared),
            grants.data ? h(GrantsSection, { ask: setDialog, grants: grants.data, pending, send }) : null,
            h(ProvidersSection, { ask: setDialog, pending, send, view: providers }),
            keys.data ? h(KeysSection, { ask: setDialog, keys: keys.data, pending, send }) : null
          )
    ),
    h(Dialogs, { dialog, send, setDialog })
  )
}

function SandboxChip() {
  const profile = useActiveProfile()
  const status = useStatus(profile) || {}
  const queryClient = useQueryClient()
  const { data } = status
  const left = leftView(status, profile)
  const lost = left ? null : lostView(status)

  // The chip is in the status bar whatever page is open: this is where a switch-off made elsewhere is followed
  // within one poll of the status (the Sandbox page does the same while it is open; asked once between them).
  useEffect(() => {
    followLost(queryClient, profile, lost)
  }, [profile, Boolean(lost), Boolean(lost?.off)])

  // And where a sign-in that ended is said, once: the user may be in a chat, and the model may be what stopped.
  useEffect(() => {
    tellExpired(profile, data)
  }, [profile, signInsKey(data)])

  if (!data?.sandboxed || lost?.off) {
    return null
  }

  return h(
    Tip,
    { label: `${T.title}: ${left?.refused ? T.leftState : left || lost ? T.lostState : stateView(data).label}` },
    h(
      'button',
      { className: CHIP_CLASS, onClick: () => host.navigate(ROUTE), type: 'button' },
      h(Codicon, { name: 'lock', size: '0.7rem' }),
      h('span', null, T.chip)
    )
  )
}

// For the plugin's own tests (tests/js): the default export is all the desktop loads.
export const __test__ = {
  ActivityBadges,
  ActivityView,
  activitySub,
  Dialogs,
  followLauncher,
  keptOpen,
  launcherStamp,
  PolicyHistory,
  RestartBar,
  AlsoChanged,
  errorText,
  followLost,
  forgetTold: () => $told.set({}),
  LeftBar,
  leftView,
  LostBar,
  lostView,
  moveKeys,
  offered: () => $offered.get(),
  policySummary,
  ProvidersBar,
  ProvidersSection,
  providersView,
  SandboxChip,
  stillMarked,
  StillOnBar,
  switchBack,
  CompatBar,
  HandbackCard,
  EndpointBar,
  endpointsDismissed: () => $endpointsDismissed.get(),
  followReview,
  GrantsSection,
  Header,
  hostProblem,
  KeptLine,
  NetworkSection,
  Row,
  recheckHost,
  reviewView,
  reviewWanted,
  SandboxPage,
  SandboxSwitch,
  saveKey,
  T,
  tellExpired,
  seedStatus,
  KeyDialog,
  setSwitching: value => $switching.set(value),
  settle,
  stateView,
  switchState: () => $switching.get(),
  turnOff,
  turnOn,
  useOs: api => {
    osApi = api
  },
  useRest: fn => {
    rest = fn
  },
  withheldEndpoints
}

export default {
  id: 'openshell',
  name: 'OpenShell',
  register(ctx) {
    rest = ctx.rest
    osApi = ctx.os || null
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: ROUTE }, render: () => h(SandboxPage) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: ROUTE, label: T.title, codicon: 'shield' } },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: { id: 'openshell.open', label: T.openCommand, keywords: ['sandbox', 'openshell', 'folders', 'network'], run: () => host.navigate(ROUTE) }
      },
      { id: 'chip', area: STATUSBAR_AREAS.right, order: 70, render: () => h(SandboxChip) }
    ])
  }
}
