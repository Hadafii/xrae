// LAYER: infrastructure
// JOB:   Build a Discord message payload. Nothing else - no HTTP here.
//
// ============================================================================
// DISCORD COMPONENTS V2 - the rules that are easy to get wrong
// ============================================================================
//  - Set the message flag IS_COMPONENTS_V2 = 1 << 15 = 32768.
//  - When executing a WEBHOOK you must also add ?with_components=true to the
//    URL, or the components are silently ignored.
//  - Once the flag is set, `content` and `embeds` are FORBIDDEN. Everything
//    goes inside `components`.
//  - A plain incoming webhook cannot receive interaction events, so any button
//    must be a LINK button (style 5). A button with a custom_id will render but
//    do nothing when clicked.
//  - The flag cannot be removed from a message later.
//
// Component types used here:
//   17 Container    a visual block with an accent colour
//   10 TextDisplay  markdown text
//   14 Separator    a divider line
//    9 Section      text with an accessory (our link button)
//    2 Button
// ============================================================================

import { ResponseLevel } from '../../domain/policy.js';
import { Confidence } from '../../domain/confidence.js';

export const IS_COMPONENTS_V2 = 1 << 15;

const COMPONENT = { ACTION_ROW: 1, BUTTON: 2, SECTION: 9, TEXT_DISPLAY: 10, SEPARATOR: 14, CONTAINER: 17 };

const ACCENT_COLOR = {
  [Confidence.CRITICAL]: 0xe5484d,
  [Confidence.HIGH]: 0xf76b15,
  [Confidence.MEDIUM]: 0xf5c518,
  [Confidence.LOW]: 0x3b82f6,
  info: 0x22c55e,
};

const BADGE = {
  [Confidence.CRITICAL]: '🔴',
  [Confidence.HIGH]: '🟠',
  [Confidence.MEDIUM]: '🟡',
  [Confidence.LOW]: '🔵',
  info: '🟢',
};

const HEADLINE = {
  [ResponseLevel.SUSPEND]: '⛔ Server suspended',
  [ResponseLevel.THROTTLE]: '🐌 Server CPU throttled',
  [ResponseLevel.ALERT]: '👁 Flagged for review — no action taken',
  [ResponseLevel.OBSERVE]: '📋 Observation only',
  [ResponseLevel.BLOCKED]: '🛑 Action withheld by safety guardrail',
};

const FAMILY_HEADING = {
  signature: 'Known-bad content',
  structure: 'File structure',
  entropy: 'Packing / entropy',
  behavior: 'Runtime behaviour',
  network: 'Network activity',
};

/**
 * Server names are chosen by tenants, which makes them untrusted input.
 * Without this, a server called "@everyone `**`" could ping the whole staff
 * channel and forge fake fields in our own alert.
 */
export function sanitiseForDiscord(value, maxLength = 96) {
  const cleaned = String(value ?? '')
    .replace(/[`*_~|\\>#]/g, '')
    .replace(/@(everyone|here)/gi, '@\u200bblocked')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
  return cleaned || 'unknown';
}

function truncate(text, maxLength) {
  return text.length <= maxLength ? text : text.slice(0, maxLength - 1) + '…';
}

const textDisplay = (content) => ({ type: COMPONENT.TEXT_DISPLAY, content });
const separator = (large = false) => ({ type: COMPONENT.SEPARATOR, divider: true, spacing: large ? 2 : 1 });

export class ComponentsV2Builder {
  /** @param {object} options @param {string} [options.panelBaseUrl] @param {number} [options.nodeId] */
  constructor({ panelBaseUrl = '', nodeId = 0 } = {}) {
    this.panelBaseUrl = panelBaseUrl.replace(/\/+$/, '');
    this.nodeId = nodeId;
  }

  /** Which agent sent this - one glance in a channel fed by a whole fleet. */
  #username() {
    return this.nodeId ? `X-Rae · node ${this.nodeId}` : 'X-Rae';
  }

  /**
   * @param {import('../../application/ports.js').AlertReport} report
   * @returns {object} a webhook payload
   */
  buildAlert(report) {
    const { server, verdict, decision, riskThreshold, failureNote } = report;
    const badge = BADGE[verdict.confidence] ?? BADGE.info;

    const children = [
      textDisplay(`## ${badge} ${HEADLINE[decision.level] ?? 'Detection'}`),
      textDisplay(`### ${sanitiseForDiscord(server.name)}\n\`${sanitiseForDiscord(server.identifier, 32)}\` · node \`${server.nodeId}\``),
      separator(),
      textDisplay(
        [
          `**Confidence** \`${verdict.confidence.toUpperCase()}\``,
          `**Risk score** \`${Math.round(verdict.totalScore)} / ${riskThreshold}\``,
          `**Seen in** \`${verdict.detections}\` consecutive cycle(s)`,
          `**Evidence families** \`${verdict.families.length}\``,
        ].join('\n'),
      ),
    ];

    const evidence = this.#renderEvidence(verdict.reasons);
    if (evidence) {
      children.push(separator(), textDisplay(evidence));
    }

    // Always explain the decision. An operator who cannot see why X-Rae acted
    // cannot defend the action to a customer.
    children.push(separator(), textDisplay(`**Why this outcome**\n${truncate(sanitiseForDiscord(decision.reason, 400), 400)}`));

    if (failureNote) {
      children.push(textDisplay(`⚠️ ${truncate(sanitiseForDiscord(failureNote, 200), 200)}`));
    }

    const serverUrl = this.#serverUrl(server.identifier);
    if (serverUrl) {
      children.push(separator(true));
      children.push({
        type: COMPONENT.SECTION,
        components: [textDisplay('Check the server before acting on this alert.')],
        accessory: { type: COMPONENT.BUTTON, style: 5, label: 'Open in panel', url: serverUrl },
      });
    }

    children.push(textDisplay(`-# X-Rae · <t:${Math.floor(Date.now() / 1000)}:R>`));

    return {
      username: this.#username(),
      flags: IS_COMPONENTS_V2,
      allowed_mentions: { parse: [] },
      components: [
        {
          type: COMPONENT.CONTAINER,
          accent_color: ACCENT_COLOR[verdict.confidence] ?? ACCENT_COLOR.info,
          components: children,
        },
      ],
    };
  }

  /** @param {{title: string, body: string, level: string}} notice */
  buildNotice({ title, body, level = 'info' }) {
    return {
      username: this.#username(),
      flags: IS_COMPONENTS_V2,
      allowed_mentions: { parse: [] },
      components: [
        {
          type: COMPONENT.CONTAINER,
          accent_color: ACCENT_COLOR[level] ?? ACCENT_COLOR.info,
          components: [
            textDisplay(`## ${BADGE[level] ?? BADGE.info} ${sanitiseForDiscord(title, 120)}`),
            separator(),
            textDisplay(truncate(body, 3000)),
            textDisplay(`-# X-Rae · <t:${Math.floor(Date.now() / 1000)}:R>`),
          ],
        },
      ],
    };
  }

  /** Fallback for the rare case Discord rejects a V2 payload. */
  buildLegacyAlert(report) {
    const { server, verdict, decision, riskThreshold } = report;
    const grouped = groupReasons(verdict.reasons);

    return {
      username: this.#username(),
      allowed_mentions: { parse: [] },
      embeds: [
        {
          title: `${BADGE[verdict.confidence] ?? ''} ${HEADLINE[decision.level] ?? 'Detection'}`.trim(),
          description:
            `**${sanitiseForDiscord(server.name)}** (\`${sanitiseForDiscord(server.identifier, 32)}\`)\n` +
            `Confidence **${verdict.confidence.toUpperCase()}** · score **${Math.round(verdict.totalScore)}/${riskThreshold}**\n\n` +
            truncate(sanitiseForDiscord(decision.reason, 500), 500),
          color: ACCENT_COLOR[verdict.confidence] ?? ACCENT_COLOR.info,
          fields: [...grouped].slice(0, 5).map(([family, items]) => ({
            name: FAMILY_HEADING[family] ?? family,
            value: truncate(items.slice(0, 4).map((i) => `• ${sanitiseForDiscord(i.detail, 90)}`).join('\n'), 1000) || '—',
          })),
          timestamp: new Date().toISOString(),
          footer: { text: 'X-Rae' },
        },
      ],
    };
  }

  #renderEvidence(reasons = []) {
    if (reasons.length === 0) return '';

    const grouped = groupReasons(reasons);
    const lines = [];
    const maxShown = 12;
    let shown = 0;

    for (const [family, items] of grouped) {
      if (shown >= maxShown) break;
      lines.push(`**${FAMILY_HEADING[family] ?? family}**`);
      for (const item of items) {
        if (shown >= maxShown) break;
        lines.push(`> \`${sanitiseForDiscord(item.ruleId, 44)}\` ${sanitiseForDiscord(item.detail, 110)}`);
        shown += 1;
      }
    }

    const hidden = reasons.length - shown;
    if (hidden > 0) lines.push(`-# ${hidden} further indicator(s) not shown`);
    return truncate(lines.join('\n'), 3800);
  }

  #serverUrl(identifier) {
    if (!this.panelBaseUrl) return null;
    const safe = String(identifier ?? '').replace(/[^a-zA-Z0-9_-]/g, '');
    return safe ? `${this.panelBaseUrl}/server/${safe}` : null;
  }
}

function groupReasons(reasons) {
  const grouped = new Map();
  for (const reason of reasons) {
    const family = reason.family ?? 'other';
    if (!grouped.has(family)) grouped.set(family, []);
    grouped.get(family).push(reason);
  }
  return grouped;
}
